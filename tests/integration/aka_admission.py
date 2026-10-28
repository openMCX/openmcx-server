#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA admission at the P-CSCF; run inside a digest client's container of the aka lab, for the IMS AKA identity
that no client registers with (as aka_negative.py). Initial REGISTERs only: no SM7 is ever sent.

--step lost: two challenged REGISTERs left without SM7 (lost challenges), then a third one is challenged too, not
refused (TS 33.203 clauses 7.3.1.4 and 7.4.2a: the new challenge deletes the registration SAs of the earlier ones).
Ports 40200, 40210, 40220.
--step parallel: six REGISTERs of the IMPI sent at once on six connections (ports 40300 to 40350), the responses
read afterwards: each is 401 or 400 (TS 33.203 clause 7.1 rule 3, admission atomic with the count).
Prints one JSON line: {"codes": {port: code}}.

Specifications: TS 24.229 V19.7.0, TS 33.203 V19.1.0 (Rel-19); RFC 3329.
"""

import argparse
import json
import secrets
import socket


def request(sock, identity, impi, domain, port_c):
    host, port = sock.getsockname()[:2]
    user = identity.split(":", 1)[1].split("@", 1)[0]
    return (
        f"REGISTER sip:{domain} SIP/2.0\r\n"
        f"Via: SIP/2.0/TCP {host}:{port};branch=z9hG4bK{secrets.token_hex(12)};rport\r\n"
        "Max-Forwards: 16\r\n"
        f"From: <{identity}>;tag={secrets.token_hex(8)}\r\n"
        f"To: <{identity}>\r\n"
        f"Call-ID: aka-admission-{secrets.token_hex(12)}\r\n"
        "CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{user}@{host}:{port};transport=tcp>\r\n"
        "Expires: 600\r\n"
        "Supported: path\r\n"
        f'Authorization: Digest username="{impi}", realm="{domain}", uri="sip:{domain}", nonce="", response=""\r\n'
        "Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;"
        f"spi-c={secrets.randbelow(1 << 30) + 4096};spi-s={secrets.randbelow(1 << 30) + 4096};"
        f"port-c={port_c};port-s={port_c + 1}\r\n"
        "Require: sec-agree\r\nProxy-Require: sec-agree\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


def final_code(sock):
    buffer = b""
    while True:
        while b"\r\n\r\n" not in buffer:
            data = sock.recv(65536)
            if not data:
                return 0
            buffer += data
        head, buffer = buffer.split(b"\r\n\r\n", 1)
        lines = head.decode(errors="replace").split("\r\n")
        length = next((int(line.split(":", 1)[1]) for line in lines if line.lower().startswith("content-length:")), 0)
        buffer = buffer[length:]
        code = int(lines[0].split()[1])
        if code >= 200:
            return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--aka-identity", required=True)
    parser.add_argument("--aka-impi", required=True)
    parser.add_argument("--step", choices=["lost", "parallel"], required=True)
    args = parser.parse_args()
    domain = json.load(open(args.config))["sip"]["identity"].split("@", 1)[1]
    codes = {}
    if args.step == "lost":
        for port_c in (40200, 40210, 40220):
            with socket.create_connection(("pcscf", 5060), timeout=10) as sock:
                sock.sendall(request(sock, args.aka_identity, args.aka_impi, domain, port_c))
                codes[port_c] = final_code(sock)
    else:
        socks = {port_c: socket.create_connection(("pcscf", 5060), timeout=20) for port_c in range(40300, 40360, 10)}
        for port_c, sock in socks.items():
            sock.sendall(request(sock, args.aka_identity, args.aka_impi, domain, port_c))
        for port_c, sock in socks.items():
            with sock:
                codes[port_c] = final_code(sock)
    print(json.dumps(dict(codes=codes)))


if __name__ == "__main__":
    main()
