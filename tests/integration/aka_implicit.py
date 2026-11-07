#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Probes of IMS AKA subscriptions with an implicit registration set, from a SIP digest client's container.

Phase "before" (the test card's keys not yet in the SIP database):
- IMP-03: a SIP digest REGISTER without Authorization of the IMS AKA client's barred ISIM identity, at the SIP core,
  is refused: its private user identity, derived from the public user identity (TS 33.203 clause P.6 with the rule of
  TS 24.229), has IMS AKA as its scheme (TS 29.228 clause 6.3.1 step 4, TS 33.180 clause 6.2.1).
- IMP-05: an IMS AKA REGISTER of the test card's identity through the P-CSCF is refused, 403: no authentication data.
Phase "after" (keys loaded by tools/load-card-keys.py):
- IMP-06: the same REGISTER is challenged, 401 (TS 24.229 clause 5.4.1.2.1A).

Specifications: TS 24.229 V19.7.0, TS 29.228 V19.2.0, TS 33.180 V19.5.0, TS 33.203 V19.1.0, TS 23.228 V19.8.0.
"""

import argparse
import json
import secrets
import socket
import ssl


def exchange(sock, text):
    """Send one request, read the final response; (status code, header lines)."""
    sock.sendall(text.encode())
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
        while b"\r\n\r\n" in data:
            head, _, data = data.partition(b"\r\n\r\n")
            lines = head.decode(errors="replace").split("\r\n")
            code = int(lines[0].split()[1])
            if code >= 200:
                return code, lines[1:]
    raise ConnectionError("no final response")


def register(sock, transport, identity, domain, impi=None, extra=""):
    """An initial REGISTER of identity; with impi an empty-nonce Authorization (TS 24.229 clause 5.1.1.2.2)."""
    host, port = sock.getsockname()[:2]
    user = identity.split(":", 1)[1].split("@", 1)[0]
    authorization = (f'Authorization: Digest username="{impi}", realm="{domain}", uri="sip:{domain}", nonce="", '
                     'response=""\r\n') if impi else ""
    return exchange(
        sock,
        f"REGISTER sip:{domain} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport} {host}:{port};branch=z9hG4bK{secrets.token_hex(12)};rport\r\n"
        "Max-Forwards: 16\r\n"
        f"From: <{identity}>;tag={secrets.token_hex(8)}\r\n"
        f"To: <{identity}>\r\n"
        f"Call-ID: aka-implicit-{secrets.token_hex(12)}\r\n"
        "CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{user}@{host}:{port};transport={transport.lower()}>\r\n"
        "Expires: 600\r\n"
        "Supported: path\r\n"
        f"{authorization}{extra}Content-Length: 0\r\n\r\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--phase", choices=["before", "after"], required=True)
    parser.add_argument("--barred-identity", required=True, help="the IMS AKA client's barred ISIM identity")
    parser.add_argument("--card-identity", required=True)
    parser.add_argument("--card-impi", required=True)
    parser.add_argument("--disable-tls", action="store_true")
    args = parser.parse_args()
    cfg = json.load(open(args.config))
    domain = cfg["sip"]["identity"].split("@", 1)[1]
    checks = []

    def check(name, passed, detail):
        checks.append(dict(name=name, passed=bool(passed), detail=detail))

    security_client = (
        "Security-Client: ipsec-3gpp;alg=hmac-sha2-256-128;ealg=aes-cbc;prot=esp;mod=trans;"
        f"spi-c={secrets.randbelow(1 << 30) + 4096};spi-s={secrets.randbelow(1 << 30) + 4096};"
        "port-c=40200;port-s=40201\r\nRequire: sec-agree\r\nProxy-Require: sec-agree\r\n"
    )
    if args.phase == "before":
        if args.disable_tls:
            core = socket.create_connection(("sip-core", 5060), timeout=10)
        else:
            context = ssl.create_default_context(cafile=cfg["tls"]["ca_file"])
            context.load_cert_chain(cfg["tls"]["cert_file"], cfg["tls"]["key_file"])
            core = context.wrap_socket(socket.create_connection(("sip-core", 5061), timeout=10),
                                       server_hostname="sip-core")
        with core:
            code, _ = register(core, "TCP" if args.disable_tls else "TLS", args.barred_identity, domain)
            check("IMP-03 digest REGISTER of a card-style identity refused by its derived IMPI", code == 403, f"{code}")
        with socket.create_connection(("pcscf", 5060), timeout=10) as sock:
            code, _ = register(sock, "TCP", args.card_identity, domain, args.card_impi, security_client)
            check("IMP-05 card subscription without its keys refused", code == 403, f"{code}")
    else:
        with socket.create_connection(("pcscf", 5060), timeout=10) as sock:
            code, headers = register(sock, "TCP", args.card_identity, domain, args.card_impi, security_client)
            challenged = any(line.lower().startswith("www-authenticate:") and "AKAv" in line for line in headers)
            check("IMP-06 card subscription challenged once its keys are loaded", code == 401 and challenged,
                  f"{code}")
    print(json.dumps(dict(passed=all(c["passed"] for c in checks), checks=checks)))


if __name__ == "__main__":
    main()
