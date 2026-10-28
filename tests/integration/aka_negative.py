#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA refusals at the P-CSCF and the SIP core; run inside a digest client's container of the aka lab, for an
IMS AKA identity that no client registers with.

AKA-01: a REGISTER to the P-CSCF's unprotected port without a Security-Client offering ipsec-3gpp is answered 421
(Extension Required) with "Require: sec-agree" (RFC 3329 clause 2.3.1, TS 33.203 annex P.3). AKA-02: a REGISTER of
a SIP digest private user identity through the P-CSCF is refused with 403 (TS 29.228 clause 6.3.1 step 4). AKA-03: a
SIP digest REGISTER of an IMS AKA identity to the SIP core is refused with 403 (TS 33.180 clause 6.2.1). AKA-04: an
initial REGISTER of the IMS AKA identity through the P-CSCF is challenged twice, AKAv2-SHA-256 first and then
AKAv1-MD5 (TS 33.203 clause 6.1.1), with one nonce of RAND and AUTN (32 bytes), qop "auth" and a Security-Server, and
without the ck and ik meant for the P-CSCF (TS 24.229 clauses 5.2.2.2 and 5.4.1.2.1A, TS 37.579-1 table
5.5.2.19.7-1); the Via carries received (TS 24.229 clause 5.2.2.2 item 2 c)). AKA-05: a Security-Client with an
integrity algorithm TS 33.203 clause 6.3 does not define is refused with 400 (TS 33.203 clause 7.1, RFC 3329).
AKA-07: a Security-Client offering only hmac-md5-96 and des-ede3-cbc, removed from TS 33.203 V19.1.0 annex H, is
refused with 400. AKA-08: the Security-Server of the AKA-04 challenge lists the P-CSCF's algorithm combinations by
priority (TS 33.203 clause 7.2, SM6). AKA-09: a new challenge deletes the registration SAs of the IMPI (TS 33.203
clauses 7.3.1.4 and 7.4.2a), so incomplete authentications never reach the six SAs per direction of clause 7.1 rule
3: three more initial REGISTERs of the IMS AKA identity (other protected ports, new SPIs) are all challenged; the
deletion of the earlier temporary sets is checked at the P-CSCF by aka_negative_scenario.py.

Example: python3 aka_negative.py --config /config/client-c.json --aka-identity sip:alice@mcx.test \
    --aka-impi alice@mcx.test

Specifications: TS 24.229 V19.7.0, TS 29.228 V19.2.0, TS 33.180 V19.4.0, TS 33.203 V19.1.0 (Rel-19); TS 37.579-1
V18.1.0; RFC 3329.
"""

import argparse
import base64
import json
import re
import secrets
import socket
import ssl


# ------------------------------------------------------------------------------
def exchange(sock, text):
    """Send one request on sock and return the first final response: (code, header lines)."""
    sock.sendall(text.encode())
    buffer = b""
    while True:
        while b"\r\n\r\n" not in buffer:
            data = sock.recv(65536)
            if not data:
                return 0, []
            buffer += data
        head, buffer = buffer.split(b"\r\n\r\n", 1)
        lines = head.decode(errors="replace").split("\r\n")
        length = next((int(line.split(":", 1)[1]) for line in lines if line.lower().startswith("content-length:")), 0)
        buffer = buffer[length:]
        code = int(lines[0].split()[1])
        if code >= 200:
            return code, lines[1:]


# ------------------------------------------------------------------------------
def register(sock, transport, identity, impi, domain, extra=""):
    """An initial REGISTER of identity with an empty-nonce Authorization for impi (TS 24.229 clause 5.1.1.2.2)."""
    host, port = sock.getsockname()[:2]
    call_id = f"aka-negative-{secrets.token_hex(12)}"
    user = identity.split(":", 1)[1].split("@", 1)[0]
    return exchange(
        sock,
        f"REGISTER sip:{domain} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport} {host}:{port};branch=z9hG4bK{secrets.token_hex(12)};rport\r\n"
        "Max-Forwards: 16\r\n"
        f"From: <{identity}>;tag={secrets.token_hex(8)}\r\n"
        f"To: <{identity}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{user}@{host}:{port};transport={transport.lower()}>\r\n"
        "Expires: 600\r\n"
        "Supported: path\r\n"
        f'Authorization: Digest username="{impi}", realm="{domain}", uri="sip:{domain}", nonce="", response=""\r\n'
        f"{extra}Content-Length: 0\r\n\r\n",
    )


# ------------------------------------------------------------------------------
def main():
    """Run AKA-01 to AKA-09 (no AKA-06: aka_protected_ports.py); print and write the result as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--aka-identity", required=True)
    parser.add_argument("--aka-impi", required=True)
    parser.add_argument("--disable-tls", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    cfg = json.load(open(args.config))
    domain = cfg["sip"]["identity"].split("@", 1)[1]
    digest_identity, digest_user = cfg["sip"]["identity"], cfg["sip"]["username"]

    def offer(port_c):
        """A Security-Client with new SPIs and the protected ports port_c, port_c + 1."""
        return (
            "Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;"
            f"spi-c={secrets.randbelow(1 << 30) + 4096};spi-s={secrets.randbelow(1 << 30) + 4096};"
            f"port-c={port_c};port-s={port_c + 1}\r\n"
            "Require: sec-agree\r\nProxy-Require: sec-agree\r\n"
        )

    security_client = offer(40100)
    checks = []

    def check(name, passed, detail):
        checks.append(dict(name=name, passed=bool(passed), detail=detail))

    def pcscf():
        return socket.create_connection(("pcscf", 5060), timeout=10)

    with pcscf() as sock:
        code, headers = register(sock, "TCP", args.aka_identity, args.aka_impi, domain)
        required = any(re.match(r"(?i)require:.*sec-agree", line) for line in headers)
        check("AKA-01 421 without Security-Client", code == 421 and required, f"{code}")
    with pcscf() as sock:
        code, _ = register(sock, "TCP", digest_identity, digest_user, domain, security_client)
        check("AKA-02 digest identity through the P-CSCF refused", code == 403, f"{code}")
    if args.disable_tls:
        core = socket.create_connection(("sip-core", 5060), timeout=10)
    else:
        context = ssl.create_default_context(cafile=cfg["tls"]["ca_file"])
        context.load_cert_chain(cfg["tls"]["cert_file"], cfg["tls"]["key_file"])
        core = context.wrap_socket(socket.create_connection(("sip-core", 5061), timeout=10), server_hostname="sip-core")
    with core:
        user = args.aka_identity.split(":", 1)[1].split("@", 1)[0]
        code, _ = register(core, "TLS" if not args.disable_tls else "TCP", args.aka_identity, user, domain)
        check("AKA-03 digest REGISTER of an AKA identity refused", code == 403, f"{code}")
    with pcscf() as sock:
        code, headers = register(sock, "TCP", args.aka_identity, args.aka_impi, domain, security_client)
        challenges = [line.split(":", 1)[1] for line in headers if line.lower().startswith("www-authenticate:")]
        algorithms = [re.search(r'(?i)algorithm="?([A-Za-z0-9-]+)', www) for www in challenges]
        nonces = {re.search(r'nonce="([^"]*)"', www).group(1) for www in challenges if re.search(r'nonce="', www)}
        try:
            nonce_length = len(base64.b64decode(next(iter(nonces)))) if len(nonces) == 1 else 0
        except ValueError:
            nonce_length = 0
        server = any(line.lower().startswith("security-server:") and "ipsec-3gpp" in line for line in headers)
        offered = []
        for line in headers:
            if line.lower().startswith("security-server:"):
                for mechanism in line.split(":", 1)[1].split(","):
                    alg = re.search(r"(?i);alg=([^;\s]+)", mechanism)
                    ealg = re.search(r"(?i);ealg=([^;\s]+)", mechanism)
                    offered.append((alg.group(1).lower() if alg else "", ealg.group(1).lower() if ealg else "null"))
        received = any(line.lower().startswith("via:") and "received=" in line for line in headers)
        check(
            "AKA-04 challenges AKAv2-SHA-256 then AKAv1-MD5, qop auth, Security-Server, no ck/ik, Via received",
            code == 401
            and [match.group(1) if match else "" for match in algorithms] == ["AKAv2-SHA-256", "AKAv1-MD5"]
            and all(re.search(r'(?i)qop="?auth', www) for www in challenges)
            and nonce_length == 32
            and server
            and received
            and not any(re.search(r"(?i)(^|[,\s])(ck|ik)\s*=", www) for www in challenges),
            f"{code} {' | '.join(www.strip()[:120] for www in challenges)}",
        )
    with pcscf() as sock:
        code, _ = register(
            sock,
            "TCP",
            args.aka_identity,
            args.aka_impi,
            domain,
            security_client.replace("hmac-sha-1-96", "hmac-sha-256"),
        )
        check("AKA-05 Security-Client with an unknown algorithm refused", code == 400, f"{code}")
    # AKA-07: only the algorithms removed from TS 33.203 V19.1.0 annex H ("Removal of hmac-md5-96", "Removal of
    # des-ede3-cbc"): refused with 400, also in a list of several mechanisms.
    with pcscf() as sock:
        removed = security_client.replace("alg=hmac-sha-1-96;ealg=aes-cbc", "alg=hmac-md5-96;ealg=des-ede3-cbc")
        removed = removed.replace("\r\nRequire:", ", " + removed.split("Security-Client: ", 1)[1].split("\r\n")[0]
                                  .replace("ealg=des-ede3-cbc", "ealg=aes-cbc") + "\r\nRequire:", 1)
        code, _ = register(sock, "TCP", args.aka_identity, args.aka_impi, domain, removed)
        check("AKA-07 Security-Client with only hmac-md5-96 / des-ede3-cbc refused", code == 400, f"{code}")
    # AKA-08 (TS 33.203 clause 7.2, SM6): the 401's Security-Server lists the P-CSCF's algorithm combinations by
    # priority (docker/pcscf.cfg IPSEC_ALGORITHMS), not only the selected one.
    expected = [("null", "aes-gcm-us"), ("null", "aes-gcm"), ("hmac-sha2-256-128", "aes-cbc"),
                ("hmac-sha-1-96", "aes-cbc"), ("aes-gmac-us", "null"), ("aes-gmac", "null"),
                ("hmac-sha2-256-128", "null"), ("hmac-sha-1-96", "null")]
    check("AKA-08 Security-Server lists the P-CSCF's algorithm combinations by priority", offered == expected,
          f"{offered}")
    # AKA-09 (TS 33.203 clauses 7.3.1.4 and 7.4.2a, 7.1 rule 3): the AKA-04 challenge left one temporary set of the
    # IMS AKA identity's IMPI; each further initial REGISTER, on a connection of its own (another contact of the same
    # IMPI), from other protected ports and with new SPIs, is challenged, its challenge deleting the earlier temporary
    # set first: never more than one set of the IMPI stays, none is refused.
    codes = []
    for port_c in (40110, 40120, 40130):
        with pcscf() as sock:
            code, _ = register(sock, "TCP", args.aka_identity, args.aka_impi, domain, offer(port_c))
            codes.append(code)
    check("AKA-09 incomplete authentications of one IMPI never refused", codes == [401, 401, 401], f"{codes}")
    result = dict(scenario="aka-negative", passed=all(item["passed"] for item in checks), checks=checks)
    if args.output:
        json.dump(result, open(args.output, "w"), indent=2)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
