#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""AKA-06: no unprotected messages on the P-CSCF's protected ports; run inside an IMS AKA UE's container.

TS 33.203 clause 7.1: "No unprotected messages shall be sent from or received on the ports port_ps and port_pc."
From the UE's own address, but from a port no security association covers, a plaintext OPTIONS request goes to the
P-CSCF's protected server port (port_ps) and protected client port (port_pc), over TCP and UDP. The P-CSCF shall not
answer it: no SIP response may come back (the request is dropped, or the connection is refused or never set up).

  aka_protected_ports.py --config /config/client-a.json --status /artifacts/client-a/status.json

Prints one JSON line {"passed": ..., "checks": [...]}.

Specifications: TS 33.203 V19.1.0 (Rel-19); RFC 3261.
"""

import argparse
import json
import secrets
import socket


# ------------------------------------------------------------------------------
def options(transport, local, identity, domain):
    """A plaintext OPTIONS request of identity, with the UE's address in its Via (as a protected request has)."""
    branch = 'z9hG4bK' + secrets.token_hex(8)
    return (
        f'OPTIONS sip:{domain} SIP/2.0\r\n'
        f'Via: SIP/2.0/{transport} {local[0]}:{local[1]};branch={branch};rport\r\n'
        'Max-Forwards: 70\r\n'
        f'From: <{identity}>;tag={secrets.token_hex(4)}\r\n'
        f'To: <{identity}>\r\n'
        f'Call-ID: {secrets.token_hex(12)}@aka-protected-ports\r\n'
        'CSeq: 1 OPTIONS\r\n'
        'Content-Length: 0\r\n\r\n'
    )


# ------------------------------------------------------------------------------
def probe(transport, host, port, identity, domain, wait=4.0):
    """The first line of an answer to a plaintext OPTIONS sent to host:port, or how it failed ('' = no answer)."""
    kind = socket.SOCK_STREAM if transport == 'TCP' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(wait)
        try:
            sock.connect((host, port))
        except OSError as error:
            return '', f'connect failed: {error.__class__.__name__}'
        local = sock.getsockname()
        try:
            sock.sendall(options(transport, local, identity, domain).encode())
            data = sock.recv(65535)
        except (TimeoutError, socket.timeout):
            return '', 'no answer'
        except OSError as error:
            return '', f'{error.__class__.__name__}'
        line = data.decode(errors='replace').split('\r\n', 1)[0]
        return line, 'answered' if line else 'connection closed'


# ------------------------------------------------------------------------------
def main():
    """Probe port_ps and port_pc over TCP and UDP; print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--status', required=True)
    args = parser.parse_args()
    cfg = json.load(open(args.config))
    sa = json.load(open(args.status)).get('sip_security') or {}
    host = cfg['sip'].get('pcscf', {}).get('address', 'pcscf')
    identity = cfg['sip']['identity']
    domain = identity.split('@', 1)[1]
    checks = []
    for name in ('port_ps', 'port_pc'):
        port = sa.get(name)
        if not port:
            checks.append(dict(name=f'{name} known', passed=False, detail='no IMS AKA security associations'))
            continue
        for transport in ('TCP', 'UDP'):
            line, how = probe(transport, host, int(port), identity, domain)
            checks.append(dict(name=f'plaintext {transport} to {name} {port} unanswered', passed=not line,
                               detail=line or how))
    print(json.dumps(dict(passed=all(check['passed'] for check in checks), checks=checks)))


if __name__ == '__main__':
    main()
