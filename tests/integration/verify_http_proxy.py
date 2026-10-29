#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify, in the HTTP proxy's request log of a lab in forward mode (--http-proxy-mode forward, --log-level debug),
that the clients sent their HTTP requests through the home HTTP proxy as TS 24.482 annex A.2.1.2 requires.

The HTTP of the lab is TLS throughout, so the request lines are not in a capture; the proxy logs each request's
target as it received it (mcx-http-proxy, MCX_LOG=debug). Checks:
  - at least one client request reached each of --require (gms, cms, content, msgstore, lms: the authorities of the
    lab's servers) through the proxy, in absolute-form (RFC 9112 section 3.2.2: "When making a request to a proxy
    ... a client MUST send the target URI in absolute-form");
  - no request in origin-form other than the proxy's own /healthz and /readyz: a client of a forward-mode lab names
    every server by its own URI;
  - no request for the IdMS (TS 24.482 annex A.2.1.2: the IdM client to IdM server connection goes to the IdM server)
    or for the KMS (kept direct: TS 24.482 annex A.2.1.2 and TS 33.180 clause 5.3.2 conflict, Known limitations);
  - no request for an authority outside the lab's servers (which the proxy refuses with 403); a 403 for a served
    server is that server's own decision, passed on (the scenarios' unauthorised requests).

The capture argument is not read (wire_check.py passes one to every verifier).

Specifications: TS 24.482 V19.1.0 (Rel-19), RFC 9112.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# mcx-http-proxy's request log line (services/internal/common/request_log.go).
LINE = re.compile(r'\[http-proxy\] HTTP (\S+) (\S+) \| (\d+) \|')
AUTHORITIES = {
    'gms': 'gms:8443',
    'cms': 'cms:8443',
    'lms': 'lms:8443',
    'content': 'content-server:8443',
    'msgstore': 'message-store:8443',
    'notification': 'notification-server:8443',
}


# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('capture', help='not read')
    parser.add_argument('proxy_log', type=Path)
    parser.add_argument('--require', default='gms,cms', help='comma-separated roles reached through the proxy')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    requests = [match.groups() for match in LINE.finditer(args.proxy_log.read_text(errors='replace'))]
    absolute = [(method, target, status) for method, target, status in requests if '://' in target]
    origin = [
        (method, target, status)
        for method, target, status in requests
        if '://' not in target and target not in ('/healthz', '/readyz')
    ]
    reached = {
        role: sum(1 for _, target, _ in absolute if target.split('://', 1)[1].startswith(authority + '/'))
        for role, authority in AUTHORITIES.items()
    }
    direct_only = [
        (method, target, status) for method, target, status in requests if re.search(r'(^|//)(idms|kms)[:/]', target)
    ]
    served = set(AUTHORITIES.values())
    forbidden = [
        (method, target, status)
        for method, target, status in absolute
        if target.split('://', 1)[1].split('/', 1)[0] not in served
    ]
    missing = [role for role in args.require.split(',') if role and not reached.get(role)]
    errors = []
    if not requests:
        errors.append('no request in the proxy log (the lab needs --log-level debug)')
    if missing:
        errors.append('no client request through the proxy for ' + ', '.join(missing))
    if origin:
        errors.append(f'{len(origin)} request(s) in origin-form')
    if direct_only:
        errors.append(f'{len(direct_only)} IdMS or KMS request(s) through the proxy')
    if forbidden:
        errors.append(f'{len(forbidden)} request(s) for a server outside the lab')
    result = dict(
        passed=not errors,
        errors=errors,
        details=dict(
            requests=len(requests),
            absolute_form=len(absolute),
            reached=reached,
            origin_form=origin[:10],
            idms_or_kms=direct_only[:10],
            forbidden=forbidden[:10],
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
