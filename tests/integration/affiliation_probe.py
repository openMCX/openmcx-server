#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Affiliation PUBLISH probes on the wire, as the lab client of --config; run inside its container.

Each probe is a raw SIP PUBLISH (Event: presence) of the client's own affiliation, digest-authenticated as the client,
to the MCPTT server and, with --mcdata, to the MCData server; the check is the server's final response:
  - no Expires, and Expires 3600: 423 (Interval Too Brief) with Min-Expires 4294967295 (TS 24.379 clause 9.2.2.2.3
    step 5; TS 24.282 clause 8.3.2.3 step 5);
  - an initial publication (no SIP-If-Match) naming a group the user is a member of and one it is not:
    200 (OK) with a SIP-ETag (step 8; the group outcome is the server's, checked by the scenario);
  - SIP-If-Match with an entity tag the server never issued: 412 (Conditional Request Failed) (RFC 3903 section 6
    step 3);
  - SIP-If-Match with the entity tag of the 200: 200 (OK).
Prints one JSON line {"service": {"check": [status, headers], ...}, ...}.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 3903.
"""

import argparse
import json
import pathlib
import secrets
import sys
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sip_negative import SipProbe  # noqa: E402

INFO = {
    'mcptt': ('application/vnd.3gpp.mcptt-info+xml', 'mcpttinfo', 'urn:3gpp:ns:mcpttInfo:1.0', 'mcptt', 'mcpttURI',
              'mcpttString', 'urn:3gpp:ns:mcpttPresInfo:1.0'),
    'mcdata': ('application/vnd.3gpp.mcdata-info+xml', 'mcdatainfo', 'urn:3gpp:ns:mcdataInfo:1.0', 'mcdata',
               'mcdataURI', 'mcdataString', 'urn:3gpp:ns:mcdataPresInfo:1.0'),
}


# ------------------------------------------------------------------------------
def body(service, user, client, groups):
    """The multipart body of an affiliation PUBLISH: the service info (request URI and client ID) and the PIDF."""
    mime, root, ns, prefix, uri, string, pres = INFO[service]
    info = (f'<?xml version="1.0"?><{root} xmlns="{ns}"><{prefix}-Params>'
            f'<{prefix}-request-uri type="Normal"><{uri}>{escape(user)}</{uri}></{prefix}-request-uri>'
            f'<{prefix}-client-id type="Normal"><{string}>{escape(client)}</{string}></{prefix}-client-id>'
            f'</{prefix}-Params></{root}>')
    affiliations = ''.join(f'<mc:affiliation group={quoteattr(group)}/>' for group in groups)
    pidf = (f'<?xml version="1.0"?><presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:mc="{pres}" '
            f'entity={quoteattr(user)}><tuple id={quoteattr(client)}><status>{affiliations}</status></tuple>'
            f'<mc:p-id>{secrets.token_hex(12)}</mc:p-id></presence>')
    boundary = 'probe-' + secrets.token_hex(12)
    text = (f'--{boundary}\r\nContent-Type: {mime}\r\n\r\n{info}\r\n'
            f'--{boundary}\r\nContent-Type: application/pidf+xml\r\n\r\n{pidf}\r\n--{boundary}--\r\n')
    return 'multipart/mixed; boundary=' + boundary, text


# ------------------------------------------------------------------------------
def main():
    """Run the probes and print the outcomes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/config/client-a.json')
    parser.add_argument('--disable-tls', action='store_true')
    parser.add_argument('--member', required=True, help='a group the user is a member of')
    parser.add_argument('--non-member', required=True, help='a group the user is not a member of')
    parser.add_argument('--mcdata', action='store_true', help='probe the MCData server too')
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    sip = SipProbe(cfg, args.disable_tls)
    outcomes = {}
    for service in ['mcptt'] + (['mcdata'] if args.mcdata else []):
        uri = cfg[service]['service_uri']
        content_type, text = body(service, cfg[service]['user_id'], cfg['mcptt']['client_id'],
                                  [args.member, args.non_member])
        seen = outcomes[service] = {}

        def publish(name, fields):
            """One digest-authenticated PUBLISH; records and returns its final status and headers."""
            fields = {'Event': 'presence', 'Content-Type': content_type, 'P-Preferred-Service':
                      'urn:urn-7:3gpp-service.ims.icsi.' + service, **fields}
            challenge = sip.request('PUBLISH', uri, fields, text)
            answer = sip.request('PUBLISH', uri, fields, text, authorization=sip.digest('PUBLISH', uri, challenge))
            if challenge[0] not in (401, 407):
                answer = challenge
            keep = {key: value for key, value in answer[1].items() if key in ('min-expires', 'sip-etag', 'expires')}
            seen[name] = [answer[0], keep]
            return answer

        publish('no_expires', {})
        publish('expires_3600', {'Expires': '3600'})
        initial = publish('initial_member_and_non_member', {'Expires': '4294967295'})
        publish('unknown_etag', {'Expires': '4294967295', 'SIP-If-Match': 'never-issued-' + secrets.token_hex(6)})
        publish('current_etag', {'Expires': '4294967295', 'SIP-If-Match': initial[1].get('sip-etag', 'none')})
    sip.sock.close()
    print(json.dumps(outcomes))


if __name__ == '__main__':
    main()
