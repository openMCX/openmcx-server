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
  - SIP-If-Match with the entity tag of the 200: 200 (OK);
  - a service info without <mcptt-client-id> (<mcdata-client-id>): 200 (OK), the client being the PIDF's tuple
    (TS 24.379 clause 9.2.1.2 step 2, clause 9.2.2.2.3 step 10);
  - Expires 0 with the service info alone, no PIDF: 200 (OK) with Expires 0, the user no longer affiliated
    (TS 24.379 clause 9.2.1.2 NOTE 2; TS 24.282 clause 8.2.2 NOTE 1); then the member group published again;
  - last, to the MCPTT server: a SUBSCRIBE out of any dialog with Expires 0, a fetch of the current state (TS 24.379
    clause 9.2.1.3 step 5): 200 (OK) (its NOTIFY may follow on this connection, so nothing is sent after it).
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
def body(service, user, client, groups, client_id=True, pidf=True):
    """The body of an affiliation PUBLISH: the service info (request URI and, with client_id, the client ID) and,
    with pidf, the PIDF in a multipart body; without, the service info alone."""
    mime, root, ns, prefix, uri, string, pres = INFO[service]
    named = f'<{prefix}-client-id type="Normal"><{string}>{escape(client)}</{string}></{prefix}-client-id>'
    info = (f'<?xml version="1.0"?><{root} xmlns="{ns}"><{prefix}-Params>'
            f'<{prefix}-request-uri type="Normal"><{uri}>{escape(user)}</{uri}></{prefix}-request-uri>'
            f'{named if client_id else ""}</{prefix}-Params></{root}>')
    if not pidf:
        return mime, info
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
        user, client = cfg[service]['user_id'], cfg['mcptt']['client_id']
        content_type, default = body(service, user, client, [args.member, args.non_member])
        seen = outcomes[service] = {}

        def publish(name, fields, content=None):
            """One digest-authenticated PUBLISH (of content, a (Content-Type, body) pair, else the default body);
            records and returns its final status and headers."""
            kind, text = content or (content_type, default)
            fields = {'Event': 'presence', 'Content-Type': kind, 'P-Preferred-Service':
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
        publish('no_client_id', {'Expires': '4294967295'}, body(service, user, client, [args.member], client_id=False))
        publish('expires_0_no_pidf', {'Expires': '0'}, body(service, user, client, [], pidf=False))
        publish('restored', {'Expires': '4294967295'}, body(service, user, client, [args.member]))
    uri, user = cfg['mcptt']['service_uri'], cfg['mcptt']['user_id']
    fields = {'Event': 'presence', 'Expires': '0', 'Accept': 'application/pidf+xml',
              'Content-Type': INFO['mcptt'][0], 'P-Preferred-Service': 'urn:urn-7:3gpp-service.ims.icsi.mcptt'}
    info = body('mcptt', user, cfg['mcptt']['client_id'], [], pidf=False)[1]
    challenge = sip.request('SUBSCRIBE', uri, fields, info)
    answer = (sip.request('SUBSCRIBE', uri, fields, info, authorization=sip.digest('SUBSCRIBE', uri, challenge))
              if challenge[0] in (401, 407) else challenge)
    outcomes['mcptt']['fetch_expires_0'] = [answer[0], {k: v for k, v in answer[1].items() if k == 'expires'}]
    sip.sock.close()
    print(json.dumps(outcomes))


if __name__ == '__main__':
    main()
