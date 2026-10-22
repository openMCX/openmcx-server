#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Private call refusals on the wire, as the lab client of --config; run inside its container.

Each probe is a raw SIP request, digest-authenticated as the client, to the MCPTT server; the check is the server's
final response. With --phase idle (the client in no call), to --target, a user the client may not call:
  - a private call INVITE with an Answer-Mode value RFC 5373 does not define, and one with Priv-Answer-Mode "Manual":
    neither is refused for its commencement mode (RFC 5373 section 2: unknown values are ignored; TS 24.379 clause
    11.1.1.3.1.1 step 18 a), so the refusal is the target's, 403 (Forbidden) with warning 144 (step 11 e);
  - a BYE in a dialog the server does not have: 481 (Call/Transaction Does Not Exist) (RFC 3261 section 15.1.2);
  - a re-INVITE in such a dialog: 481 (RFC 3261 section 12.2.2).
With --phase busy (the client in as many private calls as the server allows, one in the lab), a private call INVITE
to --target: 486 (Busy Here) with warning 124.
Prints one JSON line {"check": [status, warning], ...}.

Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 3261, RFC 5373.
"""

import argparse
import json
import pathlib
import secrets
import sys
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sip_negative import SipProbe  # noqa: E402

ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcptt'


# ------------------------------------------------------------------------------
def private_body(client, target, address):
    """The multipart body of a private call INVITE: an SDP offer of speech and floor control from address, the
    mcptt-info (private, the client ID) and the resource list naming target."""
    sdp = (f'v=0\r\no=- 1 1 IN IP4 {address}\r\ns=MCPTT\r\nc=IN IP4 {address}\r\nt=0 0\r\n'
           'm=audio 4000 RTP/AVP 96\r\ni=speech\r\na=rtpmap:96 AMR-WB/16000/1\r\n'
           'a=fmtp:96 octet-align=0;mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\n'
           'a=sendrecv\r\na=rtcp:4001\r\nm=application 5000 udp MCPTT\r\na=fmtp:MCPTT mc_floor_ssrc=1\r\n')
    info = ('<?xml version="1.0"?><mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
            '<session-type>private</session-type><mcptt-client-id type="Normal"><mcpttString>'
            f'{escape(client)}</mcpttString></mcptt-client-id></mcptt-Params></mcpttinfo>')
    resources = ('<?xml version="1.0" encoding="UTF-8"?><resource-lists '
                 f'xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri={quoteattr(target)}/></list>'
                 '</resource-lists>')
    boundary = 'probe-' + secrets.token_hex(12)
    text = ''.join(f'--{boundary}\r\nContent-Type: {mime}\r\n\r\n{part}\r\n'
                   for mime, part in [('application/sdp', sdp), ('application/vnd.3gpp.mcptt-info+xml', info),
                                      ('application/resource-lists+xml', resources)]) + f'--{boundary}--\r\n'
    return 'multipart/mixed;boundary=' + boundary, text


# ------------------------------------------------------------------------------
def main():
    """Run the probes of the phase and print the outcomes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/config/client-a.json')
    parser.add_argument('--disable-tls', action='store_true')
    parser.add_argument('--phase', choices=['idle', 'busy'], required=True)
    parser.add_argument('--target', required=True, help='the MCPTT ID the private calls are to')
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    sip = SipProbe(cfg, args.disable_tls)
    service = cfg['mcptt']['service_uri']
    address = sip.sock.getsockname()[0]
    outcomes = {}

    # ------------------------------------------------------------------------------
    def send(name, method, headers, body=''):
        """Send the request (answering the SIP core's challenge) and record its final status and Warning."""
        challenge = sip.request(method, service, headers, body)
        code, response = challenge
        if code in (401, 407):
            code, response = sip.request(method, service, headers, body,
                                         authorization=sip.digest(method, service, challenge))
        outcomes[name] = [code, response.get('warning', '')]

    # ------------------------------------------------------------------------------
    def invite(name, extra):
        """A private call INVITE to --target with the extra header fields."""
        content_type, body = private_body(cfg['mcptt']['client_id'], args.target, address)
        headers = {
            'Accept-Contact': f'*;+g.3gpp.icsi-ref="{ICSI.replace(":", "%3A")}";+g.3gpp.mcptt;require;explicit',
            'P-Preferred-Service': ICSI,
            'Content-Type': content_type,
            **extra,
        }
        send(name, 'INVITE', headers, body)

    if args.phase == 'idle':
        invite('answer_mode_unknown', {'Answer-Mode': 'Sometimes'})
        invite('priv_answer_mode_manual', {'Priv-Answer-Mode': 'Manual'})
        core = cfg['sip']['core_uri']
        dialog = {'To': f'<{service}>;tag={secrets.token_hex(8)}', 'Route': f'<{core};lr>'}
        send('bye_unknown_dialog', 'BYE', dialog)
        send('reinvite_unknown_dialog', 'INVITE', dialog)
    else:
        invite('private_call_limit', {'Answer-Mode': 'Auto'})
    sip.sock.close()
    print(json.dumps(outcomes))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
