#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify, in a clear-SIP capture at the MCPTT server, the Request-URIs of the clients' xcap-diff subscriptions.

Checks:
  - every initial SUBSCRIBE (Event xcap-diff) to group documents (org.openmobilealliance.groups) or to the <GKTPs> of
    a GKTP document (org.3gpp.MCPTT-GKTP) is sent to --gms-uri, "the configured public service identity for
    performing subscription proxy function of the GMS" (TS 24.481 clause 6.3.13.2.1 step b);
  - at least one such subscription was answered 200 and its NOTIFYs were answered 200 (the notifier is the GMS-URI);
  - with --mcs-server, at least one initial group document SUBSCRIBE of that MCS server (its PSI in the
    P-Asserted-Identity, TS 24.481 clause 6.3.13.2.2 step c), each with the ICSI urn:urn-7:3gpp-service.ims.icsi.mcptt
    in a P-Asserted-Service header field (step e) and in the g.3gpp.icsi-ref media feature tag of its Contact (step
    f); like the clients' subscriptions, it is sent to --gms-uri (step b);
  - every initial SUBSCRIBE to configuration management documents (org.3gpp.mcptt.*) stays at --service: which item
    holds the CMS subscription proxy PSI of TS 24.484 clause 6.3.13.2.2 step b) 2) is not defined (Known limitations).
A lab whose GMS-URI differs from the MCPTT PSI (--gms-user) makes a client that still sends them to the MCPTT PSI
fail here.

Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py.

Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 5875.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, timed_messages  # noqa: E402

GROUPS = 'org.openmobilealliance.groups/'
MCPTT_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcptt'
GKTP = 'org.3gpp.MCPTT-GKTP/'
CONFIGURATION = 'org.3gpp.mcptt.'


# ------------------------------------------------------------------------------
def bare(uri):
    """The URI without angle brackets and parameters."""
    uri = uri.strip()
    if '<' in uri:
        uri = uri[uri.index('<') + 1 : uri.index('>')]
    return uri.split(';')[0]


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--gms-uri', required=True, help='the GMS-URI of the lab, e.g. sip:gms-proxy@mcx.test')
    parser.add_argument('--service', required=True, help='the MCPTT PSI, e.g. sip:mcptt@mcx.test')
    parser.add_argument('--mcs-server', help='the PSI of an MCS server subscribing to group documents, e.g. sip:mcdata@mcx.test')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen = [], set()
    for message in timed_messages(args.capture):
        key = (message['call_id'], header(message, 'cseq'), message['line'])
        if key not in seen:
            seen.add(key)
            messages.append(message)
    checks, failures = [], []

    def check(label, condition):
        (checks if condition else failures).append(label)

    gms, wrong_gms, configuration, wrong_configuration = {}, [], 0, []
    server_subscriptions, server_faults = 0, []
    for message in messages:
        if not (
            message['request']
            and message['method'] == 'SUBSCRIBE'
            and header(message, 'event').split(';')[0].strip() == 'xcap-diff'
            and 'tag=' not in header(message, 'to')
        ):
            continue
        target = bare(message['line'].split()[1])
        label = f'{message["line"]} (Call-ID {message["call_id"]})'
        if GROUPS in message['body'] or GKTP in message['body']:
            gms[message['call_id']] = label
            if target != args.gms_uri:
                wrong_gms.append(label)
            if args.mcs_server and GROUPS in message['body'] and bare(header(message, 'p-asserted-identity')) == args.mcs_server:
                server_subscriptions += 1
                contact = header(message, 'contact')
                if header(message, 'p-asserted-service').strip() != MCPTT_ICSI:
                    server_faults.append('P-Asserted-Service of ' + label)
                if 'g.3gpp.icsi-ref' not in contact or not (
                    MCPTT_ICSI in contact or MCPTT_ICSI.replace(':', '%3A') in contact
                ):
                    server_faults.append('Contact g.3gpp.icsi-ref of ' + label)
        elif CONFIGURATION in message['body']:
            configuration += 1
            if target != args.service:
                wrong_configuration.append(label)
    answered = {
        message['call_id']
        for message in messages
        if not message['request'] and message['status'] == 200 and message['call_id'] in gms
        and header(message, 'cseq').split()[-1] == 'SUBSCRIBE'
    }
    notified = [
        message
        for message in messages
        if not message['request'] and message['call_id'] in gms and header(message, 'cseq').split()[-1] == 'NOTIFY'
    ]
    refused = [f'{message["line"]} (Call-ID {message["call_id"]})' for message in notified if message['status'] != 200]
    check(f'group document and GKTP subscriptions sent to {args.gms_uri} ({len(gms)})', gms and not wrong_gms)
    check('a group document or GKTP subscription answered 200', bool(answered))
    check(f'NOTIFYs of those subscriptions answered 200 ({len(notified)})', notified and not refused)
    check(f'configuration subscriptions at {args.service} ({configuration})', not wrong_configuration)
    if args.mcs_server:
        check(f'group document subscriptions of {args.mcs_server} ({server_subscriptions})', server_subscriptions > 0)
        check('those carry the MCPTT ICSI in P-Asserted-Service and in the Contact g.3gpp.icsi-ref', not server_faults)
    result = dict(
        passed=not failures,
        checks=checks,
        failures=failures,
        observations=dict(
            gms_subscriptions=len(gms),
            wrong_gms=wrong_gms[:10],
            wrong_configuration=wrong_configuration[:10],
            refused_notifies=refused[:10],
            mcs_server_subscriptions=server_subscriptions,
            mcs_server_faults=server_faults[:10],
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
