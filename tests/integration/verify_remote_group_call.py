#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify remotely initiated group-call signaling from a clear-SIP capture.

The remotely initiated group call of TS 24.379 clause 10.1.5: the request to the service URI naming the remote user and
the group (clause 10.1.5.2.1), relayed to the remote user by the controlling function (clause 10.1.5.4), rejected with
warnings 157, 120 and 167 (table 4.4.2-2); the remote user's response with the outcome (clause 10.1.5.2.2) and its group
call, carrying the requested <ric-app-level-priority> as Resource-Priority (clause 10.1.5.2.1 step 3 d) D), clause
10.1.5.2.2 step 2 b)).

Usage: verify_remote_group_call.py capture.pcap --service sip:mcptt@DOMAIN --group GROUP --output result.json
Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--group', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen = [], set()
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:
                seen.add(key)
                messages.append(message)
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    responses = collections.defaultdict(list)
    for parsed in messages:
        if not parsed['request']:
            responses[(parsed['call_id'], header(parsed, 'cseq'))].append(parsed)
    msgs = [message for message in messages if message['request'] and message['method'] == 'MESSAGE']
    requests = [
        message for message in msgs if message['info'].get('request-type') == 'remotely-initiated-group-call-request'
    ]
    fromclient = [message for message in requests if message['target'] == args.service]
    toremote = [message for message in requests if 'mcptt-server' in header(message, 'via')]
    ftar = [
        message for message in msgs if message['info'].get('response-type') == 'remotely-initiated-group-call-response'
    ]

    check(
        'originating requests go to the service URI with one resource-lists remote user and a group in mcptt-request-uri',
        bool(fromclient)
        and all(
            message['targets'] and len(message['targets']) == 1 and message['info'].get('mcptt-request-uri')
            for message in fromclient
        )
        and any(message['info'].get('mcptt-request-uri') == args.group for message in fromclient),
    )
    check(
        'requests carry a notify-remote-user flag (true and silent both exercised)',
        {message['info'].get('notify-remote-user') for message in fromclient} == {'true', 'false'},
    )
    check(
        'the relayed request names the group in mcptt-calling-group-id and the remote user in mcptt-request-uri',
        bool(toremote)
        and all(
            message['info'].get('mcptt-calling-group-id') == args.group
            and message['info'].get('mcptt-request-uri')
            and message['info'].get('mcptt-calling-user-id')
            for message in toremote
        ),
    )
    accepted = [
        response
        for message in fromclient
        for response in responses[(message['call_id'], header(message, 'cseq'))]
        if response['status'] == 200
    ]
    check('accepted requests get a 200 OK MESSAGE response', len(accepted) >= 2)
    rejected = [
        (response['status'], header(response, 'warning'))
        for message in fromclient
        for response in responses[(message['call_id'], header(message, 'cseq'))]
        if response['status'] >= 300
    ]
    check(
        'an unauthorised requester is rejected with 157',
        any(status_code == 403 and '"157 ' in warning for status_code, warning in rejected),
    )
    check(
        'a request for a group the remote user is not affiliated to is rejected with 120',
        any(status_code == 403 and '"120 ' in warning for status_code, warning in rejected),
    )
    responses_from = [message for message in ftar if message['target'] == args.service]
    responses_to = [message for message in ftar if 'mcptt-server' in header(message, 'via')]
    check(
        'responses name the called group in mcptt-request-uri (10.1.5.2.2 step 1e)',
        bool(responses_from)
        and all(message['info'].get('mcptt-request-uri') == args.group for message in responses_from),
    )
    check(
        'the relayed response names the group in mcptt-calling-group-id and the requester in mcptt-request-uri',
        bool(responses_to)
        and all(
            message['info'].get('mcptt-calling-group-id') == args.group
            and message['info'].get('mcptt-request-uri') not in (None, '', args.group)
            for message in responses_to
        ),
    )
    outcomes = collections.Counter(message['info'].get('remotely-initiated-call-outcome') for message in ftar)
    check('the remote user reports both success and failure outcomes', outcomes['success'] > 0 and outcomes['fail'] > 0)
    group_invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['info'].get('session-type') == 'prearranged'
        and message['target'] == args.service
    ]
    check('the remote user places a normal group INVITE after an accepted request', bool(group_invites))
    check(
        'a preconfigured-use-only group is rejected with 167',
        any(status_code == 403 and '"167 ' in warning for status_code, warning in rejected),
    )
    # TS 24.379 clause 10.1.5.2.1 step 1A: a member's client refuses a preconfigured-use-only group itself, so the
    # only request for that group on the wire is the one of the non-member, which the server rejects with 167.
    preconfigured = {
        message['info'].get('mcptt-request-uri')
        for message in fromclient
        for response in responses[(message['call_id'], header(message, 'cseq'))]
        if response['status'] == 403 and '"167 ' in header(response, 'warning')
    }
    check(
        'one request names the preconfigured-use-only group: the member\'s client sends none (10.1.5.2.1 step 1A)',
        len(preconfigured) == 1
        and sum(message['info'].get('mcptt-request-uri') in preconfigured for message in fromclient) == 1,
    )
    # TS 24.379 clause 10.1.5.2.1 step 3 d) D) and clause 10.1.5.2.2 step 2 b): the requested application
    # priority is relayed to the remote user and used as its Resource-Priority.
    prioritised = [message for message in fromclient if message['info'].get('ric-app-level-priority')]
    check(
        'a request carries ric-app-level-priority, relayed unchanged to the remote user',
        bool(prioritised)
        and any(
            message['info'].get('ric-app-level-priority') == prioritised[0]['info']['ric-app-level-priority']
            for message in toremote
        ),
    )
    check(
        'the remote user\'s group INVITE carries the requested value as Resource-Priority',
        bool(prioritised)
        and any(
            header(message, 'resource-priority') == prioritised[0]['info']['ric-app-level-priority']
            for message in group_invites
        ),
    )

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            sip_messages=len(messages),
            originating_requests=len(fromclient),
            relayed_requests=len(toremote),
            responses=len(ftar),
            outcomes=dict(outcomes),
            rejections=collections.Counter(f'{status_code} {warning}'.strip() for status_code, warning in rejected),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
