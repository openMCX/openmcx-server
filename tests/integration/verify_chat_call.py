#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify chat group-call signaling and floor coding from a clear-SIP capture.

The chat group call of TS 24.379 clause 10.1.2: clients join with INVITEs to the service URI naming the chat group
(clause 10.1.2.2.1.1); the controlling function answers 200 directly with an isfocus Contact holding the one chat
session URI (clause 10.1.2.4.1.1 step 16), invites affiliated but not joined members only when the call enters emergency
or imminent peril, with Resource-Priority (clause 10.1.2.4.1.1 steps 14 c) iv) and 15 c) iii)), rejects with warnings
117, 118 and 122 (table 4.4.2-2), describes the session in conference NOTIFYs and releases the remaining participants
itself. Floor messages carry the Floor Indicator 'A' bit, never 'B' (TS 24.380 table 8.2.3.15-2), and Floor Taken
permits requests (TS 24.380 clause 8.2.3.7).

Usage: verify_chat_call.py capture.pcap --service sip:mcptt@DOMAIN --chat-group GROUP --output result.json

Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py and the floor decoder of
verify_broadcast_call.py.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402
from verify_broadcast_call import floor_messages  # noqa: E402
from floor_causes import causes, summary  # noqa: E402

# TS 24.380 clause 8.2.3.15: the Floor Indicator bits A (normal call), B (broadcast group call), D (emergency call)
# and E (imminent peril call).
NORMAL_BIT, BROADCAST_BIT, EMERGENCY_BIT, IMMINENT_BIT = 0x8000, 0x4000, 0x1000, 0x0800


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--chat-group', required=True)
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

    # Initial INVITEs only; re-INVITEs (To tag present) change priority in a dialog.
    invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and not re.search(r';\s*tag=', header(message, 'to'), re.I)
    ]
    # The controlling function originates its INVITEs from the service identity.
    from_server = [
        message
        for message in invites
        if 'mcptt-server' in header(message, 'via') or args.service in header(message, 'from')
    ]
    chat = [
        message for message in invites if message['info'].get('session-type') == 'chat' and message not in from_server
    ]
    responses = collections.defaultdict(list)
    for parsed in messages:
        if not parsed['request']:
            # Keyed by CSeq number too: re-INVITEs in the same dialog have their own responses.
            responses[(parsed['call_id'], parsed['method'], header(parsed, 'cseq').split()[0])].append(parsed)
    wrong_group = {
        message['call_id']
        for message in chat
        for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
        if response['status'] in (403, 404) and any(code in header(response, 'warning') for code in ('117 ', '167 ', '148 '))
    }
    check(
        'chat INVITEs target the service URI; all but the 117/167/148 negative tests name the chat group',
        bool(chat)
        and all(
            message['target'] == args.service
            and (message['call_id'] in wrong_group or message['info'].get('mcptt-request-uri') == args.chat_group)
            for message in chat
        ),
    )
    server_invites = [
        message
        for message in from_server
        if message['info'].get('mcptt-calling-group-id') == args.chat_group
        or message['info'].get('session-type') == 'chat'
    ]
    # TS 24.379 clause 10.1.2.4.1.1 steps 14 c) iv) and 15 c) iii): only entering emergency or
    # imminent peril invites affiliated members that have not joined.
    check(
        'the server invites chat members only for emergency or imminent peril, with Resource-Priority',
        all(
            (message['info'].get('emergency-ind') == 'true' or message['info'].get('imminentperil-ind') == 'true')
            and header(message, 'resource-priority')
            for message in server_invites
        ),
    )
    if server_invites:
        check(
            'priority chat invitations name the chat group and the calling user',
            all(
                message['info'].get('mcptt-calling-group-id') == args.chat_group
                and message['info'].get('mcptt-calling-user-id')
                for message in server_invites
            ),
        )
    outcomes = [
        (response['status'], header(response, 'warning'), response)
        for message in chat
        for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
    ]
    accepted = [response for status_code, _, response in outcomes if status_code == 200]
    check(
        'chat INVITEs are answered 200 directly, without 180 Ringing',
        bool(accepted) and not any(status_code == 180 for status_code, _, _ in outcomes),
    )
    uris = collections.Counter()
    for response in accepted:
        match = re.search(r'<([^>]+)>', header(response, 'contact'))
        if match and 'isfocus' in header(response, 'contact') and ';mcptt-session=' in match.group(1):
            uris[match.group(1)] += 1
    check('every 200 OK carries an isfocus Contact with the chat session URI', sum(uris.values()) == len(accepted))
    check('later joiners receive the same session URI as the creator', bool(uris) and max(uris.values()) >= 3)
    for code, warning in [
        (486, '122 too many participants'),
        # TS 24.379 clause 6.3.5.2 steps 5c and 5d: a call type not matching the group type is not found (404).
        (404, '117 the group identity indicated in the request is a prearranged group'),
    ]:
        check(
            f'chat request rejected with {code} warning {warning[:3]}',
            any(status_code == code and warning in warning_text for status_code, warning_text, _ in outcomes),
        )
    prearranged = [
        message
        for message in invites
        if message['info'].get('session-type') == 'prearranged' and message['target'] == args.service
    ]
    check(
        'prearranged request on the chat group rejected with 404 warning 118',
        any(
            response['status'] == 404
            and '118 the group identity indicated in the request is a chat group' in header(response, 'warning')
            for message in prearranged
            for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
        ),
    )
    notifies = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'NOTIFY'
        and 'conference' in header(message, 'event')
        and f'entity="{args.chat_group}"' in message['body']
    ]
    check('conference NOTIFYs describe the chat group session', bool(notifies))
    chat_calls = {message['call_id'] for message in chat}
    server_byes = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'BYE'
        and message['call_id'] in chat_calls
        and 'mcptt-server' in header(message, 'via')
    ]
    check('the server releases remaining or idle chat participants itself', len(server_byes) >= 3)

    floor = collections.Counter()
    violations = []
    for subtype, fields in floor_messages(args.capture):
        if 13 not in fields:
            continue
        indicator = struct.unpack('!H', fields[13][:2])[0]
        floor[f'{subtype}:{indicator:#06x}'] += 1
        if indicator & BROADCAST_BIT:
            violations.append('broadcast bit in chat capture')
        # A normal call carries the A-bit, an emergency or imminent peril call the D- or E-bit instead.
        if bool(indicator & NORMAL_BIT) == bool(indicator & (EMERGENCY_BIT | IMMINENT_BIT)):
            violations.append(f'Floor Indicator {indicator:#06x}: not one of the A-bit and the D- or E-bit')
        if subtype == 2 and 5 in fields and struct.unpack('!H', fields[5][:2])[0] != 1:
            violations.append('normal Taken without permission to request')
    check('floor messages use the normal A-bit and Floor Taken permits requests', bool(floor) and not violations)
    reject_causes, cause_violations = causes(args.capture)
    check('every Floor Deny and Floor Revoke carries a Reject Cause defined for it (TS 24.380 8.2.6.2, 8.2.10.2)',
          not cause_violations)
    check('a floor request while another member has permission is denied with cause #1 (TS 24.380 6.3.5.4.4)',
          reject_causes[('Deny', 1)] > 0)

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        violations=violations + cause_violations,
        counts=dict(
            floor_reject_causes=summary(reject_causes),
            sip_messages=len(messages),
            chat_invites=len(chat),
            server_chat_invites=len(server_invites),
            chat_sessions=len(uris),
            joins_per_session=dict(uris),
            conference_notifies=len(notifies),
            server_releases=len(server_byes),
            floor_messages=dict(floor),
            chat_final_responses=dict(
                collections.Counter(
                    f'{status_code} {warning_text}'.strip() for status_code, warning_text, _ in outcomes
                )
            ),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
