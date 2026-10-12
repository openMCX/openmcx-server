#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify emergency and imminent-peril group-call signaling from a clear-SIP capture.

Emergency and imminent peril group calls of TS 24.379: requests at setup or by re-INVITE carry emergency-ind or
imminentperil-ind with the matching Resource-Priority (clauses 6.2.8.1.1, 6.2.8.1.2, 6.2.8.1.9, 6.2.8.1.12 and
10.1.1.2.1.3); the controlling function propagates the state to the participants (clause 10.1.1.4.7), signals
cancellation with emergency-ind false and rejects unauthorised requests with 403; emergency alerts and their
cancellation travel in SIP MESSAGE with a location body (clauses 12.1.1.1 and 12.1.1.2); a corrected request is followed
by SIP INFO (warning 149). Floor messages carry the Floor Indicator 'D' and 'E' bits (TS 24.380 table 8.2.3.15-2).

Usage: verify_group_priority.py capture.pcap --service sip:mcptt@DOMAIN
         --emergency-priority mcpttp.15 --imminent-priority mcpttp.10 --output result.json
Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py and
the floor decoder of verify_broadcast_call.py.

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
from verify_broadcast_call import floor_messages  # noqa: E402
from floor_causes import causes, summary  # noqa: E402
from verify_private_call import header, parse, sip_messages, tcp_streams, timed_messages  # noqa: E402


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--emergency-priority', required=True)
    parser.add_argument('--imminent-priority', required=True)
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

    # ------------------------------------------------------------------------------
    def finals(message):
        """The final responses to the request message (same Call-ID and CSeq)."""
        return [
            response
            for response in responses[(message['call_id'], header(message, 'cseq'))]
            if response['status'] >= 200
        ]

    invites = [
        message
        for message in messages
        if message['request'] and message['method'] == 'INVITE' and message['info'].get('session-type') == 'prearranged'
    ]
    from_clients = [message for message in invites if 'mcptt-server' not in header(message, 'via')]
    from_server = [message for message in invites if 'mcptt-server' in header(message, 'via')]
    emergency_req = [message for message in from_clients if message['info'].get('emergency-ind') == 'true']
    imminent_req = [message for message in from_clients if message['info'].get('imminentperil-ind') == 'true']
    check(
        'emergency requests (setup or re-INVITE) carry emergency-ind and the emergency Resource-Priority',
        bool(emergency_req)
        and all(header(message, 'resource-priority') == args.emergency_priority for message in emergency_req),
    )
    check(
        'imminent-peril requests carry imminentperil-ind and the imminent Resource-Priority',
        bool(imminent_req)
        and all(header(message, 'resource-priority') == args.imminent_priority for message in imminent_req),
    )
    check(
        'an emergency upgrade is requested in-dialog (re-INVITE on an established call)',
        any(message['target'] != args.service for message in emergency_req),
    )
    upgrades = [
        message
        for message in from_server
        if message['info'].get('emergency-ind') == 'true' or message['info'].get('imminentperil-ind') == 'true'
    ]
    check(
        'the server propagates emergency and imminent state to participants with Resource-Priority',
        any(
            message['info'].get('emergency-ind') == 'true'
            and header(message, 'resource-priority') == args.emergency_priority
            for message in upgrades
        )
        and any(
            message['info'].get('imminentperil-ind') == 'true'
            and header(message, 'resource-priority') == args.imminent_priority
            for message in upgrades
        ),
    )
    # TS 24.379 clause 10.1.1.4.7 step 6 d): the participants learn an emergency upgrade from the re-INVITE; the
    # emergency MESSAGE is for the affiliated members that are not participating (step 6 d) v)), so no participant
    # gets both.
    timeline = timed_messages(args.capture)

    def aor(message):
        return re.sub(r'^.*?<?(sips?:[^;>]+).*$', r'\1', header(message, 'to'))

    upgrade_reinvites = [
        message
        for message in timeline
        if message['request']
        and message['method'] == 'INVITE'
        and 'mcptt-server' in header(message, 'via')
        and re.search(r';\s*tag=', header(message, 'to'), re.I)
        and message['info'].get('emergency-ind') == 'true'
    ]
    emergency_messages = [
        message
        for message in timeline
        if message['request']
        and message['method'] == 'MESSAGE'
        and 'mcptt-server' in header(message, 'via')
        and message['info'].get('emergency-ind') == 'true'
    ]
    doubled = [
        aor(reinvite)
        for reinvite in upgrade_reinvites
        for notice in emergency_messages
        if aor(notice) == aor(reinvite) and abs(notice['time'] - reinvite['time']) < 1.0
    ]
    check(
        'a participant told of an emergency upgrade by re-INVITE gets no emergency MESSAGE as well (10.1.1.4.7)',
        bool(upgrade_reinvites) and not doubled,
    )
    downgrades = [message for message in from_server if message['info'].get('emergency-ind') == 'false']
    check('cancellation is signalled explicitly with emergency-ind false', bool(downgrades))
    rejected = [
        (response, message)
        for message in emergency_req + imminent_req
        for response in finals(message)
        if response['status'] == 403
    ]
    check('unauthorised priority requests are rejected with 403', bool(rejected))
    # The body of each 403 tells the client the state it did not get (TS 24.379 clauses 6.3.3.1.14, 10.1.1.4.4 steps
    # 7 and 11 and 12.1.3.1 step 4a): the MCPTT info elements per kind of refused request.
    expected_body = {
        'emergency call': (lambda info: info.get('emergency-ind') == 'true',
                           {'emergency-ind': 'false', 'alert-ind': 'false'}),
        'imminent peril call': (lambda info: info.get('imminentperil-ind') == 'true', {'imminentperil-ind': 'false'}),
        'emergency cancellation': (lambda info: info.get('emergency-ind') == 'false', {'emergency-ind': 'true'}),
        'emergency alert': (lambda info: info.get('alert-ind') == 'true' and 'emergency-ind' not in info,
                            {'alert-ind': 'false'}),
        'emergency alert cancellation': (lambda info: info.get('alert-ind') == 'false' and 'emergency-ind' not in info,
                                         {'alert-ind': 'true'}),
    }
    client_requests = [
        message
        for message in messages
        if message['request'] and message['method'] in ('INVITE', 'MESSAGE') and 'mcptt-server' not in header(message, 'via')
    ]
    refusals = collections.defaultdict(list)
    for message in client_requests:
        for response in finals(message):
            if response['status'] != 403 or 'mcptt-server' not in header(response, 'warning'):
                continue
            for kind, (matches, elements) in expected_body.items():
                if matches(message['info']):
                    refusals[kind].append(all(response['info'].get(key) == value for key, value in elements.items()))
                    break
    for kind, (_, elements) in expected_body.items():
        check(
            f'a refused {kind} gets 403 with ' + ', '.join(f'<{key}> {value}' for key, value in elements.items()),
            bool(refusals[kind]) and all(refusals[kind]),
        )
    alerts = [
        message
        for message in messages
        if message['request'] and message['method'] == 'MESSAGE' and message['info'].get('alert-ind') == 'true'
    ]
    check(
        'emergency alerts are delivered by SIP MESSAGE with a location body',
        bool(alerts)
        and any(
            'mcptt-location-info' in message['body'] and 'CurrentCoordinate' in message['body'] for message in alerts
        ),
    )
    # TS 24.379 clause 6.3.3.1.12 steps 2 and 3: every emergency alert the controlling function sends carries the
    # <mc-org> of the originator's user profile.
    server_alerts = [
        message
        for message in messages
        if message['request']
        and message['method'] in ('MESSAGE', 'INVITE')
        and 'mcptt-server' in header(message, 'via')
        and message['info'].get('alert-ind') == 'true'
    ]
    check(
        'every emergency alert from the server carries <mc-org> (6.3.3.1.12)',
        bool(server_alerts) and all(message['info'].get('mc-org') for message in server_alerts),
    )
    cancels = [
        message
        for message in messages
        if message['request'] and message['method'] == 'MESSAGE' and message['info'].get('alert-ind') == 'false'
    ]
    check('alert cancellation is signalled by SIP MESSAGE with alert-ind false', bool(cancels))
    # TS 24.379 clause 6.3.2.1.8.5: a 2xx with warning 149 to a priority call request is followed by a SIP INFO
    # request from the controlling function in the dialog of that request.
    warned = {
        message['call_id']
        for message in messages
        if not message['request'] and 200 <= message['status'] < 300 and '"149 ' in header(message, 'warning')
    }
    infos = {message['call_id'] for message in messages if message['request'] and message['method'] == 'INFO'}
    check('a corrected priority request is followed by a SIP INFO (warning 149 path)', bool(warned) and warned <= infos)
    indicators = collections.Counter()
    for subtype, fields in floor_messages(args.capture):
        if 13 in fields:
            indicators[struct.unpack('!H', fields[13][:2])[0] & 0xF800] += 1
    check(
        'floor messages carry the emergency D-bit and the imminent-peril E-bit during those calls',
        indicators[0x1000] > 0 and indicators[0x0800] > 0,
    )
    reject_causes, cause_violations = causes(args.capture)
    check('every Floor Deny and Floor Revoke carries a Reject Cause defined for it (TS 24.380 8.2.6.2, 8.2.10.2)',
          not cause_violations)
    check('the pre-empted talker gets Floor Revoke with cause #4 Media Burst pre-empted (TS 24.380 6.3.4.4.7, 8.2.10.2)',
          reject_causes[('Revoke', 4)] > 0)
    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            sip_messages=len(messages),
            emergency_requests=len(emergency_req),
            imminent_requests=len(imminent_req),
            server_priority_invites=len(upgrades),
            explicit_downgrades=len(downgrades),
            rejected=len(rejected),
            refusal_bodies={kind: outcomes for kind, outcomes in refusals.items()},
            alert_messages=len(alerts),
            alert_cancellations=len(cancels),
            info_corrections=len(infos),
            floor_reject_causes=summary(reject_causes),
            floor_call_types={f'{key:#06x}': value for key, value in indicators.items()},
            upgrade_reinvites=len(upgrade_reinvites),
            doubled_upgrade_notices=doubled,
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
