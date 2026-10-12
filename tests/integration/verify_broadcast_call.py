#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify broadcast group-call signaling and floor coding from a clear-SIP capture.

Broadcast group calls (TS 24.379 clause 4.12): prearranged group calls whose INVITEs and fan-out INVITEs carry
broadcast-ind (TS 24.379 clause 6.2.8.2), confirmed in the 200 OK; emergency and imminent peril broadcasts; a conference
SUBSCRIBE in a broadcast is rejected with 480 and warning 105 (TS 24.379 table 4.4.2-2); the server releases the
initiator's dialog when its transmission is complete; broadcast hierarchies (project profile for TS 23.379 clause
10.6.2.5.2). Floor messages carry the Floor Indicator 'B' bit for broadcasts and 'A' for normal calls, with 'D' or 'E'
for emergency or imminent peril (TS 24.380 table 8.2.3.15-2); a broadcast Floor Taken has Permission to Request the
Floor 0 (TS 24.380 clause 6.3.4.4.2) and a broadcast Floor Deny the cause 5 (TS 24.380 clause 8.2.6.2).

Usage: verify_broadcast_call.py capture.pcap --service sip:mcptt@DOMAIN --output result.json

Self-contained (no tshark): reuses the TCP/5060 SIP reassembly of verify_private_call.py and decodes RTCP APP "MCPT"
floor messages directly.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402

BROADCAST_BIT, NORMAL_BIT, EMERGENCY_BIT, IMMINENT_BIT = 0x4000, 0x8000, 0x1000, 0x0800
TYPES = {1: 'Granted', 2: 'Taken', 3: 'Deny', 5: 'Idle'}


# ------------------------------------------------------------------------------
def floor_messages(path):
    """Yield (subtype, fields) of every RTCP APP "MCPT" floor control message over UDP/IPv4 in the classic PCAP at path
    (TS 24.380 clause 8.1.2), its fields by field ID (TS 24.380 clause 8.1.3, table 8.2.3.1-2).
    """
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        yield from floor_frame(packet)


# ------------------------------------------------------------------------------
def floor_frame(packet):
    """Yield (subtype, fields) of the floor control message in one Ethernet frame, if it carries one."""
    if len(packet) < 34 or packet[12:14] != b'\x08\x00':
        return
    ip = packet[14:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 17:
        return
    payload = ip[ihl + 8 : struct.unpack_from('!H', ip, 2)[0]]
    if len(payload) < 12 or payload[0] >> 6 != 2 or payload[1] != 204 or payload[8:12] != b'MCPT':
        return
    fields, at = {}, 12
    while at + 2 <= len(payload):
        ident = payload[at]
        size = payload[at + 1] if ident < 192 else struct.unpack_from('!H', payload, at + 1)[0]
        start = at + (2 if ident < 192 else 3)
        fields[ident] = payload[start : start + size]
        at = start + size
        at += (-at) % 4
    yield payload[0] & 0x0F, fields


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
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

    invites = [message for message in messages if message['request'] and message['method'] == 'INVITE']
    broadcast = [message for message in invites if message['info'].get('broadcast-ind') == 'true']
    originating = [message for message in broadcast if message['target'] == args.service]
    terminating = [message for message in broadcast if message['target'] != args.service]
    finals = collections.defaultdict(list)
    for parsed in messages:
        if not parsed['request'] and parsed['method'] == 'INVITE' and parsed['status'] >= 200:
            finals[parsed['call_id']].append(parsed)
    check('originating broadcast INVITEs captured', bool(originating))
    check(
        'originating broadcast INVITEs are prearranged group calls to the service URI',
        all(
            message['info'].get('session-type') == 'prearranged' and message['info'].get('mcptt-request-uri')
            for message in originating
        ),
    )
    check(
        'broadcast fan-out INVITEs carry broadcast-ind true, calling group and initiator',
        len(terminating)
        >= len(
            {
                message['call_id']
                for message in originating
                if any(response['status'] == 200 for response in finals[message['call_id']])
            }
        )
        and all(
            message['info'].get('mcptt-calling-group-id') and message['info'].get('mcptt-calling-user-id')
            for message in terminating
        ),
    )
    # Broadcast hierarchies (project profile for TS 23.379 clause 10.6.2.5.2): receivers
    # reached through another group are told which one in <associated-group-id>.
    via = [message for message in terminating if message['info'].get('associated-group-id')]
    if via:
        check(
            'hierarchy fan-outs name a different associated group than the broadcast group',
            all(
                message['info']['associated-group-id'] != message['info'].get('mcptt-calling-group-id')
                for message in via
            ),
        )
        hierarchy_groups = {message['info'].get('mcptt-calling-group-id') for message in via}
        check(
            'a non-broadcast call on a hierarchy group is rejected with 403',
            any(
                response['status'] == 403 and 'requires broadcast-ind' in header(response, 'warning')
                for message in invites
                if message['target'] == args.service and message['info'].get('mcptt-request-uri') in hierarchy_groups
                for response in finals[message['call_id']]
            ),
        )
    check(
        'non-broadcast INVITEs omit broadcast-ind (normal calls stay normal)',
        any(
            'broadcast-ind' not in message['info'] and message['info'].get('session-type') == 'prearranged'
            for message in invites
        ),
    )
    accepted = [
        response for message in originating for response in finals[message['call_id']] if response['status'] == 200
    ]
    check(
        '200 OK to the initiator confirms broadcast-ind true',
        bool(accepted) and all(response['info'].get('broadcast-ind') == 'true' for response in accepted),
    )
    outcomes = [
        (response['status'], header(response, 'warning'))
        for message in originating
        for response in finals[message['call_id']]
    ]
    # Emergency and imminent-peril broadcast (H7, local policy).
    check(
        'an emergency broadcast INVITE carries broadcast-ind and emergency-ind true with Resource-Priority',
        any(
            message['info'].get('emergency-ind') == 'true' and header(message, 'resource-priority')
            for message in originating
        ),
    )
    check(
        'emergency broadcast fan-out INVITEs carry broadcast-ind and emergency-ind true',
        any(message['info'].get('emergency-ind') == 'true' for message in terminating),
    )
    check(
        "a receiver's in-dialog priority change in a broadcast is rejected with 403",
        any(
            response['status'] == 403 and 'broadcast group call receiver' in header(response, 'warning')
            for rs in finals.values()
            for response in rs
        ),
    )
    check(
        'unauthorised broadcast initiation rejected with 403',
        any(
            status_code == 403 and 'broadcast group call not authorised' in warning_text
            for status_code, warning_text in outcomes
        ),
    )
    check(
        'broadcast during an ongoing group call rejected with 486',
        any(status_code == 486 and 'group call in progress' in warning_text for status_code, warning_text in outcomes),
    )
    responses = collections.defaultdict(list)
    for parsed in messages:
        if not parsed['request']:
            responses[(parsed['call_id'], parsed['method'])].append(parsed)
    subscribes = [
        message
        for message in messages
        if message['request'] and message['method'] == 'SUBSCRIBE' and 'conference' in header(message, 'event')
    ]
    rejected = [
        response
        for message in subscribes
        for response in responses[(message['call_id'], 'SUBSCRIBE')]
        if response['status'] == 480
        and '105 subscription not allowed in a broadcast group call' in header(response, 'warning')
    ]
    check('conference SUBSCRIBE in a broadcast rejected with 480 and warning 105', bool(rejected))
    broadcast_calls = {message['call_id'] for message in broadcast}
    server_byes = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'BYE'
        and message['call_id'] in broadcast_calls
        and 'mcptt-server' in header(message, 'via')
    ]
    initiator_released = {message['call_id'] for message in server_byes} & {
        message['call_id'] for message in originating
    }
    check('server releases broadcast initiator dialogs itself (transmission complete)', len(initiator_released) >= 2)

    floor = collections.Counter()
    violations = []
    for subtype, fields in floor_messages(args.capture):
        if subtype not in TYPES or 13 not in fields:
            continue
        indicator = struct.unpack('!H', fields[13][:2])[0]
        kind = 'broadcast' if indicator & BROADCAST_BIT else 'normal' if indicator & NORMAL_BIT else 'other'
        floor[f'{kind} {TYPES[subtype]}'] += 1
        if subtype == 2 and 5 in fields:
            permission = struct.unpack('!H', fields[5][:2])[0]
            if (kind == 'broadcast') != (permission == 0):
                violations.append(f'{kind} Taken with permission {permission}')
        if subtype == 3 and kind == 'broadcast' and (len(fields.get(2, b'')) < 2 or fields[2][:2] != b'\x00\x05'):
            violations.append('broadcast Deny without cause 5')
        if indicator & BROADCAST_BIT and indicator & NORMAL_BIT:
            violations.append('broadcast and normal bits both set')
        if indicator & EMERGENCY_BIT and indicator & IMMINENT_BIT:
            violations.append('emergency and imminent bits both set')
        if kind == 'broadcast' and indicator & EMERGENCY_BIT:
            floor['broadcast emergency'] += 1
        if kind == 'broadcast' and indicator & IMMINENT_BIT:
            floor['broadcast imminent'] += 1
    for kind in ('Granted', 'Taken', 'Deny', 'Idle'):
        check(f'broadcast Floor {kind} carries the B-bit', floor[f'broadcast {kind}'] > 0)
    check('normal-call floor messages carry the A-bit', floor['normal Taken'] > 0 and floor['normal Granted'] > 0)
    check(
        'emergency broadcast floor messages carry B and D; imminent-peril broadcast ones B and E',
        floor['broadcast emergency'] > 0 and floor['broadcast imminent'] > 0,
    )
    check('broadcast Taken has permission to request 0, normal Taken 1; broadcast Deny cause 5', not violations)

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        violations=violations,
        counts=dict(
            sip_messages=len(messages),
            originating_broadcast_invites=len(originating),
            broadcast_fanout_invites=len(terminating),
            server_released_broadcast_dialogs=len(server_byes),
            floor_messages=dict(floor),
            initiator_final_responses=dict(
                collections.Counter(f'{status_code} {warning_text}'.strip() for status_code, warning_text in outcomes)
            ),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
