#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify emergency first-to-answer signaling from a clear-SIP capture.

The emergency first-to-answer call of TS 24.379 clause 11.1.1: the originating INVITE carries emergency-ind, the
emergency Resource-Priority and two or more invitees (clause 11.1.1.2.1.1); the controlling function invites each with
Priv-Answer-Mode Manual (clause 11.1.1.4.1), answers the caller with the selected invitee, cancels the others and
answers an alert not authorised for every invitee with 200 and warning 149 (clause 11.1.1.4.2), the alert being
withdrawn by SIP INFO; a re-INVITE cancels the emergency. Every floor message of the call carries the Floor Indicator
'D' bit (TS 24.380 clause 8.2.3.15).

Usage: verify_first_to_answer_emergency.py capture.pcap --service sip:mcptt@DOMAIN
         --emergency-priority mcpttp.15 --output result.json
Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402
from verify_broadcast_call import floor_frame  # noqa: E402
import struct


# ------------------------------------------------------------------------------
def packets(path):
    """Yield (time, Ethernet frame) of each packet in the classic PCAP at path."""
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = raw[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    offset = 24
    while offset + 16 <= len(raw):
        seconds, fraction, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        yield seconds + fraction / (1e9 if nano else 1e6), raw[offset : offset + captured]
        offset += captured


# ------------------------------------------------------------------------------
def cancellation_window(path):
    """The capture times from the first re-INVITE that cancels the emergency (<emergency-ind> false) to the next
    originating INVITE (the next call), or None."""
    start = None
    for stamp, frame in packets(path):
        if b'INVITE sip:' not in frame:
            continue
        if start is None:
            if b';mcptt-session=' in frame and re.search(rb'<emergency-ind[^>]*>\s*<mcpttBoolean>\s*false', frame):
                start = stamp
        elif re.search(rb'INVITE sip:mcptt@[^ ;]+ SIP/2\.0', frame):
            return start, stamp
    return (start, float('inf')) if start is not None else None


# ------------------------------------------------------------------------------
def timed_floor_messages(path):
    """Yield (time, subtype, fields) of every floor control message, as floor_messages does, with its time."""
    for stamp, frame in packets(path):
        for subtype, fields in floor_frame(frame):
            yield stamp, subtype, fields


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--emergency-priority', required=True)
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
            responses[(parsed['call_id'], parsed['method'])].append(parsed)
    fta = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['info'].get('session-type') == 'first-to-answer'
    ]
    originating = [
        message
        for message in fta
        if message['target'] == args.service and message['info'].get('emergency-ind') == 'true'
    ]
    terminating = [
        message
        for message in fta
        if 'mcptt-server' in header(message, 'via') and message['info'].get('emergency-ind') == 'true'
    ]
    check(
        'originating emergency first-to-answer INVITEs carry emergency-ind, Resource-Priority and two or more invitees',
        bool(originating)
        and all(
            header(message, 'resource-priority') == args.emergency_priority
            and message['targets']
            and len(message['targets']) >= 2
            for message in originating
        ),
    )
    check(
        'an alert request carries alert-ind and a location body',
        any(
            message['info'].get('alert-ind') == 'true' and 'mcptt-location-info' in message['body']
            for message in originating
        ),
    )
    check(
        'invitee INVITEs carry emergency-ind, the emergency Resource-Priority and Priv-Answer-Mode Manual',
        bool(terminating)
        and all(
            header(message, 'resource-priority') == args.emergency_priority
            and header(message, 'priv-answer-mode') == 'Manual'
            for message in terminating
        ),
    )
    # Match the initial INVITE's CSeq: later re-INVITEs share the Call-ID.
    outcomes = [
        (response['status'], header(response, 'warning'), response)
        for message in originating
        for response in responses[(message['call_id'], 'INVITE')]
        if response['status'] >= 200 and header(response, 'cseq') == header(message, 'cseq')
    ]
    accepted = [response for status_code, _, response in outcomes if status_code == 200]
    check(
        '200 OK names the selected invitee and confirms emergency-ind',
        bool(accepted)
        and all(
            response['info'].get('mcptt-called-party-id') and response['info'].get('emergency-ind') == 'true'
            for response in accepted
        ),
    )
    check(
        'no authorised recipient: 403 carrying emergency-ind false',
        any(
            status_code == 403
            and 'emergency private call not authorized' in warning_text
            and response['info'].get('emergency-ind') == 'false'
            for status_code, warning_text, response in outcomes
        ),
    )
    check(
        'an alert not authorised for every invitee: 200 with warning 149',
        any(
            status_code == 200 and '149 SIP INFO request pending' in warning_text
            for status_code, warning_text, _ in outcomes
        ),
    )
    infos = [
        message
        for message in messages
        if message['request'] and message['method'] == 'INFO' and message['info'].get('alert-ind') == 'false'
    ]
    check('the unauthorised alert is withdrawn by SIP INFO', bool(infos))
    cancels = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'CANCEL'
        and message['call_id'] in {invitation['call_id'] for invitation in terminating}
    ]
    check('unselected invitees are cancelled', bool(cancels))
    reinvites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['call_id'] in {origination['call_id'] for origination in originating}
        and message['info'].get('emergency-ind') == 'false'
    ]
    check(
        'after selection, an in-dialog re-INVITE cancels the emergency',
        bool(reinvites)
        and all(
            any(response['status'] == 200 for response in responses[(message['call_id'], 'INVITE')])
            for message in reinvites
        ),
    )
    # TS 24.380 clause 8.2.3.15: floor messages of the emergency call carry the D-bit (0x1000); once the in-dialog
    # re-INVITE has cancelled the emergency (TS 24.379 clause 11.1.3), the call is a normal one and its floor
    # messages carry the A-bit (0x8000) instead.
    window = cancellation_window(args.capture)
    indicators, after = collections.Counter(), collections.Counter()
    for stamp, subtype, fields in timed_floor_messages(args.capture):
        if 13 in fields:
            key = f'{subtype}:{struct.unpack("!H", fields[13][:2])[0]:#06x}'
            (after if window and window[0] < stamp < window[1] else indicators)[key] += 1
    # The only floor traffic in this capture belongs to the emergency calls (FE-03). The Floor Release of the call
    # whose emergency is cancelled may come after the cancellation.
    check(
        'every floor message of the emergency call, client and server, carries the D-bit',
        all(indicators[f'{invitation}:0x1000'] for invitation in (0, 1, 2, 5))
        and (indicators['4:0x1000'] or after['4:0x8000'])
        and all(key.endswith('0x1000') for key in indicators),
    )
    check(
        'after the emergency is cancelled, the floor messages carry the A-bit only',
        all(key.endswith('0x8000') for key in after),
    )
    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            sip_messages=len(messages),
            originating=len(originating),
            terminating=len(terminating),
            cancels=len(cancels),
            alert_withdrawals=len(infos),
            cancellation_reinvites=len(reinvites),
            floor_indicators=dict(indicators),
            floor_indicators_after_cancellation=dict(after),
            caller_final_responses=dict(
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
