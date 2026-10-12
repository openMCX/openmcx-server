#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify ad hoc group-call signaling and floor coding from a clear-SIP capture.

The ad hoc group call of TS 24.379 clause 17: originating INVITEs carry a participant list or criteria and no group
identity (clause 17.2.2.1.1; an emergency alert group call names the ad hoc group instead, clause 17.4.2.2 step 12 d));
the controlling function invites each participant with the generated ad hoc group identity (clause 17.4.2.1.1) and does
not forward Priv-Answer-Mode (clause 17.3.2.1.1 step 12 b)), answers the initiator with that identity, accepts a rejoin
(clause 17.4.4.1.1), rejects with warnings 185, 187, 189 and 190 (TS 24.379 table 4.4.2-2), uses Resource-Priority for
emergency and imminent peril ad hoc calls (clause 17.4.2.1.1 steps 6 and 7), accepts participant modifications (clause
17.2.6.1.1) and releases participants itself (clause 17.4.3.1). Floor messages carry the Floor Indicator 'A' bit, never
'B' (TS 24.380 table 8.2.3.15-2), and Floor Taken permits requests (TS 24.380 clause 8.2.3.7).

Usage: verify_adhoc_call.py capture.pcap --service sip:mcptt@DOMAIN --output result.json

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
            responses[(parsed['call_id'], parsed['method'], header(parsed, 'cseq').split()[0])].append(parsed)
    # Initial INVITEs only; re-INVITEs (To tag present) modify an established call.
    all_invites = [
        message
        for message in messages
        if message['request'] and message['method'] == 'INVITE' and message['info'].get('session-type') == 'adhoc'
    ]
    invites = [message for message in all_invites if not re.search(r';\s*tag=', header(message, 'to'), re.I)]
    modifications = [message for message in all_invites if message not in invites]
    originating = [message for message in invites if message['target'] == args.service]
    rejoins = [message for message in invites if ';mcptt-session=' in message['target']]
    terminating = [message for message in invites if 'mcptt-server' in header(message, 'via')]
    check(
        'originating ad hoc INVITEs carry a participant list or criteria (never both) and no group identity',
        bool(originating)
        and all(
            (
                bool(message['targets']) != bool(message['info'].get('call-participants-criterias'))
                # TS 24.379 clause 17.4.2.2 step 12 d): an alert-group call names the ad hoc group instead
                or (
                    message['info'].get('adhoc-grp-emg-alert-grp-ind') == 'true'
                    and not message['targets']
                    and message['info'].get('mcptt-request-uri', '').startswith('sip:adhoc-')
                )
            )
            and 'mcptt-calling-group-id' not in message['info']
            for message in originating
        ),
    )
    groups = [message['info'].get('mcptt-calling-group-id', '') for message in terminating]
    check(
        'terminating INVITEs address each invitee with the ad hoc group identity and initiator',
        bool(terminating)
        and all(
            message['info'].get('mcptt-request-uri')
            and message['info'].get('mcptt-calling-user-id')
            and group.startswith('sip:adhoc-')
            for message, group in zip(terminating, groups)
        ),
    )
    check(
        'terminating INVITEs carry no participant list and present an isfocus session Contact',
        all(
            message['targets'] is None
            and 'isfocus' in header(message, 'contact')
            and ';mcptt-session=' in header(message, 'contact')
            for message in terminating
        ),
    )
    check(
        'Priv-Answer-Mode is never forwarded to invitees (17.3.2.1.1 step 12)',
        not any(header(message, 'priv-answer-mode') for message in terminating),
    )
    outcomes = [
        (response['status'], header(response, 'warning'), response)
        for message in originating
        for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
        if response['status'] >= 200
    ]
    accepted = [response for status_code, _, response in outcomes if status_code == 200]
    check(
        '200 OK to the initiator returns the ad hoc group identity with an isfocus Contact',
        bool(accepted)
        and all(
            response['info'].get('mcptt-calling-group-id', '').startswith('sip:adhoc-')
            and 'isfocus' in header(response, 'contact')
            for response in accepted
        ),
    )
    # TS 24.379 clause 17.4.2.2: the initiator gets no 180 (Ringing); clauses 6.3.2.1.5.2 and 6.3.3.2.3.2: the 200 (OK)
    # asserts the service's identity and supports tdialog, norefersub, explicitsub and nosub.
    check(
        'the initiator gets no 180 (Ringing)',
        not any(
            response['status'] == 180
            for message in originating
            for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
        ),
    )
    check(
        '200 OK to the initiator asserts the service identity and supports tdialog, norefersub, explicitsub, nosub',
        bool(accepted)
        and all(
            args.service.replace('sips:', 'sip:') in header(response, 'p-asserted-identity').replace('sips:', 'sip:')
            and {'tdialog', 'norefersub', 'explicitsub', 'nosub'}
            <= {tag.strip().lower() for value in response['headers']['supported'] for tag in value.split(',')}
            for response in accepted
        ),
    )
    identities = {response['info'].get('mcptt-calling-group-id') for response in accepted}
    check(
        'each ad hoc call gets a distinct generated group identity',
        len(identities) == len(accepted) and len(identities) >= 3,
    )
    # A rejoin the SIP core challenges (407) is sent again with the next CSeq in the same Call-ID (RFC 3261
    # section 22.2): the rejoin is accepted when an INVITE of its Call-ID is.
    check(
        'rejoin by session identity is accepted with 200',
        bool(rejoins)
        and all(
            any(
                response['status'] == 200
                for (call_id, method, _), found in responses.items()
                if call_id == message['call_id'] and method == 'INVITE'
                for response in found
            )
            for message in rejoins
        ),
    )
    for code, warning in [
        (403, '185 user is not authorised to initiate the adhoc group call'),
        (403, '189 maximum number of allowed adhoc group participants exceeded'),
        (403, "187 can't determine the adhoc group participants"),
    ]:
        check(
            f'ad hoc request rejected with {code} warning {warning[:3]}',
            any(status_code == code and warning in warning_text for status_code, warning_text, _ in outcomes),
        )
    check('a list with no reachable invitee fails with 480', any(status_code == 480 for status_code, _, _ in outcomes))
    declined = [
        response
        for message in terminating
        for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
        if response['status'] == 480 and '110 user declined' in header(response, 'warning')
    ]
    check('an invitee decline (480 + warning 110) does not fail the call', bool(declined))
    notifies = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'NOTIFY'
        and 'conference' in header(message, 'event')
        and re.search(r'entity="sip:adhoc-', message['body'])
    ]
    check('conference NOTIFYs use the ad hoc group identity as entity', bool(notifies))
    adhoc_calls = {message['call_id'] for message in invites}
    server_byes = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'BYE'
        and message['call_id'] in adhoc_calls
        and 'mcptt-server' in header(message, 'via')
    ]
    check('the server releases ad hoc participants itself (initiator leave, timer)', len(server_byes) >= 2)
    floor = collections.Counter()
    violations = []
    broadcast_calls = [message for message in originating if message['info'].get('broadcast-ind') == 'true']
    for subtype, fields in floor_messages(args.capture):
        if 13 not in fields:
            continue
        indicator = struct.unpack('!H', fields[13][:2])[0]
        floor[f'{subtype}:{indicator:#06x}'] += 1
        # A broadcast ad hoc call (<broadcast-ind>, TS 24.379 clause 17.2.1.1) carries the B-bit, and its Floor
        # Taken gives no permission to request the floor (TS 24.380 clause 6.3.4.4.2).
        broadcast = bool(indicator & BROADCAST_BIT)
        if broadcast and not broadcast_calls:
            violations.append('broadcast bit without a broadcast ad hoc call')
        # A normal call carries the A-bit, an emergency or imminent peril call the D- or E-bit instead.
        if bool(indicator & NORMAL_BIT) == bool(indicator & (EMERGENCY_BIT | IMMINENT_BIT)):
            violations.append(f'Floor Indicator {indicator:#06x}: not one of the A-bit and the D- or E-bit')
        if subtype == 2 and 5 in fields and struct.unpack('!H', fields[5][:2])[0] != 1 and not broadcast:
            violations.append('Taken without permission to request')
    check(
        'floor messages carry the A-bit or the D- or E-bit, the B-bit only in a broadcast call, and Floor Taken '
        'permits requests except in a broadcast call',
        bool(floor) and not violations,
    )
    reject_causes, cause_violations = causes(args.capture)
    check('every Floor Deny and Floor Revoke carries a Reject Cause defined for it (TS 24.380 8.2.6.2, 8.2.10.2)',
          not cause_violations)
    check('a floor request while another participant has permission is denied with cause #1 (TS 24.380 6.3.5.4.4)',
          reject_causes[('Deny', 1)] > 0)

    # Priority ad hoc calls (TS 24.379 clause 17.4.2.1.1 steps 6 and 7): invitees learn the state with
    # Resource-Priority.
    priority_invites = [
        message
        for message in terminating
        if message['info'].get('adhoc-emergency-ind') == 'true' or message['info'].get('imminentperil-ind') == 'true'
    ]
    if priority_invites:
        check(
            'priority ad hoc invitations carry the indicator and a Resource-Priority header',
            all(header(message, 'resource-priority') for message in priority_invites),
        )
        check(
            'an unauthorised emergency ad hoc request is rejected with 403',
            any(
                status_code == 403 and 'emergency adhoc group call not authorized' in warning_text
                for status_code, warning_text, _ in outcomes
            ),
        )
    # Participant modification (TS 24.379 clause 17.2.6.1.1) carries method-tagged entries or criteria.
    if modifications:
        check(
            'modification re-INVITEs carry INVITE/BYE method entries or new criteria',
            all(
                message['targets']
                and all(';method=' in target.lower() for target in message['targets'])
                or message['info'].get('call-participants-criterias')
                for message in modifications
            ),
        )
        modify_results = [
            response
            for message in modifications
            for response in responses[(message['call_id'], 'INVITE', header(message, 'cseq').split()[0])]
            if response['status'] >= 200
        ]
        check(
            'modification accepted with 200 and unauthorised modification rejected with 403 warning 190',
            any(response['status'] == 200 for response in modify_results)
            and any(response['status'] == 403 and '190 ' in header(response, 'warning') for response in modify_results),
        )
    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        violations=violations + cause_violations,
        counts=dict(
            floor_reject_causes=summary(reject_causes),
            sip_messages=len(messages),
            originating_invites=len(originating),
            terminating_invites=len(terminating),
            rejoin_invites=len(rejoins),
            adhoc_group_identities=len(identities),
            conference_notifies=len(notifies),
            server_releases=len(server_byes),
            floor_messages=dict(floor),
            initiator_final_responses=dict(
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
