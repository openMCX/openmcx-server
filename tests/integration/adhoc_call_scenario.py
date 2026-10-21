#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise on-network, on-demand ad hoc group calls with a participant list.

Covers the client and controlling MCPTT function procedures of TS 24.379 clause 17: setup
(clauses 17.2.2.1.1 and 17.4.2.2, with the warnings 185, 187 and 189), leave and rejoin
(clauses 17.2.4.1.1, 17.2.5.1.1 and 17.4.4.1.1), release by the initiator and by timer TNG3
(clause 6.3.8.1 items 3 and 5), emergency and imminent peril calls (clause 17.4.2.2 steps 3A to
3D, 14A and 14B), participants determination by criteria (clause 17.4.6.1), participants modify
(clause 17.4.5.1.1, warning 190), and the ad hoc group emergency alert (clause 12.1A), with
floor control per TS 24.380 clause 6.3.4.

Run against a separate four-client fixture prepared with --adhoc. Check labels
carry the IDs used in tests/mcptt/ADHOC_CALL_TEST.md.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the ad hoc group call checks AH-01 to AH-17 and write integration/adhoc-call-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-adhoc')
    parser.add_argument('--skip-timer', action='store_true', help='Skip the 30-second call timer check explicitly')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcptt']['user_id'] for client in roles}
    timers = json.loads((generated / 'mcptt-server.json').read_text())['mcptt']['adhoc_call']
    nobody = 'sip:nobody.mcptt@' + ids['client-a'].split('@', 1)[1]
    checks, observations = [], {}
    result = dict(scenario='on-demand-adhoc-group-call', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """Every client's and the server's status, for the failure report."""
        return {client: status(client) for client in roles + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=15):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def sessions():
        """The server's call sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def adhoc_sessions():
        """The server's ad hoc group call sessions."""
        return [call for call in sessions() if call.get('call_type') == 'adhoc']

    # ------------------------------------------------------------------------------
    def idle(wanted=roles):
        """Every wanted client idle and the server holding no session."""
        return all(status(client).get('call_state') == 'idle' for client in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def adhoc_active(wanted):
        """Exactly one ad hoc session, started by client-a for a generated ad hoc group identity (TS 24.379
        clause 17.4.2.2 step 10), whose participants are the wanted users, each active in it."""
        current = adhoc_sessions()
        if len(current) != 1:
            return False
        group = current[0].get('group_id', '')
        return (
            group.startswith('sip:adhoc-')
            and current[0].get('initiator') == ids['client-a']
            and set(current[0].get('participants', [])) == {ids[client] for client in wanted}
            and all(
                status(client).get('call_state') == 'active'
                and status(client).get('call_type') == 'adhoc'
                and status(client).get('call_group') == group
                for client in wanted
            )
        )

    # ------------------------------------------------------------------------------
    def roster(wanted):
        """Each wanted user's conference roster lists exactly the wanted users."""
        expected = {ids[client] for client in wanted}
        return all(
            status(client).get('conference_active')
            and set(status(client).get('conference_participants', [])) == expected
            for client in wanted
        )

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning=''):
        """A predicate: the role is idle and its last call failed with the code and the warning text
        (TS 24.379 clause 17.4.2.2 steps 4, 6 and 7)."""

        # ------------------------------------------------------------------------------
        def check():
            """The role is idle and its last call failure carries the code and the warning."""
            failure = status(role).get('last_call_failure') or {}
            return (
                status(role).get('call_state') == 'idle'
                and failure.get('status') == code
                and warning in failure.get('warning', '')
            )

        return check

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(client).get('authorized') and status(client).get('affiliated') for client in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
        for role in roles:
            command(role, 'answer-mode auto')

        # AH-01 the listed users are invited; an unaffiliated invitee joins (implicit affiliation).
        command('client-c', 'deaffiliate')
        wait('AH-01 invitee c deaffiliated beforehand', lambda: not status('client-c').get('affiliated'))
        command('client-a', f"adhoc {ids['client-b']} {ids['client-c']}")
        wait(
            'AH-01 initiator and both listed users active in one ad hoc group',
            lambda: adhoc_active(['client-a', 'client-b', 'client-c']),
        )
        assert status('client-d').get('call_state') == 'idle', 'unlisted user was invited'
        checks.append('AH-01 unlisted user not invited')
        first_group = adhoc_sessions()[0]['group_id']
        session = adhoc_sessions()[0]['session_uri']
        observations['adhoc_group_id'] = first_group

        # AH-02 conference rosters use the ad hoc group identity.
        wait(
            'AH-02 conference rosters list the three participants', lambda: roster(['client-a', 'client-b', 'client-c'])
        )

        # AH-03 floor contention and two-way speech.
        denials = status('client-b').get('floor_denials', 0)
        before_b = status('client-b').get('received_packets', 0)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait('AH-03 initiator granted floor', lambda: status('client-a').get('talking'))
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('AH-03 competing request denied', lambda: status('client-b').get('floor_denials', 0) > denials)
        wait(
            'AH-03 participant receives speech',
            lambda: status('client-b').get('received_packets', 0) >= before_b + 100,
            20,
        )
        wait(
            'AH-03 floor released',
            lambda: not status('client-a').get('talking') and not adhoc_sessions()[0].get('floor_owner'),
            20,
        )
        before_a = status('client-a').get('received_packets', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('AH-03 invitee granted floor', lambda: status('client-b').get('talking'))
        wait(
            'AH-03 initiator receives speech',
            lambda: status('client-a').get('received_packets', 0) >= before_a + 100,
            20,
        )
        wait('AH-03 second floor released', lambda: not status('client-b').get('talking'), 20)

        # AH-04 a participant leaves and rejoins by session identity.
        command('client-b', 'hangup')
        wait(
            'AH-04 call continues after a participant leaves',
            lambda: status('client-b').get('call_state') == 'idle' and adhoc_active(['client-a', 'client-c']),
        )
        wait('AH-04 rosters drop the departed participant', lambda: roster(['client-a', 'client-c']))
        command('client-b', 'rejoin')
        wait(
            'AH-04 participant rejoins the same ad hoc session',
            lambda: (
                adhoc_active(['client-a', 'client-b', 'client-c'])
                and adhoc_sessions()[0]['session_uri'] == session
                and adhoc_sessions()[0]['group_id'] == first_group
            ),
        )

        # AH-05 one remaining participant does not release an ad hoc call (TS 24.379 clause 6.3.8.1
        # item 2 excludes it).
        command('client-b', 'hangup')
        command('client-c', 'hangup')
        wait(
            'AH-05 initiator alone keeps the ad hoc session',
            lambda: (
                adhoc_active(['client-a'])
                and all(status(client).get('call_state') == 'idle' for client in ['client-b', 'client-c'])
            ),
        )
        assert holds(lambda: adhoc_active(['client-a']), 3), 'lone initiator released'
        checks.append('AH-05 lone initiator still active after 3 s')

        # AH-06 the initiator leaving releases the call and deletes the ad hoc group.
        command('client-a', 'hangup')
        wait('AH-06 initiator leaving releases the ad hoc call', idle)
        command('client-c', 'affiliate')
        wait('AH-06 client c reaffiliated', lambda: status('client-c').get('affiliated'))
        command('client-a', f"adhoc {ids['client-b']} {ids['client-c']}")
        wait('AH-06 new ad hoc call active', lambda: adhoc_active(['client-a', 'client-b', 'client-c']))
        assert adhoc_sessions()[0]['group_id'] != first_group, 'ad hoc group identity reused'
        checks.append('AH-06 new call gets a new ad hoc group identity')
        command('client-a', 'hangup')
        wait('AH-06 second call released by initiator', idle)

        # AH-07 authorization and participant determination.
        for caller, targets, code, warning in [
            ('client-d', [ids['client-a']], 403, '185 user is not authorised to initiate the adhoc group call'),
            (
                'client-a',
                [ids['client-b'], ids['client-c'], ids['client-d'], nobody],
                403,
                '189 maximum number of allowed adhoc group participants exceeded',
            ),
            ('client-a', [ids['client-a']], 403, "187 can't determine the adhoc group participants"),
            ('client-a', [nobody], 480, ''),
        ]:
            command(caller, 'adhoc ' + ' '.join(targets))
            label = f'AH-07 {caller} request rejected with {code}' + (
                f' warning {warning[:3]}' if warning else ' (no reachable invitee)'
            )
            wait(label, rejected(caller, code, warning))
        wait('AH-07 rejected requests leave no session', idle)

        # AH-08 manual commencement: answer, and decline without ending the call.
        command('client-b', 'answer-mode manual')
        command('client-a', f"adhoc {ids['client-b']} {ids['client-c']}")
        wait(
            'AH-08 initiator connected once one invitee answers',
            lambda: adhoc_active(['client-a', 'client-c']) and status('client-b').get('call_state') == 'ringing',
        )
        command('client-b', 'answer')
        wait('AH-08 manual invitee joins after answering', lambda: adhoc_active(['client-a', 'client-b', 'client-c']))
        command('client-a', 'hangup')
        wait('AH-08 released', idle)
        command('client-a', f"adhoc {ids['client-b']} {ids['client-c']}")
        wait(
            'AH-08 manual invitee ringing again',
            lambda: status('client-b').get('call_state') == 'ringing' and adhoc_active(['client-a', 'client-c']),
        )
        command('client-b', 'reject')
        wait(
            'AH-08 decline leaves the call with the others',
            lambda: status('client-b').get('call_state') == 'idle' and adhoc_active(['client-a', 'client-c']),
        )
        command('client-a', 'hangup')
        wait('AH-08 declined call released by initiator', idle)
        command('client-b', 'answer-mode auto')

        # AH-09 an ad hoc call runs alongside a prearranged group call.
        first = configs['client-a']['mcptt']['group_id']
        second = next(candidate for candidate in configs['client-c']['mcptt']['allowed_groups'] if candidate != first)
        for role in ['client-c', 'client-d']:
            command(role, 'group ' + second)
        wait(
            'AH-09 clients c and d on the parallel prearranged group',
            lambda: all(
                status(client).get('affiliated') and status(client).get('group_id') == second
                for client in ['client-c', 'client-d']
            ),
        )
        command('client-c', 'call')
        wait(
            'AH-09 prearranged call active',
            lambda: (
                any(call.get('call_type') == 'prearranged' for call in sessions())
                and all(status(client).get('call_state') == 'active' for client in ['client-c', 'client-d'])
            ),
        )
        command('client-a', f"adhoc {ids['client-b']}")
        wait(
            'AH-09 ad hoc and prearranged sessions coexist',
            lambda: len(sessions()) == 2 and adhoc_active(['client-a', 'client-b']),
        )
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'AH-09 independent floors granted concurrently',
            lambda: (
                len(sessions()) == 2
                and all(
                    call.get('floor_owner')
                    == (ids['client-a'] if call.get('call_type') == 'adhoc' else ids['client-c'])
                    for call in sessions()
                )
            ),
        )
        wait('AH-09 both floors released', lambda: all(not call.get('floor_owner') for call in sessions()), 20)
        command('client-a', 'hangup')
        wait('AH-09 ending the ad hoc call keeps the group call', lambda: len(sessions()) == 1 and not adhoc_sessions())
        command('client-c', 'hangup')
        wait('AH-09 group call released', idle)

        # ------------------------------------------------------------------------------
        # AH-15 emergency and imminent peril ad hoc group calls (TS 24.379 clause 17.4.2.2
        # steps 3A to 3D, 13 and 14A; clause 17.4.2.1.1 steps 6 and 7).
        def adhoc_priority(value):
            """The one ad hoc session runs at the priority value ('emergency' or 'imminent')."""
            current = adhoc_sessions()
            return len(current) == 1 and current[0].get('priority') == value

        command('client-b', f"adhoc emergency {ids['client-a']}")
        wait(
            'AH-15 unauthorised emergency ad hoc call rejected with 403',
            rejected('client-b', 403, 'emergency adhoc group call not authorized'),
        )
        command('client-a', f"adhoc emergency {ids['client-b']} {ids['client-c']}")
        wait(
            'AH-15 authorised emergency ad hoc call established',
            lambda: adhoc_active(['client-a', 'client-b', 'client-c']) and adhoc_priority('emergency'),
        )
        wait(
            'AH-15 invitees learn the emergency ad hoc call',
            lambda: all(status(client).get('adhoc_priority') == 'emergency' for client in ['client-b', 'client-c']),
        )
        started = time.monotonic()
        limit = timers.get('emergency_timeout_ms', 300000) / 1000
        assert limit < timers['maximum_duration_ms'] / 1000, 'TNG2 must be shorter than TNG3 for this check'
        wait('AH-15 TNG2 releases the emergency ad hoc call', idle, limit + 10)
        observations['tng2_seconds'] = round(time.monotonic() - started, 2)
        assert observations['tng2_seconds'] >= limit - 3, 'released before TNG2'
        command('client-a', f"adhoc imminent {ids['client-b']}")
        wait(
            'AH-15 imminent peril ad hoc call established',
            lambda: (
                adhoc_active(['client-a', 'client-b'])
                and adhoc_priority('imminent')
                and status('client-b').get('adhoc_priority') == 'imminent'
            ),
        )
        command('client-a', 'hangup')
        wait('AH-15 imminent peril ad hoc call released', idle)

        # AH-15b emergency broadcast ad hoc call (H7): the Floor Indicator (TS 24.380
        # clause 8.2.3.15) carries B and D, and the call still ends with the initiator's transmission.
        command('client-a', f"adhoc broadcast emergency {ids['client-b']} {ids['client-c']}")

        # ------------------------------------------------------------------------------
        def emergency_broadcast_adhoc():
            """One emergency ad hoc broadcast session with the three users, each active in it as an emergency
            ad hoc call, the receivers seeing it as a broadcast."""
            # The server lists an ad hoc broadcast with call type "broadcast".
            current = [call for call in sessions() if call.get('group_id', '').startswith('sip:adhoc-')]
            return (
                len(current) == 1
                and current[0].get('call_type') == 'broadcast'
                and current[0].get('priority') == 'emergency'
                and set(current[0].get('participants', []))
                == {ids[client] for client in ['client-a', 'client-b', 'client-c']}
                and all(
                    status(client).get('call_state') == 'active'
                    and status(client).get('call_type') == 'adhoc'
                    and status(client).get('adhoc_priority') == 'emergency'
                    for client in ['client-a', 'client-b', 'client-c']
                )
                and all(status(client).get('adhoc_broadcast') for client in ['client-b', 'client-c'])
            )

        wait('AH-15b emergency broadcast ad hoc call established', emergency_broadcast_adhoc)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'AH-15b receivers see Floor Taken with B and D bits',
            lambda: all(status(client).get('floor_indicator') == 0x5000 for client in ['client-b', 'client-c']),
        )
        wait('AH-15b emergency broadcast ad hoc call released at transmission end', idle, 25)

        # AH-16 criteria-based participants (TS 24.379 clause 17.4.6.1, local-policy criterion
        # "affiliated:<group>") with continuous re-evaluation, and participant
        # list modification (TS 24.379 clause 17.4.5.1.1).
        site = json.loads((generated / 'site.json').read_text())
        first, second = site['groups'][0]['id'], site['groups'][1]['id']

        # ------------------------------------------------------------------------------
        def on(role, group):
            """Move the role to the group (affiliating it) unless it is there already, and wait for it."""
            if status(role).get('group_id') != group:
                command(role, 'group ' + group)
            wait(
                f'AH-16 {role} on {group}',
                lambda: status(role).get('affiliated') and status(role).get('group_id') == group,
                30,
            )

        on('client-c', second)
        on('client-d', first)
        command('client-a', f'adhoc criteria affiliated:{second}')
        wait(
            'AH-16 criteria call invites exactly the users affiliated to the group',
            lambda: adhoc_active(['client-a', 'client-c']),
        )
        assert all(status(client).get('call_state') == 'idle' for client in ['client-b', 'client-d']), (
            'user outside the criteria invited'
        )
        on('client-d', second)
        wait(
            'AH-16 a user newly meeting the criteria is invited',
            lambda: adhoc_active(['client-a', 'client-c', 'client-d']),
            20,
        )
        command('client-d', 'deaffiliate')
        wait('AH-16 departed user no longer meets the criteria', lambda: adhoc_active(['client-a', 'client-c']), 20)
        assert holds(lambda: adhoc_active(['client-a', 'client-c']), 5), 'user outside the criteria re-invited'
        checks.append('AH-16 a user outside the criteria is not re-invited')
        command('client-d', 'affiliate')
        wait(
            'AH-16 re-affiliated user is invited again', lambda: adhoc_active(['client-a', 'client-c', 'client-d']), 20
        )
        # TS 24.379 clauses 17.2.6.1.1 step 1 and 17.4.5.1.1 step 4: a list change of a call by criteria carries the
        # session's criteria unchanged; the list is applied.
        command('client-a', f"adhoc-modify add {ids['client-b']}")
        wait(
            'AH-16 a list change carrying the unchanged criteria is accepted: client-b invited',
            lambda: adhoc_active(['client-a', 'client-b', 'client-c', 'client-d'])
            and (status('client-a').get('last_modify_result') or {}).get('status') == 200,
            20,
        )
        # TS 24.379 clause 17.4.5.2.1 steps 4a and 5a: the criteria do not remove a user invited by a modification
        # (client-b, not affiliated to the group) nor invite again one removed by a modification (client-d, still
        # affiliated).
        assert holds(lambda: adhoc_active(['client-a', 'client-b', 'client-c', 'client-d']), 5), (
            'manually invited user removed by the criteria'
        )
        checks.append('AH-16 a user invited by a modification stays outside the criteria')
        command('client-a', f"adhoc-modify remove {ids['client-d']}")
        wait(
            'AH-16 modify removes a user meeting the criteria',
            lambda: adhoc_active(['client-a', 'client-b', 'client-c']),
        )
        assert holds(lambda: adhoc_active(['client-a', 'client-b', 'client-c']), 5), (
            'manually removed user invited again by the criteria'
        )
        checks.append('AH-16 a user removed by a modification is not invited again by the criteria')
        command('client-a', 'hangup')
        wait('AH-16 criteria call released', idle)
        on('client-c', first)
        on('client-d', first)
        command('client-a', f"adhoc {ids['client-b']}")
        wait('AH-16 list call established', lambda: adhoc_active(['client-a', 'client-b']))
        command('client-a', f"adhoc-modify add {ids['client-c']}")
        wait('AH-16 modify adds a participant', lambda: adhoc_active(['client-a', 'client-b', 'client-c']))
        command('client-a', f"adhoc-modify remove {ids['client-b']}")
        wait(
            'AH-16 modify removes a participant',
            lambda: adhoc_active(['client-a', 'client-c']) and status('client-b').get('call_state') == 'idle',
        )
        command('client-c', f"adhoc-modify add {ids['client-d']}")
        wait(
            'AH-16 unauthorised modification rejected with 403 warning 190',
            lambda: (
                (status('client-c').get('last_modify_result') or {}).get('status') == 403
                and '190 ' in (status('client-c').get('last_modify_result') or {}).get('warning', '')
            ),
        )
        assert adhoc_active(['client-a', 'client-c']), 'rejected modification changed the call'
        command('client-a', 'hangup')
        wait('AH-16 modified call released', idle)

        # AH-17 ad hoc group emergency alert (TS 24.379 clause 12.1A): recipients follow the
        # criteria, a call on the alert's ad hoc group invites them, and the
        # originator cancels the alert.
        on('client-c', second)
        on('client-d', second)
        command('client-b', f'adhoc-alert affiliated:{second}')
        wait(
            'AH-17 unauthorised ad hoc emergency alert rejected with 403',
            lambda: (status('client-b').get('last_adhoc_alert_result') or {}).get('status') == 403,
        )
        command('client-a', f'adhoc-alert affiliated:{second}')
        wait(
            'AH-17 authorised alert confirmed to the originator (AH-MEA 3)',
            lambda: (
                status('client-a').get('adhoc_alert_state', '').startswith('AH-MEA 3')
                and status('client-a').get('adhoc_alert_group')
            ),
        )
        group = status('client-a')['adhoc_alert_group']
        wait(
            'AH-17 users meeting the criteria receive the alert',
            lambda: all(
                (status(client).get('received_adhoc_alerts') or {}).get(group, {}).get('initiator') == ids['client-a']
                for client in ['client-c', 'client-d']
            ),
        )
        assert group not in (status('client-b').get('received_adhoc_alerts') or {}), 'alert sent outside the criteria'
        checks.append('AH-17 users outside the criteria are not alerted')
        on('client-d', first)
        wait(
            'AH-17 a user leaving the criteria has the alert withdrawn',
            lambda: group not in (status('client-d').get('received_adhoc_alerts') or {}),
            20,
        )
        on('client-d', second)
        wait(
            'AH-17 a user meeting the criteria again is alerted again',
            lambda: group in (status('client-d').get('received_adhoc_alerts') or {}),
            20,
        )
        command('client-a', 'adhoc emergency alert-group')
        wait(
            'AH-17 emergency call on the alert group invites the alerted users',
            lambda: (
                adhoc_active(['client-a', 'client-c', 'client-d'])
                and adhoc_sessions()[0].get('group_id') == group
                and adhoc_sessions()[0].get('priority') == 'emergency'
            ),
            20,
        )
        command('client-a', 'hangup')
        wait('AH-17 alert-group call released', idle, 20)
        command('client-a', 'adhoc-alert cancel')
        wait(
            'AH-17 cancellation withdraws the alert from every recipient',
            lambda: (
                status('client-a').get('adhoc_alert_state', '').startswith('AH-MEA 1')
                and all(
                    group not in (status(client).get('received_adhoc_alerts') or {})
                    for client in ['client-c', 'client-d']
                )
                and not status('mcptt-server').get('adhoc_alerts')
            ),
            20,
        )
        on('client-c', first)
        on('client-d', first)

        # AH-10 TNG3 group call timer releases the ad hoc call (TS 24.379 clause 6.3.8.1 item 5).
        if args.skip_timer:
            result['timer_skipped'] = True
        else:
            limit = timers['maximum_duration_ms'] / 1000
            command('client-a', f"adhoc {ids['client-b']}")
            wait('AH-10 timed ad hoc call active', lambda: adhoc_active(['client-a', 'client-b']))
            started = time.monotonic()
            command('client-a', 'ptt /artifacts/speech/alpha.wav')
            wait('AH-10 TNG3 call timer releases the ad hoc call', idle, limit + 10)
            observations['call_timer_seconds'] = round(time.monotonic() - started, 2)
            assert observations['call_timer_seconds'] >= limit - 3, 'released before the call timer'

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError, StopIteration) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/adhoc-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
