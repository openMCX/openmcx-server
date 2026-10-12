#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise on-network, on-demand private calls with floor control.

Run against a separate four-client fixture prepared with --private-call. Each
check records one assertion; IDs match tests/mcptt/PRIVATE_CALL_TEST.md.

Procedures under test: the on-demand private call and first-to-answer call with floor
control (TS 24.379 clause 11.1.1: client clause 11.1.1.2.1, participating MCPTT function
clause 11.1.1.3.1.1, controlling MCPTT function clauses 11.1.1.4.1 and 11.1.1.4.2), with the
private call timer (TS 24.379 clause 11.1.1.4.1 step 10); the rejections and their Warning
texts (TS 24.379 table 4.4.2-2); the emergency private call with its MEPC, MEPP and MPEA
states (TS 24.379 clauses 4.6.2 and 6.2.8.3, upgrade and cancellation in clauses
11.1.1.4.3 to 11.1.1.4.6); floor control in the private call (TS 24.380 clause 6.2.4).

Specifications: TS 24.379 V19.7.0, TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import threading
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run PC-01 to PC-12, PC-16 and PC-18 in order; write the results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-private')
    parser.add_argument(
        '--skip-timer', action='store_true', help='Skip the 30-second private call timer check explicitly'
    )
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    server_config = json.loads((generated / 'mcptt-server.json').read_text())
    timers = server_config['mcptt'].get('private_call', {})
    checks, observations = [], {}
    result = dict(scenario='on-demand-private-call', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """Every role's status, for the failure message and the results."""
        return {role: status(role) for role in roles + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Send a command to a role's running mcx-client."""
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
        """Record label once predicate() holds; fail with a snapshot on timeout."""
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
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def private_sessions():
        """The server's private call sessions."""
        return [session for session in sessions() if session.get('call_type') == 'private']

    # ------------------------------------------------------------------------------
    def idle(wanted=roles):
        """The wanted clients are idle and the server has no session."""
        return all(status(role).get('call_state') == 'idle' for role in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def private_active(caller, callee):
        """Exactly one private session, between caller and callee, active at both with each other as peer."""
        current = private_sessions()
        return (
            len(current) == 1
            and set(current[0].get('participants', [])) == {ids[caller], ids[callee]}
            and current[0].get('calling_user') == ids[caller]
            and current[0].get('called_user') == ids[callee]
            and all(
                status(role).get('call_state') == 'active' and status(role).get('call_type') == 'private'
                for role in (caller, callee)
            )
            and status(caller).get('private_peer') == ids[callee]
            and status(callee).get('private_peer') == ids[caller]
        )

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning=None):
        """A predicate: role's last call failed with SIP status code (and the Warning text, when given)."""

        # ------------------------------------------------------------------------------
        def check():
            """role is idle and its last call failure matches."""
            failure = status(role).get('last_call_failure') or {}
            return (
                status(role).get('call_state') == 'idle'
                and failure.get('status') == code
                and (warning is None or warning in failure.get('warning', ''))
            )

        return check

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for role in roles:
            command(role, 'answer-mode auto')

        # PC-01 automatic commencement and participant isolation. Baselines keep
        # the leak check valid on clients that have carried earlier calls.
        bystanders = {role: status(role).get('received_packets', 0) for role in ('client-c', 'client-d')}
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'PC-01 automatic commencement establishes exactly two private legs',
            lambda: private_active('client-a', 'client-b'),
        )
        assert all(status(role).get('call_state') == 'idle' for role in ('client-c', 'client-d')), (
            'group members joined a private call'
        )
        assert status('client-a').get('session_uri'), 'originator lacks private session identity'
        checks.append('PC-01 same-group members are not invited')
        assert status('client-a').get('conference_subscription', '') == '', (
            'private call subscribed to conference events'
        )
        checks.append('PC-01 no conference-event subscription for a private call')

        # PC-02 floor control and two-way speech; callee releases the call.
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
        before_b = status('client-b').get('received_packets', 0)
        denials = status('client-b').get('floor_denials', 0)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'PC-02 caller granted floor',
            lambda: (
                status('client-a').get('talking')
                and private_sessions()
                and private_sessions()[0].get('floor_owner') == ids['client-a']
            ),
        )
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('PC-02 competing callee request denied', lambda: status('client-b').get('floor_denials', 0) > denials)
        wait(
            'PC-02 callee receives caller speech',
            lambda: status('client-b').get('received_packets', 0) >= before_b + 100,
            20,
        )
        wait(
            'PC-02 caller floor released',
            lambda: (
                not status('client-a').get('talking')
                and private_sessions()
                and not private_sessions()[0].get('floor_owner')
            ),
            20,
        )
        before_a = status('client-a').get('received_packets', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('PC-02 callee granted floor', lambda: status('client-b').get('talking'))
        wait(
            'PC-02 caller receives callee speech',
            lambda: status('client-a').get('received_packets', 0) >= before_a + 100,
            20,
        )
        wait('PC-02 callee floor released', lambda: not status('client-b').get('talking'), 20)
        observations['speech_packets'] = {
            'client-a': status('client-a').get('received_packets', 0) - before_a,
            'client-b': status('client-b').get('received_packets', 0) - before_b,
        }
        assert all(status(role).get('received_packets', 0) == bystanders[role] for role in bystanders), (
            'private speech leaked'
        )
        checks.append('PC-02 non-participants received no private speech')
        command('client-b', 'hangup')
        wait('PC-02 callee hangup releases both parties and the session', idle)
        assert status('client-a').get('session_uri', '') == '', 'private session remained rejoinable'
        checks.append('PC-02 private session identity cleared after release')

        # PC-03 manual commencement answered by the callee.
        command('client-a', f"private {ids['client-b']} manual")
        wait(
            'PC-03 manual commencement rings callee',
            lambda: (
                status('client-b').get('call_state') == 'ringing' and status('client-a').get('call_state') == 'calling'
            ),
        )
        command('client-b', 'answer')
        wait('PC-03 answered manual call becomes active', lambda: private_active('client-a', 'client-b'))
        command('client-a', 'hangup')
        wait('PC-03 caller hangup releases both parties', idle)

        # PC-04 manual decline relays 480 and warning 110 to the caller.
        command('client-a', f"private {ids['client-b']} manual")
        wait('PC-04 callee ringing', lambda: status('client-b').get('call_state') == 'ringing')
        command('client-b', 'reject')
        wait(
            'PC-04 caller receives 480 with warning 110',
            rejected('client-a', 480, '110 user declined the call invitation'),
        )
        wait('PC-04 declined call cleaned up', idle)

        # PC-05 Priv-Answer-Mode forces automatic commencement over a manual callee setting.
        command('client-b', 'answer-mode manual')
        command('client-a', f"private {ids['client-b']} force-auto")
        wait('PC-05 forced auto answer bypasses manual setting', lambda: private_active('client-a', 'client-b'))
        command('client-a', 'hangup')
        wait('PC-05 forced call released', idle)

        # PC-06 caller cancels while ringing (callee still in manual mode).
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'PC-06 local manual setting rings despite requested auto',
            lambda: status('client-b').get('call_state') == 'ringing',
        )
        command('client-a', 'hangup')
        wait('PC-06 caller CANCEL clears ringing callee', idle)

        # PC-07 unanswered call fails at the configured setup timer.
        started = time.monotonic()
        command('client-a', f"private {ids['client-b']} manual")
        wait('PC-07 callee ringing before timeout', lambda: status('client-b').get('call_state') == 'ringing')
        wait(
            'PC-07 unanswered private call times out with 408',
            rejected('client-a', 408),
            timers.get('setup_timeout_ms', 30000) / 1000 + 10,
        )
        wait('PC-07 timed-out callee cleared', idle)
        observations['setup_timeout_seconds'] = round(time.monotonic() - started, 2)
        assert observations['setup_timeout_seconds'] >= timers.get('setup_timeout_ms', 30000) / 1000 - 0.5, (
            'timed out early'
        )
        command('client-b', 'answer-mode auto')

        # PC-08 originating authorization per user-profile ruleset.
        for caller, callee, mode, code, warning in [
            ('client-d', 'client-a', 'auto', 403, '107 user not authorised to make private calls'),
            (
                'client-c',
                'client-a',
                'manual',
                403,
                '126 user not authorised to make private call with manual commencement',
            ),
            ('client-b', 'client-a', 'force-auto', 403, '143 not authorised to force auto answer'),
            ('client-a', 'client-d', 'auto', 403, '144 user not authorised to call this particular user'),
        ]:
            command(caller, f"private {ids[callee]} {mode}")
            wait(f'PC-08 {caller} to {callee} {mode} rejected with {warning[:3]}', rejected(caller, code, warning))
            assert status(callee).get('call_state') == 'idle', 'rejected call reached callee'
        unknown = 'sip:nobody.mcptt@' + ids['client-a'].split('@', 1)[1]
        command('client-b', f'private {unknown} auto')
        wait('PC-08 unregistered callee rejected with 480', rejected('client-b', 480))

        # PC-08 terminating authorization per the called user's ruleset.
        for caller, callee, warning in [
            ('client-b', 'client-d', '127 user not authorised to be called in private call'),
            ('client-b', 'client-c', '159 user not authorised to be called by this originating user'),
        ]:
            command(caller, f"private {ids[callee]} auto")
            wait(f'PC-08 {caller} to {callee} rejected with {warning[:3]}', rejected(caller, 403, warning))
            assert status(callee).get('call_state') == 'idle', 'rejected call reached callee'
        command('client-a', f"private {ids['client-c']} auto")
        wait(
            'PC-08 caller on the incoming list reaches the restricted callee',
            lambda: private_active('client-a', 'client-c'),
        )
        command('client-a', 'hangup')
        wait('PC-08 incoming-list call released', idle)
        wait('PC-08 rejected requests leave no session', idle)

        # PC-09 busy handling at the private-call limit.
        command('client-a', f"private {ids['client-b']} auto")
        wait('PC-09 private call active', lambda: private_active('client-a', 'client-b'))
        command('client-c', f"private {ids['client-b']} auto")
        wait('PC-09 call to busy callee rejected with 486', rejected('client-c', 486))
        command('client-c', f"private {ids['client-a']} auto")
        wait('PC-09 call to busy caller rejected with 486', rejected('client-c', 486))
        assert private_active('client-a', 'client-b'), 'busy rejection disturbed established call'
        checks.append('PC-09 established call unaffected by rejected attempts')
        command('client-a', 'hangup')
        wait('PC-09 released', idle)

        # PC-10 private call alongside an independent group call.
        first = configs['client-a']['mcptt']['group_id']
        second = next(group_id for group_id in configs['client-c']['mcptt']['allowed_groups'] if group_id != first)
        for role in ['client-c', 'client-d']:
            command(role, 'group ' + second)
        wait(
            'PC-10 clients c and d affiliated to second group',
            lambda: all(
                status(role).get('affiliated') and status(role).get('group_id') == second
                for role in ['client-c', 'client-d']
            ),
        )
        command('client-c', 'call')
        wait(
            'PC-10 group call active',
            lambda: (
                all(status(role).get('call_state') == 'active' for role in ['client-c', 'client-d'])
                and any(session.get('group_id') == second for session in sessions())
            ),
        )
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'PC-10 private and group sessions coexist',
            lambda: private_active('client-a', 'client-b') and len(sessions()) == 2,
        )
        group = next(session for session in sessions() if session.get('call_type') == 'prearranged')
        assert set(group['participants']) == {ids['client-c'], ids['client-d']}, (
            'group session crossed into private call'
        )
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'PC-10 independent floors granted concurrently',
            lambda: (
                len(sessions()) == 2
                and all(
                    session.get('floor_owner')
                    == (ids['client-a'] if session.get('call_type') == 'private' else ids['client-c'])
                    for session in sessions()
                )
            ),
        )
        wait('PC-10 both floors released', lambda: all(not session.get('floor_owner') for session in sessions()), 20)
        command('client-a', 'hangup')
        wait(
            'PC-10 ending private call preserves group call',
            lambda: (
                not private_sessions()
                and len(sessions()) == 1
                and all(status(role).get('call_state') == 'active' for role in ['client-c', 'client-d'])
            ),
        )
        command('client-c', 'hangup')
        wait('PC-10 group call released', idle)

        # PC-11 private calls do not require group affiliation.
        command('client-b', 'deaffiliate')
        wait('PC-11 callee deaffiliated', lambda: not status('client-b').get('affiliated'))
        command('client-a', f"private {ids['client-b']} auto")
        wait('PC-11 unaffiliated callee reachable by private call', lambda: private_active('client-a', 'client-b'))
        command('client-a', 'hangup')
        wait('PC-11 released', idle)
        command('client-b', 'affiliate')
        wait('PC-11 callee reaffiliated', lambda: status('client-b').get('affiliated'))

        # ------------------------------------------------------------------------------
        # PC-16 first-to-answer call (TS 24.379 clause 11.1.1): every invitee rings in
        # forced manual mode, the first to answer is selected and the others
        # are cancelled; the caller learns the answering MCPTT ID.
        def ringing(roles_):
            return lambda: all(
                status(role).get('call_state') == 'ringing' and status(role).get('first_to_answer') for role in roles_
            )

        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']}")
        wait('PC-16 both invitees ring despite automatic local answer mode', ringing(['client-b', 'client-c']))
        wait('PC-16 caller sees session progress (183)', lambda: status('client-a').get('call_state') == 'progress')
        wait(
            'PC-16 server records both invitees',
            lambda: (
                len(private_sessions()) == 1
                and private_sessions()[0].get('first_to_answer')
                and set(private_sessions()[0].get('invitees', [])) == {ids['client-b'], ids['client-c']}
            ),
        )
        command('client-b', 'answer')
        wait('PC-16 first answerer becomes the private call peer', lambda: private_active('client-a', 'client-b'))
        wait('PC-16 other invitee cancelled', lambda: status('client-c').get('call_state') == 'idle')
        assert status('client-a').get('first_to_answer'), 'caller status lacks first-to-answer'
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        before = status('client-b').get('received_packets', 0)
        wait(
            'PC-16 selected callee receives caller speech',
            lambda: status('client-b').get('received_packets', 0) >= before + 50,
            20,
        )
        assert status('client-c').get('call_state') == 'idle', 'unselected invitee rejoined'
        command('client-a', 'hangup')
        wait('PC-16 first-to-answer call released', idle, 20)

        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']}")
        wait('PC-16 second call rings both invitees', ringing(['client-b', 'client-c']))
        command('client-c', 'answer')
        wait('PC-16 either invitee may win', lambda: private_active('client-a', 'client-c'))
        wait('PC-16 losing invitee cancelled', lambda: status('client-b').get('call_state') == 'idle')
        command('client-c', 'hangup')
        wait('PC-16 callee hangup releases the call', idle)

        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']}")
        wait('PC-16 decline test rings both invitees', ringing(['client-b', 'client-c']))
        command('client-b', 'reject')
        wait(
            'PC-16 one decline leaves the other invitee ringing',
            lambda: (
                status('client-b').get('call_state') == 'idle' and status('client-c').get('call_state') == 'ringing'
            ),
        )
        command('client-c', 'reject')
        wait('PC-16 all invitees declining fails the call with 480', rejected('client-a', 480))
        wait('PC-16 declined call cleaned up', idle)

        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']}")
        wait('PC-16 cancel test rings both invitees', ringing(['client-b', 'client-c']))
        command('client-a', 'hangup')
        wait('PC-16 caller CANCEL clears every invitee', idle)

        # Concurrent answers: exactly one invitee is selected; the other is
        # cancelled or, if its 200 OK crossed the CANCEL, released by BYE with
        # release-reason "not selected for call" (checked on the wire).
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']}")
        wait('PC-16 race test rings both invitees', ringing(['client-b', 'client-c']))
        answers = [threading.Thread(target=command, args=(role, 'answer')) for role in ('client-b', 'client-c')]
        for thread in answers:
            thread.start()
        for thread in answers:
            thread.join()
        wait(
            'PC-16 concurrent answers select exactly one invitee',
            lambda: private_active('client-a', 'client-b') or private_active('client-a', 'client-c'),
        )
        winner = 'client-b' if private_active('client-a', 'client-b') else 'client-c'
        loser = 'client-c' if winner == 'client-b' else 'client-b'
        wait('PC-16 concurrent loser released', lambda: status(loser).get('call_state') == 'idle')
        assert holds(lambda: private_active('client-a', winner), 1), 'selected invitee lost the call'
        observations['first_to_answer_race_winner'] = winner
        command('client-a', 'hangup')
        wait('PC-16 race call released', idle)

        # Filtering by the caller's <PrivateCall> list (TS 24.379 clause 11.1.1.3.1.1 step 15 a)) and rejections.
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-d']}")
        wait('PC-16 only the listed invitee rings', ringing(['client-b']))
        assert holds(lambda: status('client-d').get('call_state') == 'idle', 1), 'unlisted invitee was invited'
        command('client-a', 'hangup')
        wait('PC-16 filtered call released', idle)
        unknown_e = 'sip:nobody.mcptt@' + ids['client-a'].split('@', 1)[1]
        for caller, targets, warning in [
            (
                'client-b',
                [ids['client-a'], ids['client-c']],
                '156 user not authorised to originate a first-to-answer call',
            ),
            ('client-d', [ids['client-a'], ids['client-b']], '107 user not authorised to make private calls'),
            ('client-a', [ids['client-d'], unknown_e], '153 user not authorised to call any of the users requested'),
        ]:
            command(caller, 'first-to-answer ' + ' '.join(targets))
            wait(f'PC-16 {caller} first-to-answer rejected with {warning[:3]}', rejected(caller, 403, warning))
        wait('PC-16 rejected first-to-answer requests leave no session', idle)

        # ------------------------------------------------------------------------------
        # PC-18 emergency private call (TS 24.379 clause 6.2.8.3, clauses 11.1.1.4.3 to 11.1.1.4.6):
        # MEPC, MEPP and MPEA states, in-dialog cancel and upgrade, authorisation.
        def private_state(role, mepc=None, mepp=None, mpea=None):
            """role's MEPC, MEPP and MPEA states (TS 24.379 clause 4.6.2) start with the given numbers."""
            client_status = status(role)
            return (
                (mepc is None or client_status.get('private_emergency_state', '').startswith(f'MEPC {mepc}'))
                and (mepp is None or client_status.get('private_priority_state', '').startswith(f'MEPP {mepp}'))
                and (mpea is None or client_status.get('private_alert_state', '').startswith(f'MPEA {mpea}'))
            )

        # ------------------------------------------------------------------------------
        def server_priority(value):
            """The one private session has priority value."""

            current = private_sessions()
            return len(current) == 1 and current[0].get('priority') == value

        command('client-a', f"private {ids['client-b']} auto emergency alert")
        wait(
            'PC-18 authorised emergency private call with alert established',
            lambda: private_active('client-a', 'client-b') and server_priority('emergency'),
        )
        wait('PC-18 caller MEPC 3, MEPP 2 and MPEA 3', lambda: private_state('client-a', 3, 2, 3))
        wait(
            'PC-18 callee in-progress emergency (MEPP 2) with the caller alert',
            lambda: (
                private_state('client-b', mepp=2) and ids['client-a'] in status('client-b').get('private_alerts', [])
            ),
        )
        assert ids['client-a'] in private_sessions()[0].get('alerts', []), 'server lacks the emergency alert'
        updates = status('client-b').get('priority_updates_completed', 0)
        command('client-b', 'emergency off')
        wait(
            'PC-18 unauthorised cancellation rejected and MEPP restored',
            lambda: (
                status('client-b').get('priority_updates_completed', 0) > updates and private_state('client-b', mepp=2)
            ),
        )
        assert server_priority('emergency'), 'rejected cancellation changed the call'
        command('client-a', 'emergency off alert')
        wait(
            'PC-18 authorised cancellation of call and alert returns both parties to MEPP 1',
            lambda: (
                server_priority('normal')
                and private_state('client-a', 1, 1, 1)
                and private_state('client-b', mepp=1)
                and not status('client-b').get('private_alerts')
            ),
        )
        command('client-a', 'emergency on')
        wait(
            'PC-18 in-dialog upgrade makes both parties MEPP 2',
            lambda: (
                server_priority('emergency') and private_state('client-a', 3, 2) and private_state('client-b', mepp=2)
            ),
        )
        command('client-a', 'hangup')
        wait(
            'PC-18 emergency private call released and states reset',
            lambda: idle() and private_state('client-a', 1, 1, 1),
        )
        for caller, callee, label in [
            ('client-c', 'client-a', 'no emergency permission'),
            ('client-b', 'client-c', 'recipient not preconfigured'),
        ]:
            command(caller, f"private {ids[callee]} auto emergency")
            wait(
                f'PC-18 unauthorised emergency private call rejected ({label})',
                lambda caller=caller: (
                    rejected(caller, 403, 'emergency private call not authorized')() and private_state(caller, 1, 1)
                ),
            )
        corrections = status('client-b').get('priority_corrections_received', 0)
        command('client-b', f"private {ids['client-a']} auto emergency alert")
        wait(
            'PC-18 emergency call proceeds without an unauthorised alert',
            lambda: (
                private_active('client-b', 'client-a')
                and server_priority('emergency')
                and not private_sessions()[0].get('alerts')
            ),
        )
        wait(
            'PC-18 SIP INFO withdraws the pending alert (MPEA 1)',
            lambda: (
                status('client-b').get('priority_corrections_received', 0) > corrections
                and private_state('client-b', 3, 2, 1)
            ),
        )
        command('client-b', 'hangup')
        wait('PC-18 released', idle)

        # PC-12 private call timer (maximum duration, TS 24.379 clause 11.1.1.4.1 step 10) releases the call.
        if args.skip_timer:
            result['timer_skipped'] = True
        else:
            limit = timers.get('maximum_duration_ms', 3600000) / 1000
            assert limit <= 90, 'fixture maximum_duration_ms is too long for this scenario'
            # Past 45 s the call spans the refresh point of the 90 s SIP session
            # timer; the capture must show the refresh (verify --require-refresh).
            observations['private_call_spans_session_refresh'] = limit > 45
            command('client-a', f"private {ids['client-b']} auto")
            wait('PC-12 timed private call active', lambda: private_active('client-a', 'client-b'))
            started = time.monotonic()
            # Keep speech flowing so the inactivity timer cannot be the cause.
            command('client-a', 'ptt /artifacts/speech/alpha.wav')
            wait('PC-12 private call timer releases both parties', idle, limit + 10)
            observations['private_call_timer_seconds'] = round(time.monotonic() - started, 2)
            assert observations['private_call_timer_seconds'] >= limit - 3, 'released before private call timer'

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/private-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
