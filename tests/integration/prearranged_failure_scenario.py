#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise reject, CANCEL, setup timeout and session-refresh survival.

Run against the separate prearranged fixture. Capture SIP concurrently to prove
refresh transactions: call survival alone does not establish refresh correctness.

The calls are on-demand prearranged group calls (TS 24.379 clause 10.1.1.2.1: client
originating clause 10.1.1.2.1.1, client terminating clause 10.1.1.2.1.2, the controlling
MCPTT function clause 10.1.1.4); the pre-established session request is refused by the
participating MCPTT function per TS 24.379 clause 8.2.2 step 5; the session is refreshed
with the SIP session timer (RFC 4028).

Specifications: TS 24.379 V19.7.0 (Rel-19); RFC 4028.
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
    """Run the reject, CANCEL, setup timeout, pre-established and refresh cases; write the results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-prearranged')
    parser.add_argument('--hold-seconds', type=float, default=55)
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('requires the separate test project')
    if not 55 <= args.hold_seconds < 60:
        parser.error('hold must be >=55 and <60 seconds (90-second SIP timer, 60-second inactivity policy)')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    group = configs['client-a']['mcptt']['group_id']
    checks = []
    observations = []
    result = dict(
        scenario='prearranged-reject-cancel-timeout-refresh',
        passed=False,
        checks=checks,
        observations=observations,
        evidence_limit='Survival beyond first refresh interval; SIP capture must independently prove refresh and response.',
    )

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

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
    def snapshot():
        """Every role's status, for the observations and the failure message."""
        return {role: status(role) for role in roles + ['mcptt-server']}

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
    def idle():
        """No client in a call and no participant or session left on the server."""
        server = status('mcptt-server')
        return (
            all(status(role).get('call_state') == 'idle' for role in roles)
            and not server.get('participants')
            and not server.get('sessions')
        )

    # ------------------------------------------------------------------------------
    def pending():
        """The call from client-a is ringing at client-b, awaiting a manual answer."""
        return status('client-a').get('call_state') == 'calling' and status('client-b').get('call_state') == 'ringing'

    try:
        wait('four clients authorized', lambda: all(status(role).get('authorized') for role in roles), 90)
        wait('fixture initially idle', idle)
        initial_instance = status('mcptt-server')['instance_id']
        generated = args.compose.resolve().parent / 'generated'
        for role in ['client-a', 'client-b', 'mcptt-server']:
            config = json.loads((generated / f'{role}.json').read_text())
            assert config['sip']['session_expires'] == 90, 'fixture requires 90-second session timer'

        # ------------------------------------------------------------------------------
        # Clients restarted just before this scenario may still be affiliating: keep
        # correcting until the setup holds rather than acting on one reading.
        def settle():
            for role in ['client-c', 'client-d']:
                if status(role).get('affiliated'):
                    command(role, 'deaffiliate')
            for role in ['client-a', 'client-b']:
                if not status(role).get('affiliated'):
                    command(role, 'affiliate')

        # The setup holds at the clients and at the server, whose affiliations decide who the call invites (TS 24.379
        # clause 10.1.1.4.2): a late affiliation of a restarted client otherwise brings client-c or client-d into
        # the call.
        def only_a_and_b():
            affiliations = status('mcptt-server').get('affiliations', {})
            return (
                all(status(role).get('affiliated') for role in ['client-a', 'client-b'])
                and not any(status(role).get('affiliated') for role in ['client-c', 'client-d'])
                and all(group in affiliations.get(ids[role], []) for role in ['client-a', 'client-b'])
                and not any(group in affiliations.get(ids[role], []) for role in ['client-c', 'client-d'])
            )

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (only_a_and_b() and holds(only_a_and_b, 2)):
            settle()
            time.sleep(2)
        wait('only A and B affiliated for setup, at the clients and the server', only_a_and_b)
        command('client-b', 'answer-mode manual')
        wait('callee manual answering enabled', lambda: status('client-b').get('answer_mode') == 'manual')

        command('client-a', 'call')
        wait('reject attempt pending manual answer', pending)
        command('client-b', 'reject')
        wait('callee rejection cleans both dialogs', idle)
        observations.append(dict(case='reject', status=snapshot()))

        command('client-a', 'call')
        wait('cancel attempt pending manual answer', pending)
        command('client-a', 'hangup')
        wait('originator cancellation cleans early dialogs', idle)
        observations.append(dict(case='cancel', status=snapshot()))

        started = time.monotonic()
        command('client-a', 'call')
        wait('timeout attempt pending manual answer', pending)
        wait('unanswered setup expires and cleans early dialogs', idle, 12)
        elapsed = time.monotonic() - started
        assert elapsed >= 2.5, f'call failed prematurely after {elapsed:.2f}s instead of setup timeout'
        observations.append(dict(case='setup-timeout', elapsed_seconds=round(elapsed, 3), status=snapshot()))

        # Pre-established session setup is refused (TS 24.379 clause 8.2.2 step 5): the
        # lab has no resource sharing (TS 24.379 clause 8.1A).
        command('client-a', 'pre-establish')

        # ------------------------------------------------------------------------------
        def pre_established_refused():
            """TS 24.379 clause 8.2.2 step 5: 403 with warning text 100 and nothing left behind."""
            failure = status('client-a').get('last_call_failure') or {}
            return (
                failure.get('status') == 403
                and '100 function not allowed due to pre-established session not supported'
                in failure.get('warning', '')
                and idle()
            )

        wait('pre-established session setup refused with 403 warning 100', pre_established_refused)
        observations.append(dict(case='pre-established-refused', status=snapshot()))

        command('client-b', 'answer-mode auto')
        wait('callee automatic answering restored', lambda: status('client-b').get('answer_mode') == 'auto')
        command('client-a', 'call')
        wait(
            'refresh test has two confirmed participants',
            lambda: (
                all(status(role).get('call_state') == 'active' for role in ['client-a', 'client-b'])
                and len(status('mcptt-server').get('participants', [])) == 2
            ),
        )
        session = status('client-a')['session_uri']
        started = time.monotonic()
        print(f'Holding established session for {args.hold_seconds:g}s; capture SIP refresh concurrently', flush=True)
        while time.monotonic() - started < args.hold_seconds:
            assert status('mcptt-server')['instance_id'] == initial_instance, 'server restarted'
            assert len(status('mcptt-server').get('participants', [])) == 2, 'participant lost during hold'
            for role in ['client-a', 'client-b']:
                assert status(role).get('call_state') == 'active', role + ' disconnected during hold'
                assert status(role).get('session_uri') == session, role + ' session changed during hold'
            time.sleep(0.2)
        checks.append('session survives past first expected SIP refresh interval')
        observations.append(
            dict(case='refresh-survival', elapsed_seconds=round(time.monotonic() - started, 3), session_uri=session)
        )
        command('client-a', 'hangup')
        wait('refresh test call tears down', idle)
        assert status('mcptt-server')['instance_id'] == initial_instance, 'server restarted during tests'
        checks.append('server instance unchanged across all attempts')
        result['passed'] = True
    except (AssertionError, KeyError, ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    finally:
        result['status'] = snapshot()
        # Keep failures reviewable; bounded best-effort cleanup restores the
        # fixture's ordinary answer mode without changing any credentials.
        cleanup = []
        for role in ['client-a', 'client-b']:
            try:
                if status(role).get('call_state') not in ('idle', None):
                    command(role, 'hangup')
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                cleanup.append(str(exc))
        try:
            deadline = time.monotonic() + 5
            while status('client-b').get('call_state') != 'idle' and time.monotonic() < deadline:
                time.sleep(0.1)
            if status('client-b').get('call_state') == 'idle':
                command('client-b', 'answer-mode auto')
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            cleanup.append(str(exc))
        if cleanup:
            result['cleanup_errors'] = cleanup
        output = args.artifacts / 'integration/prearranged-failure-results.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
