#!/usr/bin/env python3
"""Exercise late entry, participant leave, rejoin and initiator teardown.

On an on-demand prearranged group call (TS 24.379 clause 10.1.1.2.1): late call entry by
the controlling MCPTT function when a member affiliates (TS 24.379 clause 10.1.1.4.6), a
participant leaving (TS 24.379 clause 10.1.1.2.3.1) and rejoining the ongoing call (TS 24.379
clauses 10.1.1.2.4.1 and 10.1.1.4.5.1), the conference event roster the controlling MCPTT
function notifies (TS 24.379 clause 6.3.3.4), and the release of the whole call when the
initiator leaves (TS 24.379 clause 6.3.8.1 item 3). Then two groups' calls run side by side
with independent floors. With --check-key-refresh, GMK renewal (TS 33.180 clause 5.7.3)
must not undo an explicit deaffiliation.

Specifications: TS 24.379 V19.7.0, TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the lifecycle and parallel-group cases; write the results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-prearranged')
    parser.add_argument('--skip-audio', action='store_true', help='Skip concurrent speech evidence explicitly')
    parser.add_argument(
        '--check-key-refresh', action='store_true', help='Verify key renewal cannot undo explicit deaffiliation'
    )
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    checks = []

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
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Record label once predicate() holds; fail with every status on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                return
            time.sleep(0.1)
        raise AssertionError(label + ': ' + json.dumps({role: status(role) for role in roles + ['mcptt-server']}))

    # ------------------------------------------------------------------------------
    def active(wanted):
        """Exactly the wanted clients are in an active call, and the server counts as many participants."""
        server = status('mcptt-server')
        current = server.get('sessions')
        if current is not None:
            current = list(current.values()) if isinstance(current, dict) else current
            count = sum(len(group_session.get('participants', [])) for group_session in current)
        else:
            count = len(server.get('participants', []))
        return all(status(role).get('call_state') == 'active' for role in wanted) and count == len(wanted)

    # ------------------------------------------------------------------------------
    def conference(wanted):
        """Each wanted client's conference roster (TS 24.379 clause 6.3.3.4) lists exactly the wanted users."""
        identities = {configs[role]['mcptt']['user_id'] for role in wanted}
        return all(
            status(role).get('conference_active') and set(status(role).get('conference_participants', [])) == identities
            for role in wanted
        )

    result = dict(scenario='prearranged-late-entry-leave-rejoin', passed=False, checks=checks)
    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in roles),
            90,
        )
        instance = status('mcptt-server')['instance_id']
        assert not status('mcptt-server').get('participants'), 'fixture must start idle'
        for role in ['client-c', 'client-d']:
            command(role, 'deaffiliate')
        wait(
            'late-entry clients deaffiliated',
            lambda: all(not status(role).get('affiliated') for role in ['client-c', 'client-d']),
        )
        if args.check_key_refresh:
            detached = ['client-c', 'client-d']
            assert all(status(role).get('protected_ready') for role in detached), 'protected fixture required'
            before = {role: status(role).get('group_key_notifications', 0) for role in detached}
            deadline = time.monotonic() + 65
            while True:
                current = {role: status(role) for role in detached}
                assert all(
                    not client.get('affiliated') and client.get('desired_affiliation') is False
                    for client in current.values()
                ), 'key refresh undid manual deaffiliation'
                if all(current[role].get('group_key_notifications', 0) > before[role] for role in detached):
                    checks.append('key refresh preserves explicit deaffiliation')
                    break
                assert time.monotonic() < deadline, 'group key refresh not observed'
                time.sleep(0.1)
        command('client-a', 'call')
        wait('initial two-participant call', lambda: active(['client-a', 'client-b']))
        wait('initial conference roster has both participants', lambda: conference(['client-a', 'client-b']))
        session = status('mcptt-server')['session_uri']
        assert session, 'missing shared session URI'
        command('client-c', 'affiliate')
        wait('third participant joins by late entry', lambda: active(['client-a', 'client-b', 'client-c']))
        wait(
            'late-entry conference roster reaches three participants',
            lambda: conference(['client-a', 'client-b', 'client-c']),
        )
        assert status('mcptt-server')['session_uri'] == session
        command('client-b', 'hangup')
        wait(
            'participant leaves while two remain',
            lambda: status('client-b').get('call_state') == 'idle' and active(['client-a', 'client-c']),
        )
        wait('departure updates both surviving conference rosters', lambda: conference(['client-a', 'client-c']))
        command('client-b', 'rejoin')
        wait('participant rejoins existing session', lambda: active(['client-a', 'client-b', 'client-c']))
        wait('rejoin restores all three conference rosters', lambda: conference(['client-a', 'client-b', 'client-c']))
        assert status('mcptt-server')['session_uri'] == session
        assert status('client-b').get('session_uri') == session
        assert status('client-d').get('call_state') == 'idle', 'deaffiliated client admitted'
        command('client-a', 'hangup')
        wait(
            'initiator policy releases entire call',
            lambda: (
                all(status(role).get('call_state') == 'idle' for role in roles)
                and not status('mcptt-server').get('participants')
                and not status('mcptt-server').get('session_uri')
            ),
        )
        first = configs['client-a']['mcptt']['group_id']
        second = next(group for group in configs['client-c']['mcptt']['allowed_groups'] if group != first)
        for role in ['client-c', 'client-d']:
            command(role, 'group ' + second)
        wait(
            'parallel clients affiliated to second group',
            lambda: all(
                status(role).get('affiliated') and status(role).get('group_id') == second
                for role in ['client-c', 'client-d']
            ),
        )
        command('client-a', 'call')
        wait('first independent group active', lambda: active(['client-a', 'client-b']))
        first_session = status('client-a')['session_uri']
        command('client-c', 'call')

        # ------------------------------------------------------------------------------
        def sessions():
            """The server's sessions as a list."""

            value = status('mcptt-server').get('sessions', [])
            return list(value.values()) if isinstance(value, dict) else value

        wait('two independent groups active', lambda: active(roles) and len(sessions()) == 2)
        second_session = status('client-c')['session_uri']
        assert first_session != second_session, 'groups share session identity'
        expected = {
            first: {configs[role]['mcptt']['user_id'] for role in ['client-a', 'client-b']},
            second: {configs[role]['mcptt']['user_id'] for role in ['client-c', 'client-d']},
        }
        for current in sessions():
            assert set(current['participants']) == expected[current['group_id']], 'participants crossed group boundary'
        checks.append('distinct session identities and exact participant isolation')
        if not args.skip_audio:
            for name in ['alpha.wav', 'bravo.wav']:
                assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
            before = {role: status(role).get('received_packets', 0) for role in ['client-b', 'client-d']}
            command('client-a', 'ptt /artifacts/speech/alpha.wav')
            command('client-c', 'ptt /artifacts/speech/bravo.wav')
            owners = {first: configs['client-a']['mcptt']['user_id'], second: configs['client-c']['mcptt']['user_id']}
            wait(
                'two groups grant independent floors concurrently',
                lambda: (
                    len(sessions()) == 2
                    and all(
                        group_session.get('floor_owner') == owners[group_session['group_id']]
                        for group_session in sessions()
                    )
                ),
            )
            wait(
                'both group receivers receive speech',
                lambda: all(status(role).get('received_packets', 0) >= before[role] + 50 for role in before),
            )
            wait(
                'both independent floors release',
                lambda: (
                    all(not status(role).get('talking') for role in ['client-a', 'client-c'])
                    and all(not group_session.get('floor_owner') for group_session in sessions())
                ),
            )
            result['audio_packet_deltas'] = {
                role: status(role).get('received_packets', 0) - before[role] for role in before
            }
            result['audio_evidence_limit'] = (
                'Independent floor owners and delivery counts; waveform/PCAP comparison needed to exclude cross-group audio.'
            )
        else:
            result['audio_skipped'] = True
        command('client-a', 'hangup')
        wait(
            'ending first group preserves second group',
            lambda: (
                active(['client-c', 'client-d'])
                and all(status(role).get('call_state') == 'idle' for role in ['client-a', 'client-b'])
                and len(sessions()) == 1
            ),
        )
        assert status('client-c')['session_uri'] == second_session
        command('client-c', 'hangup')
        wait(
            'both independent groups cleaned up',
            lambda: (
                not sessions()
                and not status('mcptt-server').get('participants')
                and all(status(role).get('call_state') == 'idle' for role in roles)
            ),
        )
        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during lifecycle'
        checks.append('server instance unchanged')
        result['passed'] = True
        result['session_uri'] = session
    except (AssertionError, KeyError, OSError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = {role: status(role) for role in roles + ['mcptt-server']}
    output = args.artifacts / 'integration/prearranged-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
