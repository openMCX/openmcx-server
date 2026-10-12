#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise priority, emergency, alert and floor procedures in a running isolated lab.

Prepare with tools/prepare-prearranged-test.py --priority --floor-queue. The
scenario controls existing clients only; it never starts or reconfigures services.

Procedures under test, on a prearranged group call (TS 24.379 clause 10.1.1):
  - upgrade to in-progress emergency or imminent peril and their cancellation
    (TS 24.379 clauses 10.1.1.2.1.3, 10.1.1.2.1.4 and 10.1.1.2.1.5), the SIP INFO the
    controlling MCPTT function sends after the ACK of a priority call (TS 24.379
    clause 6.3.3.1.18), late call entry (TS 24.379 clause 10.1.1.4.6) and the expiry of TNG2
    (TS 24.379 clause 6.3.3.1.16);
  - emergency alerts and their cancellation (TS 24.379 clauses 12.1.1.1 and 12.1.1.2,
    authorisation per clauses 6.3.3.1.13.1 and 6.3.3.1.13.3) and the in-progress emergency
    group state cancel (TS 24.379 clause 12.1.1.5);
  - the negotiated "mc_priority" fmtp attribute (TS 24.380 clause 14.2.3) and a Floor Request
    with pre-emptive priority in 'G: Floor Taken' (TS 24.380 clause 6.3.4.4.7).

Specifications: TS 24.379 V19.7.0, TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from prearranged_floor_scenario import repeat_pcm

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the priority, emergency, alert and TNG2 cases selected by the options; write the results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-prearranged')
    parser.add_argument(
        '--timer-only', action='store_true', help='run only the short TNG2 expiry procedure in a provisioned fixture'
    )
    parser.add_argument(
        '--check-timer', action='store_true', help='also wait for the fixture emergency timeout (must be <=30 seconds)'
    )
    args = parser.parse_args()
    args.artifacts = args.artifacts.resolve()
    if args.project == 'openmcx' or args.artifacts == (ROOT / 'artifacts').resolve():
        parser.error('an isolated project and artifact directory are required')
    generated = args.compose.resolve().parent / 'generated'
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    site = json.loads((generated / 'site.json').read_text())
    group = configs['client-a']['mcptt']['group_id']
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    profile = next(entry for entry in site['groups'] if entry['id'] == group)
    policy = profile['priority_policy']
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    result = {
        'scenario': 'prearranged-priority-emergency',
        'passed': False,
        'checks': [],
        'timings_ms': {},
        'audio_packet_deltas': {},
    }
    active_roles = ['client-a', 'client-b', 'client-c']
    started_call = False

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
    def session():
        """The server's session of the group, or {}."""
        values = status('mcptt-server').get('sessions', [])
        if isinstance(values, dict):
            values = values.values()
        return next((value for value in values if value.get('group_id') == group), {})

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=20):
        """Record label and its time once predicate() holds; fail with every status on timeout."""
        began = time.monotonic()
        while time.monotonic() - began < timeout:
            if predicate():
                result['checks'].append(label)
                result['timings_ms'][label] = round(1000 * (time.monotonic() - began))
                return
            time.sleep(0.05)
        raise AssertionError(label + ': ' + json.dumps({role: status(role) for role in roles + ['mcptt-server']}))

    # ------------------------------------------------------------------------------
    def priority(value, members=None):
        """The session and every member client report priority value ('normal', 'imminent', 'emergency')."""
        members = active_roles if members is None else members
        return session().get('priority') == value and all(status(role).get('priority') == value for role in members)

    # ------------------------------------------------------------------------------
    def idle_floor():
        """No floor owner, and client-a and client-b in 'U: has no permission'."""
        return not session().get('floor_owner') and all(
            status(role).get('floor_state') == 'NoPermission' for role in ['client-a', 'client-b']
        )

    # ------------------------------------------------------------------------------
    def take_floor(role, label):
        """role requests the idle floor and talks."""
        command(role, 'ptt /artifacts/speech/priority-hold.wav')
        wait(label, lambda: session().get('floor_owner') == ids[role] and status(role).get('talking'))

    # ------------------------------------------------------------------------------
    def finish_preemption(role, old, label):
        """role requests the floor held by old with pre-emptive priority (TS 24.380 clause 6.3.4.4.7),
        confirms a queued grant if asked, and talks while old has stopped."""
        command(role, 'ptt /artifacts/speech/priority-hold.wav')
        wait(
            label + ' grant',
            lambda: (
                session().get('floor_owner') == ids[role]
                and (status(role).get('pending_floor_confirmation') or status(role).get('talking'))
            ),
        )
        if status(role).get('pending_floor_confirmation'):
            command(role, 'floor-confirm')
        wait(label + ' media', lambda: status(role).get('talking') and not status(old).get('talking'))

    # ------------------------------------------------------------------------------
    def end_call(label):
        """client-a hangs up; the session and every client end idle."""

        command('client-a', 'hangup')
        wait(label, lambda: not session() and all(status(role).get('call_state') == 'idle' for role in roles))

    try:
        wait('four clients authorized', lambda: all(status(role).get('authorized') for role in roles), 90)
        assert not session(), 'fixture must start without an active call'
        instance = status('mcptt-server')['instance_id']
        for role in roles:
            assert configs[role]['mcptt'].get('floor_queue'), 'floor queue negotiation is required'
            assert status(role).get('call_state') == 'idle', role + ' has an existing call'
            if status(role).get('group_id') != group:
                command(role, 'group ' + group)
            elif not status(role).get('affiliated'):
                command(role, 'affiliate')
        wait(
            'all clients affiliated to target group',
            lambda: all(status(role).get('affiliated') and status(role).get('group_id') == group for role in roles),
        )
        command('client-d', 'deaffiliate')
        wait('late-entry client detached', lambda: not status('client-d').get('affiliated'))
        repeat_pcm(args.artifacts / 'speech/alpha.wav', args.artifacts / 'speech/priority-hold.wav')

        if not args.timer_only:
            command('client-a', 'call')
            started_call = True
            wait(
                'normal three-party call established',
                lambda: (
                    len(session().get('participants', [])) == 3
                    and all(status(role).get('call_state') == 'active' for role in active_roles)
                    and priority('normal')
                ),
            )
            uri = session()['session_uri']
            result['session_uri'] = uri
            wait(
                'negotiated priority caps returned',
                lambda: (
                    status('client-a').get('negotiated_floor_priority') == 10
                    and status('client-b').get('negotiated_floor_priority') == 90
                ),
            )
            take_floor('client-a', 'ordinary alpha owns floor')
            received = status('client-a').get('received_packets', 0)
            command('client-b', 'priority 90')
            finish_preemption('client-b', 'client-a', 'authorized numeric priority preempts')
            wait(
                'numeric preemptor speech received',
                lambda: status('client-a').get('received_packets', 0) >= received + 10,
            )
            result['audio_packet_deltas']['numeric_preemptor'] = status('client-a')['received_packets'] - received
            command('client-b', 'release')
            wait('numeric preemptor releases', idle_floor)

            command('client-a', 'imminent on')
            wait('normal call upgraded to imminent peril', lambda: priority('imminent'))
            command('client-a', 'alert on')
            wait(
                'alert precedes emergency upgrade',
                lambda: all(ids['client-a'] in status(role).get('alerts', []) for role in active_roles),
            )
            wait(
                'emergency alert encoded location reaches participants',
                lambda: all(
                    status(role).get('alert_locations', {}).get(ids['client-a'])
                    == configs['client-a']['mcptt']['emergency_location']
                    for role in active_roles
                ),
            )
            command('client-a', 'emergency on')
            wait('imminent call upgraded to emergency', lambda: priority('emergency'))
            assert all(ids['client-a'] in status(role).get('alerts', []) for role in active_roles), (
                'emergency upgrade erased outstanding alert'
            )
            corrections = status('client-b').get('priority_corrections_received', 0)
            command('client-b', 'imminent on')
            wait(
                'emergency precedence confirmed by post-ACK INFO',
                lambda: (
                    status('client-b').get('priority_corrections_received', 0) > corrections and priority('emergency')
                ),
            )
            completed = status('client-c').get('priority_updates_completed', 0)
            command('client-c', 'emergency off')
            wait(
                'unauthorized emergency cancellation rejected',
                lambda: (
                    status('client-c').get('priority_updates_completed', 0) > completed
                    and status('client-c').get('last_error') == 'priority update: 403'
                ),
            )
            assert priority('emergency'), 'denied cancellation changed authoritative priority'
            assert session()['session_uri'] == uri, 'priority update replaced the media session'

            command('client-d', 'affiliate')
            active_roles.append('client-d')
            wait(
                'late entrant inherits emergency state',
                lambda: (
                    len(session().get('participants', [])) == 4
                    and status('client-d').get('call_state') == 'active'
                    and priority('emergency')
                ),
            )
            take_floor('client-b', 'numeric preemptor takes idle emergency-group floor')
            received = status('client-b').get('received_packets', 0)
            finish_preemption('client-a', 'client-b', 'emergency originator preempts numeric priority')
            wait('emergency speech received', lambda: status('client-b').get('received_packets', 0) >= received + 10)
            result['audio_packet_deltas']['emergency_originator'] = status('client-b')['received_packets'] - received
            command('client-a', 'release')
            wait('emergency originator releases floor', idle_floor)

            completed = status('client-b').get('priority_updates_completed', 0)
            command('client-b', 'emergency on')
            wait(
                'second authorized emergency indication accepted',
                lambda: (
                    status('client-b').get('priority_updates_completed', 0) > completed
                    and ids['client-b']
                    in status('mcptt-server').get('group_priority', {}).get(group, {}).get('emergency_users', [])
                    and priority('emergency')
                ),
            )
            take_floor('client-b', 'second emergency originator transmits')
            completed = status('client-a').get('priority_updates_completed', 0)
            command('client-a', 'emergency off')
            wait(
                'cancellation refused while another emergency user transmits',
                lambda: (
                    status('client-a').get('priority_updates_completed', 0) > completed
                    and status('client-a').get('last_error') == 'priority update: 403'
                ),
            )
            assert priority('emergency'), 'active emergency was cancelled while another user spoke'
            command('client-b', 'release')
            wait('second emergency speaker releases', idle_floor)
            command('client-a', 'emergency off')
            wait('authorized cancellation restores normal call', lambda: priority('normal'))
            assert session()['session_uri'] == uri, 'downgrade replaced session identity'
            assert all(ids['client-a'] in status(role).get('alerts', []) for role in active_roles), (
                'group cancellation erased independent alert'
            )
            command('client-a', 'alert off')
            wait(
                'independent alert cancelled after group downgrade',
                lambda: all(ids['client-a'] not in status(role).get('alerts', []) for role in active_roles),
            )
            completed = status('client-c').get('priority_updates_completed', 0)
            command('client-c', 'imminent on')
            wait(
                'unauthorized imminent activation leaves normal call',
                lambda: (
                    status('client-c').get('priority_updates_completed', 0) > completed
                    and not status('client-c').get('priority_pending')
                    and priority('normal')
                    and status('client-c').get('last_error') == 'priority update: 403'
                ),
            )

            # The 403 of the imminent request above is still client-c's last error: the call must also stay normal
            # once the update has completed, which a wrongly accepted activation would change.
            completed = status('client-c').get('priority_updates_completed', 0)
            command('client-c', 'emergency on')
            wait(
                'unauthorized emergency activation leaves normal call',
                lambda: (
                    status('client-c').get('priority_updates_completed', 0) > completed
                    and not status('client-c').get('priority_pending')
                    and priority('normal')
                    and status('client-c').get('last_error') == 'priority update: 403'
                ),
            )
            assert holds(lambda: priority('normal'), 1), 'unauthorized emergency activation upgraded the call'
            command('client-c', 'alert on')
            wait(
                'unauthorized alert activation rejected',
                lambda: (
                    status('client-c').get('last_error') == 'emergency alert: 403'
                    and not status('client-c').get('alert_pending')
                ),
            )
            assert all(ids['client-c'] not in status(role).get('alerts', []) for role in roles), (
                'unauthorized alert was distributed'
            )

            command('client-b', 'alert on')
            wait(
                'independent alert delivered without upgrading call',
                lambda: (
                    priority('normal')
                    and all(ids['client-b'] in status(role).get('alerts', []) for role in roles)
                    and not status('client-b').get('alert_pending')
                ),
            )
            wait(
                'independent alert location reaches all participants',
                lambda: all(
                    status(role).get('alert_locations', {}).get(ids['client-b'])
                    == configs['client-b']['mcptt']['emergency_location']
                    for role in roles
                ),
            )
            command('client-b', 'alert off')
            wait(
                'unauthorized self alert cancellation refused',
                lambda: (
                    status('client-b').get('last_error') == 'emergency alert: 403'
                    and ids['client-b'] in status('client-b').get('alerts', [])
                ),
            )
            command('client-a', 'alert off ' + ids['client-b'])
            wait(
                'authorized third-party alert cancellation confirmed',
                lambda: (
                    all(ids['client-b'] not in status(role).get('alerts', []) for role in roles)
                    and not status('client-a').get('alert_pending')
                ),
            )
            assert all(ids['client-b'] not in status(role).get('alert_locations', {}) for role in roles), (
                'cancelled alert location retained'
            )
            assert priority('normal'), 'alert-only procedures changed group call priority'
            end_call('updated call closes cleanly')
            started_call = False

            for kind in ['imminent', 'emergency']:
                command('client-a', 'call ' + kind)
                started_call = True
                wait(
                    kind + ' initial call inherits priority at all participants',
                    lambda kind=kind: len(session().get('participants', [])) == 4 and priority(kind),
                )
                if kind == 'emergency':
                    end_call('emergency call closes while group emergency persists')
                    started_call = False
                    assert (
                        status('mcptt-server').get('group_priority', {}).get(group, {}).get('priority') == 'emergency'
                    )
                    command('client-a', 'emergency off')
                    wait(
                        'standalone emergency cancellation receipt restores group state',
                        lambda: (
                            status('mcptt-server').get('group_priority', {}).get(group, {}).get('priority') == 'normal'
                            and all(status(role).get('priority') == 'normal' for role in roles)
                        ),
                    )
                else:
                    command('client-a', kind + ' off')
                    wait(kind + ' initial call downgraded', lambda: priority('normal'))
                    end_call(kind + ' initial call closes')
                    started_call = False

        if args.check_timer or args.timer_only:
            timeout_ms = policy['emergency_timeout_ms']
            assert 0 < timeout_ms <= 30000, '--check-timer requires a timeout no longer than 30 seconds'
            command('client-a', 'call emergency')
            started_call = True
            wait('timer test emergency established', lambda: priority('emergency'))
            timer_uri = session()['session_uri']
            wait('TNG2 downgrades without releasing session', lambda: priority('normal'), timeout_ms / 1000 + 10)
            assert session()['session_uri'] == timer_uri, 'TNG2 expiry ended or replaced call'
            end_call('timer test closes')
            started_call = False
        else:
            result['timer_evidence'] = (
                'TNG2 runtime expiry not exercised; use --check-timer with a short provisioned timeout.'
            )
        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during procedure checks'
        result['checks'].append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    finally:
        if started_call:
            try:
                command('client-a', 'hangup')
            except (OSError, subprocess.SubprocessError) as exc:
                result['cleanup_error'] = str(exc)
    result['status'] = {role: status(role) for role in roles + ['mcptt-server']}
    path = args.artifacts / (
        'integration/prearranged-priority-timer-results.json'
        if args.timer_only
        else 'integration/prearranged-priority-results.json'
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
