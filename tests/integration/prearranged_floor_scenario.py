#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Check negotiated queueing, cancellation, grant confirmation and abandoned grants.

Run against an already-started isolated four-client fixture with floor_queue=true
on the server and clients A/B. No services are started or reconfigured here.
Requires client status floor_state and floor_queue_info_received counters.

Floor control with queueing negotiated by the "mc_queueing" fmtp attribute (TS 24.380
clause 14.2.2), in the floor participant state 'U: queued' (TS 24.380 clause 6.2.4.9):
Floor Queue Position Request (clause 6.2.4.9.9) and Floor Queue Position Info
(clause 6.2.4.9.7), cancelling the queued request (clause 6.2.4.9.6), accepting a queued
grant (clause 6.2.4.9.12) and the expiry of T132 (clause 6.2.4.9.13); on the server, the
expiry of T1 (End of RTP media) in 'G: Floor Taken' (TS 24.380 clause 6.3.4.4.3).

Specifications: TS 24.380 V19.2.0, TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time
import wave

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def repeat_pcm(source, destination, seconds=60):
    """Extend the existing speech fixture, preserving its exact PCM samples."""
    with wave.open(str(source), 'rb') as audio:
        if (audio.getnchannels(), audio.getsampwidth(), audio.getframerate(), audio.getcomptype()) != (
            1,
            2,
            16000,
            'NONE',
        ):
            raise ValueError('floor speech fixture must be 16-kHz mono signed 16-bit PCM')
        pcm = audio.readframes(audio.getnframes())
    if not pcm:
        raise ValueError('floor speech fixture is empty')
    required = seconds * 16000 * 2
    destination.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(destination), 'wb') as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.writeframes((pcm * ((required + len(pcm) - 1) // len(pcm)))[:required])


# ------------------------------------------------------------------------------
def main():
    """Run the queue, cancellation, confirmation and abandoned-grant cases; write the results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-prearranged')
    args = parser.parse_args()
    args.artifacts = args.artifacts.resolve()
    if args.project == 'openmcx' or args.artifacts == (ROOT / 'artifacts').resolve():
        parser.error('this scenario requires a separate test project and artifact directory')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles + ['mcptt-server']}
    group = configs['client-a']['mcptt']['group_id']
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    checks, timings = [], {}
    result = {
        'scenario': 'prearranged-floor-queue-and-confirmation',
        'passed': False,
        'checks': checks,
        'timings_ms': timings,
    }
    baseline_errors = {}
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
    def sessions():
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def owner():
        """The MCPTT ID holding the floor of the group's session, or ''."""
        return next((entry.get('floor_owner', '') for entry in sessions() if entry.get('group_id') == group), '')

    # ------------------------------------------------------------------------------
    def no_new_timeout():
        """Fail when client-a or client-b reports a floor procedure timeout it did not have before."""
        for role in ['client-a', 'client-b']:
            error = status(role).get('last_error', '')
            if error != baseline_errors.get(role, '') and 'floor procedure timeout' in error:
                raise AssertionError(role + ': unexpected ' + error)

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=20):
        """Record label and its time once predicate() holds; fail on timeout or a new floor timeout."""
        began = time.monotonic()
        deadline = began + timeout
        while time.monotonic() < deadline:
            no_new_timeout()
            if predicate():
                checks.append(label)
                timings[label] = round((time.monotonic() - began) * 1000)
                return
            time.sleep(0.05)
        raise AssertionError(label + ': ' + json.dumps({role: status(role) for role in roles + ['mcptt-server']}))

    # ------------------------------------------------------------------------------
    def floor_idle():
        """No floor owner, and client-a and client-b in 'U: has no permission' without talking."""
        return not owner() and all(
            status(role).get('floor_state') == 'NoPermission' and not status(role).get('talking')
            for role in ['client-a', 'client-b']
        )

    # ------------------------------------------------------------------------------
    def start_alpha(label):
        """client-a requests the floor and is granted it (TS 24.380 clause 6.2.4.4.2)."""
        command('client-a', 'ptt /artifacts/speech/floor-hold.wav')
        wait(
            label,
            lambda: (
                owner() == ids['client-a']
                and status('client-a').get('floor_state') == 'HasPermission'
                and status('client-a').get('talking')
            ),
        )

    # ------------------------------------------------------------------------------
    def queue_bravo(label):
        """client-b's Floor Request is queued at position 1, neither denied nor sending media
        (TS 24.380 clause 6.2.4.9)."""
        prior_denials = status('client-b').get('floor_denials', 0)
        command('client-b', 'ptt /artifacts/speech/floor-queued.wav')
        wait(
            label,
            lambda: (
                status('client-b').get('floor_state') == 'Queued'
                and status('client-b').get('queue_position') == 1
                and owner() == ids['client-a']
            ),
        )
        assert status('client-b').get('floor_denials', 0) == prior_denials, 'negotiated queue request was denied'
        assert not status('client-b').get('talking'), 'queued client sent media before a grant'

    try:
        for role in ['mcptt-server', 'client-a', 'client-b']:
            assert configs[role]['mcptt'].get('floor_queue') is True, role + ' has not enabled floor_queue'
        assert configs['client-b']['mcptt']['group_id'] == group, 'A and B must target the same group'
        wait('fixture clients authorized', lambda: all(status(role).get('authorized') for role in roles), 90)
        baseline_errors.update({role: status(role).get('last_error', '') for role in ['client-a', 'client-b']})
        assert not sessions(), 'fixture must start with no calls'
        instance = status('mcptt-server')['instance_id']
        for role in roles:
            assert status(role).get('call_state') == 'idle', role + ' is already in a call'
        for role in ['client-c', 'client-d']:
            command(role, 'deaffiliate')
        wait(
            'other clients deaffiliated',
            lambda: all(not status(role).get('affiliated') for role in ['client-c', 'client-d']),
        )
        for role in ['client-a', 'client-b']:
            if not status(role).get('affiliated'):
                command(role, 'affiliate')
        wait(
            'queue participants affiliated',
            lambda: all(status(role).get('affiliated') for role in ['client-a', 'client-b']),
        )
        repeat_pcm(args.artifacts / 'speech/alpha.wav', args.artifacts / 'speech/floor-hold.wav')
        repeat_pcm(args.artifacts / 'speech/bravo.wav', args.artifacts / 'speech/floor-queued.wav')
        command('client-a', 'call')
        started_call = True
        wait(
            'two-party queue-enabled call active',
            lambda: (
                len(sessions()) == 1
                and set(sessions()[0].get('participants', [])) == {ids['client-a'], ids['client-b']}
                and all(status(role).get('call_state') == 'active' for role in ['client-a', 'client-b'])
            ),
        )
        wait('initial floor state idle', floor_idle)
        for role in ['client-a', 'client-b']:
            assert 'floor_queue_info_received' in status(role), 'missing queue response counter: ' + role

        start_alpha('alpha receives first floor')
        queue_bravo('bravo request enters queue')
        previous_info = status('client-b')['floor_queue_info_received']
        command('client-b', 'queue-status')
        wait(
            'explicit queue query gets a fresh position response',
            lambda: (
                status('client-b').get('floor_queue_info_received', 0) > previous_info
                and status('client-b').get('queue_position') == 1
                and status('client-b').get('floor_state') == 'Queued'
            ),
        )

        timer_config = configs['client-b']['mcptt']
        cancellation_budget = (
            timer_config.get('floor_release_retry_ms', 1000) * timer_config.get('floor_transmissions', 3)
        ) / 1000
        cancellation_start = time.monotonic()
        command('client-b', 'release')
        remaining = cancellation_budget - 0.15 - (time.monotonic() - cancellation_start)
        assert remaining > 0, 'CLI latency consumed the release timer budget'
        wait(
            'queued cancellation resolves before T100 exhaustion',
            lambda: (
                status('client-b').get('floor_state') == 'NoPermission'
                and not status('client-b').get('queued')
                and owner() == ids['client-a']
            ),
            remaining,
        )
        result['queue_cancel_ms'] = round((time.monotonic() - cancellation_start) * 1000)
        result['release_exhaustion_budget_ms'] = round(cancellation_budget * 1000)

        queue_bravo('bravo requeues after cancellation')
        sent_before_confirmation = status('client-b').get('sent_packets', 0)
        received_before_confirmation = status('client-a').get('received_packets', 0)
        command('client-a', 'release')
        wait(
            'queued grant waits for user confirmation',
            lambda: (
                owner() == ids['client-b']
                and status('client-b').get('pending_floor_confirmation')
                and status('client-b').get('floor_state') == 'Queued'
            ),
        )
        assert status('client-b').get('sent_packets', 0) == sent_before_confirmation, (
            'media sent before user confirmation'
        )
        command('client-b', 'floor-confirm')
        wait(
            'confirmed queued grant sends and delivers audio',
            lambda: (
                status('client-b').get('floor_state') == 'HasPermission'
                and status('client-b').get('sent_packets', 0) >= sent_before_confirmation + 10
                and status('client-a').get('received_packets', 0) >= received_before_confirmation + 10
            ),
        )
        result['confirmed_sent_packets'] = status('client-b').get('sent_packets', 0) - sent_before_confirmation
        command('client-b', 'release')
        wait('confirmed talker releases floor', floor_idle)

        start_alpha('alpha takes floor for abandoned-grant check')
        queue_bravo('bravo queues without accepting the next grant')
        sent_before_abandon = status('client-b').get('sent_packets', 0)
        command('client-a', 'release')
        wait(
            'second queued grant awaits confirmation',
            lambda: owner() == ids['client-b'] and status('client-b').get('pending_floor_confirmation'),
        )
        action_ms = timer_config.get('floor_queued_grant_action_ms', 2000)
        idle_ms = configs['mcptt-server']['mcptt'].get('floor_media_idle_ms', 4000)
        no_media_start = time.monotonic()
        observation_seconds = max(2.2, max(action_ms, idle_ms) / 1000 + 0.3)
        deadline = no_media_start + observation_seconds + 5
        while time.monotonic() < deadline:
            no_new_timeout()
            assert status('client-b').get('sent_packets', 0) == sent_before_abandon, 'unconfirmed grant emitted RTP'
            if time.monotonic() - no_media_start >= observation_seconds and floor_idle():
                break
            time.sleep(0.05)
        else:
            raise AssertionError('unconfirmed floor grant did not clear through T132/T1')
        checks.append('unconfirmed grant produces no audio and eventually clears')
        result['unconfirmed_sent_packet_delta'] = status('client-b').get('sent_packets', 0) - sent_before_abandon
        result['unconfirmed_observation_ms'] = round((time.monotonic() - no_media_start) * 1000)
        result['unconfirmed_recovery_limit'] = (
            'Outcome covers T132/T1 recovery; status alone does not identify which timer fired first.'
        )
        assert all(status(role).get('call_state') == 'idle' for role in ['client-c', 'client-d']), (
            'deaffiliated client entered queue call'
        )
        command('client-a', 'hangup')
        wait(
            'queue call tears down cleanly',
            lambda: (
                not sessions() and all(status(role).get('call_state') == 'idle' for role in ['client-a', 'client-b'])
            ),
        )
        started_call = False
        assert status('mcptt-server').get('instance_id') == instance, 'server restarted during floor scenario'
        checks.append('server instance unchanged')
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
    output = args.artifacts / 'integration/prearranged-floor-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
