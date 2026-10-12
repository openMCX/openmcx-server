#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo private calls with and without transmission control carrying H.264 video both ways:
private call with transmission control (TS 24.281 clause 10.2.2), without it (clause 10.2.3),
ending the call (clause 10.2.4), the commencement modes (clause 6.2.3) and the refusals of the
private call authorisation (clauses 10.2.2.3.1.1 and 10.2.2.3.2, warning texts of clause 4.4.2).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): client-a may call client-b and client-c in every
commencement mode; client-b may call anyone automatically or manually; client-c is
called only by client-a; client-d may neither call nor be called. Check IDs match
tests/mcvideo/MCVIDEO_PRIVATE_CALL_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

import capture
from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
# Run the scenario against the lab and write integration/mcvideo-private-call-results.json; return 0 when every check
# passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    # Over TLS the captured SIP is encrypted: the SIP wire checks need a --debug-sip lab.
    compose = json.loads(args.compose.read_text())
    sip_on_wire = '--disable-tls' in compose['services']['client-a']['command']
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcvideo']['user_id'] for role in ROLES}
    checks, observations = [], {}
    result = dict(scenario='mcvideo-private-call', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-private-call.pcap'
    capture_name = f'{args.project}-mcvideo-private-capture'

    # ------------------------------------------------------------------------------
    # The status.json a role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The private call state of every client, for a timed-out check's message.
    def snapshot():
        keys = (
            'mcvideo_call_state',
            'mcvideo_call_type',
            'mcvideo_peer',
            'mcvideo_transmitting',
            'mcvideo_frames_received',
            'mcvideo_last_call',
            'last_error',
        )
        return {role: {key: status(role).get(key) for key in keys} for role in ROLES}

    # ------------------------------------------------------------------------------
    # Poll condition until it holds (record label as passed) or timeout seconds pass (fail with a snapshot).
    def wait(label, condition, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                return
            time.sleep(0.25)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    # Record label as passed if condition holds, else fail with detail.
    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)

    # ------------------------------------------------------------------------------
    # Send one interactive command to the mcx-client of a role.
    def command(role, text):
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
        )

    # ------------------------------------------------------------------------------
    # Compare the frames receiver decoded with those sender encoded: (frames received, frames equal, frames compared).
    def matching(sender, receiver):
        sent = status(sender).get('mcvideo_sent_frames') or {}
        received = status(receiver).get('mcvideo_received_frames') or {}
        common = [key for key in received if key in sent]
        return len(received), sum(1 for key in common if sent[key] == received[key]), len(common)

    # ------------------------------------------------------------------------------
    # True when every given role has no MCVideo call.
    def idle(*roles):
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    # MV-PC-05: caller's automatic-commencement private call to target must be refused with 403, warning code and text
    # (TS 24.281 clause 10.2.2.3.1.1 for 107 and 144, clause 10.2.2.3.2 for 127 and 159).
    def refused(caller, target, code, text):
        before = json.dumps(status(caller).get('mcvideo_last_call'))
        command(caller, f'mcvideo-private {target} auto')
        wait(
            f'MV-PC-05 {caller} to {target} answered',
            lambda: json.dumps(status(caller).get('mcvideo_last_call')) != before and idle(caller),
        )
        outcome = status(caller).get('mcvideo_last_call') or {}
        observations[f'{caller}_to_{target}'] = outcome
        check(
            f'MV-PC-05 {caller} to {target} refused with 403 "{code}"',
            outcome.get('status') == 403 and f'{code} {text}' in outcome.get('warning', ''),
            outcome,
        )

    # ------------------------------------------------------------------------------
    # Capture the SIP of mcvideo-server (tcpdump in its network namespace) until the capture container is stopped.
    def start_capture():
        server = subprocess.run(
            cli + ['ps', '-q', 'mcvideo-server'], check=True, capture_output=True, text=True
        ).stdout.strip()
        capture_file.parent.mkdir(parents=True, exist_ok=True)
        log = capture_file.with_suffix('.log')
        with open(capture_file, 'wb') as out, open(log, 'wb') as err:
            subprocess.Popen(
                [
                    'docker',
                    'run',
                    '--rm',
                    '--name',
                    capture_name,
                    '--network',
                    f'container:{server}',
                    '--cap-drop',
                    'ALL',
                    '--cap-add',
                    'NET_RAW',
                    'openmcx-dev:0.1',
                    'tcpdump',
                    '-Z',
                    'root',
                    '-i',
                    'eth0',
                    '-U',
                    '-s',
                    '0',
                    '-w',
                    '-',
                    'tcp port 5060 or tcp port 5061',
                ],
                stdout=out,
                stderr=err,
            )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and b'listening on' not in log.read_bytes():
            time.sleep(0.1)

    # ------------------------------------------------------------------------------
    # The SIP messages of the capture as text.
    def sip_text():
        return capture.sip_text(capture_file)

    try:
        wait(
            'four clients MCVideo authorised', lambda: all(status(role).get('mcvideo_authorized') for role in ROLES), 90
        )
        start_capture()
        # MV-PC-01 TS 24.281 clause 10.2.2: client-a calls client-b with automatic commencement; video
        # both ways, one transmitter at a time.
        command('client-a', f"mcvideo-private {ids['client-b']} auto")
        wait(
            'MV-PC-01 client-a and client-b in a private call',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active'
                and status(role).get('mcvideo_call_type') == 'private'
                for role in ('client-a', 'client-b')
            ),
        )
        check(
            'MV-PC-01 each side knows the other',
            status('client-a').get('mcvideo_peer') == ids['client-b']
            and status('client-b').get('mcvideo_peer') == ids['client-a'],
            {role: status(role).get('mcvideo_peer') for role in ('client-a', 'client-b')},
        )
        check('MV-PC-01 nobody else is in the call', idle('client-c', 'client-d'))
        command('client-a', 'mcvideo-transmit')
        wait('MV-PC-01 client-a granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        wait(
            'MV-PC-01 client-b decodes client-a', lambda: status('client-b').get('mcvideo_frames_received', 0) >= 20, 30
        )
        received, equal, common = matching('client-a', 'client-b')
        observations['b_from_a'] = dict(received=received, compared=common, equal=equal)
        check(
            'MV-PC-01 client-b pictures equal client-a\'s', common >= 15 and equal == common, observations['b_from_a']
        )
        command('client-a', 'mcvideo-end')
        wait('MV-PC-01 client-a released', lambda: status('client-a').get('mcvideo_transmitting') is False)
        command('client-b', 'mcvideo-transmit')
        wait('MV-PC-01 client-b granted', lambda: status('client-b').get('mcvideo_transmitting') is True)
        wait(
            'MV-PC-01 client-a decodes client-b', lambda: status('client-a').get('mcvideo_frames_received', 0) >= 20, 30
        )
        received, equal, common = matching('client-b', 'client-a')
        observations['a_from_b'] = dict(received=received, compared=common, equal=equal)
        check(
            'MV-PC-01 client-a pictures equal client-b\'s', common >= 15 and equal == common, observations['a_from_b']
        )
        # MV-PC-02 TS 24.281 clause 10.2.4: the called user ends the call; both are idle.
        command('client-b', 'mcvideo-hangup')
        wait('MV-PC-02 the call ended at both', lambda: idle('client-a', 'client-b'))
        # MV-PC-03 TS 24.281 clause 6.2.3: manual commencement; client-b rings until it answers.
        command('client-a', f"mcvideo-private {ids['client-b']} manual")
        wait('MV-PC-03 client-b rings', lambda: status('client-b').get('mcvideo_call_state') == 'ringing')
        check(
            'MV-PC-03 client-a still waits', holds(lambda: status('client-a').get('mcvideo_call_state') == 'calling', 1)
        )
        command('client-b', 'mcvideo-answer')
        wait(
            'MV-PC-03 answered: both active',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b')),
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-PC-03 the call ended at both', lambda: idle('client-a', 'client-b'))
        # MV-PC-04 the invited user declines a manual call.
        command('client-a', f"mcvideo-private {ids['client-b']} manual")
        wait('MV-PC-04 client-b rings', lambda: status('client-b').get('mcvideo_call_state') == 'ringing')
        command('client-b', 'mcvideo-reject')
        wait(
            'MV-PC-04 client-a told of the decline',
            lambda: idle('client-a') and (status('client-a').get('mcvideo_last_call') or {}).get('status') == 480,
        )
        observations['declined'] = status('client-a').get('mcvideo_last_call')
        # MV-PC-05 the private-call rulesets of the MCVideo user profiles: the refusals of TS 24.281
        # clauses 10.2.2.3.1.1 and 10.2.2.3.2, warning texts of clause 4.4.2.
        refused('client-d', ids['client-a'], 107, 'user not authorised to make private calls')
        refused('client-a', ids['client-d'], 144, 'user not authorised to call this particular user')
        refused('client-b', ids['client-d'], 127, 'user not authorised to be called in private call')
        refused('client-b', ids['client-c'], 159, 'user not authorised to be called by this originating user')
        # MV-PC-06 force of automatic commencement (Priv-Answer-Mode Auto).
        command('client-a', f"mcvideo-private {ids['client-c']} force-auto")
        wait(
            'MV-PC-06 client-c answered automatically',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-c')),
        )
        command('client-c', 'mcvideo-hangup')
        wait('MV-PC-06 the call ended at both', lambda: idle('client-a', 'client-c'))
        # MV-PC-08 TS 24.281 clause 10.2.3: without transmission control both parties send at once, each
        # with the SSRC of its SDP, and decode each other.
        command('client-a', f"mcvideo-private {ids['client-b']} auto no-control")
        wait(
            'MV-PC-08 both in a private call without transmission control',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active'
                and status(role).get('mcvideo_transmission_control') is False
                for role in ('client-a', 'client-b')
            ),
        )
        wait(
            'MV-PC-08 both send at the same time',
            lambda: all(status(role).get('mcvideo_transmitting') is True for role in ('client-a', 'client-b')),
        )
        wait(
            'MV-PC-08 each decodes the other',
            lambda: all(status(role).get('mcvideo_frames_received', 0) >= 20 for role in ('client-a', 'client-b')),
            30,
        )
        for sender, receiver in (('client-a', 'client-b'), ('client-b', 'client-a')):
            received, equal, common = matching(sender, receiver)
            observations[f'open_{receiver}_from_{sender}'] = dict(received=received, compared=common, equal=equal)
            check(
                f'MV-PC-08 {receiver} pictures equal {sender}\'s',
                common >= 15 and equal == common,
                observations[f'open_{receiver}_from_{sender}'],
            )
        command('client-a', 'mcvideo-hangup')
        wait('MV-PC-08 the call ended at both', lambda: idle('client-a', 'client-b'))
        time.sleep(1)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        # MV-PC-07 the wire: a private INVITE with the called MCVideo ID in resource-lists
        # and the commencement headers.
        if sip_on_wire:
            sip = sip_text()
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:mcvideo@')]
            private = [message for message in invites if '<session-type>private</session-type>' in message]
            observations['private_invites'] = len(private)
            check('MV-PC-07 private INVITEs to the MCVideo PSI', len(private) >= 5, len(private))
            check(
                'MV-PC-07 the called MCVideo ID in resource-lists',
                any('application/resource-lists+xml' in message and ids['client-b'] in message for message in private),
            )
            for header in ('Answer-Mode: Auto', 'Answer-Mode: Manual', 'Priv-Answer-Mode: Auto'):
                check(f'MV-PC-07 {header} on the wire', any(header in message for message in private))
            check(
                'MV-PC-07 an offer with video and without transmission control',
                any('m=video' in message and 'm=application' not in message for message in private),
            )
            check('MV-PC-07 offers with transmission control', any('udp MCVideo' in message for message in private))
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except AssertionError as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-private-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
