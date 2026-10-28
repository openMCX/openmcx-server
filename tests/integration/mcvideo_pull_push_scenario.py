#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo video push and pull (TS 24.281 clauses 12.2 and 13.2, one-to-one and to or from the
server) and remotely initiated and ended transmission (TS 23.281 clauses 7.7.1.3.7 and
7.7.1.3.6.3, with the Remote Transmission messages of TS 24.581 clauses 9.2.22 to 9.2.25), with
H.264 video checked picture by picture.

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): client-a may start and end other users'
transmissions remotely and push to and pull from the server; client-b may pull from
the server; client-c and client-d may do none of these. Check IDs match
tests/mcvideo/MCVIDEO_PULL_PUSH_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 23.281 V19.10.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import time

import capture
from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
# Run the scenario against the lab and write integration/mcvideo-pull-push-results.json; return 0 when every check
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
    result = dict(scenario='mcvideo-pull-push', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-pull-push.pcap'
    capture_name = f'{args.project}-mcvideo-pull-push-capture'

    # ------------------------------------------------------------------------------
    # The status.json a role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The call state of every client, for a timed-out check's message.
    def snapshot():
        keys = (
            'mcvideo_call_state',
            'mcvideo_call_type',
            'mcvideo_video_mode',
            'mcvideo_peer',
            'mcvideo_transmitting',
            'mcvideo_transmitter',
            'mcvideo_frames_received',
            'mcvideo_remote_result',
            'mcvideo_push_url',
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
    # Compare received frames with sent frames by RTP timestamp: frames received, compared and equal.
    def compare(sent, received):
        common = [key for key in received if key in sent]
        return dict(
            received=len(received), compared=len(common), equal=sum(1 for key in common if sent[key] == received[key])
        )

    # ------------------------------------------------------------------------------
    # Compare the frames receiver decoded with those sender encoded.
    def matching(sender, receiver):
        return compare(
            status(sender).get('mcvideo_sent_frames') or {}, status(receiver).get('mcvideo_received_frames') or {}
        )

    # ------------------------------------------------------------------------------
    # True when every given role has no MCVideo call.
    def idle(*roles):
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    # The status.json of mcvideo-server (recorded and streamed video), or {} while it is missing or half written.
    def server_status():
        try:
            return json.loads((args.artifacts / 'mcvideo-server' / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # role's command text must end its call attempt with status code and, when reason is given, that warning text.
    def refused(role, text, code, reason, label):
        before = json.dumps(status(role).get('mcvideo_last_call'))
        command(role, text)
        wait(f'{label} answered', lambda: json.dumps(status(role).get('mcvideo_last_call')) != before and idle(role))
        outcome = status(role).get('mcvideo_last_call') or {}
        observations[label] = outcome
        check(label, outcome.get('status') == code and (not reason or reason in outcome.get('warning', '')), outcome)

    # ------------------------------------------------------------------------------
    # role sends a Remote Transmission request (text 'transmit', TS 24.581 clause 9.2.22) or Remote Transmission cancel
    # request (text 'cancel', TS 24.581 clause 9.2.24) for target; return the Result of the response (TS 24.581 clauses
    # 9.2.23 and 9.2.25).
    def remote(role, text, target):
        command(role, f'mcvideo-remote-{text} {ids[target]}')
        answered = 'transmit' if text == 'transmit' else 'cancel'
        wait(
            f'{role} remote {text} of {target} answered',
            lambda: (
                (status(role).get('mcvideo_remote_result') or {}).get('answered') == answered
                and (status(role).get('mcvideo_remote_result') or {}).get('target') == ids[target]
            ),
        )
        return (status(role).get('mcvideo_remote_result') or {}).get('result')

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
                    'openmcx-dev:0.4',
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
            'four clients MCVideo authorised and affiliated',
            lambda: all(
                status(role).get('mcvideo_authorized') and status(role).get('mcvideo_affiliated') for role in ROLES
            ),
            90,
        )
        start_capture()

        # MV-PP-01 TS 24.281 clause 13.2: client-a pushes its video to client-b. client-a transmits
        # at once (implicit Transmission request, TS 24.581 clause 6.2.1); client-b is told it is a
        # push call.
        command('client-a', f"mcvideo-push {ids['client-b']} auto")
        wait(
            'MV-PP-01 client-a and client-b in a video push call',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active'
                and status(role).get('mcvideo_video_mode') == 'one-to-one video push'
                for role in ('client-a', 'client-b')
            ),
        )
        wait(
            'MV-PP-01 client-a transmits without asking', lambda: status('client-a').get('mcvideo_transmitting') is True
        )
        wait(
            'MV-PP-01 client-b decodes client-a', lambda: status('client-b').get('mcvideo_frames_received', 0) >= 20, 30
        )
        observations['push'] = matching('client-a', 'client-b')
        check(
            'MV-PP-01 client-b pictures equal client-a\'s',
            observations['push']['compared'] >= 15
            and observations['push']['equal'] == observations['push']['compared'],
            observations['push'],
        )
        check('MV-PP-01 client-b does not transmit', status('client-b').get('mcvideo_transmitting') is False)
        command('client-a', 'mcvideo-hangup')
        wait('MV-PP-01 the push call ended', lambda: idle('client-a', 'client-b'))

        # MV-PP-02 TS 24.281 clause 12.2: client-a pulls client-b's video. client-b, the called
        # user, transmits at once (its implicit request in the answer, TS 24.281 clause 12.2.2.2).
        command('client-a', f"mcvideo-pull {ids['client-b']} auto")
        wait(
            'MV-PP-02 client-a and client-b in a video pull call',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active'
                and status(role).get('mcvideo_video_mode') == 'one-to-one video pull'
                for role in ('client-a', 'client-b')
            ),
        )
        wait(
            'MV-PP-02 client-b transmits without asking', lambda: status('client-b').get('mcvideo_transmitting') is True
        )
        wait(
            'MV-PP-02 client-a decodes client-b', lambda: status('client-a').get('mcvideo_frames_received', 0) >= 20, 30
        )
        observations['pull'] = matching('client-b', 'client-a')
        check(
            'MV-PP-02 client-a pictures equal client-b\'s',
            observations['pull']['compared'] >= 15
            and observations['pull']['equal'] == observations['pull']['compared'],
            observations['pull'],
        )
        check('MV-PP-02 client-a does not transmit', status('client-a').get('mcvideo_transmitting') is False)
        command('client-a', 'mcvideo-hangup')
        wait('MV-PP-02 the pull call ended', lambda: idle('client-a', 'client-b'))

        # MV-PP-03 TS 24.281 clauses 13.2.2.4 and 13.2.3.2.3: client-a pushes its video to the
        # server, which records it and sends the recording's URL in a SIP INFO.
        recorded_before = server_status().get('video_recorded', 0)
        command('client-a', 'mcvideo-push-server')
        wait(
            'MV-PP-03 client-a in a video push call to the server',
            lambda: (
                status('client-a').get('mcvideo_call_state') == 'active'
                and status('client-a').get('mcvideo_video_mode') == 'one-to-server video push'
            ),
        )
        wait(
            'MV-PP-03 client-a transmits without asking', lambda: status('client-a').get('mcvideo_transmitting') is True
        )
        wait(
            'MV-PP-03 client-a receives the <video-push-url> in a SIP INFO',
            lambda: (status('client-a').get('mcvideo_push_url') or '').startswith('https://'),
        )
        url = status('client-a')['mcvideo_push_url']
        observations['push_url'] = url
        wait(
            'MV-PP-03 the server records client-a\'s video',
            lambda: server_status().get('video_recorded', 0) - recorded_before >= 60,
            30,
        )
        wait(
            'MV-PP-03 client-a has sent at least 30 pictures',
            lambda: status('client-a').get('mcvideo_frames_sent', 0) >= 30,
        )
        check('MV-PP-03 nobody else is in the call', idle('client-b', 'client-c', 'client-d'))
        command('client-a', 'mcvideo-hangup')
        wait('MV-PP-03 the push call ended', lambda: idle('client-a'))
        pushed = (status('client-a').get('mcvideo_last_call') or {}).get('sent_frames') or {}
        observations['pushed_frames'] = len(pushed)

        # MV-PP-04 TS 24.281 clauses 12.2.2.4 and 12.2.3.2.5: client-b pulls that recording from
        # the server and decodes the very pictures client-a pushed (same SSRC and timestamps).
        streamed_before = server_status().get('video_streamed', 0)
        command('client-b', f'mcvideo-pull-server {url}')
        wait(
            'MV-PP-04 client-b in a video pull call from the server',
            lambda: (
                status('client-b').get('mcvideo_call_state') == 'active'
                and status('client-b').get('mcvideo_video_mode') == 'one-from-server video pull'
            ),
        )
        wait(
            'MV-PP-04 client-b decodes the recording',
            lambda: status('client-b').get('mcvideo_frames_received', 0) >= 20,
            30,
        )
        wait(
            'MV-PP-04 the server streamed the whole recording',
            lambda: server_status().get('video_streamed', 0) - streamed_before >= 60,
            30,
        )
        time.sleep(1)
        observations['replay'] = compare(pushed, status('client-b').get('mcvideo_received_frames') or {})
        check(
            'MV-PP-04 client-b pictures equal the ones client-a pushed',
            observations['replay']['compared'] >= 20
            and observations['replay']['equal'] == observations['replay']['compared'],
            observations['replay'],
        )
        check('MV-PP-04 client-b does not transmit', status('client-b').get('mcvideo_transmitting') is False)
        command('client-b', 'mcvideo-hangup')
        wait('MV-PP-04 the pull call ended', lambda: idle('client-b'))

        # MV-PP-05: refusals. client-c may neither push to nor pull from the server; an
        # unknown recording is not found.
        refused(
            'client-c',
            f'mcvideo-pull-server {url}',
            403,
            '100 function not allowed',
            'MV-PP-05 client-c pulling from the server is refused with 403 and warning 100',
        )
        refused(
            'client-c',
            'mcvideo-push-server',
            403,
            '100 function not allowed',
            'MV-PP-05 client-c pushing to the server is refused with 403 and warning 100',
        )
        unknown = url[: url.rindex('/') + 1] + 'f' * 32
        refused(
            'client-b',
            f'mcvideo-pull-server {unknown}',
            404,
            '',
            'MV-PP-05 a pull of an unknown recording is refused with 404',
        )
        refused(
            'client-d',
            f"mcvideo-push {ids['client-a']} auto",
            403,
            '',
            'MV-PP-05 client-d may not make a video push call (private call rules) and is refused with 403',
        )

        # MV-RT-01 to MV-RT-04 (TS 23.281 clauses 7.7.1.3.7 and 7.7.1.3.6.3): in a group call,
        # client-a has client-b transmit and then stops it; client-c is not authorised.
        command('client-a', 'mcvideo-call')
        wait(
            'MV-RT-01 all four in the MCVideo group call',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        wait(
            'MV-RT-01 nobody transmits yet',
            lambda: not any(status(role).get('mcvideo_transmitting') for role in ROLES),
            10,
        )
        check(
            'MV-RT-01 client-a\'s Remote Transmission request is granted (Result 1)',
            remote('client-a', 'transmit', 'client-b') is True,
        )
        wait('MV-RT-01 client-b transmits', lambda: status('client-b').get('mcvideo_transmitting') is True)
        wait(
            'MV-RT-01 client-c decodes client-b', lambda: status('client-c').get('mcvideo_frames_received', 0) >= 15, 30
        )
        observations['remote'] = matching('client-b', 'client-c')
        check(
            'MV-RT-01 client-c pictures equal client-b\'s',
            observations['remote']['compared'] >= 10
            and observations['remote']['equal'] == observations['remote']['compared'],
            observations['remote'],
        )
        check(
            'MV-RT-02 client-c may not end client-b\'s transmission (Result 0)',
            remote('client-c', 'cancel', 'client-b') is False,
        )
        check('MV-RT-02 client-b still transmits', status('client-b').get('mcvideo_transmitting') is True)
        revocations = status('client-b').get('mcvideo_revocations', 0)
        check(
            'MV-RT-03 client-a\'s Remote Transmission cancel request succeeds (Result 1)',
            remote('client-a', 'cancel', 'client-b') is True,
        )
        wait('MV-RT-03 client-b stops transmitting', lambda: status('client-b').get('mcvideo_transmitting') is False)
        wait(
            'MV-RT-03 client-b is revoked with cause #5',
            lambda: (
                status('client-b').get('mcvideo_revocations', 0) > revocations
                and status('client-b').get('mcvideo_reject_cause') == 5
            ),
        )
        check(
            'MV-RT-04 client-c may not start client-d\'s transmission (Result 0)',
            remote('client-c', 'transmit', 'client-d') is False,
        )
        check(
            'MV-RT-04 client-d does not transmit',
            holds(lambda: status('client-d').get('mcvideo_transmitting') is False, 1),
        )
        check(
            'MV-RT-04 a cancel of a user who is not transmitting fails (Result 0)',
            remote('client-a', 'cancel', 'client-d') is False,
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-RT-05 the group call ends for all', lambda: idle(*ROLES), 30)

        # MV-PP-06 on the wire: the session types, the absence of resource-lists in calls
        # to the server, and the INFO with the push URL (RFC 6086).
        # The capture streams its packets through docker; let the last ones reach the file.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:mcvideo@')]
            for kind in (
                'one-to-one video push',
                'one-to-one video pull',
                'one-to-server video push',
                'one-from-server video pull',
            ):
                check(
                    f'MV-PP-06 an INVITE with <session-type>{kind}</session-type>',
                    any(f'<session-type>{kind}</session-type>' in message for message in invites),
                )
            server_calls = [message for message in invites if re.search(r'<session-type>one-(to|from)-server', message)]
            check(
                'MV-PP-06 calls to the server carry no resource-lists body',
                server_calls and not any('application/resource-lists+xml' in message for message in server_calls),
            )
            check(
                'MV-PP-06 the pull names the recording in <video-pull-url>',
                any(
                    f'<mcvideoURI>{url}</mcvideoURI>' in message and '<video-pull-url' in message
                    for message in server_calls
                ),
            )
            infos = [
                message
                for message in capture.split(sip)
                if message.startswith('INFO sip') and '<video-push-url>' in message
            ]
            check(
                'MV-PP-06 an INFO with Info-Package g.3gpp.mcvideo-info carries the <video-push-url>',
                any(
                    'Info-Package: g.3gpp.mcvideo-info' in message
                    and f'<video-push-url>{url}</video-push-url>' in message
                    for message in infos
                ),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-pull-push-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
