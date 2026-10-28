#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo ambient viewing calls on demand (TS 24.281 clause 15, without the pre-established
session of clause 15.2.2), remotely and locally initiated (clause 15.2.1.1), with H.264 video
checked picture by picture; the release capability (clause 15.2.1.3, annex D.3), the refusal of
an unauthorised user (clause 15.4.2 step 3) and the server-initiated release when the viewed-to
user is called (clause 15.4.3).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): client-a may make remotely and locally initiated
ambient viewing calls; client-b may make neither; client-c may call client-b. Check IDs
match tests/mcvideo/MCVIDEO_AMBIENT_VIEWING_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 26.281 V19.0.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

import capture

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab and write its results JSON; exit status 0 when every check passed."""
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
    result = dict(scenario='mcvideo-ambient-viewing', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-ambient-viewing.pcap'
    capture_name = f'{args.project}-mcvideo-ambient-capture'

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json as the lab container last wrote it, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The MCVideo state of every client, quoted in a timeout message."""
        keys = (
            'mcvideo_call_state',
            'mcvideo_call_type',
            'mcvideo_video_mode',
            'mcvideo_peer',
            'mcvideo_transmitting',
            'mcvideo_transmitter',
            'mcvideo_frames_received',
            'mcvideo_ambient_type',
            'mcvideo_ambient_role',
            'mcvideo_ambient_release',
            'mcvideo_last_call',
            'last_error',
        )
        return {role: {key: status(role).get(key) for key in keys} for role in ROLES}

    # ------------------------------------------------------------------------------
    def wait(label, condition, timeout=30):
        """Poll the condition until it holds (then record the check) or the timeout expires (then fail with a
        snapshot).
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                return
            time.sleep(0.25)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=None):
        """Record the check if the condition holds, otherwise fail with the detail."""
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Send a command line to the role's running mcx-client."""
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
        )

    # ------------------------------------------------------------------------------
    def compare(sent, received):
        """The number of received pictures, of those with a sent picture of the same RTP timestamp, and of
        those equal.
        """
        common = [key for key in received if key in sent]
        return dict(
            received=len(received), compared=len(common), equal=sum(1 for key in common if sent[key] == received[key])
        )

    # ------------------------------------------------------------------------------
    def matching(sender, receiver):
        """compare() of the pictures the sender encoded and the pictures the receiver decoded."""
        return compare(
            status(sender).get('mcvideo_sent_frames') or {}, status(receiver).get('mcvideo_received_frames') or {}
        )

    # ------------------------------------------------------------------------------
    def idle(*roles):
        """Whether every given client has no MCVideo call."""
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    def refused(role, text, code, reason, label):
        """Send the command and check that the call it starts is answered with the status code and, when given, the
        warning code.
        """
        before = json.dumps(status(role).get('mcvideo_last_call'))
        command(role, text)
        wait(f'{label} answered', lambda: json.dumps(status(role).get('mcvideo_last_call')) != before and idle(role))
        outcome = status(role).get('mcvideo_last_call') or {}
        observations[label] = outcome
        check(label, outcome.get('status') == code and (not reason or reason in outcome.get('warning', '')), outcome)

    # ------------------------------------------------------------------------------
    def start_capture():
        """Capture the SIP on mcvideo-server's network namespace with tcpdump in a container; return once it listens."""
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
    def sip_text():
        """The SIP messages of the capture as text."""
        return capture.sip_text(capture_file)

    # ------------------------------------------------------------------------------
    def refused_command(role, text, error):
        # The command goes to the running client, which reports a refusal in last_error.
        """Send a command the client itself should refuse; whether its last_error names the error within 10 s."""
        command(role, text)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if error in (status(role).get('last_error') or ''):
                return True
            time.sleep(0.25)
        return False

    # ------------------------------------------------------------------------------
    def in_ambient(viewing, viewed, kind):
        """Whether the viewing and the viewed-to client are both in an active ambient viewing call (TS 24.281 clause
        15) of the given type, remote-init or local-init.
        """
        return (
            status(viewing).get('mcvideo_call_state') == 'active'
            and status(viewed).get('mcvideo_call_state') == 'active'
            and status(viewing).get('mcvideo_ambient_role') == 'viewing'
            and status(viewed).get('mcvideo_ambient_role') == 'viewed-to'
            and status(viewing).get('mcvideo_ambient_type') == kind
            and status(viewed).get('mcvideo_ambient_type') == kind
        )

    try:
        wait(
            'four clients MCVideo authorised and affiliated',
            lambda: all(
                status(role).get('mcvideo_authorized') and status(role).get('mcvideo_affiliated') for role in ROLES
            ),
            90,
        )
        start_capture()

        # MV-AV-01 TS 24.281 clause 15.2.1.1 (remote-init): client-a views client-b. client-b, the viewed-to
        # user, transmits without asking and is given no way to release the call.
        command('client-a', f"mcvideo-ambient {ids['client-b']} remote")
        wait(
            'MV-AV-01 client-a views client-b in a remotely initiated ambient viewing call',
            lambda: in_ambient('client-a', 'client-b', 'remote-init'),
        )
        wait(
            'MV-AV-01 client-b transmits without asking', lambda: status('client-b').get('mcvideo_transmitting') is True
        )
        wait(
            'MV-AV-01 client-a decodes client-b', lambda: status('client-a').get('mcvideo_frames_received', 0) >= 20, 30
        )
        observations['remote'] = matching('client-b', 'client-a')
        check(
            'MV-AV-01 client-a pictures equal client-b\'s',
            observations['remote']['compared'] >= 15
            and observations['remote']['equal'] == observations['remote']['compared'],
            observations['remote'],
        )
        check(
            'MV-AV-01 client-a, the viewing user, does not transmit',
            status('client-a').get('mcvideo_transmitting') is False,
        )
        check(
            'MV-AV-01 client-a may release the call (Feature-Caps in the 200 OK, D.3)',
            status('client-a').get('mcvideo_ambient_release') is True,
        )
        check(
            'MV-AV-01 client-b may not (no Feature-Caps in its INVITE)',
            status('client-b').get('mcvideo_ambient_release') is False,
        )
        check(
            'MV-AV-01 client-b\'s release is refused by its client (15.2.1.3 step 1)',
            refused_command('client-b', 'mcvideo-hangup', 'ambient viewing call release not allowed'),
            status('client-b').get('last_error'),
        )
        check('MV-AV-01 the call is still up', in_ambient('client-a', 'client-b', 'remote-init'))
        command('client-a', 'mcvideo-hangup')
        wait('MV-AV-01 the viewing user releases the call; both idle', lambda: idle('client-a', 'client-b'))

        # MV-AV-02 TS 24.281 clause 15.2.1.1 (local-init): client-a asks client-b to view it. client-a, the
        # viewed-to originator, transmits; client-b views and may release the call.
        command('client-a', f"mcvideo-ambient {ids['client-b']} local")
        wait(
            'MV-AV-02 client-b views client-a in a locally initiated ambient viewing call',
            lambda: in_ambient('client-b', 'client-a', 'local-init'),
        )
        wait(
            'MV-AV-02 client-a transmits without asking', lambda: status('client-a').get('mcvideo_transmitting') is True
        )
        wait(
            'MV-AV-02 client-b decodes client-a', lambda: status('client-b').get('mcvideo_frames_received', 0) >= 20, 30
        )
        observations['local'] = matching('client-a', 'client-b')
        check(
            'MV-AV-02 client-b pictures equal client-a\'s',
            observations['local']['compared'] >= 15
            and observations['local']['equal'] == observations['local']['compared'],
            observations['local'],
        )
        check(
            'MV-AV-02 both may release the call',
            status('client-a').get('mcvideo_ambient_release') is True
            and status('client-b').get('mcvideo_ambient_release') is True,
        )
        command('client-b', 'mcvideo-hangup')
        wait('MV-AV-02 the viewing user releases the call; both idle', lambda: idle('client-a', 'client-b'))

        # MV-AV-03 TS 24.281 clause 15.4.2 step 3: client-b is not authorised; 403 with warning 154.
        refused(
            'client-b',
            f"mcvideo-ambient {ids['client-a']} remote",
            403,
            '154',
            'MV-AV-03 client-b\'s ambient viewing call is refused with 403 and warning 154',
        )

        # MV-AV-04 TS 24.281 clause 15.4.3: a call to the viewed-to user ends the ambient viewing
        # call; the viewing user's BYE says why (step 3c), and the new call goes through.
        command('client-a', f"mcvideo-ambient {ids['client-b']} remote")
        wait('MV-AV-04 client-a views client-b again', lambda: in_ambient('client-a', 'client-b', 'remote-init'))
        before = json.dumps(status('client-a').get('mcvideo_last_call'))
        command('client-c', f"mcvideo-private {ids['client-b']} auto")
        wait(
            'MV-AV-04 the ambient viewing call ends for client-a',
            lambda: json.dumps(status('client-a').get('mcvideo_last_call')) != before and idle('client-a'),
        )
        outcome = status('client-a').get('mcvideo_last_call') or {}
        observations['released'] = {
            key: outcome.get(key) for key in ('ambient_type', 'ambient_role', 'release_reason', 'reason')
        }
        check(
            'MV-AV-04 its BYE carries <release-reason> call-request-for-viewed-to-client',
            outcome.get('release_reason') == 'call-request-for-viewed-to-client',
            observations['released'],
        )
        wait(
            'MV-AV-04 client-c\'s private call to client-b goes through',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active'
                and status(role).get('mcvideo_call_type') == 'private'
                and not status(role).get('mcvideo_ambient_type')
                for role in ('client-c', 'client-b')
            ),
        )
        command('client-c', 'mcvideo-hangup')
        wait('MV-AV-04 the private call ended', lambda: idle('client-b', 'client-c'))

        # MV-AV-05 on the wire.
        # The capture streams its packets through docker; let the last ones reach the file.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:')]
            ambient = [message for message in invites if '<session-type>ambient-viewing</session-type>' in message]
            check('MV-AV-05 INVITEs with <session-type>ambient-viewing</session-type>', len(ambient) >= 4, len(ambient))
            for kind in ('remote-init', 'local-init'):
                check(
                    f'MV-AV-05 an INVITE with <ambient-viewing-type>{kind}</ambient-viewing-type>',
                    any(f'<ambient-viewing-type>{kind}</ambient-viewing-type>' in message for message in ambient),
                )
            check(
                'MV-AV-05 every ambient viewing INVITE has Priv-Answer-Mode: Auto',
                all('Priv-Answer-Mode: Auto' in message for message in ambient),
            )
            check(
                'MV-AV-05 the viewed-to user of a remote-init call is invited with a null alert',
                any('Alert-Info: <file:///dev/null>' in message and 'remote-init' in message for message in ambient),
            )
            check(
                'MV-AV-05 the viewing user of a local-init call is invited with the release capability',
                any(
                    'Feature-Caps:' in message
                    and 'g.3gpp.mcvideo.ambient-viewing-call-release' in message
                    and 'local-init' in message
                    for message in ambient
                ),
            )
            responses = [
                message
                for message in capture.split(sip)
                if message.startswith('SIP/2.0 200') and 'ambient-viewing' in message
            ]
            check(
                'MV-AV-05 a 200 (OK) to an ambient viewing INVITE carries the release capability',
                any('g.3gpp.mcvideo.ambient-viewing-call-release' in message for message in responses),
            )
            byes = [message for message in capture.split(sip) if message.startswith('BYE sip')]
            check(
                'MV-AV-05 a BYE with <release-reason>call-request-for-viewed-to-client</release-reason>',
                any(
                    '<release-reason>call-request-for-viewed-to-client</release-reason>' in message for message in byes
                ),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-ambient-viewing-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
