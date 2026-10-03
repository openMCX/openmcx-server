#!/usr/bin/env python3
"""MCVideo ad hoc group calls (TS 24.281 clause 22, on-demand sessions): with a list of MCVideo
users (clause 22.2.2.1.1) and with participant criteria (clause 22.2.2.1.1 step 12, clause 22.4.6.1),
the ad hoc group identity the controlling function assigns (clause 22.4.2), H.264 video checked
picture by picture, a refused originator (warning 185, clause 22.3.2.1.1), and the ad hoc group
emergency alert (clause 12.1A).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): every user but client-d may make ad hoc group calls;
mcvideo-server allows 3 participants besides the originator. Check IDs match
tests/mcvideo/MCVIDEO_ADHOC_TEST.md.

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
    result = dict(scenario='mcvideo-adhoc', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-adhoc.pcap'
    capture_name = f'{args.project}-mcvideo-adhoc-capture'

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
            'mcvideo_group',
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
    def sip_text():
        """The SIP messages of the capture as text."""
        return capture.sip_text(capture_file)

    group = json.loads((generated / 'client-a.json').read_text())['mcvideo']['group_id']

    # ------------------------------------------------------------------------------
    def in_adhoc(roles):
        """Whether all given clients are in one active ad hoc group call (TS 24.281 clause 22) with the same, non-empty
        ad hoc group identity.
        """
        groups = {status(role).get('mcvideo_group') for role in roles}
        return (
            all(
                status(role).get('mcvideo_call_state') == 'active' and status(role).get('mcvideo_call_type') == 'adhoc'
                for role in roles
            )
            and len(groups) == 1
            and None not in groups
            and '' not in groups
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

        # MV-AH-01 TS 24.281 clause 22.2.2.1.1 and clause 22.4.2: client-a calls client-b and client-c. The server
        # assigns an ad hoc group identity, which all three share; client-d is not invited.
        command('client-a', f"mcvideo-adhoc {ids['client-b']} {ids['client-c']}")
        wait(
            'MV-AH-01 client-a, client-b and client-c in one ad hoc group call',
            lambda: in_adhoc(['client-a', 'client-b', 'client-c']),
        )
        adhoc_group = status('client-a').get('mcvideo_group')
        observations['adhoc_group'] = adhoc_group
        check('MV-AH-01 the ad hoc group identity is not the preconfigured group', adhoc_group != group, adhoc_group)
        check('MV-AH-01 client-d is not in the call', idle('client-d'))
        command('client-a', 'mcvideo-transmit')
        wait('MV-AH-01 client-a granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        for role in ('client-b', 'client-c'):
            wait(
                f'MV-AH-01 {role} decodes client-a',
                lambda role=role: status(role).get('mcvideo_frames_received', 0) >= 15,
                30,
            )
            observations[f'{role}_from_a'] = matching('client-a', role)
            got = observations[f'{role}_from_a']
            check(
                f'MV-AH-01 {role} pictures equal client-a\'s',
                got['compared'] >= 10 and got['equal'] == got['compared'],
                got,
            )
        command('client-a', 'mcvideo-release')
        wait('MV-AH-01 client-a released', lambda: status('client-a').get('mcvideo_transmitting') is False)
        command('client-b', 'mcvideo-transmit')
        wait('MV-AH-01 client-b granted in turn', lambda: status('client-b').get('mcvideo_transmitting') is True)
        wait(
            'MV-AH-01 client-c decodes client-b',
            lambda: (
                len(status('client-c').get('mcvideo_received_frames') or {})
                > observations['client-c_from_a']['received'] + 10
            ),
            30,
        )
        observations['c_from_b'] = matching('client-b', 'client-c')
        check(
            'MV-AH-01 client-c pictures of client-b equal client-b\'s',
            observations['c_from_b']['equal'] >= 5
            and observations['c_from_b']['equal'] == observations['c_from_b']['compared'],
            observations['c_from_b'],
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-AH-02 the originator leaving ends the call for all', lambda: idle(*ROLES), 30)

        # MV-AH-03 TS 24.281 clause 22.2.2.1.1 step 12 and clause 22.4.6.1: participants by criteria. Everyone
        # affiliated to the MCVideo group is invited.
        command('client-a', f'mcvideo-adhoc criteria affiliated:{group}')
        wait('MV-AH-03 the criteria call invites every user affiliated to the group', lambda: in_adhoc(ROLES))
        command('client-a', 'mcvideo-hangup')
        wait('MV-AH-03 the call ended', lambda: idle(*ROLES), 30)

        # MV-AH-04 TS 24.281 clause 22.3.2.1.1: client-d may not make ad hoc group calls (warning 185).
        refused(
            'client-d',
            f"mcvideo-adhoc {ids['client-a']}",
            403,
            '185',
            'MV-AH-04 client-d\'s ad hoc group call is refused with 403 and warning 185',
        )

        # MV-AH-06 TS 24.281 clause 12.1A.1.1 and clause 12.1A.1.2: client-a raises an ad hoc group
        # emergency alert to the users affiliated to the group. The server answers with the alert's ad
        # hoc group, confirms receipt to client-a (clause 12.1A.3.1 step 3e) and tells the others; the
        # cancellation ends it. client-b is refused with 403 (clause 12.1A.3.1 step 3a).
        command('client-a', f'mcvideo-adhoc-alert affiliated:{group}')
        wait(
            'MV-AH-06 client-a\'s ad hoc group emergency alert is accepted and confirmed',
            lambda: (
                status('client-a').get('mcvideo_adhoc_alert_state') == 3
                and (status('client-a').get('mcvideo_adhoc_alert_result') or {}).get('status') == 200
                and bool(status('client-a').get('mcvideo_adhoc_alert_group'))
            ),
        )
        alert_group = status('client-a').get('mcvideo_adhoc_alert_group')
        observations['adhoc_alert_group'] = alert_group
        wait(
            'MV-AH-06 the other members receive the alert from client-a with its ad hoc group',
            lambda: all(
                ((status(role).get('mcvideo_received_adhoc_alerts') or {}).get(alert_group) or {}).get('initiator')
                == ids['client-a']
                for role in ('client-b', 'client-c', 'client-d')
            ),
        )
        command('client-a', 'mcvideo-adhoc-alert cancel')
        wait(
            'MV-AH-06 the cancellation clears the alert everywhere',
            lambda: (
                status('client-a').get('mcvideo_adhoc_alert_state') == 1
                and all(
                    alert_group not in (status(role).get('mcvideo_received_adhoc_alerts') or {})
                    for role in ('client-b', 'client-c', 'client-d')
                )
            ),
        )
        command('client-b', f'mcvideo-adhoc-alert affiliated:{group}')
        wait(
            'MV-AH-06 client-b, without <allow-activate-adhoc-group-emergency-alert>, is refused with 403',
            lambda: (
                (status('client-b').get('mcvideo_adhoc_alert_result') or {}).get('status') == 403
                and status('client-b').get('mcvideo_adhoc_alert_state') == 1
            ),
        )

        # MV-AH-05 on the wire: <call-participants-criteria> as in TS 24.281 annex F.1.
        # The capture streams its packets through docker; let the last ones reach the file.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:mcvideo@')]
            adhoc = [message for message in invites if '<session-type>adhoc</session-type>' in message]
            check('MV-AH-05 ad hoc INVITEs to the MCVideo PSI', len(adhoc) >= 2, len(adhoc))
            check(
                'MV-AH-05 the called MCVideo IDs in a resource-lists body',
                any(
                    'application/resource-lists+xml' in message
                    and ids['client-b'] in message
                    and ids['client-c'] in message
                    for message in adhoc
                ),
            )
            check(
                'MV-AH-05 the criteria in <call-participants-criteria> (TS 24.281 F.1, without the MCPTT "s")',
                any(
                    f'<call-participants-criteria>affiliated:{group}</call-participants-criteria>' in message
                    for message in adhoc
                ),
            )
            answers = [
                message
                for message in capture.split(sip)
                if message.startswith('SIP/2.0 200') and '<session-type>adhoc' in message
            ]
            check(
                'MV-AH-05 the 200 (OK) names the ad hoc group in <mcvideo-calling-group-id>',
                any(
                    f'<mcvideo-calling-group-id type="Normal"><mcvideoURI>{adhoc_group}</mcvideoURI>' in message
                    for message in answers
                ),
            )
            messages = [message for message in capture.split(sip) if message.startswith('MESSAGE sip:')]
            check(
                'MV-AH-06 the alert carries <adhoc-alert-ind>true, the criteria and an MCVideo location body',
                any(
                    '<adhoc-alert-ind>true</adhoc-alert-ind>' in message
                    and f'affiliated:{group}' in message
                    and 'application/vnd.3gpp.mcvideo-location-info+xml' in message
                    for message in messages
                ),
            )
            check(
                'MV-AH-06 client-a is sent <adhoc-alert-ind-rcvd>true',
                any('<adhoc-alert-ind-rcvd>true</adhoc-alert-ind-rcvd>' in message for message in messages),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-adhoc-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
