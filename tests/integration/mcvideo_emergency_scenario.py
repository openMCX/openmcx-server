#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo emergency and imminent peril calls and emergency alerts (TS 24.281 clause 4.6): an
emergency group call (clause 6.2.8.1.1, clause 9.2.1.2.1.1) and its cancellation (clause 6.2.8.1.3,
clause 9.2.1.2.1.4), an unauthorised upgrade (clause 6.3.2.1.6.1), imminent peril (clause 6.2.8.1.9,
clause 6.2.8.1.11), pre-emption of a normal transmission (clause 4.6.1), an emergency private call
(clause 6.2.8.3.2, clause 10.2.2) and an emergency alert with its cancellation (clause 11.2.1.1,
clause 11.2.1.2).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): on group operations client-a and client-b may raise
and cancel emergency and imminent peril and emergency alerts (only client-a cancels
alerts); client-c may not; client-a may make emergency private calls. Check IDs match
tests/mcvideo/MCVIDEO_EMERGENCY_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19).
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
    result = dict(scenario='mcvideo-emergency', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-emergency.pcap'
    capture_name = f'{args.project}-mcvideo-emergency-capture'

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
            'mcvideo_priority',
            'mcvideo_transmitting',
            'mcvideo_revocations',
            'mcvideo_priority_result',
            'mcvideo_alerts',
            'mcvideo_alerting',
            'mcvideo_last_call',
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
    def priority(role):
        """The client's MCVideo priority state of its call: normal, emergency or imminent."""
        return status(role).get('mcvideo_priority')

    # ------------------------------------------------------------------------------
    def result_of(role, action, enabled):
        """The client's last priority request outcome if it was the given action (emergency or imminent) set on or off,
        else None.
        """
        outcome = status(role).get('mcvideo_priority_result') or {}
        return outcome if outcome.get('action') == action and outcome.get('enabled') == enabled else None

    # ------------------------------------------------------------------------------
    def idle(*roles):
        """Whether every given client has no MCVideo call."""
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

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
                    'openmcx-dev:0.3',
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

    try:
        wait(
            'four clients MCVideo authorised and affiliated',
            lambda: all(status(role).get('mcvideo_affiliated') for role in ROLES),
            90,
        )
        start_capture()
        # MV-EM-01 TS 24.281 clause 6.2.8.1.1 and clause 9.2.1.2.1.1: client-a calls operations as an emergency group
        # call; every member joins the call in the emergency state.
        command('client-a', 'mcvideo-call emergency')
        wait(
            'MV-EM-01 all four in the call',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        wait(
            'MV-EM-01 every member knows the call is an emergency',
            lambda: all(priority(role) == 'emergency' for role in ROLES),
        )
        # MV-EM-02 TS 24.281 clause 9.2.1.2.1.4 and clause 6.2.8.1.3: client-a cancels the in-progress
        # emergency; all return to normal.
        command('client-a', 'mcvideo-emergency off')
        wait(
            'MV-EM-02 cancellation accepted',
            lambda: (result_of('client-a', 'emergency', False) or {}).get('status') == 200,
        )
        wait('MV-EM-02 every member back to normal', lambda: all(priority(role) == 'normal' for role in ROLES))
        # MV-EM-03 TS 24.281 clause 6.3.2.1.6.1: client-c may not raise an emergency on operations.
        command('client-c', 'mcvideo-emergency on')
        wait('MV-EM-03 client-c answered', lambda: result_of('client-c', 'emergency', True))
        refused = result_of('client-c', 'emergency', True)
        observations['unauthorised_emergency'] = refused
        check(
            'MV-EM-03 client-c refused as not authorised, not for a malformed request',
            refused['status'] == 403 and '"150 ' not in refused['warning'],
            refused,
        )
        check('MV-EM-03 the call stays normal', all(priority(role) == 'normal' for role in ROLES))
        # MV-EM-04 TS 24.281 clause 6.2.8.1.9 and clause 6.2.8.1.11: client-b raises imminent peril,
        # then ends it.
        command('client-b', 'mcvideo-imminent on')
        wait('MV-EM-04 every member in imminent peril', lambda: all(priority(role) == 'imminent' for role in ROLES))
        command('client-b', 'mcvideo-imminent off')
        wait('MV-EM-04 every member back to normal', lambda: all(priority(role) == 'normal' for role in ROLES))
        # MV-EM-05 TS 24.281 clause 4.6.1: an emergency pre-empts a normal transmission. client-c
        # transmits; client-a raises the emergency and asks to transmit; client-c is revoked.
        command('client-c', 'mcvideo-transmit')
        wait('MV-EM-05 client-c transmits', lambda: status('client-c').get('mcvideo_transmitting') is True)
        command('client-a', 'mcvideo-emergency on')
        wait('MV-EM-05 the call is an emergency again', lambda: all(priority(role) == 'emergency' for role in ROLES))
        command('client-a', 'mcvideo-transmit')
        wait('MV-EM-05 client-a granted over client-c', lambda: status('client-a').get('mcvideo_transmitting') is True)
        check(
            'MV-EM-05 client-c revoked',
            status('client-c').get('mcvideo_revocations', 0) >= 1
            and status('client-c').get('mcvideo_transmitting') is False,
            {
                key: status('client-c').get(key)
                for key in ('mcvideo_revocations', 'mcvideo_transmitting', 'mcvideo_reject_cause')
            },
        )
        command('client-a', 'mcvideo-end')
        command('client-a', 'mcvideo-emergency off')
        wait('MV-EM-05 back to normal', lambda: all(priority(role) == 'normal' for role in ROLES))
        for role in ROLES:
            command(role, 'mcvideo-hangup')
        wait('MV-EM-05 all left the call', lambda: idle(*ROLES))
        # MV-EM-06 TS 24.281 clause 6.2.8.3.2: client-a makes an emergency private call to client-b.
        command('client-a', f"mcvideo-private {ids['client-b']} auto emergency")
        wait(
            'MV-EM-06 emergency private call established',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b')),
        )
        wait(
            'MV-EM-06 both in the emergency state',
            lambda: all(priority(role) == 'emergency' for role in ('client-a', 'client-b')),
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-EM-06 the call ended', lambda: idle('client-a', 'client-b'))
        # MV-EM-07 TS 24.281 clause 11.2.1.1 and clause 11.2.1.2: client-a's emergency alert reaches the
        # other affiliated members with its location; its cancellation withdraws it.
        command('client-a', 'mcvideo-alert on')
        wait('MV-EM-07 alert accepted', lambda: status('client-a').get('mcvideo_alerting') is True)
        wait(
            'MV-EM-07 the others received the alert with a location',
            lambda: all(
                ((status(role).get('mcvideo_alerts') or {}).get(ids['client-a']) or {}).get('location')
                for role in ('client-b', 'client-c', 'client-d')
            ),
        )
        observations['alert'] = (status('client-b').get('mcvideo_alerts') or {}).get(ids['client-a'])
        command('client-a', 'mcvideo-alert off')
        wait('MV-EM-07 alert cancelled', lambda: status('client-a').get('mcvideo_alerting') is False)
        wait(
            'MV-EM-07 the others see it withdrawn',
            lambda: all(
                ids['client-a'] not in (status(role).get('mcvideo_alerts') or {})
                for role in ('client-b', 'client-c', 'client-d')
            ),
        )
        time.sleep(1)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        # MV-EM-08 the wire: the Resource-Priority of TS 24.281 clause 6.2.8.1.2 and clause 6.2.8.1.12, in
        # the MCPTT namespace of RFC 8101 (clause 6.2.8.1.16).
        if sip_on_wire:
            sip = sip_text()
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:mcvideo@')]
            check(
                'MV-EM-08 emergency INVITE with emergency-ind and Resource-Priority',
                any('Resource-Priority: mcpttp.15' in message and '<emergency-ind' in message for message in invites),
            )
            check('MV-EM-08 imminent peril with its Resource-Priority', 'Resource-Priority: mcpttp.10' in sip)
            messages = [message for message in capture.split(sip) if message.startswith('MESSAGE sip:')]
            check(
                'MV-EM-08 alert MESSAGE with the MCVideo location body',
                any(
                    'application/vnd.3gpp.mcvideo-location-info+xml' in message
                    and 'urn:3gpp:ns:mcvideoLocationInfo:1.0' in message
                    for message in messages
                ),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except AssertionError as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-emergency-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
