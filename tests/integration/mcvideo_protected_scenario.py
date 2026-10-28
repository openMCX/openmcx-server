#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Protected MCVideo group calls (media security, TS 24.281 clause 4.7.1; TS 33.180 with the
MCVideo CS-IDs of TS 33.180 table E.1.3-1): each client's CSK uploaded at MCVideo service authorisation,
the group's GMK through the GKTP subscription to the MCVideo server, transmission
control as SRTCP under the CSK, and H.264 video as SRTP under the GMK, relayed unchanged
by the server and decoded at every receiver picture by picture.

Run against a fixture prepared with --mcvideo --protected. Check IDs match
tests/mcvideo/MCVIDEO_PROTECTED_TEST.md. Private and ambient viewing calls
(V9f) are protected with a PCK in a=key-mgmt: the private call of TS 24.281 clauses 10.2.2.2.1
and 10.2.3 and the remotely initiated ambient viewing call of TS 24.281 clause 15.2.1.1, keyed
as in TS 33.180 clause 7.4.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import time

import capture

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
# Run the scenario against the lab and write integration/mcvideo-protected-results.json; return 0 when every check
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
    result = dict(scenario='mcvideo-protected', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json a role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The call and key state of every client, for a timed-out check's message.
    def snapshot():
        keys = (
            'mcvideo_call_state',
            'mcvideo_transmitting',
            'mcvideo_transmitter',
            'mcvideo_frames_sent',
            'mcvideo_frames_received',
            'mcvideo_undecoded',
            'mcvideo_last_call',
            'mcvideo_csk_id',
            'mcvideo_group_key_id',
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

    capture_file = args.artifacts / 'integration/mcvideo-protected.pcap'
    capture_name = f'{args.project}-mcvideo-protected-capture'

    # ------------------------------------------------------------------------------
    # Capture the traffic of mcvideo-server (tcpdump in its network namespace) until the capture container is stopped.
    def start_capture():
        # tools/test-lab's capture, in mcvideo-server's network namespace: its SIP,
        # transmission control and video.
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
                    '(udp and not port 53) or tcp port 5060 or tcp port 5061',
                ],
                stdout=out,
                stderr=err,
            )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and b'listening on' not in log.read_bytes():
            time.sleep(0.1)

    # ------------------------------------------------------------------------------
    # Stop the capture container (no error if it is already gone).
    def stop_capture():
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)

    # ------------------------------------------------------------------------------
    # Read the finished capture.
    def wire():
        """The UDP payloads and the SIP text of the capture (pcap of Ethernet, IPv4)."""
        return capture.read(capture_file)

    # ------------------------------------------------------------------------------
    # Compare the frames receiver decoded with those sender encoded.
    def matching(sender, receiver):
        """Pictures the receiver decoded, and how many equal the sender's for the same timestamp."""
        sent = status(sender).get('mcvideo_sent_frames') or {}
        received = status(receiver).get('mcvideo_received_frames') or {}
        common = [ts for ts in received if ts in sent]
        return len(received), sum(1 for ts in common if sent[ts] == received[ts]), len(common)

    # ------------------------------------------------------------------------------
    # The status.json of mcvideo-server, or {} while it is missing or half written.
    def server_status():
        try:
            return json.loads((args.artifacts / 'mcvideo-server' / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    try:
        # MV-SE-01 TS 24.281 clause 4.7 with clause 7.2.5: the CSK went with the MCVideo service authorisation, and
        # the GMK arrived through the GKTP subscription to the MCVideo server.
        wait(
            'MV-SE-01 four clients MCVideo authorised and affiliated, each with its own CSK and the group GMK',
            lambda: all(
                status(role).get('mcvideo_affiliated')
                and status(role).get('mcvideo_csk_id')
                and status(role).get('mcvideo_group_key_id')
                for role in ROLES
            ),
            120,
        )
        csks = {role: status(role)['mcvideo_csk_id'] for role in ROLES}
        check(
            'MV-SE-01 the MCVideo CSKs carry purpose tag 2 and differ from the MCPTT CSKs',
            all(csks[role] >> 28 == 2 and csks[role] != status(role).get('csk_id') for role in ROLES),
            csks,
        )
        check(
            'MV-SE-01 every member holds the same GMK',
            len({status(role)['mcvideo_group_key_id'] for role in ROLES}) == 1
            and status('client-a')['mcvideo_group_key_id'] >> 28 == 0,
        )
        start_capture()

        # MV-SE-02 TS 24.281 clause 4.7.1: a protected group call; transmission control and video are keyed.
        command('client-a', 'mcvideo-call')
        wait(
            'MV-SE-02 all four in the protected MCVideo group call',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        command('client-a', 'mcvideo-transmit')
        wait(
            'MV-SE-02 client-a is granted over protected transmission control',
            lambda: status('client-a').get('mcvideo_transmitting') is True,
        )
        wait(
            'MV-SE-02 the others learn client-a transmits',
            lambda: all(
                status(role).get('mcvideo_transmitter') == ids['client-a'] for role in ('client-b', 'client-c')
            ),
        )
        wait(
            'MV-SE-02 client-b and client-c decode client-a\'s protected video',
            lambda: all(status(role).get('mcvideo_frames_received', 0) >= 15 for role in ('client-b', 'client-c')),
            40,
        )
        for role in ('client-b', 'client-c'):
            received, equal, common = matching('client-a', role)
            observations[f'{role}_from_a'] = dict(received=received, equal=equal, compared=common)
            check(
                f'MV-SE-02 {role}\'s pictures equal client-a\'s',
                common >= 10 and equal == common,
                observations[f'{role}_from_a'],
            )
        command('client-a', 'mcvideo-end')
        wait('MV-SE-02 client-a releases', lambda: status('client-a').get('mcvideo_transmitting') is False)

        # MV-SE-03: a second sender under the same GMK, keyed by its own identity (GUK-ID).
        command('client-b', 'mcvideo-transmit')
        wait('MV-SE-03 client-b is granted', lambda: status('client-b').get('mcvideo_transmitting') is True)
        before = status('client-c').get('mcvideo_frames_received', 0)
        wait(
            'MV-SE-03 client-c decodes client-b\'s protected video',
            lambda: status('client-c').get('mcvideo_frames_received', 0) >= before + 15,
            40,
        )
        received, equal, common = matching('client-b', 'client-c')
        check(
            'MV-SE-03 client-c\'s pictures of client-b equal client-b\'s',
            common >= 10 and equal == common,
            dict(received=received, equal=equal, compared=common),
        )
        command('client-b', 'mcvideo-end')
        for role in ROLES:
            if status(role).get('mcvideo_call_state') not in (None, 'idle'):
                command(role, 'mcvideo-hangup')
        wait(
            'MV-SE-03 the call ended',
            lambda: all(status(role).get('mcvideo_call_state') == 'idle' for role in ROLES),
            30,
        )
        log = subprocess.run(cli + ['logs', 'mcvideo-server'], capture_output=True, text=True).stdout
        check(
            'MV-SE-04 the server ended no leg for missing or failed keys',
            '"protected_leg_ended"' not in log and '"transmission_control_sent"' in log,
        )
        observations['video_forwarded'] = server_status().get('video_forwarded')

        # ------------------------------------------------------------------------------
        # True when every given role has no MCVideo call.
        def idle(*roles):
            return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

        # ------------------------------------------------------------------------------
        # The key identifier of the PCK of role's current private or ambient viewing call (TS 33.180 clause 7.4).
        def pck(role):
            return status(role).get('mcvideo_private_key_id')

        # MV-SE-06 TS 24.281 clause 10.2.2.2.1 with TS 33.180 clause 7.4: a protected private call
        # with transmission control. client-a's PCK for client-b goes in a=key-mgmt; both select it (purpose
        # tag 1), and client-b decodes client-a's video under it.
        command('client-a', f"mcvideo-private {ids['client-b']} auto")
        wait(
            'MV-SE-06 client-a and client-b are in a protected private call sharing one PCK',
            lambda: (
                all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b'))
                and pck('client-a')
                and pck('client-a') == pck('client-b')
                and pck('client-a') >> 28 == 1
            ),
        )
        command('client-a', 'mcvideo-transmit')
        wait('MV-SE-06 client-a is granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        wait(
            'MV-SE-06 client-b decodes client-a\'s video',
            lambda: status('client-b').get('mcvideo_frames_received', 0) >= 15,
            40,
        )
        received, equal, common = matching('client-a', 'client-b')
        observations['private_b_from_a'] = dict(received=received, equal=equal, compared=common)
        check(
            'MV-SE-06 client-b\'s pictures equal client-a\'s',
            common >= 10 and equal == common,
            observations['private_b_from_a'],
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-SE-06 the call ended', lambda: idle('client-a', 'client-b'), 30)

        # MV-SE-07 TS 24.281 clause 10.2.3: without transmission control, both parties send under the PCK,
        # with the initiator's and the receiver's crypto sessions (CS-IDs 2 and 3 of TS 33.180 table E.1.3-1).
        first = pck('client-a')
        command('client-a', f"mcvideo-private {ids['client-b']} auto no-control")
        wait(
            'MV-SE-07 a new PCK for the new protected call',
            lambda: (
                all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b'))
                and pck('client-a') == pck('client-b')
                and pck('client-a') != first
            ),
        )
        wait(
            'MV-SE-07 each decodes the other',
            lambda: all(status(role).get('mcvideo_frames_received', 0) >= 15 for role in ('client-a', 'client-b')),
            40,
        )
        for sender, receiver in (('client-a', 'client-b'), ('client-b', 'client-a')):
            received, equal, common = matching(sender, receiver)
            observations[f'open_{receiver}_from_{sender}'] = dict(received=received, equal=equal, compared=common)
            check(
                f'MV-SE-07 {receiver}\'s pictures equal {sender}\'s',
                common >= 10 and equal == common,
                observations[f'open_{receiver}_from_{sender}'],
            )
        command('client-a', 'mcvideo-hangup')
        wait('MV-SE-07 the call ended', lambda: idle('client-a', 'client-b'), 30)

        # MV-SE-08 TS 24.281 clause 15.2.1.1: a protected remotely initiated ambient viewing call; client-a's
        # PCK reaches client-b through the server, and client-a decodes client-b's video.
        second = pck('client-a')
        command('client-a', f"mcvideo-ambient {ids['client-b']} remote")
        wait(
            'MV-SE-08 client-a views client-b under a new PCK both hold',
            lambda: (
                all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b'))
                and pck('client-a') == pck('client-b')
                and pck('client-a') not in (first, second)
            ),
        )
        wait(
            'MV-SE-08 client-a decodes client-b', lambda: status('client-a').get('mcvideo_frames_received', 0) >= 15, 40
        )
        received, equal, common = matching('client-b', 'client-a')
        observations['ambient_a_from_b'] = dict(received=received, equal=equal, compared=common)
        check(
            'MV-SE-08 client-a\'s pictures equal client-b\'s',
            common >= 10 and equal == common,
            observations['ambient_a_from_b'],
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-SE-08 the call ended', lambda: idle('client-a', 'client-b'), 30)

        # MV-SE-05 on the wire: SRTP and SRTCP, no clear transmission control.
        time.sleep(3)
        stop_capture()
        packets, sip = wire()
        control = [
            packet for src, dst, packet in packets if len(packet) >= 12 and packet[0] >> 6 == 2 and packet[1] == 204
        ]
        observations['control_packets'] = len(control)
        check('MV-SE-05 transmission control crossed the wire', len(control) >= 8, len(control))
        check(
            'MV-SE-05 no transmission control message is readable: the MCV name is encrypted by SRTCP',
            not any(packet[8:12] in (b'MCV0', b'MCV1', b'MCV2') for packet in control),
        )
        check(
            'MV-SE-05 each SRTCP packet carries the E-flag and index word and the 4-byte MKI after the 16-byte tag',
            all(len(packet) >= 12 + 4 + 16 + 4 for packet in control),
        )
        if sip_on_wire:
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:')]
            check(
                'MV-SE-05 the offers carry the video and audio as RTP/SAVP',
                any(
                    re.search(r'm=video \d+ RTP/SAVP', message) and re.search(r'm=audio \d+ RTP/SAVP', message)
                    for message in invites
                ),
            )
            check(
                'MV-SE-09 the private and ambient offers carry the PCK in a=key-mgmt:mikey',
                sum(
                    1
                    for message in invites
                    if 'a=key-mgmt:mikey' in message
                    and '<session-type>' in message
                    and ('private' in message or 'ambient-viewing' in message)
                )
                >= 3,
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        stop_capture()
    output = args.artifacts / 'integration/mcvideo-protected-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
