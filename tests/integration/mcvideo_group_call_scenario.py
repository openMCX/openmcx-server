#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""An MCVideo prearranged group call carrying video end to end (TS 24.281 clause 9.2.1), with
transmission control (TS 24.581 clause 6.2 and clause 6.3) and H.264 video (TS 26.281 clause 4).

Run against a fixture prepared with --mcvideo: the four clients are MCVideo members
of group operations. client-a calls the group; the controlling MCVideo function
invites the other affiliated members. client-a requests the permission to
transmit, sends its H.264 test pattern, and every other member decodes what the
media distribution function relays; each decoded picture must equal the sender's
own reconstruction of the same RTP timestamp. Then client-b takes over. Check IDs
match tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 26.281 V19.0.0 (Rel-19),
TS 24.484 V19.6.0 (Rel-19).
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
# TS 24.581 clause 9.1.3: application specific data fields from this field ID on have a two-octet length.
LONG_FIELD_ID = 192


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
    result = dict(scenario='mcvideo-group-call', passed=False, checks=checks, observations=observations)

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
            'mcvideo_transmitting',
            'mcvideo_transmitter',
            'mcvideo_frames_sent',
            'mcvideo_frames_received',
            'mcvideo_undecoded',
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

    capture_file = args.artifacts / 'integration/mcvideo-group-call.pcap'
    capture_name = f'{args.project}-mcvideo-capture'

    # ------------------------------------------------------------------------------
    def start_capture():
        """tools/test-lab's capture, in mcvideo-server's network namespace (its SIP, transmission control and
        video); return once tcpdump listens.
        """
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
                    'openmcx-dev:0.2',
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
    def stop_capture():
        """Stop the capture container."""
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)

    # ------------------------------------------------------------------------------
    def wire():
        """The UDP payloads and the SIP text of the capture (pcap of Ethernet, IPv4)."""
        return capture.read(capture_file)

    # ------------------------------------------------------------------------------
    def matching(sender, receiver):
        """Pictures the receiver decoded, and how many equal the sender's for the same timestamp."""
        sent = status(sender).get('mcvideo_sent_frames') or {}
        received = status(receiver).get('mcvideo_received_frames') or {}
        common = [ts for ts in received if ts in sent]
        return len(received), sum(1 for ts in common if sent[ts] == received[ts]), len(common)

    try:
        wait(
            'four clients MCVideo authorised and affiliated',
            lambda: all(status(role).get('mcvideo_affiliated') for role in ROLES),
            90,
        )
        # MV-GC-14 (TS 24.484 clause 9.3 and clause 9.3.1A): each client read its MCVideo user profile,
        # which the CMS builds from its "mcvideo" record: its MCVideo ID, the group, and
        # its rights (client-a may call privately and modify ad hoc calls, client-d may not).
        profiles = {role: status(role).get('mcvideo_profile') or {} for role in ROLES}
        observations['mvgc14_profiles'] = profiles
        group = json.loads((generated / 'client-a.json').read_text())['mcvideo']['group_id']
        check(
            'MV-GC-14 each client read its MCVideo user profile: its MCVideo ID and the group',
            all(
                profiles[role].get('user_id') == ids[role] and group in (profiles[role].get('groups') or [])
                for role in ROLES
            ),
        )
        actions = {role: set(profiles[role].get('actions') or []) for role in ROLES}
        check(
            'MV-GC-14 the profiles carry the configured rights',
            {
                'allow-private-call',
                'allow-emergency-private-call',
                'allow-to-modify-adhoc-group-call-participants-info',
                'allow-request-remote-initiated-ambient-viewing',
                'allow-regroup',
                'allow-video-push-to-server',
            }
            <= actions['client-a']
            and 'allow-private-call' not in actions['client-d']
            and 'allow-regroup' not in actions['client-b']
            and ids['client-c'] in (profiles['client-a'].get('private_call_targets') or []),
        )
        start_capture()
        # MV-GC-01 TS 24.281 clause 9.2.1.2.1.1 and clause 9.2.1.4.1.1: client-a calls the group;
        # every affiliated member joins.
        command('client-a', 'mcvideo-call')
        wait(
            'MV-GC-01 all four in the MCVideo group call',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        check('MV-GC-01 MCPTT stays idle', all(status(role).get('call_state') == 'idle' for role in ROLES))
        # MV-GC-12 TS 24.281 clause 9.2.3: each member subscribes to the session's conference events and
        # sees the four MCVideo IDs connected.
        wait(
            'MV-GC-12 every member sees the four participants',
            lambda: all(
                set((status(role).get('mcvideo_participants') or {}).keys()) == set(ids.values())
                and set((status(role).get('mcvideo_participants') or {}).values()) == {'connected'}
                for role in ROLES
            ),
        )
        check(
            'MV-GC-12 the session URI is the MCVideo PSI with a session parameter',
            all(
                (status(role).get('mcvideo_session_uri') or '').startswith(('sip:mcvideo@', 'sips:mcvideo@'))
                for role in ROLES
            ),
            {role: status(role).get('mcvideo_session_uri') for role in ROLES},
        )
        # MV-GC-02 TS 24.581 clause 6.2.4 and clause 6.3.4: a Transmission Request is granted; the
        # others learn from the Media Transmission Notification who transmits (clauses 6.3.4.4.2 step 3, 6.3.6.3.3).
        command('client-a', 'mcvideo-transmit')
        wait('MV-GC-02 client-a granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        wait(
            'MV-GC-02 the others see client-a transmitting',
            lambda: all(status(role).get('mcvideo_transmitter') == ids['client-a'] for role in ROLES[1:]),
        )
        # MV-GC-13 TS 24.581 clauses 6.3.6.3.3 step 1b and 6.3.7.3.3: in an ordinary group call the Media
        # Transmission Notification to every other member says manual reception (Reception Mode '1'); they
        # accept with Receive Media Request, except client-d, which receives nothing until it accepts by hand.
        wait(
            'MV-GC-13 every other member notified of the transmission',
            lambda: all(status(role).get('mcvideo_reception_notifications', 0) >= 1 for role in ROLES[1:]),
        )
        check(
            'MV-GC-13 client-d receives nothing before accepting',
            holds(
                lambda: (
                    status('client-d').get('mcvideo_receiving') is False
                    and status('client-d').get('mcvideo_frames_received', 0) == 0
                ),
                1.5,
            ),
            {key: status('client-d').get(key) for key in ('mcvideo_receiving', 'mcvideo_frames_received')},
        )
        command('client-d', 'mcvideo-receive')
        wait('MV-GC-13 client-d accepted', lambda: status('client-d').get('mcvideo_receiving') is True)
        # MV-GC-03 TS 26.281 clause 4 with RFC 6184: the relayed video decodes at every receiver
        # and equals what client-a encoded.
        wait(
            'MV-GC-03 each receiver decoded 30 pictures',
            lambda: all(status(role).get('mcvideo_frames_received', 0) >= 30 for role in ROLES[1:]),
            40,
        )
        for receiver in ROLES[1:]:
            received, equal, common = matching('client-a', receiver)
            observations[f'{receiver}_from_a'] = dict(received=received, compared=common, equal=equal)
            check(
                f'MV-GC-03 {receiver} pictures equal the sender\'s',
                common >= 25 and equal == common,
                observations[f'{receiver}_from_a'],
            )
        check(
            'MV-GC-03 the transmitter does not receive its own video',
            status('client-a').get('mcvideo_frames_received', 0) == 0,
            status('client-a').get('mcvideo_frames_received'),
        )
        forwarded = status('mcvideo-server').get('video_forwarded', 0)
        observations['video_forwarded'] = forwarded
        check('MV-GC-03 the MCVideo server relayed the video', forwarded > 0, forwarded)
        # MV-GC-13 a member stops receiving (Media Reception End Request) and resumes.
        command('client-b', 'mcvideo-stop-receiving')
        wait('MV-GC-13 client-b stopped receiving', lambda: status('client-b').get('mcvideo_receiving') is False)
        stopped = status('client-b').get('mcvideo_frames_received', 0)
        check(
            'MV-GC-13 no video relayed to client-b meanwhile',
            holds(lambda: status('client-b').get('mcvideo_frames_received', 0) <= stopped + 1, 1.5),
            (stopped, status('client-b').get('mcvideo_frames_received')),
        )
        command('client-b', 'mcvideo-receive')
        wait(
            'MV-GC-13 client-b receives again',
            lambda: status('client-b').get('mcvideo_frames_received', 0) >= stopped + 10,
        )
        # MV-GC-04 TS 24.581 clause 9.2.20: client-a ends its transmission (Transmission End Request); then
        # client-b is granted and client-a receives.
        command('client-a', 'mcvideo-end')
        wait('MV-GC-04 client-a no longer transmits', lambda: status('client-a').get('mcvideo_transmitting') is False)
        command('client-b', 'mcvideo-transmit')
        wait('MV-GC-04 client-b granted', lambda: status('client-b').get('mcvideo_transmitting') is True)
        wait(
            'MV-GC-04 client-d notified of client-b\'s transmission',
            lambda: status('client-d').get('mcvideo_reception_notifications', 0) >= 2,
        )
        command('client-d', 'mcvideo-receive')
        before = {role: status(role).get('mcvideo_frames_received', 0) for role in ('client-c', 'client-d')}
        wait(
            'MV-GC-04 every other member decodes client-b\'s video',
            lambda: (
                status('client-a').get('mcvideo_frames_received', 0) >= 20
                and all(status(role).get('mcvideo_frames_received', 0) >= before[role] + 20 for role in before)
            ),
            30,
        )
        for receiver in ('client-a', 'client-c', 'client-d'):
            received, equal, common = matching('client-b', receiver)
            observations[f'{receiver}_from_b'] = dict(received=received, compared=common, equal=equal)
            check(
                f'MV-GC-04 {receiver} pictures equal client-b\'s',
                common >= 15 and equal == common,
                observations[f'{receiver}_from_b'],
            )
        check(
            'MV-GC-04 no picture left undecoded at a change of transmitter',
            all(status(role).get('mcvideo_undecoded', 0) == 0 for role in ROLES),
            {role: status(role).get('mcvideo_undecoded') for role in ROLES},
        )
        # MV-GC-05 TS 24.581 clause 6.3.4: while client-b transmits, client-c's request is queued
        # (both sides negotiated mc_queueing) and client-d's, without queueing, rejected
        # with cause 1 (TS 24.581 clause 9.2.6.2).
        command('client-c', 'mcvideo-transmit')
        wait('MV-GC-05 client-c queued at position 1', lambda: status('client-c').get('mcvideo_queue_position') == 1)
        check(
            'MV-GC-05 client-c not granted while client-b transmits',
            status('client-c').get('mcvideo_transmitting') is False
            and status('client-b').get('mcvideo_transmitting') is True,
        )
        command('client-d', 'mcvideo-transmit')
        wait('MV-GC-05 client-d rejected with cause 1', lambda: status('client-d').get('mcvideo_reject_cause') == 1)
        # MV-GC-08 client-b releases; the queued client-c is granted without asking again.
        command('client-b', 'mcvideo-end')
        wait('MV-GC-08 client-c granted from the queue', lambda: status('client-c').get('mcvideo_transmitting') is True)
        granted_at = time.monotonic()
        wait(
            'MV-GC-08 the others see client-c transmitting',
            lambda: all(
                status(role).get('mcvideo_transmitter') == ids['client-c']
                for role in ('client-a', 'client-b', 'client-d')
            ),
        )
        # MV-GC-09 TS 24.581 clause 9.2.10: after the 15 s transmission limit the server revokes
        # (cause 2, clause 9.2.10.2); client-c stops and releases, and nobody transmits.
        wait(
            'MV-GC-09 client-c revoked after the transmission limit',
            lambda: status('client-c').get('mcvideo_revocations', 0) >= 1,
            30,
        )
        observations['revoked_after_s'] = round(time.monotonic() - granted_at, 1)
        check(
            'MV-GC-09 revoked no sooner than the limit',
            observations['revoked_after_s'] >= 14,
            observations['revoked_after_s'],
        )
        check(
            'MV-GC-09 revoke cause 2 (transmitted too long)',
            status('client-c').get('mcvideo_reject_cause') == 2,
            status('client-c').get('mcvideo_reject_cause'),
        )
        wait('MV-GC-09 client-c stopped transmitting', lambda: status('client-c').get('mcvideo_transmitting') is False)
        # MV-GC-06 everyone leaves the call.
        for role in ROLES:
            command(role, 'mcvideo-hangup')
        wait(
            'MV-GC-06 all four left the call',
            lambda: all(status(role).get('mcvideo_call_state') == 'idle' for role in ROLES),
        )
        # MV-GC-10 TS 24.281 clause 6.4: client-d calls with an implicit transmission request
        # (mc_implicit_request); it is granted as the call starts, without a
        # Transmission Request, and the others decode its video.
        command('client-d', 'mcvideo-call implicit')
        wait(
            'MV-GC-10 client-d granted by its implicit request',
            lambda: status('client-d').get('mcvideo_transmitting') is True,
        )
        wait(
            'MV-GC-10 the others decode client-d\'s video',
            lambda: all(
                status(role).get('mcvideo_frames_received', 0) >= 15 for role in ('client-a', 'client-b', 'client-c')
            ),
            30,
        )
        for receiver in ('client-a', 'client-b', 'client-c'):
            received, equal, common = matching('client-d', receiver)
            check(
                f'MV-GC-10 {receiver} pictures equal client-d\'s',
                common >= 10 and equal == common,
                dict(received=received, compared=common, equal=equal),
            )
        for role in ROLES:
            command(role, 'mcvideo-hangup')
        wait(
            'MV-GC-10 all four left the second call',
            lambda: all(status(role).get('mcvideo_call_state') == 'idle' for role in ROLES),
        )
        # MV-GC-11 TS 24.281 clause 9.2.2: a chat group call; members join the session themselves, and
        # a late joiner decodes the video from the next IDR picture.
        chat = f"sip:video-chat@{ids['client-a'].split('@', 1)[1]}"
        command('client-a', f'mcvideo-chat {chat}')
        command('client-b', f'mcvideo-chat {chat}')
        wait(
            'MV-GC-11 client-a and client-b in the chat session',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b')),
        )
        check(
            'MV-GC-11 client-c and client-d not invited to the chat session',
            all(status(role).get('mcvideo_call_state') == 'idle' for role in ('client-c', 'client-d')),
        )
        command('client-a', 'mcvideo-transmit')
        wait(
            'MV-GC-11 client-a granted in the chat session',
            lambda: status('client-a').get('mcvideo_transmitting') is True,
        )
        wait('MV-GC-11 client-b decodes client-a', lambda: status('client-b').get('mcvideo_frames_received', 0) >= 15)
        command('client-c', f'mcvideo-chat {chat}')
        wait(
            'MV-GC-11 late joiner client-c decodes client-a',
            lambda: status('client-c').get('mcvideo_frames_received', 0) >= 10,
            30,
        )
        for receiver in ('client-b', 'client-c'):
            received, equal, common = matching('client-a', receiver)
            check(
                f'MV-GC-11 {receiver} chat pictures equal client-a\'s',
                common >= 8 and equal == common,
                dict(received=received, compared=common, equal=equal),
            )
        for role in ('client-a', 'client-b', 'client-c'):
            command(role, 'mcvideo-hangup')
        wait(
            'MV-GC-11 the chat members left',
            lambda: all(status(role).get('mcvideo_call_state') == 'idle' for role in ROLES),
        )
        time.sleep(1)
        stop_capture()
        # MV-GC-07 the wire, as captured at mcvideo-server.
        packets, sip = wire()
        if sip_on_wire:
            invite = next((message for message in capture.split(sip) if message.startswith('INVITE sip:mcvideo@')), '')
            observations['invite_excerpt'] = invite[:200]
            # A client asks for the service (P-Preferred-Service, TS 24.281 clause 9.2.1.2.1.1 step 6);
            # a participating MCVideo server in front of the controlling one asserts it (clause
            # 6.3.2.1.3 step 6).
            relayed = any(args.artifacts.glob('mcvideo-part-*/status.json'))
            header = 'P-Asserted-Service' if relayed else 'P-Preferred-Service'
            check(
                f'MV-GC-07 INVITE to the MCVideo PSI with the MCVideo ICSI in {header}',
                f'{header}: urn:urn-7:3gpp-service.ims.icsi.mcvideo' in invite,
                invite[:400],
            )
            check('MV-GC-07 a chat join with session-type chat', '<session-type>chat</session-type>' in sip)
            check(
                'MV-GC-07 SUBSCRIBE and NOTIFY of the conference event package',
                'SUBSCRIBE sip:mcvideo@' in sip
                and 'Event: conference' in sip
                and 'application/conference-info+xml' in sip,
            )
            check(
                'MV-GC-07 an offer with mc_implicit_request, accepted in the answer',
                sip.count('mc_implicit_request') >= 2,
                sip.count('mc_implicit_request'),
            )
            check(
                'MV-GC-07 SDP offer with MCVideo audio, H.264 video and transmission control',
                all(
                    fragment in invite
                    for fragment in (
                        's=MCVideo',
                        'm=video',
                        'H264/90000',
                        'packetization-mode=1',
                        'udp MCVideo',
                        'a=fmtp:MCVideo mc_transmission_ssrc=',
                    )
                ),
                invite[-600:],
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        app = [
            (src, dst, bytes(payload[8:12]).decode('latin-1'), payload[0] & 0x0F)
            for src, dst, payload in packets
            if len(payload) >= 12 and payload[0] >> 6 == 2 and payload[1] == 204 and payload[8:11] == b'MCV'
        ]
        kinds = {(name, subtype) for _, _, name, subtype in app}
        observations['transmission_control'] = sorted(f'{name}/{subtype}' for name, subtype in kinds)
        for label, name, subtype in (
            ('Transmission Request', 'MCV0', 0),
            ('Transmission Granted', 'MCV1', 0),
            ('Transmission Rejected', 'MCV1', 1),
            ('Transmission Revoked', 'MCV1', 4),
            ('Queue Position Info', 'MCV1', 5),
            ('Transmission idle', 'MCV1', 15),
            ('Receive Media Request', 'MCV0', 4),
            ('Receive Media Response', 'MCV1', 7),
            ('Media Transmission Notification', 'MCV1', 6),
            ('Transmission End Request', 'MCV2', 0),
            ('Transmission End Response', 'MCV2', 1),
            ('Media Reception End Request', 'MCV2', 2),
            ('Media Reception End Response', 'MCV2', 3),
        ):
            check(
                f'MV-GC-07 {label} ({name}, subtype {subtype}) on the wire',
                (name, subtype) in kinds,
                observations['transmission_control'],
            )
        # TS 24.581 clause 6.2.4.5.3: on-network, a participant ends its transmission with Transmission End Request;
        # Transmission Release (MCV0, subtype 2) is the participating function's and off-network's (clauses 6.5, 7.2).
        check(
            'MV-GC-07 no Transmission Release (MCV0, subtype 2) on-network',
            ('MCV0', 2) not in kinds,
            observations['transmission_control'],
        )
        # TS 24.581 clauses 6.3.4.4.2 step 3, 6.3.6.3.3 and 6.3.7.3.3: on-network, the other members learn of a
        # transmission from the Media Transmission Notification; the server's state machines (clause 6.3) send no
        # Transmission Arbitration Taken (clause 7.2, off-network) and no Media Reception Notification.
        for label, name, subtype in (
            ('Transmission Arbitration Taken', 'MCV1', 2),
            ('Media Reception Notification', 'MCV1', 8),
        ):
            check(
                f'MV-GC-07 no {label} ({name}, subtype {subtype}) on-network',
                (name, subtype) not in kinds,
                observations['transmission_control'],
            )
        granted = [
            payload
            for src, dst, payload in packets
            if len(payload) >= 12 and payload[1] == 204 and payload[8:12] == b'MCV1' and payload[0] & 0x0F == 0
        ]

        # ------------------------------------------------------------------------------
        def field_ids(packet):
            """The field IDs of a transmission control message after its 12-byte RTCP APP header, each field padded to
            32 bits (TS 24.581 clause 9.1.3: a one-octet length below field ID 192, a two-octet one from 192 on).
            """
            ids, offset = [], 12
            while offset + 2 <= len(packet):
                field_id = packet[offset]
                ids.append(field_id)
                if field_id < LONG_FIELD_ID:
                    header, length = 2, packet[offset + 1]
                elif offset + 3 <= len(packet):
                    header, length = 3, int.from_bytes(packet[offset + 1 : offset + 3], 'big')
                else:
                    break
                offset += (header + length + 3) // 4 * 4
            return ids

        observations['granted_fields'] = [field_ids(packet) for packet in granted[:1]]
        check(
            'MV-GC-07 Transmission Granted carries Duration, Audio SSRC, Video SSRC (ID 23) and Priority',
            bool(granted) and all(set(field_ids(packet)) >= {1, 14, 23, 0} for packet in granted),
            observations['granted_fields'],
        )
        video = [
            (src, dst, payload)
            for src, dst, payload in packets
            if len(payload) > 12 and payload[0] >> 6 == 2 and payload[1] & 0x7F == 97
        ]
        nal_types = {payload[12] & 0x1F for _, _, payload in video}
        observations['video_packets'] = len(video)
        observations['nal_types'] = sorted(nal_types)
        # At 240p the test pattern's NAL units fit one packet each; FU-A is unit-tested.
        check(
            'MV-GC-07 H.264 RTP (payload type 97) with SPS, PPS, IDR and P slices',
            len(video) > 100 and {1, 5, 7, 8} <= nal_types,
            observations['nal_types'],
        )
        senders = {src for src, _, _ in video}
        receivers = {dst for _, dst, _ in video}
        observations['video_hosts'] = dict(senders=len(senders), receivers=len(receivers))
        # With participating MCVideo servers (TS 24.281 clause 6.3.2), the controlling server
        # exchanges video with them, and each relays it to and from its own clients.
        parts = sorted(path.name for path in args.artifacts.glob('mcvideo-part-*') if (path / 'status.json').exists())
        if parts:
            observations['relayed_video'] = {part: status(part).get('relay_video_forwarded', 0) for part in parts}
            check(
                'MV-GC-07 video exchanged between the controlling server and each participating server',
                len(senders) >= len(parts) + 1 and len(receivers) >= len(parts) + 1,
                observations['video_hosts'],
            )
            check(
                'MV-GC-07 each participating server relayed video (TS 24.581 6.4.3)',
                all(count > 0 for count in observations['relayed_video'].values()),
                observations['relayed_video'],
            )
        else:
            check(
                'MV-GC-07 video sent by the granted clients and relayed to the others',
                len(senders) >= 3 and len(receivers) >= 4,
                observations['video_hosts'],
            )
        observations['undecoded'] = {
            role: (status(role).get('mcvideo_last_call') or {}).get('undecoded') for role in ROLES
        }
        result['passed'] = True
    except AssertionError as error:
        result['error'] = str(error)
    output = args.artifacts / 'integration/mcvideo-group-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
