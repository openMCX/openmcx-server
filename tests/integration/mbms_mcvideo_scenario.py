#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MBMS delivery of an MCVideo group call's video over a pre-activated MBMS bearer (TS 24.281 clause 16, TS 24.581
clauses 4.1.2 and 10; the BM-SC and the radio are emulated on the lab network).

Run against a fixture prepared with --mcvideo --multicast: the MCVideo server announces its bearer (TMGI
00000299f907) to the four MCVideo users (TS 24.281 clause 16.3.2); client-a to client-c, in its service area, listen
to its general purpose subchannel, client-d is outside. In one prearranged MCVideo group call:

1. client-a transmits: the granted transmission maps the conversation to the bearer's first subchannel (Map Group To
   Bearer, "MCV3", TS 24.581 clause 10.2.2.2); client-b and client-c join its video port and report "listening" for
   the session (TS 24.281 clause 16.2.3), and decode the video from the subchannel; each decoded picture equals the
   sender's own reconstruction. client-d (manual reception) accepts and receives by unicast.
2. client-c's radio conditions turn bad: it reports "not-listening" and keeps decoding by unicast; good again, it
   rejoins on the next Map Group To Bearer.
3. The call is released: Unmap Group To Bearer; every client has left the subchannel.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 26.281 V19.0.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
LISTENERS = ['client-b', 'client-c']
# The MCVideo bearer of tools/prepare-prearranged-test.py (MBMS_VIDEO_BEARER) and the first subchannel of its pool.
TMGI = '00000299f907'
SUBCHANNEL = '239.10.0.4:40006'


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab and write its results JSON; exit status 0 when every check passed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-prearranged')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
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
        """Record label once predicate() holds; fail with the relevant status on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                return
            time.sleep(0.1)
        raise AssertionError(label + ': ' + json.dumps({role: status(role) for role in ROLES + ['mcvideo-server']}))

    # ------------------------------------------------------------------------------
    def bearer(role):
        """The client's view of the MCVideo bearer, or {}."""
        return status(role).get('mbms_bearers', {}).get(TMGI, {})

    # ------------------------------------------------------------------------------
    def listening():
        """The MCVideo IDs the MCVideo server counts as listening to the conversation's subchannel."""
        return {entry['user_id'] for entry in status('mcvideo-server').get('multicast_listening', [])}

    # ------------------------------------------------------------------------------
    def conversation():
        """The MCVideo server's MBMS conversation, or {}."""
        conversations = status('mcvideo-server').get('mbms_conversations', [])
        return conversations[0] if conversations else {}

    # ------------------------------------------------------------------------------
    def equal_pictures(receiver):
        """The pictures of the receiver that client-a also encoded, and how many of them are equal."""
        sent = status('client-a').get('mcvideo_sent_frames') or {}
        received = status(receiver).get('mcvideo_received_frames') or {}
        common = [key for key in received if key in sent]
        return len(common), sum(received[key] == sent[key] for key in common)

    generated = args.compose.resolve().parent / 'generated'
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcvideo']['user_id'] for role in ROLES}
    result = dict(scenario='mbms-mcvideo-group-call', passed=False, checks=checks)
    try:
        wait(
            'four clients authorized for MCVideo',
            lambda: all(status(role).get('mcvideo_authorized') for role in ROLES),
            90,
        )
        wait(
            'MV-MB-01 the MCVideo bearer is announced; client-a to client-c listen to its general purpose subchannel',
            lambda: set(status('mcvideo-server').get('mbms_announced', [])) >= set(ids.values())
            and all(bearer(role).get('accepted') for role in ['client-a'] + LISTENERS)
            and bearer('client-d').get('service') == 'mcvideo'
            and not bearer('client-d').get('joined'),
        )
        command('client-a', 'mcvideo-call')
        wait('all four in the MCVideo group call', lambda: all(status(r).get('mcvideo_call_state') == 'active' for r in ROLES))
        command('client-a', 'mcvideo-transmit')
        wait('client-a granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        wait(
            'MV-MB-02 Map Group To Bearer: the conversation has the first subchannel of the pool',
            lambda: conversation().get('subchannel') == SUBCHANNEL and conversation().get('tmgi') == TMGI,
        )
        wait(
            'MV-MB-03 client-b and client-c joined the subchannel and the server took their listening reports',
            lambda: all(status(role).get('mcvideo_multicast_listening') for role in LISTENERS)
            and {ids[role] for role in LISTENERS} <= listening(),
        )
        command('client-d', 'mcvideo-receive')
        wait(
            'MV-MB-04 every receiver decoded 30 pictures, client-b and client-c from the subchannel',
            lambda: all(status(role).get('mcvideo_frames_received', 0) >= 30 for role in ROLES[1:])
            and all(status(role).get('mcvideo_multicast_received_packets', 0) > 0 for role in LISTENERS),
            40,
        )
        for receiver in ROLES[1:]:
            common, equal = equal_pictures(receiver)
            assert common >= 25 and equal == common, f'{receiver}: {equal} of {common} pictures equal the sender\'s'
        checks.append('MV-MB-04 every decoded picture equals the sender\'s')
        assert status('client-d').get('mcvideo_multicast_received_packets', 0) == 0, 'client-d received from MBMS'
        assert status('client-a').get('mcvideo_frames_received', 0) == 0, 'the transmitter decoded its own video'
        server = status('mcvideo-server')
        assert server.get('multicast_video_forwarded', 0) > 0, 'no video over the subchannel'
        checks.append(
            f'MV-MB-05 {server.get("multicast_video_forwarded")} video packets over the subchannel, '
            f'{server.get("video_forwarded")} by unicast; client-d by unicast only, the transmitter none'
        )

        command('client-c', 'mbms quality bad')
        wait(
            'MV-MB-06 bad radio conditions: client-c leaves the subchannel and the server takes it off',
            lambda: ids['client-c'] not in listening() and status('client-c').get('mcvideo_multicast_joined') == '',
            10,
        )
        before = status('client-c').get('mcvideo_frames_received', 0)
        wait(
            'MV-MB-06 client-c keeps decoding by unicast',
            lambda: status('client-c').get('mcvideo_frames_received', 0) >= before + 15,
        )
        command('client-c', 'mbms quality good')
        wait(
            'MV-MB-07 good again: client-c rejoins on the next Map Group To Bearer',
            lambda: ids['client-c'] in listening() and status('client-c').get('mcvideo_multicast_listening'),
        )
        common, equal = equal_pictures('client-c')
        assert equal == common, f'client-c: {equal} of {common} pictures equal the sender\'s'
        checks.append('MV-MB-07 client-c\'s pictures (MBMS, unicast, MBMS) equal the sender\'s')

        unmaps = status('mcvideo-server').get('mbms_unmap_sent', 0)
        for role in ROLES:
            command(role, 'mcvideo-hangup')
        wait(
            'MV-MB-08 the call is released: Unmap Group To Bearer, every client left the subchannel',
            lambda: not conversation()
            and status('mcvideo-server').get('mbms_unmap_sent', 0) > unmaps
            and all(status(role).get('mcvideo_multicast_joined', '') == '' for role in ROLES),
        )
        result['passed'] = True
    except (AssertionError, KeyError, OSError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = {role: status(role) for role in ROLES + ['mcvideo-server']}
    output = args.artifacts / 'integration/mbms-mcvideo-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
