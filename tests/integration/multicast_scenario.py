#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IP multicast delivery of a prearranged group call's speech (an OpenMCX profile, include/mcx/multicast.hpp).

In the --multicast lab client-a, client-b and client-c are on the MCPTT server's opt-in list and join the group's
IPv4 host group; client-d is not and keeps unicast. In one prearranged group call (TS 24.379 clause 10.1.1.2.1)
client-a talks, then client-b (floor control of TS 24.380 clause 6.2.4, unicast throughout). For each talk burst:
the server sends each RTP packet once to the host group and once by unicast to client-d, and to nobody else; the
opted-in receivers receive every packet from the host group; the talker receives none of its own speech; the
multicast and the unicast receivers decode the same speech. The clients join when the call starts and leave when it
ends. The wire verifier (verify_multicast.py) checks the same on the capture at the server.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.3.0 (Rel-19), RFC 1112, RFC 3550.
"""

import argparse
import json
from pathlib import Path
import subprocess
import time
import wave

ROOT = Path(__file__).resolve().parents[2]
HOST_GROUP = '239.10.0.1:40000'
OPTED_IN = ['client-a', 'client-b', 'client-c']
ROLES = OPTED_IN + ['client-d']
# A talk burst of the lab's speech fixtures is several seconds of 20 ms packets (RFC 4867 section 4.3).
MIN_PACKETS = 50


# ------------------------------------------------------------------------------
def main():
    """Run the two talk bursts and the call's end; write the results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-prearranged')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
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
        """Record label once predicate() holds; fail with every status on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                return
            time.sleep(0.1)
        raise AssertionError(label + ': ' + json.dumps({role: status(role) for role in ROLES + ['mcptt-server']}))

    # ------------------------------------------------------------------------------
    def address(role):
        """The IPv4 address of a role's container on the lab network."""
        container = subprocess.run(cli + ['ps', '-q', role], capture_output=True, text=True, check=True).stdout.strip()
        template = '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
        return subprocess.run(
            ['docker', 'inspect', '-f', template, container], capture_output=True, text=True, check=True
        ).stdout.strip()

    # ------------------------------------------------------------------------------
    def counters():
        """The packet counters of the clients and the server."""
        current = {
            role: dict(
                received=status(role).get('received_packets', 0),
                multicast=status(role).get('multicast_received_packets', 0),
            )
            for role in ROLES
        }
        server = status('mcptt-server')
        current['mcptt-server'] = dict(
            multicast=server.get('multicast_forwarded', 0), unicast=server.get('media_forwarded', 0)
        )
        return current

    # ------------------------------------------------------------------------------
    def floor_free():
        """No client talks and no session has a floor owner."""
        sessions = status('mcptt-server').get('sessions', [])
        sessions = list(sessions.values()) if isinstance(sessions, dict) else sessions
        return not any(status(role).get('talking') for role in ROLES) and not any(
            session.get('floor_owner') for session in sessions
        )

    # ------------------------------------------------------------------------------
    def talk_burst(talker, speech):
        """One talk burst: the deltas of every counter, checked against one copy per receiver path."""
        before = counters()
        command(talker, f'ptt /artifacts/speech/{speech}')
        receivers = [role for role in ROLES if role != talker]
        wait(
            f'{talker} talk burst reaches every receiver',
            lambda: all(
                status(role).get('received_packets', 0) >= before[role]['received'] + MIN_PACKETS for role in receivers
            ),
        )
        wait(f'{talker} talk burst ends', floor_free, 60)
        time.sleep(1)  # the last packets of the burst
        after = counters()
        delta = {role: {key: after[role][key] - before[role][key] for key in after[role]} for role in after}
        sent = delta['mcptt-server']['multicast']
        assert sent >= MIN_PACKETS, f'{talker}: the server sent {sent} packets to the host group'
        assert delta['mcptt-server']['unicast'] == sent, (
            f'{talker}: unicast copies {delta["mcptt-server"]["unicast"]}, expected one per packet (client-d only)'
        )
        checks.append(f'{talker}: one multicast and one unicast copy per packet ({sent})')
        for role in receivers:
            assert delta[role]['received'] == sent, f'{role} received {delta[role]["received"]} of {sent} packets'
        for role in [role for role in receivers if role in OPTED_IN]:
            assert delta[role]['multicast'] == sent, f'{role}: {delta[role]["multicast"]} of {sent} by multicast'
        assert delta['client-d']['multicast'] == 0, 'client-d received speech from the host group'
        checks.append(f'{talker}: opted-in receivers by multicast, client-d by unicast, every packet')
        assert delta[talker]['received'] == 0, f'{talker} received {delta[talker]["received"]} of its own packets'
        checks.append(f'{talker}: no speech of its own back')
        return delta

    # ------------------------------------------------------------------------------
    def speech(role):
        """The received speech of a role, as 16 kHz PCM16 frames."""
        with wave.open(str(args.artifacts / role / 'received.wav'), 'rb') as audio:
            return audio.readframes(audio.getnframes())

    result = dict(scenario='multicast-group-call', passed=False, checks=checks, host_group=HOST_GROUP)
    try:
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        server = status('mcptt-server')
        assert server.get('multicast_groups') == 1 and server.get('multicast_forwarded') == 0, 'multicast not set up'
        assert all(status(role).get('multicast_joined') == '' for role in OPTED_IN), 'joined before any call'
        result['addresses'] = {role: address(role) for role in ROLES + ['mcptt-server']}

        command('client-a', 'call')
        wait('four-participant call', lambda: all(status(role).get('call_state') == 'active' for role in ROLES))
        wait(
            'opted-in clients joined the host group',
            lambda: all(status(role).get('multicast_joined') == HOST_GROUP for role in OPTED_IN),
        )
        assert 'multicast_joined' not in status('client-d'), 'client-d has a multicast block'

        result['bursts'] = {
            'client-a': talk_burst('client-a', 'alpha.wav'),
            'client-b': talk_burst('client-b', 'bravo.wav'),
        }

        command('client-a', 'hangup')
        wait('call released', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))
        wait(
            'host group left at the end of the call',
            lambda: all(status(role).get('multicast_joined') == '' for role in OPTED_IN),
        )
        # client-c (multicast) and client-d (unicast) received both bursts: the same speech.
        wait(
            'received speech written', lambda: all((args.artifacts / role / 'received.wav').is_file() for role in ROLES)
        )
        time.sleep(2)
        assert speech('client-c') == speech('client-d'), 'multicast and unicast receivers decoded different speech'
        checks.append('multicast and unicast receivers decoded the same speech')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, subprocess.SubprocessError, wave.Error) as exc:
        result['error'] = str(exc)
    result['status'] = {role: status(role) for role in ROLES + ['mcptt-server']}
    output = args.artifacts / 'integration/multicast-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
