#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IP multicast delivery of a prearranged group call's speech (an OpenMCX profile, include/mcx/multicast.hpp).

In the --multicast lab the four clients join the group's IPv4 host group when the call starts and report
"listening" (TS 24.379 clause 14.3.3.2). The MCPTT server takes the reports of client-a, client-b and client-c,
which are on its opt-in list, and refuses client-d's with 403, so client-d leaves the host group and keeps unicast
(clause 14.2.3). In one prearranged group call (TS 24.379 clause 10.1.1.2.1), with floor control unicast throughout:

1. client-a talks: the server sends each RTP packet once to the host group and once by unicast to client-d; client-b
   and client-c receive every packet from the host group, client-a none of its own.
2. client-b talks, and client-c stops listening during the burst ("multicast off"): client-c reports
   "not-listening", the server sends it the rest of the burst by unicast (TS 24.380 clause 6.4.3 step 3 a), and
   client-c receives every packet of the burst once, some by multicast and the rest by unicast; while it stays in the
   host group for a moment after the server's answer, a copy that arrives both ways is dropped.
3. client-c listens again ("multicast on"), and client-a talks: client-c receives the whole burst from the host group.

At the end the clients leave the host group, and client-c (multicast, then unicast, then multicast) and client-d
(unicast) have decoded the same speech. The wire verifier (verify_multicast.py) checks the server's copies on the
capture.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 1112, RFC 3550.
"""

import argparse
import json
from pathlib import Path
import subprocess
import time
import wave

ROOT = Path(__file__).resolve().parents[2]
HOST_GROUP = '239.10.0.1:40000'
# The pre-activated MBMS bearer (tools/prepare-prearranged-test.py MBMS_BEARER).
TMGI = '00000199f907'
GENERAL_PURPOSE = '239.10.1.1:40100'
OPTED_IN = ['client-a', 'client-b', 'client-c']
ROLES = OPTED_IN + ['client-d']
# A talk burst of the lab's speech fixtures is several seconds of 20 ms packets (RFC 4867 section 4.3).
MIN_PACKETS = 50
# Packets client-c receives by multicast in burst 2 before it stops listening.
BEFORE_FALLBACK = 60


# ------------------------------------------------------------------------------
def main():
    """Run the three talk bursts and the call's end; write the results."""
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
            time.sleep(0.05)
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
    def listening():
        """The MCPTT IDs the server counts as listening (TS 24.379 clause 14.2.3)."""
        return {entry['user_id'] for entry in status('mcptt-server').get('multicast_listening', [])}

    # ------------------------------------------------------------------------------
    def counters():
        """The packet counters of the clients and the server."""
        current = {
            role: dict(
                received=status(role).get('received_packets', 0),
                multicast=status(role).get('multicast_received_packets', 0),
                unicast_copies=status(role).get('duplicates_dropped_unicast', 0),
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
    def talk_burst(talker, speech, during=None):
        """One talk burst, with during(before) run once it has started; the deltas of every counter, checked: every
        receiver gets every packet once, the talker none, the server one multicast copy per packet and one unicast
        copy per packet a receiver got by unicast."""
        before = counters()
        command(talker, f'ptt /artifacts/speech/{speech}')
        receivers = [role for role in ROLES if role != talker]
        if during:
            during(before)
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
        for role in receivers:
            assert delta[role]['received'] == sent, f'{role} received {delta[role]["received"]} of {sent} packets'
        assert delta[talker]['received'] == 0, f'{talker} received {delta[talker]["received"]} of its own packets'
        # Every unicast copy arrived: kept, or dropped as a copy of one that came by multicast (during a change).
        by_unicast = sum(
            delta[role]['received'] - delta[role]['multicast'] + delta[role]['unicast_copies'] for role in receivers
        )
        assert delta['mcptt-server']['unicast'] == by_unicast, (
            f'{talker}: {delta["mcptt-server"]["unicast"]} unicast copies sent, {by_unicast} arrived by unicast'
        )
        assert delta['client-d']['multicast'] == 0, 'client-d received speech from the host group'
        checks.append(f'{talker}: every packet to every receiver once ({sent}), none back, one copy per path')
        return delta

    # ------------------------------------------------------------------------------
    def fall_back(before):
        """client-c stops listening once it has received part of the burst by multicast."""
        wait(
            'client-c receives part of the burst by multicast',
            lambda: status('client-c').get('multicast_received_packets', 0)
            >= before['client-c']['multicast'] + BEFORE_FALLBACK,
        )
        command('client-c', 'multicast off')
        wait('server takes client-c off multicast', lambda: ids['client-c'] not in listening(), 10)
        wait('client-c left the host group', lambda: status('client-c').get('multicast_joined') == '', 10)

    # ------------------------------------------------------------------------------
    def speech(role):
        """The received speech of a role, as 16 kHz PCM16 frames."""
        with wave.open(str(args.artifacts / role / 'received.wav'), 'rb') as audio:
            return audio.readframes(audio.getnframes())

    # ------------------------------------------------------------------------------
    def bearer(role):
        """The client's view of the announced bearer (core/mbms.cpp), or {}."""
        return status(role).get('mbms_bearers', {}).get(TMGI, {})

    # ------------------------------------------------------------------------------
    def general_purpose():
        """The MCPTT IDs the server counts as listening to the general purpose subchannel of the bearer."""
        return {
            entry['user_id']
            for entry in status('mcptt-server').get('mbms_general_purpose', [])
            if TMGI in entry.get('tmgis', [])
        }

    # ------------------------------------------------------------------------------
    def announcements(ids):
        """MB-01 to MB-06: the MBMS bearer announcement (TS 24.379 clause 14.2.2.2, clause 14.3.2), the listening
        status reports on the general purpose subchannel (clause 14.3.3) as the emulated MBMS interface moves between
        service areas and radio conditions, and the Bearer Announcement over the bearer (TS 24.380 clause 10.3.6)."""
        wait(
            'MB-01 the bearer is announced to the four users',
            lambda: set(status('mcptt-server').get('mbms_announced', [])) >= set(ids.values())
            and all(bearer(role).get('general_purpose') == GENERAL_PURPOSE for role in ROLES),
        )
        wait(
            'MB-02 client-a to client-c listen to the general purpose subchannel, client-d (outside) does not',
            lambda: general_purpose() == {ids[role] for role in OPTED_IN}
            and all(bearer(role).get('joined') and bearer(role).get('accepted') for role in OPTED_IN)
            and not bearer('client-d').get('joined')
            and not bearer('client-d').get('reported_listening'),
        )
        wait(
            'MB-03 Bearer Announcements over the general purpose subchannel reach the listeners only',
            lambda: all(status(role).get('mbms_bearer_announcements', 0) >= 1 for role in OPTED_IN)
            and status('client-d').get('mbms_bearer_announcements', 0) == 0,
            15,
        )
        command('client-d', 'mbms area 0001')
        wait(
            'MB-04 client-d enters the service area and listens',
            lambda: ids['client-d'] in general_purpose() and bearer('client-d').get('accepted'),
            10,
        )
        command('client-c', 'mbms quality bad')
        wait(
            'MB-05 bad radio conditions: client-c reports not-listening',
            lambda: ids['client-c'] not in general_purpose() and not bearer('client-c').get('joined'),
            10,
        )
        command('client-c', 'mbms quality good')
        wait('MB-05 good again: client-c listens', lambda: ids['client-c'] in general_purpose(), 10)
        command('client-d', 'mbms area 0002')
        wait(
            'MB-06 client-d leaves the service area: not-listening',
            lambda: ids['client-d'] not in general_purpose() and not bearer('client-d').get('joined'),
            10,
        )

    generated = args.compose.resolve().parent / 'generated'
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcptt']['user_id'] for role in ROLES}
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
        assert not server.get('multicast_listening'), 'listening before any call'
        assert all(status(role).get('multicast_joined') == '' for role in ROLES), 'joined before any call'
        result['addresses'] = {role: address(role) for role in ROLES + ['mcptt-server']}
        announcements(ids)

        command('client-a', 'call')
        wait('four-participant call', lambda: all(status(role).get('call_state') == 'active' for role in ROLES))
        wait(
            'opted-in clients joined and the server took their listening reports',
            lambda: all(status(role).get('multicast_listening') for role in OPTED_IN)
            and listening() == {ids[role] for role in OPTED_IN},
        )
        wait(
            'client-d refused (403) and left the host group',
            lambda: status('client-d').get('multicast_refused') == 403
            and status('client-d').get('multicast_joined') == '',
        )

        bursts = result['bursts'] = {}
        bursts['1 client-a'] = talk_burst('client-a', 'alpha.wav')
        first = bursts['1 client-a']
        assert all(first[role]['multicast'] == first[role]['received'] for role in ['client-b', 'client-c'])
        checks.append('burst 1: client-b and client-c by multicast only')

        bursts['2 client-b, client-c falls back'] = second = talk_burst('client-b', 'bravo.wav', fall_back)
        assert 0 < second['client-c']['multicast'] < second['client-c']['received'], 'client-c did not change path'
        assert second['client-a']['multicast'] == second['client-a']['received'], 'client-a left multicast'
        checks.append(
            f'burst 2: client-c {second["client-c"]["multicast"]} by multicast, '
            f'{second["client-c"]["received"] - second["client-c"]["multicast"]} by unicast, none lost'
        )

        command('client-c', 'multicast on')
        wait(
            'client-c listening again',
            lambda: ids['client-c'] in listening() and status('client-c').get('multicast_listening'),
        )
        bursts['3 client-a'] = third = talk_burst('client-a', 'alpha.wav')
        assert third['client-c']['multicast'] == third['client-c']['received'], 'client-c not back on multicast'
        checks.append('burst 3: client-c by multicast only again')

        command('client-a', 'hangup')
        wait('call released', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))
        wait(
            'host group left at the end of the call',
            lambda: all(status(role).get('multicast_joined') == '' for role in ROLES),
        )
        wait(
            'received speech written', lambda: all((args.artifacts / role / 'received.wav').is_file() for role in ROLES)
        )
        time.sleep(2)
        assert speech('client-c') == speech('client-d'), 'client-c and client-d decoded different speech'
        checks.append('client-c (multicast and unicast) and client-d (unicast) decoded the same speech')
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
