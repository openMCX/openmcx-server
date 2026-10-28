#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MBMS delivery of a prearranged group call's speech over a pre-activated MBMS bearer (TS 24.379 clause 14,
TS 24.380 clauses 4.1.3 and 10; the BM-SC and the radio are emulated on the lab network).

The bearer is announced to the four users (TS 24.379 clause 14.2.2.2); client-a to client-c, in its service area,
listen to its general purpose subchannel, client-d moves in and out (MB-01 to MB-06). In one prearranged group call
(TS 24.379 clause 10.1.1.2.1), with floor control unicast throughout:

0. client-a talks first: the granted floor starts the conversation's MBMS subchannel (Map Group To Bearer over the
   general purpose subchannel, repeated every T16, TS 24.380 clause 10.2.2.2); client-a to client-c join it and report
   "listening" for the session (TS 24.379 clause 14.3.3.1 condition 1); client-d, outside, keeps unicast.
1. client-a talks: the server sends each RTP packet once over the subchannel and once by unicast to client-d.
2. client-b talks, and client-c's radio conditions turn bad during the burst ("mbms quality bad"): client-c reports
   "not-listening" on the general purpose subchannel, which ends its listening to the subchannel (TS 24.379 clause
   14.2.3 NOTE 2); the server sends it the rest of the burst by unicast, and client-c receives every packet once.
3. "mbms quality good": client-c listens again, hears the next Map Group To Bearer and rejoins; client-a talks, and
   client-c receives the whole burst over the subchannel.
4. A silence longer than T15: Unmap Group To Bearer over the subchannel, repeated every T17 until C17 (clauses
   10.2.3.6, 10.2.3.8 and 10.2.3.9); the clients report "not-listening" and leave (clause 10.3.4).

At the end the call is released and client-c (MBMS, unicast, MBMS) and client-d (unicast) have decoded the same
speech. The wire verifier (verify_multicast.py) checks the server's copies and the subchannel control messages on
the capture.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 1112, RFC 3550.
"""

import argparse
import json
from pathlib import Path
import subprocess
import time
import wave

ROOT = Path(__file__).resolve().parents[2]
# The MBMS subchannel the conversation gets: the first of the bearer's pool.
HOST_GROUP = '239.10.0.2:40002'
# The pre-activated MBMS bearer (tools/prepare-prearranged-test.py MBMS_BEARER).
TMGI = '00000199f907'
GENERAL_PURPOSE = '239.10.1.1:40100'
OPTED_IN = ['client-a', 'client-b', 'client-c']
ROLES = OPTED_IN + ['client-d']
# A talk burst of the lab's speech fixtures is several seconds of 20 ms packets (RFC 4867 section 4.3).
MIN_PACKETS = 50
# Packets client-c receives by multicast in burst 2 before it stops listening.
BEFORE_FALLBACK = 60
# T15 (Conversation) of the lab (tools/prepare-prearranged-test.py), in seconds.
T15 = 10


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
    def warm_up(talker, speech):
        """A talk burst whose counters are recorded but not checked packet by packet: the conversation's MBMS
        subchannel starts with its floor, and the listeners join while it goes on (TS 24.380 clause 10.2.2.2)."""
        before = counters()
        command(talker, f'ptt /artifacts/speech/{speech}')
        wait(f'{talker} warm-up burst starts', lambda: not floor_free(), 15)
        wait(f'{talker} warm-up burst ends', floor_free, 60)
        time.sleep(1)
        after = counters()
        return {role: {key: after[role][key] - before[role][key] for key in after[role]} for role in after}

    # ------------------------------------------------------------------------------
    def group_data(role, group):
        """The group dynamic data a client received over MBMS (Group Dynamic Data Notify), or {}."""
        return status(role).get('mbms_group_dynamic_data', {}).get(group, {})

    # ------------------------------------------------------------------------------
    def server_config():
        """The MCPTT server's generated configuration."""
        return json.loads((generated / 'mcptt-server.json').read_text())

    # ------------------------------------------------------------------------------
    def conversation():
        """The server's MBMS conversation of the call, or {}."""
        conversations = status('mcptt-server').get('mbms_conversations', [])
        return conversations[0] if conversations else {}

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
        command('client-c', 'mbms quality bad')
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
    result = dict(
        scenario='mbms-group-call', passed=False, checks=checks, host_group=HOST_GROUP, general_purpose=GENERAL_PURPOSE
    )
    try:
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        server = status('mcptt-server')
        assert server.get('mbms_bearers') == 1 and server.get('multicast_forwarded') == 0, 'MBMS not set up'
        assert not server.get('multicast_listening'), 'listening before any call'
        assert all(status(role).get('multicast_joined') == '' for role in ROLES), 'joined before any call'
        result['addresses'] = {role: address(role) for role in ROLES + ['mcptt-server']}
        announcements(ids)

        # TS 24.379 clauses 14B.2.2.2, 14B.3.2 and 14B.3.5: on 5G MBS sessions (the mbs lab) the announcement is the
        # MBS one and the listeners send a UE session join notification for the multicast session.
        mbs = any(b.get('system') == 'mbs' for b in server_config()['mcptt']['mbms']['bearers'])
        if mbs:
            wait(
                'MBS-01 MBS session announced; client-a to client-c sent the UE session join notification',
                lambda: all(bearer(role).get('system') == 'mbs' for role in ROLES)
                and {ids[role] for role in OPTED_IN}
                <= {e['user_id'] for e in status('mcptt-server').get('mbs_joined', []) if e['mbs_session_id'] == TMGI},
            )
        command('client-a', 'call')
        wait('four-participant call', lambda: all(status(role).get('call_state') == 'active' for role in ROLES))
        group = json.loads((generated / 'client-a.json').read_text())['mcptt']['group_id']
        wait(
            'MS-10 Group Dynamic Data Notify over the general purpose subchannel: a call is ongoing (TS 24.380 10A.1)',
            lambda: all(group_data(role, group).get('call_ongoing') is True for role in OPTED_IN)
            and not group_data('client-d', group),
            10,
        )
        time.sleep(2)
        assert not conversation() and status('mcptt-server').get('mbms_map_sent') == 0, 'mapped before any floor'
        checks.append('MS-01 no MBMS subchannel before the floor is granted')

        bursts = result['bursts'] = {}
        bursts['0 client-a, warm-up'] = warm_up('client-a', 'alpha.wav')
        wait(
            'MS-02 Map Group To Bearer: the conversation has the first subchannel of the pool',
            lambda: conversation().get('subchannel') == HOST_GROUP and conversation().get('tmgi') == TMGI,
        )
        maps = status('mcptt-server').get('mbms_map_sent', 0)
        wait('MS-03 Map Group To Bearer repeated every T16', lambda: status('mcptt-server').get('mbms_map_sent', 0) > maps + 3)
        wait(
            'MS-04 client-a to client-c joined the subchannel and the server took their listening reports',
            lambda: all(status(role).get('multicast_listening') for role in OPTED_IN)
            and listening() == {ids[role] for role in OPTED_IN},
        )
        assert status('client-d').get('multicast_joined') == '', 'client-d joined from outside the service area'
        checks.append('MS-05 client-d, outside the service area, stays on unicast')

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

        command('client-c', 'mbms quality good')
        wait(
            'client-c rejoined the subchannel on the next Map Group To Bearer and listens again',
            lambda: ids['client-c'] in listening() and status('client-c').get('multicast_listening'),
        )
        bursts['3 client-a'] = third = talk_burst('client-a', 'alpha.wav')
        assert third['client-c']['multicast'] == third['client-c']['received'], 'client-c not back on multicast'
        checks.append('burst 3: client-c by multicast only again')

        # TS 24.380 clauses 10.2.3.2, 10.2.3.3 and 10.3.3: Floor Taken and Floor Idle to the listeners over the
        # subchannel, once each; client-d by unicast. Under protected floor control they stay unicast.
        control = status('mcptt-server').get('mbms_control_sent', 0)
        received = {role: status(role).get('mbms_floor_received', 0) for role in ROLES}
        assert control > 0 and received['client-d'] == 0, f'floor over the subchannel: {control}, {received}'
        assert all(received[role] > 0 for role in ['client-b', 'client-c']), f'floor not received: {received}'
        checks.append(f'MS-08 {control} Floor Taken/Idle over the subchannel, received {received}')
        server = status('mcptt-server')
        if server.get('mbms_musik_id'):
            # TS 24.379 clauses 14.2.2.2 step 5 d and 14.2.2.5, TS 24.380 clause 13: an MSCCK in the announcement and a
            # MuSiK downloaded to each user, both purpose tags right; the floor messages above were SRTCP under it.
            assert server['mbms_musik_id'] >> 28 == 6 and server.get('mbms_mscck_id', 0) >> 28 == 5, server
            assert set(server.get('mbms_musik_users', [])) >= {ids[role] for role in OPTED_IN}, server
            assert all(bearer(role).get('mscck') for role in ROLES), 'MSCCK not taken'
            assert all(status(role).get('mbms_musik_id') == server['mbms_musik_id'] for role in ROLES), 'MuSiK'
            checks.append('MS-09 MSCCK (tag 5) in the announcement and MuSiK (tag 6) downloaded to every user')
            result['protected_signalling'] = dict(mscck=server['mbms_mscck_id'], musik=server['mbms_musik_id'])
        result['floor_over_subchannel'] = control
        unmaps = status('mcptt-server').get('mbms_unmap_sent', 0)
        wait(
            'MS-06 silence longer than T15: Unmap Group To Bearer, repeated C17 times, then released',
            lambda: status('mcptt-server').get('mbms_unmap_sent', 0) >= unmaps + 4 and not conversation(),
            T15 + 10,
        )
        wait(
            'MS-07 the clients left the subchannel and the server counts nobody listening',
            lambda: all(status(role).get('multicast_joined') == '' for role in ROLES) and not listening(),
            5,
        )
        # TS 24.379 clause 14.2.3 (suspension) and TS 24.380 clauses 4.1.3.6, 10.2.3.12 and 10.3.5: a new conversation
        # on the bearer; client-b reports that the bearer is about to be suspended; the server moves the conversation
        # to unicast (Application Paging, then Unmap Group To Bearer) and maps nothing on the bearer until
        # "not-suspending".
        bursts['4 client-a, warm-up again'] = warm_up('client-a', 'alpha.wav')
        wait(
            'MS-11 a new conversation is mapped and listened to',
            lambda: conversation().get('subchannel') == HOST_GROUP and listening() == {ids[r] for r in OPTED_IN},
        )
        paged = {role: status(role).get('mbms_paging_received', 0) for role in ROLES}
        command('client-b', f'mbms suspend {TMGI}')
        wait(
            'MS-12 suspension reported: Application Paging to the listeners, the conversation unmapped and released',
            lambda: TMGI in status('mcptt-server').get('mbms_suspended', [])
            and all(status(role).get('mbms_paging_received', 0) > paged[role] for role in OPTED_IN)
            and status('client-d').get('mbms_paging_received', 0) == paged['client-d']
            and not conversation()
            and all(status(role).get('multicast_joined') == '' for role in ROLES),
            10,
        )
        maps = status('mcptt-server').get('mbms_map_sent', 0)
        bursts['5 client-a, bearer suspended'] = suspended = warm_up('client-a', 'alpha.wav')
        assert suspended['mcptt-server']['multicast'] == 0 and not conversation(), 'mapped while suspended'
        assert status('mcptt-server').get('mbms_map_sent', 0) == maps, 'Map Group To Bearer while suspended'
        assert all(suspended[role]['received'] >= MIN_PACKETS for role in ROLES if role != 'client-a'), suspended
        checks.append('MS-13 while suspended the next talk burst goes by unicast to everyone, nothing is mapped')
        command('client-b', f'mbms resume {TMGI}')
        wait('MS-14 "not-suspending": the bearer takes conversations again', lambda: not status('mcptt-server').get('mbms_suspended'))
        command('client-a', 'hangup')
        wait('call released', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))
        wait(
            'MS-15 Group Dynamic Data Notify: no call ongoing',
            lambda: all(group_data(role, group).get('call_ongoing') is False for role in OPTED_IN),
            10,
        )
        wait(
            'subchannel left at the end of the call',
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
