#!/usr/bin/env python3
# Lab tooling: the Rx lab scenario. It implements no 3GPP procedure; its checks follow TS 29.214 V19.3.0 clauses
# 4.4.1 to 4.4.6, 5.3, 5.4.1, 5.6 and annex A.13.2, TS 23.379 V19.11.0 clauses 5.7.3 and 7.5.2.6 and
# TS 24.379 V19.7.0 clause 4.13.
"""Rx AF role: mcptt-server requests MCPTT QoS from a PCRF (TS 29.214) for its EPS UEs, and none for a UE on WLAN.

Run against a fixture prepared with --rx --priority --floor-queue --private-call: mock-pcrf
(tests/integration/mock_pcrf.py) records every request and sends Re-Auth and Abort-Session requests on demand.
client-a to client-c are EPS UEs (rx.ue_subnets), client-d is on WLAN.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
EPS = ROLES[:3]
MCPTT_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcptt'
FEATURE_MCPTT = 1 << 17
SUCCESS, IP_CAN_SESSION_NOT_AVAILABLE = 2001, 5065


def first(fields, name, default=None):
    return fields.get(name, [default])[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-rx')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {r: json.loads((generated / f'{r}.json').read_text()) for r in ROLES}
    rx_cfg = json.loads((generated / 'mcptt-server.json').read_text())['rx']
    ids = {r: configs[r]['mcptt']['user_id'] for r in ROLES}
    group = configs['client-a']['mcptt']['group_id']
    checks, observations = [], {}
    result = dict(scenario='rx-af', passed=False, checks=checks, observations=observations)

    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    def rx_status():
        return status('mcptt-server').get('rx', {})

    def exec_(service, *command, timeout=15):
        run = subprocess.run(cli + ['exec', '-T', service, *command], capture_output=True, text=True, timeout=timeout)
        if run.returncode:
            raise RuntimeError(f'{service} {command}: {run.stderr.strip() or run.stdout.strip()}')
        return run.stdout

    def command(role, text):
        exec_(role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text)

    def mock(path, body=None):
        command_line = ['curl', '-sf', f'http://127.0.0.1:8080{path}']
        if body is not None:
            command_line += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
        out = exec_('mock-pcrf', *command_line)
        return json.loads(out) if out.strip() else None

    def records():
        return mock('/mock/requests') or []

    def received(kind, since=0, request_type=None):
        out = [r for r in records()[since:] if r.get('direction') == 'request' and r.get('command') == kind]
        if request_type is not None:
            out = [r for r in out if first(r, 'Rx-Request-Type') == request_type]
        return out

    def answers(command_code, since=0):
        return [r for r in records()[since:] if r.get('direction') == 'answer' and r.get('command') == command_code]

    def snapshot():
        return dict(
            rx=rx_status(),
            clients={r: {k: status(r).get(k) for k in ('call_state', 'call_type', 'priority')} for r in ROLES},
            records=records()[-6:],
        )

    def wait(label, condition, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot())[:3000])

    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(f'{label}: {json.dumps(detail)[:3000] if detail is not None else "failed"}')
        checks.append(label)
        print(label, flush=True)

    def session():
        for value in status('mcptt-server').get('sessions', []):
            if value.get('group_id') == group:
                return value
        return {}

    def idle(*roles):
        return all(status(r).get('call_state') == 'idle' for r in roles)

    try:
        wait('four clients authorised', lambda: all(status(r).get('authorized') for r in ROLES), 90)
        wait('fixture initially idle', lambda: idle(*ROLES))
        check(
            'Rx-00 the AF is enabled and holds no Rx session',
            rx_status().get('enabled') and rx_status().get('active') == 0,
            rx_status(),
        )

        def address(service):
            container = subprocess.run(
                cli + ['ps', '-q', service], check=True, capture_output=True, text=True
            ).stdout.strip()
            return subprocess.run(
                ['docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', container],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.split()[0]

        addresses = {r: address(r) for r in ROLES + ['mcptt-server']}
        observations['addresses'] = addresses
        server_ip = addresses['mcptt-server']
        by_ue = {addresses[r]: r for r in ROLES}
        for r in ROLES:
            command(r, 'answer-mode auto')
            if status(r).get('group_id') != group:
                command(r, 'group ' + group)
            elif not status(r).get('affiliated'):
                command(r, 'affiliate')
        wait(
            'clients affiliated',
            lambda: all(status(r).get('affiliated') and status(r).get('group_id') == group for r in ROLES),
        )

        # Rx-01 a group call: one Rx session per confirmed leg of an EPS UE; the WLAN UE takes part without one.
        mark = len(records())
        command('client-a', 'call')
        wait(
            'Rx-01 four-party group call established',
            lambda: (
                len(session().get('participants', [])) == 4
                and all(status(r).get('call_state') == 'active' for r in ROLES)
            ),
        )
        wait(
            'Rx-01 one initial AA-Request per EPS leg',
            lambda: len(received('AAR', mark, 0)) == 3 and rx_status().get('active') == 3,
        )
        initial = received('AAR', mark, 0)
        observations['aar_example'] = initial[0]
        legs = {by_ue.get(first(r, 'Framed-IP-Address')): r for r in initial}
        check('Rx-01 Framed-IP-Address: the three EPS UEs, not the WLAN UE', set(legs) == set(EPS), list(legs))
        check('Rx-01 client-d on WLAN is in the call', ids['client-d'] in session().get('participants', []), session())
        sessions = {role: first(r, 'Session-Id') for role, r in legs.items()}
        observations['sessions'] = sessions
        for role, request in legs.items():
            ue = addresses[role]
            check(
                f'Rx-01 {role}: Auth-Application-Id Rx, Destination-Realm and -Host',
                first(request, 'Auth-Application-Id') == 16777236
                and first(request, 'Destination-Realm') == rx_cfg['destination_realm']
                and first(request, 'Destination-Host') == rx_cfg['destination_host'],
                request,
            )
            check(
                f'Rx-01 {role}: AF-Application-Identifier is the MCPTT ICSI (TS 23.379 clause 5.7.3)',
                first(request, 'AF-Application-Identifier') == MCPTT_ICSI,
                request.get('AF-Application-Identifier'),
            )
            check(
                f'Rx-01 {role}: Specific-Action release of bearer, successful and failed allocation',
                sorted(request.get('Specific-Action', [])) == [4, 8, 9],
                request.get('Specific-Action'),
            )
            features = first(request, 'Supported-Features', {})
            check(
                f'Rx-01 {role}: Supported-Features list 1 with MCPTT',
                first(features, 'Feature-List-ID') == 1 and first(features, 'Feature-List') == FEATURE_MCPTT,
                features,
            )
            check(
                f'Rx-01 {role}: mcpttp.0 gives MCPTT-Identifier mcpttp, Reservation-Priority 0 (annex A.13.2)',
                first(request, 'MCPTT-Identifier') == 'mcpttp' and first(request, 'Reservation-Priority') == 0,
                request,
            )
            components = request.get('Media-Component-Description', [])
            check(
                f'Rx-01 {role}: one AUDIO component of 41 kbit/s each way, enabled',
                len(components) == 1
                and first(components[0], 'Media-Component-Number') == 1
                and first(components[0], 'Media-Type') == 0
                and first(components[0], 'Max-Requested-Bandwidth-UL') == 41000
                and first(components[0], 'Max-Requested-Bandwidth-DL') == 41000
                and first(components[0], 'Flow-Status') == 2,
                components,
            )
            subs = {first(sub, 'Flow-Number'): sub for sub in components[0].get('Media-Sub-Component', [])}
            check(
                f'Rx-01 {role}: RTP, RTCP (Flow-Usage RTCP) and floor control flows',
                sorted(subs) == [1, 2, 3]
                and first(subs[2], 'Flow-Usage') == 1
                and 'Flow-Usage' not in subs[1]
                and 'Flow-Usage' not in subs[3],
                subs,
            )
            ports = []
            for number in (1, 2, 3):
                down, up = subs[number].get('Flow-Description', ['', ''])
                down_fields, up_fields = down.split(), up.split()
                ok = (
                    down_fields[:4] == ['permit', 'out', '17', 'from']
                    and down_fields[4] == server_ip
                    and down_fields[7] == ue
                    and up_fields[:4] == ['permit', 'in', '17', 'from']
                    and up_fields[4] == ue
                    and up_fields[7] == server_ip
                    and down_fields[5] == up_fields[8]
                    and down_fields[8] == up_fields[5]
                )
                check(
                    f'Rx-01 {role}: flow {number} downlink "permit out" and uplink "permit in" (clause 5.3.8)',
                    ok,
                    subs[number].get('Flow-Description'),
                )
                ports.append(int(down_fields[5]))
            check(
                f'Rx-01 {role}: server RTCP is RTP + 1 and floor is separate',
                ports[1] == ports[0] + 1 and ports[2] not in ports[:2],
                ports,
            )
        check(
            'Rx-01 the MCPTT feature accepted for every session',
            all(s.get('features') == FEATURE_MCPTT for s in rx_status().get('sessions', [])),
            rx_status(),
        )

        # Rx-02 emergency upgrade: an update per Rx session with Reservation-Priority 15 and the MCPTT-Identifier.
        mark = len(records())
        command('client-a', 'emergency on')
        wait('Rx-02 the group call is an emergency call', lambda: session().get('priority') == 'emergency')
        wait('Rx-02 one update AA-Request per Rx session', lambda: len(received('AAR', mark, 1)) == 3)
        updates = received('AAR', mark, 1)
        observations['update_example'] = updates[0]
        check(
            'Rx-02 on the same Rx sessions',
            {first(r, 'Session-Id') for r in updates} == set(sessions.values()),
            updates,
        )
        check(
            'Rx-02 Reservation-Priority 15 and MCPTT-Identifier mcpttp, no Framed-IP-Address',
            all(
                first(r, 'Reservation-Priority') == 15
                and first(r, 'MCPTT-Identifier') == 'mcpttp'
                and 'Framed-IP-Address' not in r
                for r in updates
            ),
            updates,
        )
        check('Rx-02 accepted', all(r['result'] == SUCCESS for r in updates))

        # Rx-03 emergency cancelled: back to Reservation-Priority 0.
        mark = len(records())
        command('client-a', 'emergency off')
        wait('Rx-03 the group call is back to normal priority', lambda: session().get('priority') == 'normal')
        wait('Rx-03 one update AA-Request per Rx session', lambda: len(received('AAR', mark, 1)) == 3)
        check(
            'Rx-03 Reservation-Priority 0',
            all(first(r, 'Reservation-Priority') == 0 for r in received('AAR', mark, 1)),
            received('AAR', mark, 1),
        )

        # Rx-04 the PCRF's Re-Auth-Request (failed resource allocation) is answered; best effort: the call goes on.
        mark = len(records())
        mock('/mock/rar', dict(session_id=sessions['client-b'], specific_action=9))
        wait(
            'Rx-04 Re-Auth-Answer DIAMETER_SUCCESS',
            lambda: any(first(r, 'Result-Code') == SUCCESS for r in answers(258, mark)),
        )
        wait('Rx-04 Re-Auth-Request counted', lambda: rx_status().get('re_auth') == 1)
        check('Rx-04 the call goes on', all(status(r).get('call_state') == 'active' for r in ROLES))

        # Rx-05 hang-up: every Rx session terminated.
        mark = len(records())
        command('client-a', 'hangup')
        wait('Rx-05 the call ended', lambda: not session() and idle(*ROLES))
        wait(
            'Rx-05 one Session-Termination-Request per Rx session',
            lambda: (
                len(received('STR', mark)) == 3 and rx_status().get('active') == 0 and not rx_status().get('sessions')
            ),
        )
        check(
            'Rx-05 on each Rx session, Termination-Cause DIAMETER_LOGOUT',
            {first(r, 'Session-Id') for r in received('STR', mark)} == set(sessions.values())
            and all(first(r, 'Termination-Cause') == 1 for r in received('STR', mark)),
            received('STR', mark),
        )

        # Rx-06 private call; the PCRF's Abort-Session-Request is answered and followed by the AF's
        # Session-Termination-Request (clause 4.4.6.1); the call goes on (release_on_terminate is false).
        mark = len(records())
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'Rx-06 private call active',
            lambda: all(
                status(r).get('call_state') == 'active' and status(r).get('call_type') == 'private'
                for r in ('client-a', 'client-b')
            ),
        )
        wait(
            'Rx-06 two initial AA-Requests',
            lambda: len(received('AAR', mark, 0)) == 2 and rx_status().get('active') == 2,
        )
        private = {by_ue[first(r, 'Framed-IP-Address')]: first(r, 'Session-Id') for r in received('AAR', mark, 0)}
        check('Rx-06 Rx sessions for both parties', set(private) == {'client-a', 'client-b'}, private)
        mock('/mock/asr', dict(session_id=private['client-b'], abort_cause=0))
        wait(
            'Rx-06 Abort-Session-Answer DIAMETER_SUCCESS',
            lambda: any(first(r, 'Result-Code') == SUCCESS for r in answers(274, mark)),
        )
        wait(
            'Rx-06 the AF terminates the aborted Rx session',
            lambda: (
                [first(r, 'Session-Id') for r in received('STR', mark)] == [private['client-b']]
                and rx_status().get('active') == 1
            ),
        )
        time.sleep(1)
        check('Rx-06 the call goes on', all(status(r).get('call_state') == 'active' for r in ('client-a', 'client-b')))
        command('client-a', 'hangup')
        wait('Rx-06 the call ended', lambda: idle('client-a', 'client-b'))
        wait(
            'Rx-06 the remaining Rx session terminated once',
            lambda: len(received('STR', mark)) == 2 and rx_status().get('active') == 0,
        )
        time.sleep(1)
        check(
            'Rx-06 no second termination of the aborted Rx session',
            len(received('STR', mark)) == 2,
            received('STR', mark),
        )

        # Rx-07 the PCRF refuses (IP-CAN_SESSION_NOT_AVAILABLE): best effort, the call is set up anyway and nothing
        # is terminated.
        mock('/mock/config', dict(fail_create=True))
        mark = len(records())
        failed_before = rx_status().get('failed', 0)
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'Rx-07 private call active despite the refusal',
            lambda: all(status(r).get('call_state') == 'active' for r in ('client-a', 'client-b')),
        )
        wait(
            'Rx-07 both AA-Requests refused',
            lambda: (
                len(received('AAR', mark, 0)) == 2
                and all(r['result'] == IP_CAN_SESSION_NOT_AVAILABLE for r in received('AAR', mark, 0))
                and rx_status().get('failed', 0) - failed_before == 2
            ),
        )
        command('client-a', 'hangup')
        wait('Rx-07 the call ended', lambda: idle('client-a', 'client-b'))
        time.sleep(1.5)
        check(
            'Rx-07 nothing to terminate',
            not received('STR', mark) and not rx_status().get('sessions'),
            records()[mark:],
        )
        mock('/mock/config', dict(fail_create=False))

        # Rx-08 the WLAN UE starts a group call: the EPS UEs' legs have Rx sessions, the caller's own leg none
        # (TS 24.379 clause 4.13).
        mark = len(records())
        command('client-d', 'call')
        wait(
            'Rx-08 group call from the WLAN UE established',
            lambda: (
                len(session().get('participants', [])) == 4
                and all(status(r).get('call_state') == 'active' for r in ROLES)
            ),
        )
        wait(
            'Rx-08 one initial AA-Request per EPS leg',
            lambda: len(received('AAR', mark, 0)) == 3 and rx_status().get('active') == 3,
        )
        check(
            'Rx-08 none for the WLAN caller',
            {by_ue.get(first(r, 'Framed-IP-Address')) for r in received('AAR', mark, 0)} == set(EPS),
            received('AAR', mark, 0),
        )
        command('client-d', 'hangup')
        wait('Rx-08 the call ended', lambda: not session() and idle(*ROLES))
        wait(
            'Rx-08 its Rx sessions terminated',
            lambda: len(received('STR', mark)) == 3 and rx_status().get('active') == 0,
        )

        # Overall: every Rx session the PCRF accepted was terminated exactly once.
        everything = records()
        accepted = {
            first(r, 'Session-Id')
            for r in everything
            if r.get('command') == 'AAR' and first(r, 'Rx-Request-Type') == 0 and r['result'] == SUCCESS
        }
        terminated = [
            first(r, 'Session-Id') for r in everything if r.get('direction') == 'request' and r.get('command') == 'STR'
        ]
        observations['totals'] = dict(accepted=len(accepted), terminated=len(terminated))
        check(
            'Rx-09 every Rx session terminated exactly once',
            sorted(terminated) == sorted(accepted),
            observations['totals'],
        )
        result['passed'] = True
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        result['error'] = str(error)
    output = args.artifacts / 'integration/rx-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(
        json.dumps(
            dict(
                scenario=result['scenario'], passed=result['passed'], checks=len(checks), error=result.get('error', '')
            )
        )
    )
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
