#!/usr/bin/env python3
"""Exercise MCVideo location management: the location procedures of TS 24.281 clause 18
(reporting configuration, clauses 18.2.2 and 18.3.2; location information request, clauses
18.2.3 and 18.3.3; location information report, clauses 18.2.4 and 18.3.4, with the 403
warnings 191, 192 and 193 of clauses 18.2.2 and 18.2.3.2) and the location report carried in a
SIP request (TS 24.281 clause 6.2.9.1), with group geographic area affiliation and an emergency
alert area.

Specifications: TS 24.281 V19.6.0 (Rel-19).

Run against a four-client fixture prepared with --mcvideo --location: the MCVideo server
sends the same reporting configuration as the MCPTT one, and each MCVideo profile carries
the same location rights, naming MCVideo IDs. Check IDs match
tests/mcvideo/MCVIDEO_LOCATION_TEST.md. Positions are simulated with "location position".
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
ZONE = (48.01, 2.0)
HAZARD = (48.05, 2.05)
GROUP_AREA = (48.02, 2.02)


# ------------------------------------------------------------------------------
# Run the scenario against the lab and write mcvideo-location.json; return 0 when every check passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo-location')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    if any('mcvideo' not in configs[role] for role in roles):
        parser.error('the fixture must be prepared with --mcvideo --location')
    ids = {role: configs[role]['mcvideo']['user_id'] for role in roles}
    group = configs['client-a']['mcvideo']['group_id']
    checks, observations = [], {}
    result = dict(scenario='mcvideo-location', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json a role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The location state of every client and of mcvideo-server, for a failed check's message.
    def snapshot():
        return {role: status(role).get('mcvideo_location') for role in roles} | {
            'mcvideo-server': status('mcvideo-server').get('location')
        }

    # ------------------------------------------------------------------------------
    # Send one interactive command to the mcx-client of a role; fail on a non-zero exit.
    def command(role, text):
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Poll predicate until it holds (record label as passed) or timeout seconds pass (fail with a snapshot).
    def wait(label, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.1)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    # Record label as passed if condition holds, else fail with a snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot()))
        checks.append(label)
        print(label, flush=True)

    # Accessors of the client's and the server's location status.
    loc = lambda role: status(role).get('mcvideo_location') or {}
    server = lambda: status('mcvideo-server').get('location') or {}
    counter = lambda name: server().get('counters', {}).get(name, 0)
    sent = lambda role: loc(role).get('sent', [])
    received = lambda role: loc(role).get('received', [])
    stored = lambda role: server().get('users', {}).get(ids[role], {})
    last_result = lambda role: loc(role).get('last_result') or {}

    # ------------------------------------------------------------------------------
    # True when coordinate is within tolerance degrees of latitude lat and longitude lon.
    def near(coordinate, lat, lon, tolerance=1e-4):
        return (
            bool(coordinate)
            and abs(coordinate['latitude'] - lat) < tolerance
            and abs(coordinate['longitude'] - lon) < tolerance
        )

    # ------------------------------------------------------------------------------
    # The location reports role sent, from its report number after on, that name trigger among their triggers.
    def reports_with(role, trigger, after=0):
        return [report for report in sent(role)[after:] if trigger in report.get('triggers', [])]

    # ------------------------------------------------------------------------------
    # Simulate a new position of role.
    def move(role, lat, lon):
        command(role, f'location position {lat} {lon}')

    # ------------------------------------------------------------------------------
    # The location reports role received in answer to its request request_id.
    def answered(role, request_id):
        return [report for report in received(role) if report.get('id') == request_id]

    # ------------------------------------------------------------------------------
    # TS 24.281 clause 18.3.3.2: role sends an MCVideo location information request (words: options and targets); return
    # its RequestId.
    def request(role, *words):
        before = loc(role).get('last_request')
        command(role, 'mcvideo-location request ' + ' '.join(words))
        wait(
            f'{role} issued an MCVideo location request',
            lambda: loc(role).get('last_request') not in (None, '', before),
            5,
        )
        return loc(role)['last_request']

    try:
        wait(
            'MV-LC-01 every MCVideo client holds the configuration sent after its MCVideo service authorisation (18.2.2)',
            lambda: all(loc(role).get('configured') for role in roles) and counter('configured') >= 4,
            40,
        )
        check(
            'MV-LC-01 the participating MCVideo function stores it with TriggerIds t1 to t7',
            stored('client-a').get('configuration', {}).get('triggers') == ['t1', 't2', 't3', 't4', 't5', 't6']
            and stored('client-a').get('configuration', {}).get('emergency_triggers') == ['t7'],
        )
        wait(
            'MV-LC-02 each reporting client reports its log-on position (18.3.4)',
            lambda: all(
                near(stored(role).get('report', {}).get('coordinate'), 48.0, 2.0 + 0.01 * index)
                for index, role in enumerate(['client-a', 'client-b', 'client-c'])
            ),
            20,
        )
        wait(
            'MV-LC-03 a user not authorised to report is refused and nothing is stored',
            lambda: sent('client-d') and counter('refused') >= 1 and not stored('client-d').get('report'),
        )

        before = len(sent('client-a'))
        move('client-a', *ZONE)
        wait(
            'MV-LC-04 moving into the zone fires the travelled-distance t3 and zone-entry t4 triggers',
            lambda: reports_with('client-a', 't4', before) and reports_with('client-a', 't3', before),
        )
        wait(
            'MV-LC-04 the stored position follows',
            lambda: near(stored('client-a').get('report', {}).get('coordinate'), *ZONE),
        )

        before = len(sent('client-b'))
        command('client-b', 'mcvideo-call')
        wait(
            'MV-LC-05 a non-emergency MCVideo group call fires the signalling event trigger t2',
            lambda: reports_with('client-b', 't2', before),
            20,
        )
        for role in roles:
            if status(role).get('mcvideo_call_state') not in (None, 'idle'):
                command(role, 'mcvideo-hangup')
        wait(
            'MV-LC-05 the call ended',
            lambda: all(status(role).get('mcvideo_call_state') == 'idle' for role in roles),
            30,
        )

        rid = request('client-a', ids['client-b'])
        wait(
            'MV-LC-06 an authorised request is answered with the RequestId, the reporting MCVideo ID and the position (18.2.3.2)',
            lambda: any(
                report.get('reporting_uri') == ids['client-b'] and near(report.get('coordinate'), 48.0, 2.01)
                for report in answered('client-a', rid)
            ),
        )
        requested = counter('requested')
        rid = request('client-a', 'refresh', ids['client-b'])
        wait(
            'MV-LC-07 with refresh the participating function asks the client first (18.2.3.1)',
            lambda: counter('requested') > requested and answered('client-a', rid),
        )
        rid = request('client-a', 'filter', 't4', 'in', ids['client-b'])
        time.sleep(3)
        check(
            'MV-LC-08 a LocationFilter for users inside the zone excludes a user outside it',
            not answered('client-a', rid),
        )
        rid = request('client-a', ids['client-c'])
        time.sleep(3)
        check('MV-LC-08 a user sharing only with another user is not reported', not answered('client-a', rid))

        request('client-b', ids['client-a'])
        wait(
            'MV-LC-09 a user without the right to request is refused 403 warning 192',
            lambda: (
                last_result('client-b').get('status') == 403 and '192' in last_result('client-b').get('warning', '')
            ),
        )
        request('client-a', 'no-list')
        wait(
            'MV-LC-09 a request naming no one is refused 403 warning 191',
            lambda: (
                last_result('client-a').get('status') == 403 and '191' in last_result('client-a').get('warning', '')
            ),
        )
        command(
            'client-c', f'mcvideo-location configure {ids["client-a"]} ' + json.dumps({'triggers': [{'periodic': 5}]})
        )
        wait(
            'MV-LC-09 a user without the right to configure is refused 403 warning 193',
            lambda: (
                last_result('client-c').get('status') == 403 and '193' in last_result('client-c').get('warning', '')
            ),
        )

        command(
            'client-a',
            f'mcvideo-location configure {ids["client-b"]} '
            + json.dumps({'scope': 'update', 'triggers': [{'periodic': 2, 'id': 'every-2s'}]}),
        )
        wait(
            'MV-LC-10 an authorised user adds a periodic trigger and the target reports on it (18.2.2, 18.3.2.2)',
            lambda: last_result('client-a').get('status') == 200 and len(reports_with('client-b', 'every-2s')) >= 2,
            15,
        )

        check(
            'MV-LC-11 client-c starts affiliated to its MCVideo group',
            status('client-c').get('mcvideo_affiliated') is True,
        )
        move('client-c', *GROUP_AREA)
        wait(
            'MV-LC-11 entering the group geographic area is notified and recorded (6.3.3.1.21, 11.2.1.4)',
            lambda: stored('client-c').get('areas', {}).get('group:' + group) is True,
        )
        move('client-c', 48.0, 2.02)
        wait(
            'MV-LC-11 leaving it de-affiliates the client from the MCVideo group',
            lambda: (
                stored('client-c').get('areas', {}).get('group:' + group) is False
                and status('client-c').get('mcvideo_affiliated') is False
            ),
        )
        move('client-c', *GROUP_AREA)
        wait(
            'MV-LC-11 entering it again affiliates the client once more',
            lambda: status('client-c').get('mcvideo_affiliated') is True,
        )

        move('client-a', *HAZARD)
        wait(
            'MV-LC-12 entering the emergency alert area starts an MCVideo emergency alert',
            lambda: (
                stored('client-a').get('areas', {}).get('alert:hazard') is True
                and status('client-a').get('mcvideo_alerting') is True
                and ids['client-a'] in (status('client-b').get('mcvideo_alerts') or {})
            ),
            20,
        )
        before = len(sent('client-a'))
        wait(
            'MV-LC-12 in the emergency state the client reports Emergency on the emergency trigger t7',
            lambda: any(report.get('emergency') is True for report in reports_with('client-a', 't7', before)),
            10,
        )
        command('client-a', 'mcvideo-alert off')
        move('client-a', 48.0, 2.0)
        wait(
            'MV-LC-12 leaving the area is notified and the cancelled alert is gone',
            lambda: (
                stored('client-a').get('areas', {}).get('alert:hazard') is False
                and status('client-a').get('mcvideo_alerting') is False
                and ids['client-a'] not in (status('client-b').get('mcvideo_alerts') or {})
            ),
            20,
        )
        observations['server'] = server()
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:2000], flush=True)
    finally:
        (args.artifacts / 'mcvideo-location.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
