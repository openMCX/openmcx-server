#!/usr/bin/env python3
"""Exercise MCPTT location management (TS 24.379 clauses 13, 6.3.2.4, 12.1.1.4 and 12.1.1.6).

Run against a four-client fixture prepared with --priority --location. Check IDs
match tests/mcptt/LOCATION_TEST.md. Positions are simulated: each client starts
at its own point near 48 N 2 E and is moved by the "location position" command.

The SEAL checks (SL) use the location management server of TS 24.545 V19.4.0.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.545 V19.4.0 (cited, not kept locally).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
ZONE = (48.01, 2.0)  # the configured reporting zone (TriggerIds t4 enter, t5 exit)
HAZARD = (48.05, 2.05)  # an emergency alert area
GROUP_AREA = (48.02, 2.02)  # the group's geographic area
# Two E-UTRAN cell global identities (PLMN 208 01, as text) for the cell change trigger.
ECGI_1 = '208010' + '0' * 27 + '1'
ECGI_2 = '208010' + '0' * 26 + '10'


# ------------------------------------------------------------------------------
def main():
    """Run the location checks LOC-01 to LOC-17 and the SEAL checks SL-01 to SL-06, and write location.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-location')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {item: json.loads((generated / f'{item}.json').read_text()) for item in roles}
    ids = {item: configs[item]['mcptt']['user_id'] for item in roles}
    server_config = json.loads((generated / 'mcptt-server.json').read_text())
    if 'location' not in server_config['mcptt']:
        parser.error('the fixture must be prepared with --location')
    group = configs['client-a']['mcptt']['group_id']
    checks, observations = [], {}
    result = dict(scenario='location', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The container's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The location and SEAL part of every client's and the server's status, for the failure report."""
        return {
            item: {'location': status(item).get('location'), 'seal': status(item).get('seal')}
            for item in roles + ['mcptt-server']
        }

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=15):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.1)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record the label as a passed check if the condition holds; raise with a snapshot otherwise."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot()))
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def loc(role):
        """The role's location state, or {}."""
        return status(role).get('location') or {}

    # ------------------------------------------------------------------------------
    def server():
        """The server's location state, or {}."""
        return status('mcptt-server').get('location') or {}

    # ------------------------------------------------------------------------------
    def counter(name):
        """One location counter of the server."""
        return server().get('counters', {}).get(name, 0)

    # ------------------------------------------------------------------------------
    def sent(role):
        """The location reports the role sent."""
        return loc(role).get('sent', [])

    # ------------------------------------------------------------------------------
    def received(role):
        """The location reports the role received for its requests."""
        return loc(role).get('received', [])

    # ------------------------------------------------------------------------------
    def stored(role):
        """What the participating function stores for the role's user."""
        return server().get('users', {}).get(ids[role], {})

    # ------------------------------------------------------------------------------
    def near(coordinate, lat, lon, tolerance=1e-4):
        """The coordinate is within the tolerance of the latitude and longitude."""
        return (
            bool(coordinate)
            and abs(coordinate['latitude'] - lat) < tolerance
            and abs(coordinate['longitude'] - lon) < tolerance
        )

    # ------------------------------------------------------------------------------
    def reports_with(role, trigger, after=0):
        """The role's reports, from index `after` on, that name the trigger."""
        return [item for item in sent(role)[after:] if trigger in item.get('triggers', [])]

    # ------------------------------------------------------------------------------
    def last_result(role):
        """The role's last location request result, or {}."""
        return status(role).get('location_last_result') or {}

    # ------------------------------------------------------------------------------
    def move(role, lat, lon):
        """Set the role's simulated position."""
        command(role, f'location position {lat} {lon}')

    # ------------------------------------------------------------------------------
    def answered(role, request_id):
        """The location reports the role received for the request ID."""
        return [item for item in received(role) if item.get('id') == request_id]

    # ------------------------------------------------------------------------------
    def request(role, *words):
        """Issue a location request on the role (TS 24.379 clause 13.2.3.2) and wait until it is sent; its
        request ID."""
        before = status(role).get('location_last_request')
        command(role, 'location request ' + ' '.join(words))
        wait(
            f'{role} issued a location request',
            lambda: status(role).get('location_last_request') not in (None, before),
            5,
        )
        return status(role)['location_last_request']

    try:
        # LOC-01: TS 24.379 clause 13.2.2, every served user is configured upon service authorisation.
        wait(
            'LOC-01 every client holds the reporting configuration sent after its authorisation',
            lambda: all(loc(item).get('configured') for item in roles) and counter('configured') >= 4,
            30,
        )
        configuration = stored('client-a').get('configuration', {})
        check(
            'LOC-01 the stored configuration numbers its triggers t1 to t6, the emergency periodic trigger t7',
            configuration.get('triggers') == ['t1', 't2', 't3', 't4', 't5', 't6']
            and configuration.get('emergency_triggers') == ['t7']
            and configuration.get('minimum_interval') == 1,
        )

        # LOC-02: InitialLogOn fires once the configuration arrives (TS 24.379 clause 13.3.4).
        wait(
            'LOC-02 each reporting client reports its log-on position (trigger t1)',
            lambda: all(reports_with(item, 't1') for item in ['client-a', 'client-b', 'client-c']),
            20,
        )
        wait(
            'LOC-02 the participating function stores each report with its coordinate',
            lambda: all(
                near(stored(item).get('report', {}).get('coordinate'), 48.0, 2.0 + 0.01 * index)
                for index, item in enumerate(['client-a', 'client-b', 'client-c'])
            ),
        )
        report = sent('client-a')[0]
        check(
            'LOC-02 the report is NonEmergency, time-stamped, with the coordinate requested',
            report.get('emergency') is False
            and report.get('timestamp', '').endswith('Z')
            and near(report.get('coordinate'), 48.0, 2.0),
        )
        # LOC-03: a user whose profile denies reporting (TS 24.379 clause 13.2.4.1).
        wait(
            'LOC-03 a user not authorised to report is refused 403 and nothing is stored',
            lambda: sent('client-d') and not stored('client-d').get('report') and counter('refused') >= 1,
        )

        # LOC-04: travelled distance (250 m).
        before = len(sent('client-a'))
        move('client-a', 48.0, 2.004)
        wait(
            'LOC-04 moving 300 m fires the travelled-distance trigger t3',
            lambda: reports_with('client-a', 't3', before),
        )
        wait(
            'LOC-04 the new coordinate is stored',
            lambda: near(stored('client-a').get('report', {}).get('coordinate'), 48.0, 2.004),
        )

        # LOC-05: area entry and exit with border widths.
        before = len(sent('client-a'))
        move('client-a', *ZONE)
        wait('LOC-05 entering the configured zone fires t4', lambda: reports_with('client-a', 't4', before))
        before = len(sent('client-a'))
        move('client-a', 48.0, 2.004)
        wait('LOC-05 leaving it fires t5', lambda: reports_with('client-a', 't5', before))

        # LOC-06: cell change; the serving ECGI is part of what is requested.
        command('client-a', f'location radio cell {ECGI_1}')
        before = len(sent('client-a'))
        command('client-a', f'location radio cell {ECGI_2}')
        wait(
            'LOC-06 a cell change fires t6 and the report carries the serving ECGI',
            lambda: any(item.get('serving_ecgi') == ECGI_2 for item in reports_with('client-a', 't6', before)),
        )

        # LOC-07: a non-emergency group call is a signalling event trigger.
        before = len(sent('client-a'))
        command('client-a', 'call')
        wait('LOC-07 a group call fires t2', lambda: reports_with('client-a', 't2', before))
        command('client-a', 'hangup')
        wait('LOC-07 the call ends', lambda: status('client-a').get('call_state') == 'idle', 20)

        # LOC-08: TS 24.379 clause 13.2.3.2, an authorised user's request answered from what is stored or fresh.
        requested = counter('requested')
        rid = request('client-a', ids['client-b'])
        wait(
            'LOC-08 the requester receives the report with its RequestId and the reporting user',
            lambda: any(
                item.get('reporting_uri') == ids['client-b'] and near(item.get('coordinate'), 48.0, 2.01)
                for item in answered('client-a', rid)
            ),
        )
        check('LOC-08 the request was accepted 200', last_result('client-a').get('status') == 200)
        # LOC-09: refresh makes the participating function ask the client (TS 24.379 clause 13.2.3.1).
        b_before = len(sent('client-b'))
        rid = request('client-a', 'refresh', ids['client-b'])
        wait(
            'LOC-09 with refresh the participating function requests the client, which answers at once',
            lambda: (
                counter('requested') > requested
                and any(item.get('id') and item.get('id') != rid for item in sent('client-b')[b_before:])
            ),
        )
        wait('LOC-09 the fresh report reaches the requester', lambda: answered('client-a', rid))

        # LOC-10: LocationFilter against the configured zone t4.
        rid = request('client-a', 'filter', 't4', 'in', ids['client-b'])
        check(
            'LOC-10 a filter for users inside the zone yields no report for a user outside it',
            holds(lambda: not answered('client-a', rid), 3),
        )
        rid = request('client-a', 'filter', 't4', 'out', ids['client-b'])
        wait('LOC-10 a filter for users outside the zone yields the report', lambda: answered('client-a', rid))

        # LOC-11: the requested user does not share with the requester (silently ignored).
        rid = request('client-a', ids['client-c'])
        check(
            'LOC-11 a user sharing only with another user is not reported to the requester',
            holds(lambda: not answered('client-a', rid), 3) and last_result('client-a').get('status') == 200,
        )

        # LOC-12 to LOC-14: refusals of TS 24.379 clauses 13.2.3.2 and 13.2.2A.
        request('client-b', ids['client-a'])
        wait(
            'LOC-12 a user without the right to request is refused 403 warning 193',
            lambda: (
                last_result('client-b').get('status') == 403 and '193' in last_result('client-b').get('warning', '')
            ),
        )
        request('client-a', 'no-list')
        wait(
            'LOC-13 a request naming no one is refused 403 warning 192',
            lambda: (
                last_result('client-a').get('status') == 403 and '192' in last_result('client-a').get('warning', '')
            ),
        )
        command('client-c', f'location configure {ids["client-a"]} ' + json.dumps({'triggers': [{'periodic': 5}]}))
        wait(
            'LOC-14 a user without the right to configure is refused 403 warning 194',
            lambda: (
                last_result('client-c').get('status') == 403 and '194' in last_result('client-c').get('warning', '')
            ),
        )

        # LOC-15: TS 24.379 clause 13.2.2A, an authorised user adds a periodic trigger for another user.
        update = {'scope': 'update', 'triggers': [{'periodic': 2, 'id': 'every-2s'}]}
        command('client-a', f'location configure {ids["client-b"]} ' + json.dumps(update))
        wait(
            'LOC-15 the configuration change is accepted and the target holds the added trigger',
            lambda: (
                last_result('client-a').get('status') == 200
                and 'every-2s' in loc('client-b').get('configuration', {}).get('triggers', [])
                and 'every-2s' in stored('client-b').get('configuration', {}).get('triggers', [])
            ),
        )
        before = len(sent('client-b'))
        wait(
            'LOC-15 the target reports periodically', lambda: len(reports_with('client-b', 'every-2s', before)) >= 2, 10
        )

        # LOC-16: TS 24.379 clauses 6.3.2.4.2 and 12.1.1.4, the group's geographic area.
        check('LOC-16 client-c starts affiliated', status('client-c').get('affiliated') is True)
        move('client-c', *GROUP_AREA)
        wait(
            'LOC-16 entering the group area is notified and recorded on 200',
            lambda: (
                any(
                    notice.get('kind') == 'group_geographic_area' and notice.get('entered') is True
                    for notice in loc('client-c').get('area_notices', [])
                )
                and stored('client-c').get('areas', {}).get('group:' + group) is True
            ),
        )
        move('client-c', 48.0, 2.02)
        wait(
            'LOC-16 leaving it is notified and the client de-affiliates from the group',
            lambda: (
                stored('client-c').get('areas', {}).get('group:' + group) is False
                and status('client-c').get('affiliated') is False
            ),
        )
        move('client-c', *GROUP_AREA)
        wait(
            'LOC-16 entering it again affiliates the client once more',
            lambda: status('client-c').get('affiliated') is True,
        )

        # LOC-17: TS 24.379 clauses 6.3.2.4.1 and 12.1.1.6, an emergency alert area starts an alert.
        move('client-b', *HAZARD)
        wait(
            'LOC-17 entering the emergency alert area is notified and the client raises an alert',
            lambda: (
                stored('client-b').get('areas', {}).get('alert:hazard') is True
                and ids['client-b'] in status('mcptt-server').get('group_priority', {}).get(group, {}).get('alerts', [])
            ),
            20,
        )
        before = len(sent('client-b'))
        wait(
            'LOC-17 in the emergency state the client reports Emergency on the emergency trigger t7',
            lambda: any(item.get('emergency') is True for item in reports_with('client-b', 't7', before)),
            10,
        )
        # Only client-a may cancel alerts in this fixture (TS 24.379 clause 12.1.1.5 NOTE 2: a user may lack the right
        # to clear its own alert), so client-a clears client-b's.
        command('client-a', f'alert off {ids["client-b"]}')
        move('client-b', 48.0, 2.01)
        wait(
            'LOC-17 leaving the area is notified; the alert is cleared by an authorised user',
            lambda: (
                stored('client-b').get('areas', {}).get('alert:hazard') is False
                and ids['client-b']
                not in status('mcptt-server').get('group_priority', {}).get(group, {}).get('alerts', [])
            ),
            20,
        )

        observations['server'] = server()
        observations['clients'] = {
            item: {key: value for key, value in loc(item).items() if key in ('configuration', 'area_notices')}
            for item in roles
        }

        # ------------------------------------------------------------------------------
        # SL: the SEAL location management server (TS 24.545 V19.4.0) in the LMS.
        def server_command(text):
            """Run one openmcx-mcptt-server command at the MCPTT server; a failure raises RuntimeError."""
            run = subprocess.run(
                cli
                + [
                    'exec',
                    '-T',
                    'mcptt-server',
                    'openmcx-mcptt-server',
                    '--config',
                    '/config/mcptt-server.json',
                    '--command',
                    text,
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if run.returncode:
                raise RuntimeError(f'mcptt-server {text}: {run.stderr.strip() or run.stdout.strip()}')

        # ------------------------------------------------------------------------------
        def seal(role):
            """The container's SEAL location management state, or {}."""
            return status(role).get('seal') or {}

        # ------------------------------------------------------------------------------
        def seal_at(user):
            """The position of the user that the MCPTT server learnt through SEAL, or {}."""
            return (seal('mcptt-server').get('positions') or {}).get(user) or {}

        # SL-01 TS 24.545 clause 6.2.2.2.1: bob's client reads its reporting configuration.
        command('client-b', 'seal start')
        wait(
            'SL-01 bob\'s client reads its configuration: a periodic report every 2 seconds',
            lambda: (
                seal('client-b').get('started')
                and seal('client-b').get('periodic') == 2
                and '/seal-lm/v1/users/' in seal('client-b').get('report_uri', '')
            ),
        )
        wait(
            'SL-01 it reports its position (6.2.2.2.2)',
            lambda: seal('client-b').get('reports_sent', 0) >= 2 and seal('client-b').get('last_status') == 200,
            20,
        )
        # SL-02 TS 24.545 clause 6.2.6.1.2: the MCPTT server subscribes to three users' location.
        users = [ids['client-b'], ids['client-c'], ids['client-d']]
        server_command(f"seal-subscribe {','.join(users)} 1 120")
        wait(
            'SL-02 the MCPTT server subscribes to the location of bob, carol and dave',
            lambda: (
                seal('mcptt-server').get('subscription')
                and sorted(seal('mcptt-server').get('users', [])) == sorted(users)
            ),
        )
        # SL-03 TS 24.545 clause 6.2.7: bob's position is notified.
        wait(
            'SL-03 bob\'s reported position is notified to the MCPTT server',
            lambda: (
                near(seal_at(ids['client-b']), 48.0, 2.01) and seal_at(ids['client-b']).get('via') == 'notification'
            ),
            20,
        )
        move('client-b', 48.1, 2.1)
        wait('SL-03 bob moves: the new position is notified', lambda: near(seal_at(ids['client-b']), 48.1, 2.1), 20)
        # SL-04 TS 24.545 clause 6.2.8: on demand.
        server_command(f"seal-locate {ids['client-b']}")
        wait(
            'SL-04 the MCPTT server asks for bob\'s location on demand and gets it',
            lambda: (
                (seal('mcptt-server').get('last_request') or {}).get('status') == 200
                and (seal('mcptt-server').get('last_request') or {}).get('reports') == 1
                and seal_at(ids['client-b']).get('via') == 'request'
            ),
        )
        # SL-05 TS 24.545 clause 6.2.20: while offline, bob's client stores its positions; back online
        # it sends them in a history location result report, notified as history.
        command('client-b', 'seal offline')
        move('client-b', 48.2, 2.2)
        wait(
            'SL-05 offline, bob\'s client stores the positions its trigger produces',
            lambda: seal('client-b').get('stored', 0) >= 2,
            20,
        )
        sent_before = seal('client-b').get('reports_sent', 0)
        command('client-b', 'seal online')
        wait(
            'SL-05 back online it sends them in a history location result report',
            lambda: seal('client-b').get('history_sent', 0) >= 2 and seal('client-b').get('stored') == 0,
        )
        wait(
            'SL-05 the MCPTT server is notified of bob\'s history',
            lambda: any(
                near(entry, 48.2, 2.2) for entry in (seal('mcptt-server').get('history') or {}).get(ids['client-b'], [])
            ),
            20,
        )
        server_command(f"seal-locate history {ids['client-b']}")
        wait(
            'SL-05 on demand, the history comes with the reported positions',
            lambda: (
                (seal('mcptt-server').get('last_request') or {}).get('reports', 0)
                > seal('client-b').get('history_sent', 0)
                and seal('client-b').get('reports_sent', 0) > sent_before
            ),
        )
        # SL-06 unsubscription.
        server_command('seal-unsubscribe')
        wait('SL-06 the MCPTT server unsubscribes', lambda: seal('mcptt-server').get('subscription') == '')
        command('client-b', 'seal stop')
        observations['seal'] = seal('mcptt-server')
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:2000], flush=True)
    finally:
        (args.artifacts / 'location.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
