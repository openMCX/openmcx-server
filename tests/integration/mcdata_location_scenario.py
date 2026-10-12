#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise MCData location management: location reporting configuration (TS 24.282 clauses 17.2.2
and 17.3.2), location information requests (TS 24.282 clauses 17.2.3.2 and 17.3.3.2, refused with
the Warning codes 244, 245 and 246 of TS 24.282 table 4.9.2-2), location information reports and
their triggers (TS 24.282 clauses 17.2.4.1 and 17.3.4), and the notifications of entry into or exit
from an emergency alert area and a group geographic area (TS 24.282 clauses 6.3.7.1.6, 6.3.7.1.7,
16.2.1.4 and 16.2.1.5). With --protected, the location XML is confidentiality protected
(TS 33.180 clause 9.3).

Run against a four-client fixture prepared with --mcdata --location (optionally
--protected, which encrypts the location XML with each client's CSK). Check IDs match
tests/mcdata/MCDATA_LOCATION_TEST.md. Positions are simulated with "location position".

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
ZONE = (48.01, 2.0)
HAZARD = (48.05, 2.05)
GROUP_AREA = (48.02, 2.02)


# ------------------------------------------------------------------------------
# Run the MCData location scenario against the running lab, write mcdata-location.json and return 0 when every check
# passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcdata-location')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    if any('mcdata' not in configs[role] for role in roles):
        parser.error('the fixture must be prepared with --mcdata --location')
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    group = configs['client-a']['mcdata']['group_id']
    protected = configs['client-a']['mcdata'].get('confidentiality_protection', False)
    checks, observations = [], dict(protected=protected)
    result = dict(scenario='mcdata-location', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the role last wrote, or {} while it has none.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The location part of every client's and the MCData server's status, attached to a failure.
    def snapshot():
        return {role: status(role).get('mcdata_location') for role in roles} | {
            'mcdata-server': status('mcdata-server').get('location')
        }

    # ------------------------------------------------------------------------------
    # Run one mcx-client console command in the role's container.
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
    # Poll the predicate until it holds (recorded as a passed check) or the timeout expires (AssertionError).
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
    # Record the check as passed if the condition holds, else raise AssertionError with the snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot()))
        checks.append(label)
        print(label, flush=True)

    loc = lambda role: status(role).get('mcdata_location') or {}
    server = lambda: status('mcdata-server').get('location') or {}
    counter = lambda name: server().get('counters', {}).get(name, 0)
    sent = lambda role: loc(role).get('sent', [])
    received = lambda role: loc(role).get('received', [])
    stored = lambda role: server().get('users', {}).get(ids[role], {})
    last_result = lambda role: status(role).get('mcdata_location_last_result') or {}

    # ------------------------------------------------------------------------------
    # Whether the reported coordinate lies within the tolerance of the given latitude and longitude.
    def near(coordinate, lat, lon, tolerance=1e-4):
        return (
            bool(coordinate)
            and abs(coordinate['latitude'] - lat) < tolerance
            and abs(coordinate['longitude'] - lon) < tolerance
        )

    # ------------------------------------------------------------------------------
    # The location reports the client sent, from index 'after' on, that name the trigger.
    def reports_with(role, trigger, after=0):
        return [report for report in sent(role)[after:] if trigger in report.get('triggers', [])]

    # ------------------------------------------------------------------------------
    # Set the client's simulated position.
    def move(role, lat, lon):
        command(role, f'location position {lat} {lon}')

    # ------------------------------------------------------------------------------
    # The location reports the client received in answer to the request with this RequestId.
    def answered(role, request_id):
        return [report for report in received(role) if report.get('id') == request_id]

    # ------------------------------------------------------------------------------
    # The client sends a location information request (TS 24.282 clause 17.3.3.2); returns its RequestId.
    def request(role, *words):
        before = status(role).get('mcdata_location_last_request')
        command(role, 'mcdata-location request ' + ' '.join(words))
        wait(
            f'{role} issued an MCData location request',
            lambda: status(role).get('mcdata_location_last_request') not in (None, before),
            5,
        )
        return status(role)['mcdata_location_last_request']

    try:
        wait(
            'MDL-01 every MCData client holds the configuration sent after its MCData service authorisation',
            lambda: all(loc(role).get('configured') for role in roles) and counter('configured') >= 4,
            40,
        )
        check(
            'MDL-01 the participating MCData function stores it with TriggerIds t1 to t7',
            stored('client-a').get('configuration', {}).get('triggers') == ['t1', 't2', 't3', 't4', 't5', 't6']
            and stored('client-a').get('configuration', {}).get('emergency_triggers') == ['t7'],
        )
        wait(
            'MDL-02 each reporting client reports its log-on position',
            lambda: all(
                near(stored(role).get('report', {}).get('coordinate'), 48.0, 2.0 + 0.01 * index)
                for index, role in enumerate(['client-a', 'client-b', 'client-c'])
            ),
            20,
        )
        # The server's refusal count, as the client's last_error is shared with its MCPTT side.
        wait(
            'MDL-03 a user not authorised to report is refused 403 and nothing is stored',
            lambda: sent('client-d') and counter('refused') >= 1 and not stored('client-d').get('report'),
        )

        before = len(sent('client-a'))
        move('client-a', *ZONE)
        wait(
            'MDL-04 moving into the zone fires the travelled-distance t3 and zone-entry t4 triggers',
            lambda: reports_with('client-a', 't4', before) and reports_with('client-a', 't3', before),
        )
        wait(
            'MDL-04 the stored position follows',
            lambda: near(stored('client-a').get('report', {}).get('coordinate'), *ZONE),
        )

        rid = request('client-a', ids['client-b'])
        wait(
            'MDL-05 an authorised request is answered with the RequestId, the reporting MCData ID and the position',
            lambda: any(
                report.get('reporting_uri') == ids['client-b'] and near(report.get('coordinate'), 48.0, 2.01)
                for report in answered('client-a', rid)
            ),
        )
        requested = counter('requested')
        rid = request('client-a', 'refresh', ids['client-b'])
        wait(
            'MDL-06 with refresh the participating function asks the client first',
            lambda: counter('requested') > requested and answered('client-a', rid),
        )
        rid = request('client-a', 'filter', 't4', 'in', ids['client-b'])
        check(
            'MDL-07 a LocationFilter for users inside the zone excludes a user outside it',
            holds(lambda: not answered('client-a', rid), 3),
        )
        rid = request('client-a', ids['client-c'])
        check(
            'MDL-08 a user sharing only with another user is not reported',
            holds(lambda: not answered('client-a', rid), 3),
        )

        request('client-b', ids['client-a'])
        wait(
            'MDL-09 a user without the right to request is refused 403 warning 245',
            lambda: (
                last_result('client-b').get('status') == 403 and '245' in last_result('client-b').get('warning', '')
            ),
        )
        request('client-a', 'no-list')
        wait(
            'MDL-09 a request naming no one is refused 403 warning 244',
            lambda: (
                last_result('client-a').get('status') == 403 and '244' in last_result('client-a').get('warning', '')
            ),
        )
        command(
            'client-c', f'mcdata-location configure {ids["client-a"]} ' + json.dumps({'triggers': [{'periodic': 5}]})
        )
        wait(
            'MDL-09 a user without the right to configure is refused 403 warning 246',
            lambda: (
                last_result('client-c').get('status') == 403 and '246' in last_result('client-c').get('warning', '')
            ),
        )

        command(
            'client-a',
            f'mcdata-location configure {ids["client-b"]} '
            + json.dumps({'scope': 'update', 'triggers': [{'periodic': 2, 'id': 'every-2s'}]}),
        )
        wait(
            'MDL-10 an authorised user adds a periodic trigger and the target reports on it',
            lambda: last_result('client-a').get('status') == 200 and len(reports_with('client-b', 'every-2s')) >= 2,
            15,
        )

        check(
            'MDL-11 client-c starts affiliated to its MCData group', status('client-c').get('mcdata_affiliated') is True
        )
        move('client-c', *GROUP_AREA)
        wait(
            'MDL-11 entering the group geographic area is notified and recorded',
            lambda: stored('client-c').get('areas', {}).get('group:' + group) is True,
        )
        move('client-c', 48.0, 2.02)
        wait(
            'MDL-11 leaving it de-affiliates the client from the MCData group',
            lambda: (
                stored('client-c').get('areas', {}).get('group:' + group) is False
                and status('client-c').get('mcdata_affiliated') is False
            ),
        )
        move('client-c', *GROUP_AREA)
        wait(
            'MDL-11 entering it again affiliates the client once more',
            lambda: status('client-c').get('mcdata_affiliated') is True,
        )

        move('client-a', *HAZARD)
        wait(
            'MDL-12 entering the emergency alert area starts an MCData emergency alert',
            lambda: (
                stored('client-a').get('areas', {}).get('alert:hazard') is True
                and ids['client-a'] in status('mcdata-server').get('emergency_alerts', {}).get(group, [])
            ),
            20,
        )
        before = len(sent('client-a'))
        wait(
            'MDL-12 in the emergency state the client reports Emergency on the emergency trigger t7',
            lambda: any(report.get('emergency') is True for report in reports_with('client-a', 't7', before)),
            10,
        )
        command('client-a', 'mcdata-alert cancel')
        move('client-a', 48.0, 2.0)
        wait(
            'MDL-12 leaving the area is notified and the cancelled alert is gone',
            lambda: (
                stored('client-a').get('areas', {}).get('alert:hazard') is False
                and ids['client-a'] not in status('mcdata-server').get('emergency_alerts', {}).get(group, [])
            ),
            20,
        )
        if protected:
            xml = status('mcdata-server').get('xml_protection') or {}
            check(
                'MDL-13 with confidentiality protection the location XML was encrypted and decrypted, none refused',
                xml.get('encrypted', 0) > 0 and xml.get('decrypted', 0) > 0 and xml.get('refused', 0) == 0,
            )
            observations['xml_protection'] = xml
        observations['server'] = server()
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:2000], flush=True)
    finally:
        (args.artifacts / 'mcdata-location.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
