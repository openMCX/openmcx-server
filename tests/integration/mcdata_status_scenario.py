#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise MCData enhanced status on-network (TS 24.282 clause 14.2): the client takes the
operational values from the group document (TS 24.282 clause 14.2.1.1), sends the "id" of one
as a group standalone SDS that the controlling function treats like any group SDS (TS 24.282
clause 9.2.2.4.2 step 6), and each receiving client renders the matching value or discards an
unknown one (TS 24.282 clause 14.2.1.2).

Run against a fixture prepared with --mcdata (see add_mcdata_policy in
tools/prepare-prearranged-test.py): group "operations" allows enhanced status
with the operational values 1 "On scene", 2 "En route" and 3 "Available";
"operations-noemergency" has values but does not allow enhanced status; client-c
may not transmit on "operations". Check IDs match tests/mcdata/MCDATA_STATUS_TEST.md.

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
# Run the scenario: check ES-01 to ES-05 and write the results file.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcdata')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    group = configs['client-a']['mcdata']['group_id']
    domain = group.split('@', 1)[1]
    group_user = group.split(':', 1)[1].split('@', 1)[0]
    not_allowed = f'sip:{group_user}-noemergency@{domain}'
    checks, observations = [], {}
    result = dict(scenario='mcdata-enhanced-status', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the container of a role writes, or {} while it is missing or partly written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The enhanced status fields of every client, attached to a failure.
    def snapshot():
        keep = (
            'mcdata_enhanced_status',
            'mcdata_enhanced_status_values',
            'mcdata_last_result',
            'mcdata_discarded',
            'last_error',
        )
        return {role: {key: value for key, value in status(role).items() if key in keep} for role in roles}

    # ------------------------------------------------------------------------------
    # Run one mcx-client command in the container of a role.
    def command(role, text):
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Poll a predicate until it holds (the check passes) or the timeout expires (the scenario fails).
    def wait(label, predicate, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    checks.append(label)
                    print(label, flush=True)
                    return
            except (KeyError, IndexError, TypeError):
                pass
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    # Record a passed check, or fail the scenario with a snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    # The enhanced statuses a client has rendered (TS 24.282 clause 14.2.1.2 step 3).
    def statuses(role):
        return status(role).get('mcdata_enhanced_status') or []

    # ------------------------------------------------------------------------------
    # The outcome of the last SDS a client sent.
    def last(role):
        return status(role).get('mcdata_last_result') or {}

    # ------------------------------------------------------------------------------
    # The outcome of the last SDS a client sent if it is of a message sent after the earlier outcome, else {}.
    def new_result(role, earlier):
        result = last(role)
        return result if result.get('message_id') not in (None, earlier.get('message_id')) else {}

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(role).get('mcdata_authorized') and status(role).get('mcdata_affiliated') for role in roles
            ),
            90,
        )

        # ES-01 the operational values come from the group document (TS 24.282 clause 14.2.1.1).
        command('client-a', f'sds-status-values {group}')
        wait(
            'ES-01 the group document allows enhanced status and names three operational values',
            lambda: (
                (status('client-a').get('mcdata_enhanced_status_values') or {}).get(group)
                == {
                    'allowed': True,
                    'values': [
                        {'id': '1', 'value': 'On scene'},
                        {'id': '2', 'value': 'En route'},
                        {'id': '3', 'value': 'Available'},
                    ],
                }
            ),
        )

        # ES-02 an enhanced status is a group standalone SDS whose payload is the "id"
        # of the operational value (TS 24.282 clause 14.2.1.1), rendered by each member
        # (TS 24.282 clause 14.2.1.2).
        earlier = last('client-a')
        command('client-a', f'sds-status {group} 1')
        wait(
            'ES-02 the group SDS carrying the enhanced status is accepted with 202',
            lambda: new_result('client-a', earlier).get('status') == 202,
        )
        wait(
            'ES-02 every other affiliated member renders "On scene" from its own group document',
            lambda: all(
                [
                    entry
                    for entry in statuses(role)
                    if entry['from'] == ids['client-a']
                    and entry['group'] == group
                    and entry['id'] == '1'
                    and entry['value'] == 'On scene'
                ]
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        check('ES-02 the sender does not receive its own status', not statuses('client-a'))
        command('client-b', f'sds-status {group} 2')
        wait(
            'ES-02 another member reports "En route"',
            lambda: all(
                [entry for entry in statuses(role) if entry['from'] == ids['client-b'] and entry['value'] == 'En route']
                for role in ['client-a', 'client-c', 'client-d']
            ),
        )

        # ES-03 the client checks <mcdata-allow-enhanced-status> and the values (TS 24.282 clause 14.2.1.1).
        command('client-a', f'sds-status {not_allowed} 1')
        wait(
            'ES-03 a group without <mcdata-allow-enhanced-status> is refused by the client',
            lambda: 'enhanced status is not allowed' in status('client-a').get('last_error', ''),
        )
        command('client-a', f'sds-status {group} 9')
        wait(
            'ES-03 an id that is not an operational value of the group is refused by the client',
            lambda: 'no operational value' in status('client-a').get('last_error', ''),
        )

        # ES-04 a received id without a matching operational value is discarded (TS 24.282 clause 14.2.1.2 step 3).
        discarded = {role: status(role).get('mcdata_discarded', 0) for role in ['client-b', 'client-c', 'client-d']}
        before = {role: len(statuses(role)) for role in ['client-b', 'client-c', 'client-d']}
        earlier = last('client-a')
        command('client-a', f'sds-status {group} 9 force')
        wait(
            'ES-04 the server relays it like any group SDS',
            lambda: new_result('client-a', earlier).get('status') == 202,
        )
        wait(
            'ES-04 each member discards the unknown operational value without rendering it',
            lambda: all(
                status(role).get('mcdata_discarded', 0) == discarded[role] + 1 and len(statuses(role)) == before[role]
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )

        # ES-05 an enhanced status is subject to the group SDS transmission control
        # (TS 24.282 clause 9.2.2.4.2 step 6).
        earlier = last('client-c')
        command('client-c', f'sds-status {group} 3')
        wait(
            'ES-05 a member without transmit permission on the group is rejected with 403/201',
            lambda: (
                new_result('client-c', earlier).get('status') == 403
                and '"201 ' in new_result('client-c', earlier).get('warning', '')
            ),
        )

        observations['rendered'] = {role: statuses(role) for role in roles}
        result['passed'] = True
    except (AssertionError, KeyError, IndexError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-status-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
