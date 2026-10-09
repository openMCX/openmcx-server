#!/usr/bin/env python3
"""MCVideo service authorisation and affiliation (TS 24.281 clauses 7 and 8): service authorisation by SIP
PUBLISH (TS 24.281 clauses 7.2.2 and 7.3.3), the affiliation status determination and change procedures
(TS 24.281 clauses 8.2.1.3 and 8.2.1.2) and a group the user is not a member of left out (TS 24.281 clause 8.2.2.2.3).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): the four clients are MCVideo members of group
operations; group video-closed has client-a as its only member. Each client
authorises for MCVideo by PUBLISH poc-settings to the MCVideo PSI (TS 24.281 clause 7.2.2),
subscribes to its affiliation status (TS 24.281 clause 8.2.1.3) and affiliates (TS 24.281 clause 8.2.1.2) at
mcvideo-server, beside its MCPTT service at mcptt-server. Check IDs match
tests/mcvideo/MCVIDEO_AFFILIATION_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
# Run the MCVideo affiliation scenario against the running lab, write integration/mcvideo-affiliation-results.json and
# return 0 when every check passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text())['mcvideo'] for role in ROLES}
    group = configs['client-a']['group_id']
    closed = f"sip:video-closed@{group.split('@', 1)[1]}"
    checks, observations = [], {}
    result = dict(scenario='mcvideo-affiliation', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the role last wrote, or {} while it has none.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # Poll the condition until it holds (recorded as a passed check; its value is returned) or the timeout expires
    # (AssertionError with every role's MCVideo status).
    def wait(label, condition, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = condition()
            if value:
                checks.append(label)
                return value
            time.sleep(0.5)
        raise AssertionError(
            f'{label} timed out: '
            + json.dumps(
                {
                    role: {key: value for key, value in status(role).items() if key.startswith('mcvideo')}
                    for role in ROLES + ['mcvideo-server']
                }
            )
        )

    # ------------------------------------------------------------------------------
    # Record the check as passed if the condition holds, else raise AssertionError with the detail.
    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)

    # ------------------------------------------------------------------------------
    # Run one mcx-client console command in the role's container.
    def command(role, text):
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
        )

    # ------------------------------------------------------------------------------
    # The client's last MCVideo result if it was for this action, else None.
    def last(role, action):
        outcome = status(role).get('mcvideo_last_result') or {}
        return outcome if outcome.get('action') == action else None

    # ------------------------------------------------------------------------------
    # The client's last MCVideo result if it was for this action, is not the earlier result and is a refusal (a
    # refresh of the client's own affiliation or authorisation may be answered 200 meanwhile), else None.
    def refusal(role, action, earlier):
        outcome = last(role, action)
        return outcome if outcome and outcome != earlier and outcome.get('status') != 200 else None

    try:
        # MV-AF-01 TS 24.281 clauses 7.2.2 and 7.3.3: every client authorises for MCVideo with its access
        # token and client ID; the MCVideo server binds its MCVideo ID.
        wait(
            'MV-AF-01 all four clients MCVideo authorised',
            lambda: all(status(role).get('mcvideo_authorized') for role in ROLES),
            60,
        )
        wait(
            'MV-AF-01 the MCVideo server holds four authorised users',
            lambda: status('mcvideo-server').get('authorized_users') == 4,
        )
        # MV-AF-02 TS 24.281 clause 8.2.1.3 then clause 8.2.1.2: the affiliation status is learnt by SUBSCRIBE,
        # the affiliation follows, and the NOTIFY echoes the PUBLISH's p-id.
        wait(
            'MV-AF-02 all four affiliated to operations',
            lambda: all(status(role).get('mcvideo_affiliated') for role in ROLES),
        )
        wait(
            'MV-AF-02 the MCVideo server holds four affiliated users',
            lambda: status('mcvideo-server').get('affiliated_users') == 4,
        )
        pids = status('client-a').get('mcvideo_affiliation_p_id', {})
        check(
            'MV-AF-02 NOTIFY echoes the p-id of the affiliation PUBLISH',
            pids.get('sent') and pids.get('sent') == pids.get('received'),
            pids,
        )
        # MV-AF-03 TS 24.281 clause 7.1: MCPTT keeps working on the same registration.
        check(
            'MV-AF-03 MCPTT authorised and affiliated beside MCVideo',
            all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
        )
        check(
            'MV-AF-03 the MCPTT server keeps its own users',
            status('mcptt-server').get('authorized_users') == 4 and status('mcptt-server').get('service') == 'mcptt',
        )
        # MV-AF-04 TS 24.281 clause 7.3.3 step 6: a refused access token gets 403 with warning 101.
        earlier = status('client-b').get('mcvideo_last_result')
        command('client-b', 'mcvideo-authorize not-a-valid-token')
        refused = wait('MV-AF-04 invalid token answered', lambda: refusal('client-b', 'authorize', earlier))
        observations['refused_authorisation'] = refused
        check(
            'MV-AF-04 403 with warning 101',
            refused['status'] == 403 and '101 service authorisation failed' in refused['warning'],
            refused,
        )
        check('MV-AF-04 the client stays authorised', status('client-b').get('mcvideo_authorized') is True)
        # MV-AF-05 TS 24.281 clause 8.2.2.2.3 step 8: the PUBLISH naming a group the user is not an MCVideo member of
        # is answered 200 (OK); the group is refused by its controlling function (clause 8.2.2.3.3) and removed, so
        # the NOTIFY (clause 8.2.2.2.5) still lists operations only.
        earlier = status('client-b').get('mcvideo_last_result')
        command('client-b', f'mcvideo-affiliate {closed}')
        outcome = wait(
            'MV-AF-05 non-member affiliation answered',
            lambda: (lambda result: result if result and result != earlier else None)(last('client-b', 'affiliate')),
        )
        observations['non_member_affiliation'] = outcome
        check('MV-AF-05 200 for a PUBLISH naming a non-member group', outcome['status'] == 200, outcome)
        wait(
            'MV-AF-05 still affiliated to operations only',
            lambda: status('client-b').get('mcvideo_affiliations') == [group],
        )
        # MV-AF-06 a member affiliates to a second group; the NOTIFY lists both.
        command('client-a', f'mcvideo-affiliate {closed}')
        wait(
            'MV-AF-06 member affiliated to video-closed too',
            lambda: sorted(status('client-a').get('mcvideo_affiliations', [])) == sorted([group, closed]),
        )
        # MV-AF-07 TS 24.281 clause 8.2.1.2: de-affiliation with Expires 0.
        command('client-d', 'mcvideo-deaffiliate')
        wait('MV-AF-07 client-d de-affiliated', lambda: status('client-d').get('mcvideo_affiliated') is False)
        wait(
            'MV-AF-07 the MCVideo server holds three affiliated users',
            lambda: status('mcvideo-server').get('affiliated_users') == 3,
        )
        check('MV-AF-07 MCPTT affiliation of client-d untouched', status('client-d').get('affiliated') is True)
        observations['mcvideo_server'] = {
            key: status('mcvideo-server').get(key) for key in ('authorized_users', 'affiliated_users')
        }
        result['passed'] = True
    except AssertionError as error:
        result['error'] = str(error)
    output = args.artifacts / 'integration/mcvideo-affiliation-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
