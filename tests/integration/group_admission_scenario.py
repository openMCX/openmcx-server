#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Group calls refused by the group document and its call policy.

Run in a lab prepared with --admission-groups: four groups of the four clients, each refusing a group call for one
reason. The scenario checks that the controlling function refuses
  - GA-01 a call on a group with <on-network-disabled> with 403 (Forbidden) and warning "115 group is disabled"
    (TS 24.379 clause 6.3.5.2 step 5a);
  - GA-02 a call from a member the call policy does not allow to initiate one with 403 and warning "119 user is not
    authorised to initiate the group call" (clause 10.1.1.4.2);
  - GA-03 a member the policy does not allow to join an ongoing call with 403 and warning "121 user is not authorised
    to join the group call" (clause 6.3.5.3), while the members it allows are in the call;
  - GA-04 a call while a required member is not affiliated with 480 (Temporarily Unavailable) and warning "112 group
    call abandoned due to required group members not part of the group session" (clause 6.3.8.2);
  - GA-05 a chat join that needs an implicit affiliation beyond the user's N2 limit with 486 (Busy Here) and warning
    "102 too many simultaneous affiliations" (clause 10.1.2.3.1.1 step 7), also for an emergency request the user is
    not authorised for; an authorised emergency request is spared by local policy (NOTE 5, clause 6.3.2.1.8.1).

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/group-admission-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-group-admission')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    checks, observations = [], {}
    result = dict(scenario='group-admission', passed=False, checks=checks, observations=observations)

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
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps({role: status(role) for role in ROLES})[:4000])

    # ------------------------------------------------------------------------------
    def select(roles, group):
        """Select (and affiliate the roles to) the group; wait until each is affiliated and on it."""
        for role in roles:
            command(role, 'group ' + group)
        wait(
            f'{", ".join(roles)} on {group}',
            lambda: all(status(role).get('affiliated') and status(role).get('group_id') == group for role in roles),
        )

    # ------------------------------------------------------------------------------
    def refused(label, role, code, warning):
        """Call from role on its group; wait until the call failed with code and warning."""
        before = status(role).get('last_call_failure')
        command(role, 'call')

        def failed():
            failure = status(role).get('last_call_failure') or {}
            return (
                failure != before
                and status(role).get('call_state') == 'idle'
                and failure.get('status') == code
                and warning in failure.get('warning', '')
            )

        wait(label, failed)
        observations[label.split()[0]] = status(role).get('last_call_failure')

    try:
        wait(
            'four clients authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        base = status('client-a').get('group_id')
        group = {kind: base.replace('@', f'-{kind}@') for kind in ('disabled', 'initiate', 'join', 'required')}

        select(['client-a'], group['disabled'])
        refused('GA-01 a call on a disabled group: 403 with warning 115', 'client-a', 403, '115 group is disabled')

        select(['client-a'], group['initiate'])
        refused(
            'GA-02 a call from a member not allowed to initiate: 403 with warning 119',
            'client-a',
            403,
            '119 user is not authorised to initiate the group call',
        )

        select(['client-a', 'client-b', 'client-c'], group['join'])
        command('client-b', 'call')
        wait(
            'GA-03 client-b calls, client-c is in the call',
            lambda: all(status(role).get('call_state') not in (None, 'idle') for role in ('client-b', 'client-c')),
        )
        wait('GA-03 client-a, not allowed to join, is not invited', lambda: status('client-a').get('call_state') == 'idle')
        refused(
            'GA-03 a member not allowed to join the ongoing call: 403 with warning 121',
            'client-a',
            403,
            '121 user is not authorised to join the group call',
        )
        command('client-b', 'hangup')
        wait('GA-03 the call ends', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))

        select(['client-a', 'client-b'], group['required'])
        refused(
            'GA-04 a call while the required member client-d is not affiliated: 480 with warning 112',
            'client-a',
            480,
            '112 group call abandoned due to required group members not part of the group session',
        )
        select(['client-a', 'client-b', 'client-c'], base)

        # GA-05: client-c and client-d are affiliated to their group, which is their N2 limit of 1; joining the chat
        # group needs an implicit affiliation.
        chat = base.replace('@', '-n2chat@')

        def outcomes(role):
            """How many refused chat joins the role's client has logged."""
            run = subprocess.run(
                cli + ['logs', '--no-color', '--no-log-prefix', role], capture_output=True, text=True, timeout=30
            )
            return run.stdout.count('"reason":"chat join: ')

        def join(label, role, text, code, warning=''):
            # Two refusals in a row leave the same last_call_failure, so a refusal is told apart by the count.
            before = outcomes(role)
            command(role, f'chat-join {text}')
            wait(
                label,
                lambda: (
                    (code < 300 or outcomes(role) > before)
                    and (failure := status(role).get('last_call_failure') or {}).get('status') == code
                    and warning in failure.get('warning', '')
                ),
            )
            wait(f'{label}: client back to idle', lambda: status(role).get('call_state') == 'idle')
            observations[label.split(' ', 2)[1]] = status(role).get('last_call_failure')

        join('GA-05 d a chat join beyond N2: 486 with warning 102', 'client-d', chat, 486, '102 too many simultaneous')
        join(
            'GA-05 e an unauthorised emergency chat join beyond N2: 486 with warning 102',
            'client-d',
            f'{chat} emergency',
            486,
            '102 too many simultaneous',
        )
        join('GA-05 c an authorised emergency chat join beyond N2 is accepted', 'client-c', f'{chat} emergency', 200)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'group-admission-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
