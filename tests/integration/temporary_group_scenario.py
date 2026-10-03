#!/usr/bin/env python3
"""Exercise temporary groups formed by the GMS and the group and chat calls on them.

Formation: the GMS refuses a user not authorised to form temporary groups (TS 24.481 clause 6.3.14.3.1 step b)), asks
the GMS of each constituent group to check and mark it (clauses 6.3.14.3.1 and 6.3.14.3.2) and creates the temporary
group's document; a constituent group is in one temporary group at a time and carries no call of its own while combined
(TS 24.379 warning 148). Group calls and chat group calls on the temporary group identity reach the members of both
constituent groups (TS 24.379 clauses 10.1.1 and 10.1.2). Tear down by the requester only (TS 24.481 clause 6.3.15) ends
the call and frees the constituent groups.

Run against a fixture prepared with --regroup (see add_regroup_policy in tools/prepare-prearranged-test.py): client-a
may form temporary groups, client-b may not, and the two constituent groups hold the members. Check IDs match
tests/mcptt/TEMPORARY_GROUP_TEST.md.

Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the checks TG-01 to TG-08 and write integration/temporary-group-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-regroup')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    north = configs['client-a']['mcptt']['group_id']
    south = configs['client-c']['mcptt']['group_id']
    domain = north.split('@', 1)[1]
    group_user = north.split(':', 1)[1].split('-north@', 1)[0]
    tgi = f'sip:{group_user}-temp-1@{domain}'
    chat_tgi = f'sip:{group_user}-temp-2@{domain}'
    checks, observations = [], {}
    result = dict(scenario='mcptt-temporary-group', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The group, call and regroup fields of every client and the server's regroups, for failure messages."""
        keys = (
            'group_id',
            'affiliated',
            'call_state',
            'session_uri',
            'regroups',
            'last_call_failure',
            'xcap_last',
            'last_error',
        )
        return {role: {key: status(role).get(key) for key in keys} for role in roles} | {
            'mcptt-server': {key: status('mcptt-server').get(key) for key in ('regroups', 'regrouped_groups')}
        }

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container and return its output."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')
        return run.stdout

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=25):
        """Poll predicate every 50 ms until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label if condition holds, else raise with a snapshot."""
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def xcap(role, text):
        """Send an XCAP command from role and return the client's next XCAP answer (status and body)."""
        # The answer shows in the status once the client has written it.
        before = (status(role).get('xcap_last') or {}).get('seq', 0)
        command(role, text)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            last = status(role).get('xcap_last') or {}
            if last.get('seq', 0) > before:
                return last
            time.sleep(0.05)
        raise AssertionError(f'{role} {text}: no XCAP answer')

    # ------------------------------------------------------------------------------
    def regroups(role):
        """The regroups (temporary groups) the role was notified of, by group identity."""
        return status(role).get('regroups') or {}

    # ------------------------------------------------------------------------------
    def held(tgi):
        """What the server holds about the temporary group tgi."""
        return (status('mcptt-server').get('regroups') or {}).get(tgi) or {}

    # ------------------------------------------------------------------------------
    def regrouped():
        """The server's constituent groups currently combined, with the group combining each."""
        return status('mcptt-server').get('regrouped_groups') or {}

    try:
        wait(
            'four clients authorised and affiliated to their own constituent group',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in roles),
            90,
        )

        # TG-01 TS 24.481 clause 6.3.14.3.1 step b): a user not authorised to form temporary groups.
        answer = xcap('client-b', f'temporary-create temp-1 {tgi} {north},{south}')
        check('TG-01 a user without the right to form temporary groups is refused 403', answer.get('status') == 403)
        check(
            'TG-01 nothing was formed', holds(lambda: not regroups('client-a') and not held(tgi) and not regrouped(), 3)
        )

        # TG-02 formation: each constituent group is checked, then marked, then the
        # temporary group's document is created (TS 24.481 clauses 6.3.14.3.1 and 6.3.14.3.2).
        answer = xcap('client-a', f'temporary-create temp-1 {tgi} {north},{south}')
        check(
            'TG-02 an authorised user forms the temporary group: 200 with the document\'s entity tag',
            answer.get('status') == 200
            and '<temporary-group-document-ETag>' in answer.get('body', '')
            and answer.get('etag'),
        )
        wait(
            'TG-02 the MCPTT server holds it as a group regroup and marks both constituent groups regrouped',
            lambda: (
                held(tgi).get('temporary')
                and held(tgi).get('controlling')
                and sorted(held(tgi).get('groups', [])) == sorted([north, south])
                and regrouped().get(north) == tgi
                and regrouped().get(south) == tgi
            ),
            20,
        )
        wait(
            'TG-02 every affiliated member of both constituent groups is told of it',
            lambda: all(
                tgi in regroups(role) and sorted(regroups(role)[tgi].get('groups', [])) == sorted([north, south])
                for role in roles
            ),
            20,
        )
        observations['temporary_group'] = held(tgi)

        # TG-03 the identity is taken, and a constituent group is in one temporary group at a time.
        answer = xcap('client-a', f'temporary-create temp-1 {tgi} {north}')
        check('TG-03 forming the same document again is refused 409', answer.get('status') == 409)
        answer = xcap('client-a', f'temporary-create temp-3 sip:{group_user}-temp-3@{domain} {north}')
        check('TG-03 a group already combined cannot be combined again: 403', answer.get('status') == 403)

        # TG-04 a regrouped constituent group carries no call (warning 148).
        command('client-a', 'call')
        wait(
            'TG-04 a call on a constituent group of the temporary group is refused with warning 148',
            lambda: '148' in json.dumps(status('client-a').get('last_call_failure') or {}),
            40,
        )

        # TG-05 a group call on the temporary group reaches both constituent groups.
        for role in roles:
            command(role, f'group {tgi}')
        wait(
            'TG-05 every member uses the temporary group, whose document it reads from the GMS',
            lambda: all(status(role).get('group_id') == tgi and status(role).get('affiliated') for role in roles),
            40,
        )
        command('client-a', 'call')
        wait(
            'TG-05 the call on the temporary group joins members of both constituent groups',
            lambda: (
                status('client-a').get('call_state') == 'active'
                and status('client-b').get('call_state') == 'active'
                and (
                    status('client-c').get('call_state') == 'active' or status('client-d').get('call_state') == 'active'
                )
            ),
            40,
        )
        observations['joined'] = {role: status(role).get('call_state') for role in roles}

        # TG-06 TS 24.481 clause 6.3.15: only the requester (or a manager) tears it down; the call ends with it.
        answer = xcap('client-b', 'temporary-delete temp-1')
        check('TG-06 another user cannot tear the temporary group down', answer.get('status') in (403, 404))
        answer = xcap('client-a', 'temporary-delete temp-1')
        check('TG-06 the requester tears the temporary group down with 200', answer.get('status') == 200)
        wait(
            'TG-06 the call on the temporary group is released',
            lambda: all(status(role).get('call_state') != 'active' for role in roles),
            40,
        )
        wait(
            'TG-06 every member is told, and the constituent groups are free',
            lambda: all(tgi not in regroups(role) for role in roles) and not held(tgi) and not regrouped(),
            30,
        )

        # TG-07 the constituent groups carry calls again.
        for role in roles:
            command(role, f'group {north if role in ("client-a", "client-b") else south}')
        wait(
            'TG-07 the members select their constituent groups again',
            lambda: all(status(role).get('affiliated') for role in roles),
            40,
        )
        command('client-a', 'call')
        wait(
            'TG-07 a call on a freed constituent group is answered',
            lambda: (
                status('client-a').get('call_state') == 'active' and status('client-b').get('call_state') == 'active'
            ),
            40,
        )
        command('client-a', 'hangup')
        wait('TG-07 released', lambda: all(status(role).get('call_state') != 'active' for role in roles), 30)

        # TG-08 a chat temporary group: the type comes from its own document.
        answer = xcap('client-a', f'temporary-create temp-2 {chat_tgi} {north},{south} chat')
        check('TG-08 a chat temporary group is formed', answer.get('status') == 200)
        wait(
            'TG-08 every member of both constituent groups is told',
            lambda: all(chat_tgi in regroups(role) for role in roles),
            20,
        )
        command('client-a', f'group {chat_tgi}')
        wait('TG-08 alice uses the chat temporary group', lambda: status('client-a').get('group_id') == chat_tgi)
        command('client-a', 'chat')
        wait(
            'TG-08 the chat call on the temporary group is accepted',
            lambda: status('client-a').get('call_state') == 'active',
            40,
        )
        command('client-c', f'group {chat_tgi}')
        wait(
            'TG-08 a member of the other constituent group uses it',
            lambda: status('client-c').get('group_id') == chat_tgi,
        )
        command('client-c', 'chat')
        wait(
            'TG-08 it joins the same chat session from its own constituent group',
            lambda: (
                status('client-c').get('call_state') == 'active'
                and status('client-c').get('session_uri') == status('client-a').get('session_uri')
            ),
            40,
        )
        command('client-a', 'hangup')
        command('client-c', 'hangup')
        answer = xcap('client-a', 'temporary-delete temp-2')
        check('TG-08 the chat temporary group is torn down', answer.get('status') == 200)
        wait(
            'TG-08 every member is told and both constituent groups are free',
            lambda: all(chat_tgi not in regroups(role) for role in roles) and not regrouped(),
            30,
        )
        result['passed'] = True
    except (AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
        print(str(error)[:3000], flush=True)
    finally:
        out = args.artifacts / 'integration'
        out.mkdir(parents=True, exist_ok=True)
        (out / 'temporary-group.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
