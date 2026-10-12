#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise a group regroup and a user regroup using a preconfigured group.

The procedures under test, all of TS 24.379: the group regroup of clause 16.2 (client requests of clauses 16.2.1.1 and
16.2.1.2, authorisation by the participating function in clauses 16.2.2.2 and 16.2.2.3 step 3 with warnings 160 and 161,
creation and removal by the controlling function in clauses 16.2.3.1 to 16.2.3.3 with warnings 165 and 163, notification
of late affiliated members in clause 16.2.4.3), the user regroup of clause 16.3 (clauses 16.3.1.1, 16.3.2.2, 16.3.2.4,
16.3.3.1), calls on a regroup and on a regrouped constituent group (warning 148), and chat group calls on a regroup
(clause 10.1.2.4.1.1 steps 4 c) ii), 5, 5a and 6 b)).

Run against a fixture prepared with --regroup (see add_regroup_policy in tools/prepare-prearranged-test.py): the
preconfigured group holds the configuration, and the two constituent groups hold the members. Check IDs match
tests/mcptt/REGROUP_TEST.md.

Specifications: TS 24.379 V19.7.0 (Rel-19).
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
    """Run the checks RG-01 to RG-11, RU-01 to RU-06 and RC-01 to RC-05 and write integration/regroup-results.json."""
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
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    north = configs['client-a']['mcptt']['group_id']
    south = configs['client-c']['mcptt']['group_id']
    domain = north.split('@', 1)[1]
    group_user = north.split(':', 1)[1].split('-north@', 1)[0]
    preconf = f'sip:{group_user}-preconf@{domain}'
    tgi = f'sip:{group_user}-regroup-1@{domain}'
    user_tgi = f'sip:{group_user}-regroup-2@{domain}'
    late_tgi = f'sip:{group_user}-regroup-3@{domain}'
    decided_tgi = f'sip:{group_user}-regroup-4@{domain}'
    chat_preconf = f'sip:{group_user}-chat-preconf@{domain}'
    chat_tgi = f'sip:{group_user}-regroup-5@{domain}'
    checks, observations = [], {}
    result = dict(scenario='mcptt-regroup', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client and of the server, for failure messages."""
        return {role: status(role) for role in roles + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one command in the role's container (mcptt-server or mcx-client) and return its output."""
        binary, config = (
            ('openmcx-mcptt-server', '/config/mcptt-server.json')
            if role == 'mcptt-server'
            else ('mcx-client', f'/config/{role}.json')
        )
        run = subprocess.run(
            cli + ['exec', '-T', role, binary, '--config', config, '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
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
    def regroup_result(role):
        """The response to the role's last regroup request (status and warning)."""
        return status(role).get('regroup_result') or {}

    # ------------------------------------------------------------------------------
    def regroups(role):
        """The regroups the role was notified of, by regroup identity."""
        return status(role).get('regroups') or {}

    # ------------------------------------------------------------------------------
    def regroup(role, text, expect, label, warning=None):
        """Send a regroup command from role and wait until it is answered expect (with the warning text, if given)."""
        command(role, text)
        wait(
            label,
            lambda: (
                regroup_result(role).get('status') == expect
                and (warning is None or warning in regroup_result(role).get('warning', ''))
            ),
        )

    try:
        wait(
            'four clients authorised and affiliated to their own constituent group',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in roles),
            90,
        )

        # RG-01 the participating function authorises the request from the user
        # profile before anything is created (TS 24.379 clause 16.2.2.2 step 3, warning 160).
        regroup(
            'client-b',
            f'regroup create {tgi} {preconf} {north},{south}',
            403,
            'RG-01 a user without <allow-regroup> is refused 403 with warning 160',
            '160',
        )
        check('RG-01 nothing was created', not regroups('client-a') and not regroups('client-c'))

        # RG-02 creation by an authorised user (TS 24.379 clauses 16.2.1.1 and 16.2.3.1).
        regroup(
            'client-a',
            f'regroup create {tgi} {preconf} {north},{south}',
            200,
            'RG-02 an authorised user creates the regroup and is answered 200',
        )
        wait(
            'RG-02 every affiliated member of both constituent groups is told of the regroup',
            lambda: all(tgi in regroups(role) for role in roles),
        )
        check(
            'RG-02 the notification names the preconfigured group and both constituents',
            all(
                regroups(role)[tgi].get('preconfigured') == preconf
                and sorted(regroups(role)[tgi].get('groups', [])) == sorted([north, south])
                for role in roles
            ),
        )
        wait(
            'RG-02 the server records the regroup and both constituent groups',
            lambda: (status('mcptt-server').get('regroups') or {}).get(tgi, {}).get('preconfigured') == preconf,
        )
        observations['regroup'] = (status('mcptt-server').get('regroups') or {}).get(tgi)

        # RG-03 the identity is in use once created (TS 24.379 clause 16.2.3.1 step 3, warning 165).
        regroup(
            'client-a',
            f'regroup create {tgi} {preconf} {north},{south}',
            403,
            'RG-03 a second regroup with the same identity is refused 403 with warning 165',
            '165',
        )

        # RG-04 a constituent group is regrouped and cannot carry a call (warning 148).
        command('client-a', f'group {north}')
        wait('RG-04 client-a selects its constituent group', lambda: status('client-a').get('group_id') == north)
        command('client-a', 'call')
        wait(
            'RG-04 a call on a regrouped constituent group is refused with warning 148',
            lambda: '148' in json.dumps(status('client-a').get('last_call_failure') or {}),
        )

        # RG-05 a call on the regroup reaches the members of both constituents.
        command('client-a', f'group {tgi}')
        wait(
            'RG-05 a client uses the regroup at once, with the preconfigured group\'s configuration',
            lambda: status('client-a').get('group_id') == tgi and status('client-a').get('affiliated'),
        )
        for role in ['client-b', 'client-c', 'client-d']:
            command(role, f'group {tgi}')
        wait(
            'RG-05 every member of both constituent groups affiliates to the regroup',
            lambda: all(status(role).get('group_id') == tgi and status(role).get('affiliated') for role in roles),
        )
        command('client-a', 'call')
        wait(
            'RG-05 the call on the regroup is answered and joins members of both constituent groups',
            lambda: (
                status('client-a').get('call_state') == 'active'
                and sum(
                    1 for role in ['client-b', 'client-c', 'client-d'] if status(role).get('call_state') == 'active'
                )
                >= 2
            ),
            40,
        )
        observations['joined'] = {role: status(role).get('call_state') for role in roles}
        check(
            'RG-05 a member of the other constituent group is in the call',
            status('client-c').get('call_state') == 'active' or status('client-d').get('call_state') == 'active',
        )

        # RG-06 removal is authorised the same way (TS 24.379 clause 16.2.2.3 step 3, warning 161).
        regroup(
            'client-b',
            f'regroup remove {tgi}',
            403,
            'RG-06 a user without <allow-regroup> cannot remove a regroup either (161)',
            '161',
        )
        check('RG-06 the regroup is still held', tgi in regroups('client-a'))

        # RG-07 removal releases the call and frees the constituent groups.
        regroup('client-a', f'regroup remove {tgi}', 200, 'RG-07 an authorised user removes the regroup with 200')
        wait('RG-07 every member is told the regroup is gone', lambda: all(tgi not in regroups(role) for role in roles))
        wait('RG-07 the call on the regroup is released', lambda: status('client-a').get('call_state') != 'active', 40)
        wait(
            'RG-07 the server no longer holds the regroup',
            lambda: tgi not in (status('mcptt-server').get('regroups') or {}),
        )

        # RG-08 the constituent groups carry calls again once the regroup is gone.
        for role in roles:
            command(role, f'group {north if role in ("client-a", "client-b") else south}')
        wait(
            'RG-08 the members select their constituent groups again',
            lambda: all(status(role).get('affiliated') for role in roles),
            40,
        )
        command('client-a', 'call')
        wait(
            'RG-08 a call on a freed constituent group is answered',
            lambda: (
                status('client-a').get('call_state') == 'active' and status('client-b').get('call_state') == 'active'
            ),
            40,
        )
        command('client-a', 'hangup')

        # RG-09 removing a regroup that does not exist (TS 24.379 clause 16.2.3.2 step 3, warning 163).
        regroup(
            'client-a',
            f'regroup remove {tgi}',
            403,
            'RG-09 removing an unknown regroup is refused 403 with warning 163',
            '163',
        )

        # RU-01 a user regroup is authorised like a group regroup (TS 24.379 clause 16.3.2.2 step 3).
        members = [ids['client-a'], ids['client-c']]
        regroup(
            'client-b',
            f'regroup users {user_tgi} {preconf} {",".join(members)}',
            403,
            'RU-01 a user without <allow-regroup> cannot create a user regroup (160)',
            '160',
        )

        # RU-02 creation (TS 24.379 clauses 16.3.1.1, 16.3.3.1 and 16.3.2.4): only the named users are
        # told, each notice names the users and no groups.
        regroup(
            'client-a',
            f'regroup users {user_tgi} {preconf} {",".join(members)}',
            200,
            'RU-02 an authorised user creates a user regroup of client-a and client-c with 200',
        )
        wait(
            'RU-02 both named users are told of the user regroup',
            lambda: all(user_tgi in regroups(role) for role in ('client-a', 'client-c')),
        )
        check(
            'RU-02 the notice names the preconfigured group and the users, and no groups',
            all(
                regroups(role)[user_tgi].get('preconfigured') == preconf
                and sorted(regroups(role)[user_tgi].get('users', [])) == sorted(members)
                and not regroups(role)[user_tgi].get('groups')
                for role in ('client-a', 'client-c')
            ),
        )
        check(
            'RU-02 users outside the regroup are not told',
            holds(lambda: all(user_tgi not in regroups(role) for role in ('client-b', 'client-d')), 1),
        )
        held = (status('mcptt-server').get('regroups') or {}).get(user_tgi, {})
        check(
            'RU-02 the server holds the user regroup with both users affiliated to it',
            sorted(held.get('users', [])) == sorted(members)
            and sorted(held.get('affiliated', [])) == sorted(members)
            and not held.get('groups'),
        )
        observations['user_regroup'] = held
        check(
            'RU-02 no constituent group is regrouped by a user regroup',
            not any(value == user_tgi for value in (status('mcptt-server').get('regrouped_groups') or {}).values()),
        )

        # RU-03 the identity is in use (TS 24.379 clause 16.3.3.1 step 3, warning 165).
        regroup(
            'client-a',
            f'regroup users {user_tgi} {preconf} {ids["client-b"]}',
            403,
            'RU-03 a second regroup with the same identity is refused 403 with warning 165',
            '165',
        )

        # RU-04 a call on the user regroup reaches a member that never selected it.
        command('client-a', f'group {user_tgi}')
        wait(
            'RU-04 client-a uses the user regroup with the preconfigured group\'s configuration',
            lambda: status('client-a').get('group_id') == user_tgi and status('client-a').get('affiliated'),
        )
        check(
            'RU-04 client-c still has its own constituent group selected', status('client-c').get('group_id') == south
        )
        command('client-a', 'call')
        wait(
            'RU-04 the call on the user regroup is answered by client-c without selecting it',
            lambda: (
                status('client-a').get('call_state') == 'active' and status('client-c').get('call_state') == 'active'
            ),
            40,
        )
        check('RU-04 client-c takes the call on the user regroup', status('client-c').get('call_group') == user_tgi)
        check(
            'RU-04 users outside the regroup are not invited',
            holds(lambda: all(status(role).get('call_state') != 'active' for role in ('client-b', 'client-d')), 1),
        )
        observations['user_regroup_call'] = {role: status(role).get('call_state') for role in roles}

        # RU-05 removal (TS 24.379 clause 16.3.1.2 with clause 16.2.1.2, clause 16.2.3.2 steps 3 and 6,
        # clause 16.2.2.5).
        regroup(
            'client-b',
            f'regroup remove {user_tgi}',
            403,
            'RU-05 a user without <allow-regroup> cannot remove the user regroup (161)',
            '161',
        )
        regroup(
            'client-a', f'regroup remove {user_tgi}', 200, 'RU-05 an authorised user removes the user regroup with 200'
        )
        wait(
            'RU-05 both members are told the user regroup is gone',
            lambda: all(user_tgi not in regroups(role) for role in ('client-a', 'client-c')),
        )
        wait(
            'RU-05 the call on the user regroup is released',
            lambda: (
                status('client-a').get('call_state') != 'active' and status('client-c').get('call_state') != 'active'
            ),
            40,
        )
        wait(
            'RU-05 the server no longer holds the user regroup',
            lambda: user_tgi not in (status('mcptt-server').get('regroups') or {}),
        )
        regroup(
            'client-a',
            f'regroup remove {user_tgi}',
            403,
            'RU-05 removing it again is refused 403 with warning 163',
            '163',
        )

        # RG-10 a member that affiliates to a constituent group after the regroup
        # exists is told of it (TS 24.379 clause 16.2.4.3).
        command('client-a', f'group {north}')
        wait(
            'RG-10 client-a is back on its own constituent group',
            lambda: status('client-a').get('group_id') == north and status('client-a').get('affiliated'),
        )
        command('client-d', 'deaffiliate')
        wait(
            'RG-10 client-d is no longer affiliated to its constituent group',
            lambda: not status('client-d').get('affiliated'),
        )
        regroup(
            'client-a',
            f'regroup create {late_tgi} {preconf} {north},{south}',
            200,
            'RG-10 a group regroup is created while client-d is not affiliated',
        )
        wait(
            'RG-10 the affiliated members are told',
            lambda: all(late_tgi in regroups(role) for role in ('client-a', 'client-b', 'client-c')),
        )
        check(
            'RG-10 client-d is not told while it is not affiliated',
            holds(lambda: late_tgi not in regroups('client-d'), 1),
        )
        command('client-d', 'affiliate')
        wait(
            'RG-10 client-d affiliates to its constituent group again and is told of the regroup',
            lambda: status('client-d').get('affiliated') and late_tgi in regroups('client-d'),
        )
        check(
            'RG-10 the notice names the preconfigured group and both constituents',
            regroups('client-d')[late_tgi].get('preconfigured') == preconf
            and sorted(regroups('client-d')[late_tgi].get('groups', [])) == sorted([north, south]),
        )

        # RG-11 the controlling function decides to remove the regroup (TS 24.379 clause 16.2.3.3).
        command('mcptt-server', f'regroup-remove {late_tgi}')
        wait(
            'RG-11 every member is told the regroup the controlling function removed is gone',
            lambda: all(late_tgi not in regroups(role) for role in roles),
        )
        wait(
            'RG-11 the server no longer holds it and the constituent groups are free',
            lambda: (
                late_tgi not in (status('mcptt-server').get('regroups') or {})
                and not (status('mcptt-server').get('regrouped_groups') or {})
            ),
        )

        # RU-06 the same for a user regroup.
        regroup(
            'client-a',
            f'regroup users {decided_tgi} {preconf} {ids["client-a"]},{ids["client-c"]}',
            200,
            'RU-06 a user regroup of client-a and client-c is created',
        )
        wait(
            'RU-06 both users are told', lambda: all(decided_tgi in regroups(role) for role in ('client-a', 'client-c'))
        )
        command('mcptt-server', f'regroup-remove {decided_tgi}')
        wait(
            'RU-06 the controlling function removes it and both users are told',
            lambda: (
                all(decided_tgi not in regroups(role) for role in ('client-a', 'client-c'))
                and decided_tgi not in (status('mcptt-server').get('regroups') or {})
            ),
        )
        # RC-01 a chat group call on a regroup (TS 24.379 clause 10.1.2.4.1.1 steps 5, 5a and 6 b)):
        # the regroup takes the chat configuration of its preconfigured group.
        regroup(
            'client-a',
            f'regroup create {chat_tgi} {chat_preconf} {north},{south}',
            200,
            'RC-01 a regroup over a chat preconfigured group is created',
        )
        wait(
            'RC-01 every member of both constituent groups is told',
            lambda: all(chat_tgi in regroups(role) for role in roles),
        )

        # RC-02 a call on the regroup names the constituent group it comes from.
        command('client-a', f'group {chat_tgi}')
        wait('RC-02 client-a uses the regroup', lambda: status('client-a').get('group_id') == chat_tgi)
        command('client-a', 'chat')
        wait(
            'RC-02 the chat call on the regroup is accepted',
            lambda: status('client-a').get('call_state') == 'active',
            40,
        )
        command('client-c', f'group {chat_tgi}')
        wait(
            'RC-02 a member of the other constituent group uses the regroup',
            lambda: status('client-c').get('group_id') == chat_tgi,
        )
        command('client-c', 'chat')
        wait(
            'RC-02 it joins the same chat session from its own constituent group',
            lambda: (
                status('client-c').get('call_state') == 'active'
                and status('client-c').get('session_uri') == status('client-a').get('session_uri')
            ),
            40,
        )
        command('client-a', 'hangup')
        command('client-c', 'hangup')
        wait(
            'RC-02 both leave the session',
            lambda: all(status(role).get('call_state') == 'idle' for role in ('client-a', 'client-c')),
            40,
        )

        # RC-03 a call naming a group that is not a constituent (step 6 b)).
        command('client-b', f'group {chat_tgi} from={preconf}')
        wait(
            'RC-03 client-b uses the regroup naming another group',
            lambda: status('client-b').get('group_id') == chat_tgi,
        )
        command('client-b', 'chat')
        wait(
            'RC-03 a call naming a group that is not a constituent is refused with 120',
            lambda: '120' in json.dumps(status('client-b').get('last_call_failure') or {}),
            40,
        )

        # RC-04 a call on a regroup that names no constituent group (step 5a).
        command('client-b', f'group {chat_tgi} from=')
        command('client-b', 'chat')
        wait(
            'RC-04 a call on a regroup with no calling group identity is refused 403',
            lambda: (
                (status('client-b').get('last_call_failure') or {}).get('status') == 403
                and '120' not in json.dumps(status('client-b').get('last_call_failure') or {})
            ),
            40,
        )

        # RC-05 step 4 c) ii): a caller on a regrouped constituent group is refused
        # 148 and sent a copy of the notification of the regroup it is now in.
        seen = (regroups('client-b').get(chat_tgi) or {}).get('notifications', 0)
        command('client-b', f'group {north}')
        wait('RC-05 client-b selects its constituent group', lambda: status('client-b').get('group_id') == north)
        command('client-b', 'call')
        wait(
            'RC-05 the call on the regrouped constituent group is refused with 148',
            lambda: '148' in json.dumps(status('client-b').get('last_call_failure') or {}),
            40,
        )
        wait(
            'RC-05 the caller is sent a copy of the regroup notification',
            lambda: (regroups('client-b').get(chat_tgi) or {}).get('notifications', 0) > seen,
            40,
        )

        regroup('client-a', f'regroup remove {chat_tgi}', 200, 'RC-06 the chat regroup is removed')
        wait(
            'RC-06 every member is told and both constituent groups are free',
            lambda: (
                all(chat_tgi not in regroups(role) for role in roles)
                and not (status('mcptt-server').get('regrouped_groups') or {})
            ),
        )
        result['passed'] = True
    except (AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    finally:
        output = args.artifacts / 'integration/regroup-results.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({key: result[key] for key in ('scenario', 'passed')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
