#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Group document writes (XCAP) and subscriptions (TS 24.481 V19.3.0 clauses 6.3.2 to 6.3.13).

Run against a four-client fixture prepared with --group-management. Check IDs match
tests/mcptt/GROUP_MANAGEMENT_TEST.md.

The procedures under test: group document creation (TS 24.481 clause 6.3.2), deletion (clause
6.3.5), element creation and deletion (clauses 6.3.6 and 6.3.7), subscription and notification
(clause 6.3.13) with the authorization policies of clause 7.2.12, and the user profile document's
subscription and update at the CMS (TS 24.484 clauses 6.3.13 and 6.3.4).

Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the group management checks GM-00 to GM-08 and the configuration checks CFG-01 to CFG-04, and
    write group-management.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-groups')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcptt']['user_id'] for client in roles}
    group = configs['client-a']['mcptt']['group_id']
    domain = group.split('@')[1]
    squad = f'sip:squad-{int(time.time()) % 100000}@{domain}'
    checks, observations = [], {}
    result = dict(scenario='group-management', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The group management part of every client's status and the server's subscriptions, for the
        failure report."""
        return {
            client: {
                field: status(client).get(field)
                for field in ('xcap_last', 'group_documents', 'group_subscription_result')
            }
            for client in roles
        } | {'mcptt-server': status('mcptt-server').get('group_document_subscriptions')}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=20):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record the label as a passed check if the condition holds; raise with a snapshot otherwise."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def xcap(role, text, expect, label):
        """Run an XCAP command on the role and wait (as the labelled check) for its result with the expected
        status; the result."""
        before = json.dumps(status(role).get('xcap_last'))
        command(role, text)
        wait(
            label,
            lambda: (
                json.dumps(status(role).get('xcap_last')) != before and status(role)['xcap_last']['status'] == expect
            ),
            10,
        )
        return status(role)['xcap_last']

    # ------------------------------------------------------------------------------
    def docs(role):
        """The group documents the role has read from its subscription."""
        return status(role).get('group_documents') or {}

    # ------------------------------------------------------------------------------
    def notified(role, group_id):
        """The number of notifications the role has had for the group."""
        return docs(role).get(group_id, {}).get('notifications', 0)

    try:
        wait('GM-00 every client is authorised', lambda: all(status(client).get('authorized') for client in roles), 40)
        # GM-01 and GM-02: TS 24.481 clause 6.3.2 creation, uniqueness and rights.
        xcap(
            'client-a',
            f'group-create squad {squad} {ids["client-a"]} {ids["client-c"]}',
            201,
            'GM-01 a user allowed to create groups creates one in its own tree: 201',
        )
        reply = xcap(
            'client-a',
            f'group-create other {group} {ids["client-a"]}',
            409,
            'GM-02 a group ID already in use is refused 409',
        )
        check(
            'GM-02 with a <uniqueness-failure> offering an alternative ID',
            '<uniqueness-failure>' in reply['body'] and '<alt-value>sip:other-' in reply['body'],
        )
        xcap(
            'client-c',
            f'group-create mine sip:mine@{domain} {ids["client-c"]}',
            403,
            'GM-02 a user without the right to create groups is refused 403',
        )

        # GM-03: TS 24.481 clause 6.3.13, a member subscribes to both groups and learns their state.
        command('client-c', f'group-subscribe {squad} {group}')
        wait(
            'GM-03 the subscription is accepted 200',
            lambda: (status('client-c').get('group_subscription_result') or {}).get('status') == 200,
        )
        wait(
            'GM-03 the first NOTIFY carries both documents and the member reads them',
            lambda: (
                notified('client-c', squad) >= 1
                and notified('client-c', group) >= 1
                and sorted(docs('client-c')[squad].get('members', [])) == sorted([ids['client-a'], ids['client-c']])
            ),
        )
        # GM-04: TS 24.481 clauses 6.3.6 and 6.3.7 by the owner and by a manager, each notified.
        before = notified('client-c', squad)
        etag = docs('client-c')[squad]['etag']
        xcap('client-a', f'group-member add {squad} {ids["client-b"]}', 201, 'GM-04 the owner adds a member: 201')
        wait(
            'GM-04 the subscriber is notified with a new entity tag and reads the new member',
            lambda: (
                notified('client-c', squad) > before
                and docs('client-c')[squad]['etag'] != etag
                and ids['client-b'] in docs('client-c')[squad].get('members', [])
            ),
            15,
        )
        before = notified('client-c', group)
        xcap(
            'client-b',
            f'group-member remove {group} {ids["client-d"]}',
            200,
            'GM-04 the manager of the provisioned group removes a member: 200',
        )
        wait(
            'GM-04 the change of the provisioned group is notified too',
            lambda: notified('client-c', group) > before,
            15,
        )
        xcap(
            'client-c',
            f'group-member add {squad} {ids["client-d"]}',
            403,
            'GM-05 a member who does not manage the group is refused 403',
        )
        xcap(
            'client-b',
            f'group-member add {squad} {ids["client-d"]}',
            403,
            'GM-05 a manager of another group is refused 403 on this one',
        )
        # GM-06: TS 24.481 clause 7.2.12, subscribing to a group one is not a member of.
        command('client-d', f'group-subscribe {group}')
        wait(
            'GM-06 a user no longer a member cannot subscribe: 403',
            lambda: (status('client-d').get('group_subscription_result') or {}).get('status') == 403,
        )
        # GM-08: TS 24.481 clause 6.3.13.2.1, a re-SUBSCRIBE with a modified list: its entries are the whole list. With
        # the provisioned group alone, the squad document is no longer followed; listed again, it is notified anew. RFC
        # 5875 section 4.7: each re-subscription is answered with the full state, unchanged documents included.
        group_before = notified('client-c', group)
        command('client-c', f'group-resubscribe {group}')
        wait(
            'GM-08 the re-SUBSCRIBE with the provisioned group alone is accepted 200',
            lambda: (status('client-c').get('group_subscription_result') or {}).get('groups') == [group]
            and status('client-c')['group_subscription_result'].get('status') == 200,
        )
        wait(
            'GM-08 the GMS follows only the provisioned group for client-c',
            lambda: any(
                sub.get('subscriber') == ids['client-c'] and sorted(sub.get('groups', {})) == [group]
                for sub in (status('mcptt-server').get('group_document_subscriptions') or {}).get('subscriptions', [])
            ),
            10,
        )
        wait(
            'GM-08 the re-subscription is notified with the full state: the unchanged provisioned group again',
            lambda: notified('client-c', group) > group_before,
            10,
        )
        before = notified('client-c', squad)
        xcap('client-a', f'group-member add {squad} {ids["client-d"]}', 201, 'GM-08 the owner changes the squad: 201')
        time.sleep(8)  # four polls of the GMS (document_poll_ms 2000)
        check('GM-08 the squad change is not notified to client-c', notified('client-c', squad) == before)
        command('client-c', f'group-resubscribe {squad} {group}')
        wait(
            'GM-08 listed again, the squad document is notified with its new member',
            lambda: notified('client-c', squad) > before
            and ids['client-d'] in docs('client-c')[squad].get('members', []),
            15,
        )
        # GM-07: TS 24.481 clause 6.3.5, the owner deletes the document; the subscriber learns it is gone.
        xcap('client-a', 'group-delete squad', 200, 'GM-07 the owner deletes the document')
        wait(
            'GM-07 the subscriber is notified of the removal',
            lambda: docs('client-c')[squad].get('removed') is True,
            15,
        )
        xcap(
            'client-b',
            f'group-member add {group} {ids["client-d"]}',
            201,
            'GM-07 the manager restores the provisioned group',
        )
        observations['server'] = status('mcptt-server').get('group_document_subscriptions')
        # CFG-01 to CFG-04: service configuration (TS 24.484 clauses 6.3.13 and 6.3.4). Each
        # client subscribes to its user profile document through the CMS's
        # subscription proxy; an administrator changes client-b's profile.
        wait(
            'CFG-01 client-b subscribed to its user profile document and got the initial notification',
            lambda: (
                (status('client-b').get('configuration') or {}).get('subscription_status') == 200
                and (status('client-b').get('configuration') or {}).get('notifies', 0) >= 1
            ),
        )
        action = next(
            candidate for candidate in status('client-b').get('profile_actions', []) if candidate.startswith('allow-')
        )
        observations['revoked_action'] = action
        xcap(
            'client-c',
            f"profile-revoke {ids['client-b']} {action}",
            403,
            'CFG-02 a user without the administrator right cannot update another profile: 403',
        )
        xcap(
            'client-a',
            f"profile-revoke {ids['client-b']} {action}",
            200,
            'CFG-03 the administrator updates client-b\'s profile: 200',
        )
        wait(
            'CFG-04 client-b is notified and reads its changed profile',
            lambda: (
                (status('client-b').get('configuration') or {}).get('refreshes', 0) >= 1
                and action not in status('client-b').get('profile_actions', [])
            ),
            30,
        )
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:3000], flush=True)
    finally:
        (args.artifacts / 'group-management.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
