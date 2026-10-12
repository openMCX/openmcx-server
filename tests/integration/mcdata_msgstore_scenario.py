#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise the MCData message store (TS 24.282 clause 21): the control of communications storage
(TS 24.282 clauses 21.3.2.2, 21.3.2.3 and 21.3.3.2, refused with the Warning codes 234 and 235 of
TS 24.282 table 4.9.2-2), the deposit of one-to-one, group and file distribution communications
(TS 24.282 clause 21.2.5A), the message store client procedures (TS 24.282 clauses 21.2.1 to
21.2.24), notification channels and subscriptions (TS 24.282 clauses 21.2.12A, 21.2.13A, 21.2.16,
21.2.19 and 21.2.22), and a file sent by reference to the message store (TS 24.282 clauses 10.2.2.1
and 10.2.2.2).

Run against a four-client fixture prepared with --mcdata --msgstore. Check IDs match
tests/mcdata/MCDATA_MESSAGE_STORE_TEST.md.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
PSI_WARNING_234 = '234 user not authorized to enable or disable the storage'
PSI_WARNING_235 = '235 unable to determine target user or group'


# ------------------------------------------------------------------------------
# Run the MCData message store scenario against the running lab, write mcdata-msgstore.json and return 0 when every
# check passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-msgstore')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    site = json.loads((generated / 'site.json').read_text())
    if not any('store_comms' in (user.get('mcdata') or {}) for user in site['users']):
        parser.error('the fixture must be prepared with --mcdata --msgstore')
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    group = configs['client-a']['mcdata']['group_id']
    service = configs['client-a']['mcdata']['service_uri']
    store_root = configs['client-a']['endpoints']['msgstore']
    checks, observations = [], {}
    sync_markers = itertools.count(1)
    result = dict(scenario='mcdata-msgstore', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the role last wrote, or {} while it has none.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The client's message store state.
    def store(role):
        return status(role).get('msgstore') or {}

    # ------------------------------------------------------------------------------
    # Every client's message store state (objects counted, not listed) and the server's, attached to a failure.
    def snapshot():
        return {
            role: {key: value for key, value in store(role).items() if key != 'objects'}
            | {'objects': len(store(role).get('objects', {}))}
            for role in roles
        } | {'mcdata-server': status('mcdata-server').get('msgstore')}

    # ------------------------------------------------------------------------------
    # Run one mcx-client console command in the role's container.
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
    # Poll the predicate until it holds (recorded as a passed check) or the timeout expires (AssertionError).
    def wait(label, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    # Record the check as passed if the condition holds, else raise AssertionError with the snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    # The result of the client's last message store operation.
    def last(role):
        return store(role).get('last') or {}

    # ------------------------------------------------------------------------------
    def op(role, text, expect=None):
        """A message store operation; waits for its result in the status file. Not for sync (see sync()) nor payload,
        which leave no new last request.
        """
        before = json.dumps(last(role))
        command(role, 'mcdata-msgstore ' + text)
        wait(f'{role} performed "{text.split()[0]}"', lambda: json.dumps(last(role)) != before, 10)
        if expect is not None:
            got = last(role).get('status')
            check(f'{role} "{text}" answered {expect}', got == expect)
        return last(role)

    # ------------------------------------------------------------------------------
    # The client sends a request to enable or disable communications storage (TS 24.282 clause 21.3.2.2 or 21.3.2.3) and
    # returns the answer.
    def control(role, text):
        before = json.dumps(store(role).get('control'))
        command(role, 'mcdata-msgstore-ctrl ' + text)
        wait(f'{role} storage control "{text}" answered', lambda: json.dumps(store(role).get('control')) != before, 10)
        return store(role)['control']

    # ------------------------------------------------------------------------------
    # Synchronise the client with the message store and return the objects it holds once the synchronisation has run.
    # A synchronisation ends with the VanishedObjects search (TS 24.282 clause 21.2.17.1), which is then the client's
    # last request, as it was after the previous one; a get of an object that does not exist, sent first, tells them
    # apart (the client runs its commands in order).
    def sync(role):
        marker = f'sync-marker-{next(sync_markers)}'
        command(role, 'mcdata-msgstore get ' + marker)
        settle(f'{role} looked up {marker}', lambda: last(role).get('url', '').endswith('/objects/' + marker))
        command(role, 'mcdata-msgstore sync')
        settle(
            f'{role} synchronised',
            lambda: (
                last(role).get('method') == 'POST' and last(role).get('url', '').endswith('/objects/operations/search')
            ),
        )
        return store(role).get('objects', {})

    # ------------------------------------------------------------------------------
    # Poll the predicate until it holds, without recording a check, or raise AssertionError after the timeout.
    def settle(what, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                raise AssertionError(what + ' timed out: ' + json.dumps(snapshot())[:6000])
            time.sleep(0.1)

    # ------------------------------------------------------------------------------
    # The client's stored objects whose attributes have the given values (an underscore stands for a hyphen in the
    # attribute name).
    def objects_where(role, **attributes):
        return {
            key: entry
            for key, entry in sync(role).items()
            if all(entry.get(name.replace('_', '-')) == value for name, value in attributes.items())
        }

    # ------------------------------------------------------------------------------
    # The client sends a one-to-one or (target 'group=<id>') group SDS and waits for its 202 (Accepted).
    def sds(role, target, text):
        before = [message['message_id'] for message in status(role).get('mcdata_sent') or []]
        command(role, (f'sds-group {target[6:]} ' if target.startswith('group=') else f'sds {target} ') + text)
        wait(
            f'{role} sent "{text}" (202)',
            lambda: (
                lambda sent: (
                    sent
                    and sent[-1]['message_id'] not in before
                    and (status(role).get('mcdata_last_result') or {}).get('message_id') == sent[-1]['message_id']
                    and (status(role).get('mcdata_last_result') or {}).get('status') == 202
                )
            )(status(role).get('mcdata_sent') or []),
            10,
        )

    # ------------------------------------------------------------------------------
    # The number of objects the MCData server has deposited in the message store (TS 24.282 clause 21.2.5A.1).
    def deposited():
        return (status('mcdata-server').get('msgstore') or {}).get('counters', {}).get('deposited', 0)

    try:
        wait(
            'MS-00 every client is authorised for MCData',
            lambda: all(status(role).get('mcdata_authorized') for role in roles),
            40,
        )

        # MS-01 and MS-02: TS 24.282 clause 21.3.3.2.
        reply = control('client-a', 'enable all-private all-group')
        check(
            'MS-01 a user allowed to store enables all its private and group communications: 200 from the PSI',
            reply['status'] == 200 and service in reply.get('asserted', ''),
        )
        reply = control('client-b', f'enable private={ids["client-a"]}')
        check('MS-01 a user enables the storage of its communications with one user (D.7 body)', reply['status'] == 200)
        reply = control('client-c', 'enable all-private')
        check(
            'MS-02 a user without <allow-store-comms-in-msgstore> is refused 403 warning 234',
            reply['status'] == 403 and PSI_WARNING_234 in reply['warning'],
        )
        reply = control('client-d', 'enable all-private')
        check(
            'MS-02 a user without <allow-store-private-comms-in-msgstore> is refused 234 for private communications',
            reply['status'] == 403 and PSI_WARNING_234 in reply['warning'],
        )
        reply = control('client-a', 'enable none')
        check(
            'MS-02 a request naming no user or group is refused 403 warning 235',
            reply['status'] == 403 and PSI_WARNING_235 in reply['warning'],
        )
        reply = control('client-b', f'enable group={group}')
        check(
            'MS-02 a group whose <allow-store-group-comm-in-msgstore> is absent is refused 234',
            reply['status'] == 403 and PSI_WARNING_234 in reply['warning'],
        )

        # MS-03 to MS-05: deposits (TS 24.282 clause 21.2.5A) of the communications chosen.
        base = deposited()
        sds('client-a', ids['client-b'], 'stored-one-to-one')
        wait('MS-03 a one-to-one SDS is deposited for its sender and its recipient', lambda: deposited() >= base + 2)
        outgoing = objects_where('client-a', Text='stored-one-to-one')
        check(
            'MS-03 the sender finds it in its Inbox as an outgoing object with the SDS parts',
            len(outgoing) == 1
            and next(iter(outgoing.values())).get('Direction') == 'Out'
            and next(iter(outgoing.values())).get('folder') == '/Inbox'
            and next(iter(outgoing.values())).get('parts') == 2,
        )
        incoming = objects_where('client-b', Text='stored-one-to-one')
        check(
            'MS-03 the recipient finds it as an incoming object from the sender',
            len(incoming) == 1
            and next(iter(incoming.values())).get('From') == ids['client-a']
            and next(iter(incoming.values())).get('Direction') == 'In',
        )
        base = deposited()
        sds('client-a', f'group={group}', 'stored-group')
        wait(
            'MS-04 a group SDS is deposited for the sender who stores group communications',
            lambda: deposited() >= base + 1,
        )
        check(
            'MS-04 but not for members who do not',
            holds(lambda: deposited() == base + 1, 2)
            and not objects_where('client-b', Text='stored-group')
            and objects_where('client-a', Text='stored-group'),
        )
        reply = control('client-a', f'disable private={ids["client-b"]}')
        base = deposited()
        sds('client-a', ids['client-b'], 'not-for-a')
        wait(
            'MS-05 after disabling one user, only the recipient that stores keeps the SDS',
            lambda: deposited() == base + 1 and objects_where('client-b', Text='not-for-a'),
        )
        check(
            'MS-05 the sender no longer stores it',
            reply['status'] == 200 and not objects_where('client-a', Text='not-for-a'),
        )
        control('client-a', f'enable private={ids["client-b"]}')

        # MS-06: a file (FD) is deposited by reference and fetched by the message store.
        payload = b'stored-file-' + hashlib.sha256(b'seed').hexdigest()[:32].encode()
        (args.artifacts / 'client-a' / 'stored.bin').write_bytes(payload)
        command('client-a', f'fd-send {ids["client-b"]} /artifacts/client-a/stored.bin')
        wait(
            'MS-06 a file distribution is deposited for both users',
            lambda: any(entry.get('Request-Type') == 'one-to-one-fd' for entry in sync('client-b').values()),
            30,
        )
        file_object = next(
            key for key, entry in store('client-b')['objects'].items() if entry.get('Request-Type') == 'one-to-one-fd'
        )
        command('client-b', f'mcdata-msgstore payload {file_object}')
        wait(
            'MS-06 the message store fetched the file from the content server into the user\'s area',
            lambda: (store('client-b').get('payload') or {}).get('sha256') == hashlib.sha256(payload).hexdigest(),
        )

        # MS-07: the message store client (TS 24.282 clauses 21.2.1 to 21.2.4, 21.2.6 to 21.2.11, 21.2.15, 21.2.18,
        # 21.2.23 and 21.2.24).
        one = next(iter(objects_where('client-a', Text='stored-one-to-one')))
        op('client-a', f'get {one}', 200)
        op('client-a', f'flag {one} \\Seen', 200)
        check(
            'MS-07 a flag is set on an object',
            '\\Seen' in (last('client-a').get('body') or {}).get('flagList', {}).get('flag', []),
        )
        op('client-a', f'unflag {one} \\Recent', 200)
        op('client-a', f'search From={ids["client-a"]} flag=\\Seen', 200)
        check('MS-07 a search by attribute and flag finds it', store('client-a').get('search') == [one])
        op('client-a', 'folder-create Squad1', 201)
        op('client-a', 'folders', 200)
        folders = store('client-a').get('folders', {})
        check(
            'MS-07 the folder hierarchy lists the root, the Inbox and the new folder',
            {'/', '/Inbox', '/Squad1'} <= set(folders),
        )
        op('client-a', f'move {folders["/Squad1"]} {one}', 200)
        op('client-a', f'folder {folders["/Squad1"]}', 200)
        check('MS-07 the object moved into the folder', store('client-a').get('folder', {}).get('objects') == [one])
        op('client-a', f'copy {folders["/Inbox"]} {one}', 200)
        check('MS-07 a copy is created in the Inbox', '"code": 201' in json.dumps(last('client-a')))
        op('client-a', 'folder-search Squad1', 200)
        op('client-a', f'copy-folder {folders["/Inbox"]} {folders["/Squad1"]}', 200)
        op('client-a', 'folders', 200)
        check('MS-07 a folder is copied with its content', '/Inbox/Squad1' in store('client-a').get('folders', {}))
        op('client-a', f'folder-delete {store("client-a")["folders"]["/Inbox/Squad1"]}', 204)
        op('client-a', f'folder-delete {folders["/Inbox"]}', 403)
        before = sync('client-a')
        op('client-a', 'bulk-flag \\Flagged ' + ' '.join(list(before)[:2]), 200)
        check('MS-07 a bulk update flags several objects', json.dumps(last('client-a')).count('"code": 200') == 2)
        (args.artifacts / 'client-a' / 'note.txt').write_text('uploaded-by-client')
        op('client-a', 'upload /artifacts/client-a/note.txt', 201)
        uploaded = last('client-a')['body']['reference']['resourceURL'].rsplit('/', 1)[1]
        vanishing = [key for key in sync('client-a') if key != one and key != uploaded][:1]
        op('client-a', 'delete ' + vanishing[0], 204)
        check(
            'MS-07 a synchronisation drops the deleted object and keeps the uploaded one',
            vanishing[0] not in sync('client-a') and uploaded in store('client-a')['objects'],
        )
        # MS-08: another user's storage area is out of reach.
        op('client-b', f'get {store_root}/nms/v1/mcdata/{ids["client-a"]}/objects/{one}', 403)

        # MS-09: notifications through a channel of the notification server (TS 24.282 clauses 21.2.12A, 21.2.16,
        # 21.2.19 and 21.2.22).
        command('client-a', 'mcdata-msgstore subscribe')
        wait(
            'MS-09 a LongPolling channel and a subscription naming its callback are created',
            lambda: store('client-a').get('channel') and store('client-a').get('subscription'),
        )
        events = store('client-a').get('events', 0)
        sds('client-b', ids['client-a'], 'notified-deposit')
        wait(
            'MS-09 a deposit reaches the client as a notification through the channel',
            lambda: store('client-a').get('events', 0) > events and store('client-a').get('notifications'),
            25,
        )
        notification = store('client-a')['notifications'][-1]
        check(
            'MS-09 it carries the index, the restart token and the callback data',
            notification['index'] > 0
            and notification['restart_token']
            and notification['callback_data'] == ids['client-a'],
        )
        count = len(store('client-a')['notifications'])
        op('client-a', 'restart 0', 200)
        sds('client-b', ids['client-a'], 'after-restart')
        wait(
            'MS-10 restarting the subscription from index 0 resends the earlier changes',
            lambda: (
                len(store('client-a')['notifications']) > count
                and sum(notification['events'] for notification in store('client-a')['notifications'][count:]) > 1
            ),
            25,
        )

        # MS-11: upload by reference (TS 24.282 clause 10.2.2.1 NOTE 3, clause 10.2.2.2).
        command('client-a', f'fd-send ref={uploaded} {ids["client-b"]}')
        wait(
            'MS-11 a file of the message store is sent by reference and the recipient downloads it intact',
            lambda: any(
                file.get('hash_verified') and file.get('sha256') == hashlib.sha256(b'uploaded-by-client').hexdigest()
                for file in status('client-b').get('mcdata_files', [])
            ),
            30,
        )
        command('client-a', 'mcdata-msgstore unsubscribe')
        wait(
            'MS-12 unsubscribing removes the channel and the subscription',
            lambda: 'channel' not in store('client-a') and 'subscription' not in store('client-a'),
        )
        observations['server'] = status('mcdata-server').get('msgstore')
        observations['objects'] = {role: len(store(role).get('objects', {})) for role in roles}
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:3000], flush=True)
    finally:
        (args.artifacts / 'mcdata-msgstore.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
