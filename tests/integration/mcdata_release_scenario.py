#!/usr/bin/env python3
"""Exercise MCData communication release (TS 24.282 clause 13): the release policies of the controlling
MCData function (TS 24.282 clauses 13.2.2.2.4.1 to 13.2.2.2.4.3), release by the server without and with
prior indication (TS 24.282 clauses 13.2.3 and 13.2.4, timer TDC3), and release by an authorised user
without and with prior indication (TS 24.282 clauses 13.2.5 and 13.2.6), over the media plane, for IP
connectivity and for file distribution over HTTP.

Run against a fixture prepared with --mcdata --mcdata-release (see
add_mcdata_release_policy in tools/prepare-prearranged-test.py): the server
releases a communication after 20 s or 5000 bytes, TDC3 is 5 s and an extension
request is accepted. client-b holds <release_any_user>; client-c does not.
Check IDs match tests/mcdata/MCDATA_RELEASE_TEST.md.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
# Run the MCData communication release scenario against the running lab, write integration/mcdata-release-results.json
# and return 0 when every check passed.
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
    checks, observations = [], {}
    result = dict(scenario='mcdata-communication-release', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the role last wrote, or {} while it has none.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The release-related part of every role's status, attached to a failure and to the results.
    def snapshot():
        keep = (
            'mcdata_media_result',
            'mcdata_media_session',
            'mcdata_release',
            'mcdata_ipconn',
            'last_error',
            'media_sessions',
            'pending_releases',
            'counters',
            'ipconn_sessions',
            'mcdata_files_sent',
        )
        return {
            role: {key: value for key, value in status(role).items() if key in keep}
            for role in roles + ['mcdata-server']
        }

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
    # Run one openmcx-mcdata-server console command in the MCData server's container.
    def server_command(text):
        run = subprocess.run(
            cli
            + [
                'exec',
                '-T',
                'mcdata-server',
                'openmcx-mcdata-server',
                '--config',
                '/config/mcdata-server.json',
                '--command',
                text,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode:
            raise RuntimeError(f'server {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Run a shell command in the role's container and return its output.
    def shell(role, text):
        run = subprocess.run(cli + ['exec', '-T', role, 'sh', '-c', text], capture_output=True, text=True, timeout=30)
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip()}')
        return run.stdout

    # ------------------------------------------------------------------------------
    # Poll the predicate until it holds (recorded as a passed check) or the timeout expires (AssertionError).
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
    # Record the check as passed if the condition holds, else raise AssertionError with the snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    # The result of the client's last media plane transaction.
    def media(role):
        return status(role).get('mcdata_media_result') or {}

    # ------------------------------------------------------------------------------
    # Whether the client has an MCData media plane session.
    def in_session(role):
        return bool(status(role).get('mcdata_media_session'))

    # ------------------------------------------------------------------------------
    # The client's communication release state.
    def release(role):
        return status(role).get('mcdata_release') or {}

    # ------------------------------------------------------------------------------
    # The MCData server's status.
    def server():
        return status('mcdata-server')

    # ------------------------------------------------------------------------------
    # The MCData server's counters.
    def counters():
        return server().get('counters') or {}

    # ------------------------------------------------------------------------------
    # The media plane session legs the MCData server holds.
    def legs():
        return server().get('media_sessions') or []

    # ------------------------------------------------------------------------------
    # Wait until the server lists the owner's originating leg and return its dialog.
    def origin_dialog(owner):
        # ------------------------------------------------------------------------------
        # The owner's originating legs that carry a key.
        def found():
            return [leg for leg in legs() if leg['owner'] == ids[owner] and leg['originating'] and leg['key']]

        wait(f'the server lists the originating leg of {owner}', lambda: bool(found()))
        return found()[0]['dialog']

    # ------------------------------------------------------------------------------
    # The caller opens an SDS session and waits until it is open at the caller and every member.
    def open_session(caller, target, members, label):
        command(caller, f'sds-session {target}')
        wait(
            label, lambda: media(caller).get('state') == 'open' and all(in_session(role) for role in [caller] + members)
        )

    # ------------------------------------------------------------------------------
    # Wait until no listed client is in a session, the server holds no leg and, if given, every client got the reason.
    def released(roles_, label, reason=None, timeout=25):
        wait(
            label,
            lambda: (
                not any(in_session(role) for role in roles_)
                and not legs()
                and (reason is None or all(media(role).get('release_reason') == reason for role in roles_))
            ),
            timeout,
        )

    # ------------------------------------------------------------------------------
    # Wait until the previous communication is fully released (no session, leg or IP connectivity session).
    def idle(roles_):
        wait(
            'the previous communication is fully released',
            lambda: not any(in_session(role) for role in roles_) and not legs() and not server().get('ipconn_sessions'),
            30,
        )

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(role).get('mcdata_authorized') and status(role).get('mcdata_affiliated') for role in roles
            ),
            90,
        )
        instance = server()['instance_id']

        # REL-01 the group release policy (TS 24.282 clause 13.2.2.2.4.1): a participant that leaves
        # does not end the communication; the initiator leaving does (step 4).
        open_session(
            'client-a',
            f'group={group}',
            ['client-b', 'client-c', 'client-d'],
            'REL-01 a group SDS session is open at the four members',
        )
        command('client-c', 'sds-session close')
        wait(
            'REL-01 a participant that leaves is released alone and the others continue',
            lambda: (
                not in_session('client-c')
                and all(in_session(role) for role in ['client-a', 'client-b', 'client-d'])
                and len(legs()) == 3
            ),
        )
        before = counters().get('releases_policy', 0)
        command('client-a', 'sds-session close')
        released(['client-a', 'client-b', 'client-d'], 'REL-01 the initiator leaving releases every participant')
        check('REL-01 the server counts a release by policy', counters().get('releases_policy', 0) == before + 1)

        # REL-02 the one-to-one release policy (TS 24.282 clause 13.2.2.2.4.2 step 3).
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-02 a one-to-one SDS session is open')
        command('client-b', 'sds-session close')
        released(['client-a', 'client-b'], 'REL-02 the other party leaving releases the originator too')
        check('REL-02 a release by policy carries no reason', 'release_reason' not in media('client-a'))

        # REL-03 the data limit per communication (TS 24.282 clause 13.2.2.2.4.2 step 2 with clause 13.2.3.2).
        open_session('client-a', ids['client-c'], ['client-c'], 'REL-03 a session from client-a to client-c is open')
        for index in range(3):
            command('client-a', 'sds-session send ' + chr(ord('a') + index) * 2000)
            time.sleep(0.3)
        released(
            ['client-a', 'client-c'],
            'REL-03 beyond 5000 bytes the server releases both parties with the reason',
            'data volume limit',
        )
        check('REL-03 the server counts a release of its own', counters().get('releases_server', 0) >= 1)

        # REL-04 the transmission time limit (TS 24.282 clause 13.2.2.2.4.2 step 1 with clause 13.2.3.2).
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-04 a session is open')
        opened = time.monotonic()
        released(
            ['client-a', 'client-b'],
            'REL-04 after 20 s the server releases both parties with the reason',
            'time limit expiry',
            35,
        )
        check('REL-04 the time limit, not the 25 s idle timer, ended it', time.monotonic() - opened < 25)

        # REL-05 an operator releases a communication without prior indication (TS 24.282 clause 13.2.3.2).
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-05 a session is open')
        server_command(f'release-session {origin_dialog("client-a")} maintenance window')
        released(
            ['client-a', 'client-b'],
            'REL-05 the operator release reaches both parties with its reason',
            'maintenance window',
        )

        # REL-06 a release announced to the originator (TS 24.282 clause 13.2.4), which asks for and gets an extension.
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-06 a session is open')
        dialog = origin_dialog('client-a')
        key = next(leg['key'] for leg in legs() if leg['dialog'] == dialog)
        server_command(f'release-session-intent {dialog} query budget review')
        wait(
            'REL-06 the originator receives the intent to release with its reason and the data query (13.2.4.2.1)',
            lambda: (
                release('client-a').get('state') == 'release-pending'
                and release('client-a').get('reason') == 'budget review'
                and release('client-a').get('query') is True
            ),
        )
        wait(
            'REL-06 the originator reports its remaining amount of data, which the server stores (13.2.4.4.2)',
            lambda: (
                (server().get('pending_releases') or {}).get(key, {}).get('remaining') == '0'
                and (server().get('pending_releases') or {}).get(key, {}).get('tdc3_running')
            ),
        )
        command('client-a', 'mcdata-release extend')
        wait(
            'REL-06 the extension request is accepted (13.2.4.4.3, 13.2.4.4.4)',
            lambda: release('client-a').get('state') == 'extended' and not server().get('pending_releases'),
        )
        check('REL-06 the session outlives TDC3', holds(lambda: in_session('client-a') and in_session('client-b'), 6))
        check('REL-06 the server counts the accepted extension', counters().get('extensions_accepted', 0) >= 1)
        command('client-a', 'sds-session close')
        idle(['client-a', 'client-b'])

        # REL-07 without an extension request, TDC3 ends the communication (TS 24.282 clause 13.2.4.4.1).
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-07 a session is open')
        server_command(f'release-session-intent {origin_dialog("client-a")} quota reached')
        wait(
            'REL-07 the intent arrives without a data query',
            lambda: release('client-a').get('state') == 'release-pending' and release('client-a').get('query') is False,
        )
        released(
            ['client-a', 'client-b'],
            'REL-07 TDC3 expires and both parties are released with the reason',
            'quota reached',
            15,
        )

        # REL-08 an authorised participant releases the communication (TS 24.282 clause 13.2.5.2).
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-08 a session with the authorised client-b is open')
        before = counters().get('releases_authorised', 0)
        command('client-b', 'mcdata-release now operator decision')
        released(
            ['client-a', 'client-b'],
            'REL-08 the authorised user releases both parties with its reason',
            'operator decision',
        )
        check(
            'REL-08 the request was accepted with 200 and counted',
            release('client-b').get('last_status') == 200 and counters().get('releases_authorised', 0) == before + 1,
        )
        open_session('client-a', ids['client-c'], ['client-c'], 'REL-08 a session with client-c is open')
        command('client-c', 'mcdata-release now')
        wait(
            'REL-08 a participant without the authorisation is refused with 403 (13.2.5.2.4.1 step 3)',
            lambda: release('client-c').get('last_status') == 403,
        )
        check('REL-08 the refused request leaves the session open', in_session('client-a') and in_session('client-c'))
        command('client-a', 'sds-session close')
        idle(['client-a', 'client-c'])

        # REL-09 an authorised participant announces the release (TS 24.282 clause 13.2.6.2): the
        # originator's remaining data and extension request go to it, and its refusal
        # ends the communication.
        open_session('client-a', ids['client-b'], ['client-b'], 'REL-09 a session is open')
        command('client-b', 'mcdata-release intent query supervisor request')
        wait(
            'REL-09 the originator receives the intent with the authorised user\'s reason (13.2.6.2.4.1)',
            lambda: (
                release('client-b').get('last_status') == 200
                and release('client-a').get('state') == 'release-pending'
                and release('client-a').get('reason') == 'supervisor request'
            ),
        )
        wait(
            'REL-09 the remaining amount of data reaches the authorised user (13.2.6.2.4.2)',
            lambda: release('client-b').get('remaining') == '0',
        )
        command('client-a', 'mcdata-release extend')
        wait(
            'REL-09 the extension request reaches the authorised user (13.2.6.2.4.3)',
            lambda: release('client-b').get('state') == 'extension-requested',
        )
        command('client-b', 'mcdata-release reject')
        wait(
            'REL-09 the refusal reaches the originator (13.2.6.2.4.4)',
            lambda: release('client-a').get('state') == 'extension-refused',
        )
        released(
            ['client-a', 'client-b'], 'REL-09 and the communication is released with the reason', 'supervisor request'
        )

        # REL-10 an ad hoc group communication (TS 24.282 clause 13.2.2.2.4.3 step 3A): an ordinary
        # participant leaves alone; an authorised user's "User requested release" ends it.
        command('client-a', f'sds-session adhoc={ids["client-b"]},{ids["client-c"]}')
        wait(
            'REL-10 an ad hoc group SDS session is open at three participants',
            lambda: (
                media('client-a').get('state') == 'open'
                and all(in_session(role) for role in ['client-a', 'client-b', 'client-c'])
            ),
        )
        command('client-c', 'sds-session close')
        wait('REL-10 an ordinary participant leaves alone', lambda: not in_session('client-c') and len(legs()) == 2)
        command('client-b', 'sds-session close all')
        released(
            ['client-a', 'client-b'], 'REL-10 the authorised user\'s BYE with "User requested release" ends it for all'
        )

        # ------------------------------------------------------------------------------
        # REL-11 IP connectivity: an operator release and an authorised user's release
        # (TS 24.282 clauses 13.2.3.2 and 13.2.5.2 apply to IPCONN).
        # The client's current IP connectivity session state.
        def ipcon(role):
            return status(role).get('mcdata_ipconn') or {}

        # ------------------------------------------------------------------------------
        # The IP connectivity sessions the MCData server relays.
        def tunnels():
            return server().get('ipconn_sessions') or []

        command('client-a', f'ipcon {ids["client-b"]}')
        wait(
            'REL-11 an IP connectivity session is open',
            lambda: ipcon('client-a').get('state') == 'open' and ipcon('client-b').get('state') == 'open' and tunnels(),
        )
        wait('REL-11 the server lists the tunnel', lambda: tunnels() and tunnels()[0].get('established'))
        server_command(f'release-session {tunnels()[0]["dialog"]} tunnel audit')
        wait(
            'REL-11 the operator release ends both legs with the reason',
            lambda: (
                all(
                    ipcon(role).get('state') == 'released' and ipcon(role).get('release_reason') == 'tunnel audit'
                    for role in ['client-a', 'client-b']
                )
                and not tunnels()
            ),
        )
        command('client-a', f'ipcon {ids["client-b"]}')
        wait(
            'REL-11 a second IP connectivity session is open',
            lambda: ipcon('client-a').get('state') == 'open' and ipcon('client-b').get('state') == 'open' and tunnels(),
        )
        command('client-b', 'mcdata-release ipcon now')
        wait(
            'REL-11 the authorised user releases it, and the originator learns why',
            lambda: (
                ipcon('client-a').get('state') == 'released'
                and ipcon('client-a').get('release_reason') == 'released by an authorised MCData user'
                and not tunnels()
            ),
        )

        # ------------------------------------------------------------------------------
        # REL-12 file distribution over HTTP: an authorised user announces the release
        # (TS 24.282 clause 13.2.6.3), receives the extension request and refuses it.
        # The file distribution client-a sent with this message ID, or {}.
        def sent_file(message):
            return next(
                (file for file in status('client-a').get('mcdata_files_sent') or [] if file['message_id'] == message),
                {},
            )

        # ------------------------------------------------------------------------------
        # The FD HTTP notifications the client received for this message ID.
        def notes(role, message):
            return [
                notification
                for notification in status(role).get('mcdata_file_notifications') or []
                if notification.get('message_id') == message
            ]

        shell('client-a', 'head -c 200 /dev/urandom | base64 | head -c 200 > /tmp/release.bin')
        previous = {file['message_id'] for file in status('client-a').get('mcdata_files_sent') or []}
        command('client-a', f'fd-send {ids["client-b"]} /tmp/release.bin')
        wait(
            'REL-12 a file is distributed to client-b over HTTP',
            lambda: [
                file
                for file in status('client-a').get('mcdata_files_sent') or []
                if file['message_id'] not in previous and (file.get('status') or 0) // 100 == 2
            ],
        )
        message = next(
            file['message_id']
            for file in status('client-a').get('mcdata_files_sent')
            if file['message_id'] not in previous
        )
        wait(
            'REL-12 client-b has the file offer',
            lambda: any(file.get('message_id') == message for file in status('client-b').get('mcdata_files') or []),
        )
        command('client-b', f'fd-release-intent {message} audit hold')
        wait(
            'REL-12 the originator is told of the release with the authorised user\'s reason (13.2.6.3.4.1)',
            lambda: (
                sent_file(message).get('state') == 'release-pending'
                and any(
                    notification.get('termination') == 4 and 'audit hold' in notification.get('reason', '')
                    for notification in notes('client-a', message)
                )
            ),
        )
        command('client-a', f'fd-extend {message}')
        wait(
            'REL-12 the extension request is passed to the authorised user (13.2.6.3.4.2)',
            lambda: any(notification.get('termination') == 5 for notification in notes('client-b', message)),
        )
        command('client-b', f'fd-extension-response reject {message}')
        wait(
            'REL-12 the refusal reaches the originator and the transmission is stopped (13.2.6.3.4.3)',
            lambda: (
                sent_file(message).get('state') == 'stopped'
                and any(
                    notification.get('termination') == 6 and notification.get('extension') == 2
                    for notification in notes('client-a', message)
                )
            ),
        )
        wait(
            'REL-12 the authorised user receives RELEASE SUCCESS',
            lambda: any(
                notification.get('termination') == 2 and notification.get('release') == 1
                for notification in notes('client-b', message)
            ),
        )

        observations['server_counters'] = {
            key: value for key, value in counters().items() if key.startswith(('release', 'extension', 'fd_stopped'))
        }
        check('server instance unchanged', server()['instance_id'] == instance)
        result['passed'] = True
    except (
        AssertionError,
        KeyError,
        IndexError,
        StopIteration,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-release-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
