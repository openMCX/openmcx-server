#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise MCData file distribution over HTTP (TS 24.282 clauses 10.2.2 to 10.2.4, 12.2 and 12.4).

Run against a fixture prepared with --mcdata (see add_mcdata_policy in
tools/prepare-prearranged-test.py). Check IDs match tests/mcdata/MCDATA_FD_TEST.md.

Also covered: auto-receive (TS 24.282 clause 11.2), the media storage function's discovery
(clause 10.2.1.3) and upload checks (clause 10.2.2.2), and the release of a distribution by its
originator (clause 6.2.2.4), by the server (clauses 13.2.3.3.4 and 13.2.4.5) and by an authorised
user (clause 13.2.5.3).

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
# FD disposition notification types (TS 24.282 table 15.2.6-1) and the FILE EXPIRED UNAVAILABLE TO
# DOWNLOAD notification type (TS 24.282 table 15.2.18-1).
ACCEPTED, REJECTED, COMPLETED, DEFERRED = 1, 2, 3, 4
EXPIRED = 1
# TS 24.282 table 15.2.22-1: Termination information type of an FD HTTP TERMINATION message.
TERMINATION_RESPONSE = 2
TRANSMISSION_STOPPED = 3
INTENT_TO_RELEASE = 4
EXTENSION_REQUEST = 5
EXTENSION_RESPONSE = 6
# TS 24.282 table 15.2.23-1: Release response type RELEASE SUCCESS.
RELEASE_SUCCESS = 1
# TS 24.282 table 15.2.21-1: Extension response type ACCEPTED.
EXTENSION_ACCEPTED = 1


# ------------------------------------------------------------------------------
def main():
    """Run the MCData file distribution checks FD-01 to FD-11 and write integration/mcdata-fd-results.json."""
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
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcdata']['user_id'] for client in roles}
    group = configs['client-a']['mcdata']['group_id']
    domain = group.split('@', 1)[1]
    group_user = group.split(':', 1)[1].split('@', 1)[0]
    checks, observations = [], {}
    result = dict(scenario='mcdata-file-distribution', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The container's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """Every client's and the MCData server's status, for the failure report."""
        return {client: status(client) for client in roles + ['mcdata-server']}

    # ------------------------------------------------------------------------------
    def command(role, text, timeout=30):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def shell(role, text):
        """Run a shell command in the role's container; its output, a failure raising RuntimeError."""
        run = subprocess.run(cli + ['exec', '-T', role, 'sh', '-c', text], capture_output=True, text=True, timeout=30)
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip()}')
        return run.stdout

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=20):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
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
        """Record the label as a passed check if the condition holds; raise with a snapshot otherwise."""
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def files(role):
        """The files the role was offered."""
        return status(role).get('mcdata_files') or []

    # ------------------------------------------------------------------------------
    def offered(role, name):
        """The role's offers of the named file."""
        return [file_entry for file_entry in files(role) if file_entry.get('name') == name]

    # ------------------------------------------------------------------------------
    def sent(role):
        """The role's sent file distributions."""
        return status(role).get('mcdata_files_sent') or []

    # ------------------------------------------------------------------------------
    def last(role):
        """The result of the role's last file distribution request, or {}."""
        return status(role).get('mcdata_fd_last_result') or {}

    # ------------------------------------------------------------------------------
    def notifications(role, message_id):
        """The file notifications the role received for the message."""
        return [
            notification
            for notification in status(role).get('mcdata_file_notifications') or []
            if notification.get('message_id') == message_id
        ]

    # ------------------------------------------------------------------------------
    def send(role, text, expect=202, warning=None, label=None):
        """Run a file distribution command on the role and wait (as the labelled check) for its new request's
        result with the expected status and warning; the message ID."""
        before = [outgoing['message_id'] for outgoing in sent(role)]
        command(role, text)
        wait(
            label or f'{role}: {text[:50]} -> {expect}',
            lambda: (
                lambda entries: (
                    entries
                    and entries[-1]['message_id'] not in before
                    and last(role).get('message_id') == entries[-1]['message_id']
                    and last(role).get('status') == expect
                    and (warning is None or warning in last(role).get('warning', ''))
                )
            )(sent(role)),
        )
        return sent(role)[-1]['message_id']

    # ------------------------------------------------------------------------------
    def make(role, name, size):
        """Create a file of random text of the size in the role's /tmp; its SHA-256 digest."""
        shell(role, f'head -c {size} /dev/urandom | base64 | head -c {size} > /tmp/{name}')
        return shell(role, f'sha256sum /tmp/{name}').split()[0]

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(client).get('mcdata_authorized') and status(client).get('mcdata_affiliated') for client in roles
            ),
            90,
        )
        instance = status('mcdata-server')['instance_id']

        # FD-01 one-to-one FD using HTTP with automatic reception (TS 24.282 clause 11.2): the file is
        # small enough for the controlling function to make the download mandatory.
        small = f'small-{secrets.token_hex(3)}.txt'
        digest = make('client-a', small, 40)
        message = send(
            'client-a',
            f'fd-send completed {ids["client-b"]} /tmp/{small}',
            label='FD-01 one-to-one FD request accepted with 202',
        )
        record = sent('client-a')[-1]
        check(
            'FD-01 the file was uploaded to the media storage function and named by its URL',
            record['file_url'].endswith('/' + small) and '/mcdata/files/' in record['file_url'],
        )
        wait(
            'FD-01 the recipient downloads the file automatically (auto-receive, 11.2)',
            lambda: (
                offered('client-b', small)
                and offered('client-b', small)[0]['state'] == 'downloaded'
                and offered('client-b', small)[0]['mandatory']
            ),
        )
        check(
            'FD-01 the downloaded file is identical to the file that was sent',
            shell('client-b', 'sha256sum /artifacts/client-b/downloads/' + small).split()[0] == digest,
        )
        check(
            'FD-01 the metadata carries the file hash and the recipient verified it (RFC 5547 hash selector)',
            offered('client-b', small)[0].get('sha256') == digest
            and offered('client-b', small)[0].get('hash_verified') is True,
        )
        wait(
            'FD-01 the originator receives the accepted and completed FD notifications (12.2)',
            lambda: (
                {notification['type'] for notification in notifications('client-a', message) if 'type' in notification}
                == {ACCEPTED, COMPLETED}
            ),
        )
        wait(
            'FD-01 the server records the recipient as having downloaded the file',
            lambda: (
                (status('mcdata-server').get('file_transfers') or {}).get(message, {}).get('downloaded')
                == [ids['client-b']]
            ),
        )

        # FD-02 group FD: every affiliated member is offered the file and decides.
        large = f'large-{secrets.token_hex(3)}.txt'
        digest = make('client-a', large, 600)
        message = send(
            'client-a',
            f'fd-send completed group={group} /tmp/{large}',
            label='FD-02 group FD request accepted with 202',
        )
        wait(
            'FD-02 every other affiliated member is offered the file without mandatory download',
            lambda: all(
                offered(client, large)
                and offered(client, large)[0]['state'] == 'offered'
                and not offered(client, large)[0]['mandatory']
                and offered(client, large)[0]['group'] == group
                for client in ['client-b', 'client-c', 'client-d']
            ),
        )
        check('FD-02 the sender is not offered its own file', not offered('client-a', large))
        command('client-b', f'fd-accept {message}')
        command('client-c', f'fd-reject {message}')
        command('client-d', f'fd-defer {message}')
        wait(
            'FD-02 the accepting member downloads the file',
            lambda: offered('client-b', large) and offered('client-b', large)[0]['state'] == 'downloaded',
        )
        check(
            'FD-02 the downloaded group file is identical to the file that was sent',
            shell('client-b', 'sha256sum /artifacts/client-b/downloads/' + large).split()[0] == digest,
        )
        wait(
            'FD-02 accepted, completed, rejected and deferred notifications reach the originator',
            lambda: (
                {notification['type'] for notification in notifications('client-a', message) if 'type' in notification}
                == {ACCEPTED, COMPLETED, REJECTED, DEFERRED}
            ),
        )
        wait(
            'FD-02 the server records the download and the rejection',
            lambda: (
                lambda transfer: (
                    transfer.get('downloaded') == [ids['client-b']] and transfer.get('rejected') == [ids['client-c']]
                )
            )((status('mcdata-server').get('file_transfers') or {}).get(message, {})),
        )
        check('FD-02 the deferring member keeps the offer', offered('client-d', large)[0]['state'] == 'deferred')
        # FD-08 aggregation (TS 24.282 clause 12.2.3 step 15c): one member deferred, so the aggregate
        # goes out at TDC1 expiry and carries every notification collected so far.
        check(
            'FD-08 the group notifications arrive in one aggregated SIP MESSAGE',
            len(notifications('client-a', message)) == 4
            and all(notification.get('aggregated') == 4 for notification in notifications('client-a', message)),
        )
        command('client-d', f'fd-accept {message}')
        wait(
            'FD-08 a notification after the aggregate is relayed individually',
            lambda: any(
                notification['from'] == ids['client-d']
                and notification['type'] == COMPLETED
                and notification.get('aggregated') == 1
                for notification in notifications('client-a', message)
            ),
        )

        # FD-03 TDC2 (file availability timer, TS 24.282 clause 12.4): the sender asks for 3 seconds.
        expiring = f'expiring-{secrets.token_hex(3)}.txt'
        make('client-a', expiring, 600)
        expired_before = (status('mcdata-server').get('counters') or {}).get('fd_expired', 0)
        message = send(
            'client-a',
            f'fd-send available=3 group={group} /tmp/{expiring}',
            label='FD-03 FD request with a short file availability accepted with 202',
        )
        wait(
            'FD-03 the members are offered the file',
            lambda: all(offered(client, expiring) for client in ['client-b', 'client-c']),
        )
        wait(
            'FD-03 TDC2 expiry tells the members that the file is no longer available (12.4.2.2)',
            lambda: (
                all(
                    offered(client, expiring) and offered(client, expiring)[0]['state'] == 'expired'
                    for client in ['client-b', 'client-c']
                )
                and (status('mcdata-server').get('counters') or {}).get('fd_expired', 0) > expired_before
            ),
            30,
        )
        check(
            'FD-03 the network notification names the expired file',
            any(
                notification.get('network_notification') == EXPIRED
                for notification in notifications('client-b', message)
            ),
        )
        wait(
            'FD-03 the server forgets the transfer once the file is gone',
            lambda: message not in (status('mcdata-server').get('file_transfers') or {}),
        )
        command('client-b', f'fd-accept {message}')
        wait(
            'FD-03 a download after the file was removed fails',
            lambda: offered('client-b', expiring)[0].get('download_status') == 404,
        )

        # FD-04 rejections (TS 24.282 clause 10.2.4.3.1 step 7, clause 10.2.4.4.2 steps 7 and 12). The file is
        # uploaded once and the FD requests then name its URL, so that each rejection is
        # the one made by the MCData server and not by the media storage function.
        note = f'note-{secrets.token_hex(3)}.txt'
        make('client-a', note, 40)
        make('client-c', note, 40)
        make('client-d', note, 40)
        send(
            'client-a',
            f'fd-send available=120 {ids["client-b"]} /tmp/{note}',
            label='FD-04 a file for the rejection cases is stored',
        )
        url = sent('client-a')[-1]['file_url']
        send(
            'client-d',
            f'fd-send url={url} {ids["client-a"]} /tmp/{note}',
            403,
            '200',
            'FD-04 a user without <allow-transmit-data> is rejected with 200',
        )
        send(
            'client-a',
            f'fd-send url={url} {ids["client-d"]} /tmp/{note}',
            403,
            '229',
            'FD-04 a target outside the one-to-one list is rejected with 229',
        )
        send(
            'client-c',
            f'fd-send url={url} {ids["client-b"]} /tmp/{note}',
            403,
            '230',
            "FD-04 a sender outside the target's incoming list is rejected with 230",
        )
        send(
            'client-a',
            f'fd-send url={url} group=sip:{group_user}-nosds@{domain} /tmp/{note}',
            403,
            '213',
            'FD-04 a group without <mcdata-allow-file-distribution> is rejected with 213',
        )
        send(
            'client-a',
            f'fd-send url={url} group=sip:{group_user}-nosupport@{domain} /tmp/{note}',
            488,
            '214',
            'FD-04 a group without the FD enabler is rejected with 488/214',
        )
        send(
            'client-a',
            f'fd-send url={url} group=sip:{group_user}-nosuch@{domain} /tmp/{note}',
            404,
            '163',
            'FD-04 an unknown group is rejected with 404/163',
        )
        send(
            'client-a',
            f'fd-send url=https://http-proxy:8443/content/mcdata/files/{"0" * 32}/none.txt {ids["client-b"]} /tmp/{note}',
            403,
            '212',
            'FD-04 a file URL that does not exist is rejected with 212',
        )
        big = f'big-{secrets.token_hex(3)}.txt'
        make('client-a', big, 2500)
        send(
            'client-a',
            f'fd-send url={url} group={group} /tmp/{big}',
            403,
            '208',
            'FD-04 a file over the group limit is rejected with 208',
        )
        send(
            'client-a',
            f'fd-send url={url} {ids["client-b"]} /tmp/{big}',
            403,
            '202',
            'FD-04 a file over the one-to-one limit is rejected with 202',
        )
        # The media storage function refuses the upload itself (TS 24.282 clause 10.2.2.2 step 1).
        huge = f'huge-{secrets.token_hex(3)}.txt'
        make('client-a', huge, 5000)
        command('client-a', f'fd-send {ids["client-b"]} /tmp/{huge}')
        wait(
            'FD-04 the media storage function refuses a file over <max-data-size-fd-bytes> with 413',
            lambda: last('client-a').get('upload_status') == 413,
        )
        command('client-d', f'fd-send {ids["client-a"]} /tmp/{note}')
        wait(
            'FD-04 the media storage function refuses an upload by a user who may not transmit data',
            lambda: last('client-d').get('upload_status') == 403,
        )

        # FD-05 FD to a functional alias: 300 Multiple Choices, then the selected user
        # (client-c has no one-to-one target list, so the alias is an allowed target).
        medic = f'sip:medic.fa@{domain}'
        command('client-d', f'mcdata-fa activate {medic}')
        wait(
            'FD-05 client-d holds the functional alias',
            lambda: medic in (status('client-d').get('mcdata_functional_aliases') or []),
        )
        alias_file = f'alias-{secrets.token_hex(3)}.txt'
        digest = make('client-c', alias_file, 40)
        command('client-c', f'fd-send completed fa={medic} /tmp/{alias_file}')
        wait(
            'FD-05 the alias is resolved with 300 and the file reaches the selected user',
            lambda: (
                [entry['status'] for entry in sent('client-c') if entry['name'] == alias_file][-2:] == [300, 202]
                and [entry['target'] for entry in sent('client-c') if entry['name'] == alias_file][-1]
                == ids['client-d']
                and offered('client-d', alias_file)
                and offered('client-d', alias_file)[0]['state'] == 'downloaded'
            ),
        )
        check(
            'FD-05 the file delivered through the alias is identical',
            shell('client-d', 'sha256sum /artifacts/client-d/downloads/' + alias_file).split()[0] == digest,
        )
        command('client-d', f'mcdata-fa deactivate {medic}')

        # FD-06 release of a distribution (TS 24.282 clause 6.2.2.4, clause 10.2.4.4.2 step 17): the originator
        # cancels, the file is deleted and the recipients are told.
        cancelled = f'cancelled-{secrets.token_hex(3)}.txt'
        make('client-a', cancelled, 600)
        message = send(
            'client-a', f'fd-send group={group} /tmp/{cancelled}', label='FD-06 a group FD request to release later'
        )
        wait(
            'FD-06 the members are offered the file',
            lambda: all(offered(client, cancelled) for client in ['client-b', 'client-c']),
        )
        terminated_before = (status('mcdata-server').get('counters') or {}).get('fd_terminated', 0)
        command('client-a', f'fd-cancel {message}')
        wait(
            'FD-06 the termination request is accepted with 202',
            lambda: last('client-a').get('action') == 'terminate' and last('client-a').get('status') == 202,
        )
        wait(
            'FD-06 the originator receives a TERMINATION RESPONSE with RELEASE SUCCESS',
            lambda: (
                any(
                    notification.get('termination') == TERMINATION_RESPONSE
                    and notification.get('release') == RELEASE_SUCCESS
                    and notification['message_id'] == message
                    for notification in notifications('client-a', message)
                )
                and [entry['state'] for entry in sent('client-a') if entry['message_id'] == message] == ['terminated']
            ),
        )
        wait(
            'FD-06 the recipients are told the file was deleted (12.4.2.1)',
            lambda: (
                all(
                    offered(client, cancelled) and offered(client, cancelled)[0]['state'] == 'deleted'
                    for client in ['client-b', 'client-c']
                )
                and (status('mcdata-server').get('counters') or {}).get('fd_terminated', 0) > terminated_before
            ),
        )
        wait(
            'FD-06 the server forgets the released transfer',
            lambda: message not in (status('mcdata-server').get('file_transfers') or {}),
        )
        command('client-b', f'fd-accept {message}')
        wait(
            'FD-06 the deleted file can no longer be downloaded',
            lambda: offered('client-b', cancelled)[0].get('download_status') == 404,
        )
        # FD-07 releasing a transfer the server has already forgotten is rejected with 224.
        command('client-a', f'fd-cancel {message}')
        wait(
            'FD-07 a release naming an unknown transmission is rejected with 404/224',
            lambda: last('client-a').get('status') == 404 and '224' in last('client-a').get('warning', ''),
        )

        # ------------------------------------------------------------------------------
        # FD-10 server-initiated release (TS 24.282 clause 13.2.3.3.4) with prior indication and an
        # extension (clause 13.2.4.5). The operator triggers both through the server's
        # control interface, which stands in for the release policy.
        def server_command(text):
            """Run one openmcx-mcdata-server command at the MCData server; a failure raises RuntimeError."""
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
                raise RuntimeError(f'mcdata-server {text}: {run.stderr.strip() or run.stdout.strip()}')

        # ------------------------------------------------------------------------------
        def state(role, message_id):
            """The states of the role's sent file distribution of the message."""
            return [entry['state'] for entry in sent(role) if entry['message_id'] == message_id and 'state' in entry]

        kept = f'kept-{secrets.token_hex(3)}.txt'
        make('client-a', kept, 600)
        message = send(
            'client-a',
            f'fd-send available=120 group={group} /tmp/{kept}',
            label='FD-10 a group FD request to release with prior indication',
        )
        wait(
            'FD-10 the members are offered the file',
            lambda: all(offered(client, kept) for client in ['client-b', 'client-c']),
        )
        server_command(f'release-intent {message}')
        wait(
            'FD-10 the originator is told of the intent to release, with the reason (13.2.4.5.2.1)',
            lambda: (
                state('client-a', message) == ['release-pending']
                and any(
                    notification.get('termination') == INTENT_TO_RELEASE and 'expire' in notification.get('reason', '')
                    for notification in notifications('client-a', message)
                )
            ),
        )
        wait(
            'FD-10 the server records the pending release',
            lambda: (status('mcdata-server').get('file_transfers') or {}).get(message, {}).get('release_intent'),
        )
        command('client-a', f'fd-extend {message}')
        wait(
            'FD-10 the extension request is accepted (13.2.4.5.2.3)',
            lambda: (
                state('client-a', message) == ['extended']
                and any(
                    notification.get('termination') == EXTENSION_RESPONSE
                    and notification.get('extension') == EXTENSION_ACCEPTED
                    for notification in notifications('client-a', message)
                )
                and (status('mcdata-server').get('file_transfers') or {}).get(message, {}).get('extended')
            ),
        )
        server_command(f'release {message} data volume limit')
        wait(
            'FD-10 the server stops the transmission and tells the originator the reason (13.2.3.3.4)',
            lambda: (
                state('client-a', message) == ['stopped']
                and any(
                    notification.get('termination') == TRANSMISSION_STOPPED
                    and 'data volume limit' in notification.get('reason', '')
                    for notification in notifications('client-a', message)
                )
            ),
        )
        wait(
            'FD-10 the recipients are told the file was deleted',
            lambda: all(
                offered(client, kept) and offered(client, kept)[0]['state'] == 'deleted'
                for client in ['client-b', 'client-c']
            ),
        )

        # FD-11 release by an authorised MCData user (TS 24.282 clause 13.2.5.3).
        # Over the auto-receive size so that the offer waits, under the one-to-one limit.
        seized = f'seized-{secrets.token_hex(3)}.txt'
        make('client-a', seized, 200)
        message = send(
            'client-a',
            f'fd-send available=120 group={group} /tmp/{seized}',
            label='FD-11 a group FD request for an authorised user to release',
        )
        wait(
            'FD-11 the members are offered the file',
            lambda: all(offered(client, seized) for client in ['client-b', 'client-c']),
        )
        command('client-c', f'fd-release {message}')
        wait(
            'FD-11 a user without the release authorisation is rejected with 403',
            lambda: last('client-c').get('action') == 'release' and last('client-c').get('status') == 403,
        )
        command('client-b', f'fd-release {message}')
        wait(
            'FD-11 the authorised user is answered with RELEASE SUCCESS (13.2.5.3.4.1)',
            lambda: (
                last('client-b').get('status') == 202
                and any(
                    notification.get('termination') == TERMINATION_RESPONSE
                    and notification.get('release') == RELEASE_SUCCESS
                    for notification in notifications('client-b', message)
                )
            ),
        )
        wait(
            'FD-11 the originator is told that its transmission was stopped',
            lambda: (
                state('client-a', message) == ['stopped']
                and any(
                    notification.get('termination') == TRANSMISSION_STOPPED
                    and 'authorised' in notification.get('reason', '')
                    for notification in notifications('client-a', message)
                )
            ),
        )

        # ------------------------------------------------------------------------------
        # FD-09 discovery of the media storage function URI (TS 24.282 clause 10.2.1.3).
        def discovery(role):
            """The role's last media storage function discovery result (TS 24.282 clause 10.2.1.3), or {}."""
            return status(role).get('mcdata_discovery_result') or {}

        configured = configs['client-a']['endpoints']['content']
        command('client-a', 'fd-discover')
        wait(
            'FD-09 the absolute URI of the media storage function is discovered',
            lambda: (
                discovery('client-a').get('uri') == configured
                and status('client-a').get('mcdata_content_server') == configured
            ),
        )
        command('client-a', f'fd-discover group={group}')
        wait(
            'FD-09 discovery for a group returns the same URI with the group named',
            lambda: discovery('client-a').get('group') == group and discovery('client-a').get('uri') == configured,
        )
        command('client-a', f'fd-discover group=sip:{group_user}-nosds@{domain}')
        wait(
            'FD-09 discovery for a group without file distribution is rejected with 213',
            lambda: discovery('client-a').get('status') == 403 and '213' in discovery('client-a').get('warning', ''),
        )
        command('client-d', 'fd-discover')
        wait(
            'FD-09 discovery by a user without <allow-transmit-data> is rejected with 200',
            lambda: discovery('client-d').get('status') == 403 and '200' in discovery('client-d').get('warning', ''),
        )

        observations['server_counters'] = (status('mcdata-server') or {}).get('counters')
        check('server instance unchanged', status('mcdata-server')['instance_id'] == instance)
        result['passed'] = True
    except (AssertionError, KeyError, IndexError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-fd-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
