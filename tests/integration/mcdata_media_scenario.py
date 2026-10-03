#!/usr/bin/env python3
"""Exercise MCData over the media plane: standalone SDS (TS 24.282 clause 9.2.3, TS 24.582
clause 6.1.1), the SDS session (TS 24.282 clause 9.2.4, TS 24.582 clause 6.1.2) with emergency
one-to-one and emergency or imminent peril group communications (TS 24.282 clauses 6.2.8 and
6.3.7), FD over the media plane (TS 24.282 clause 10.2.5, TS 24.582 clause 7), and ad hoc group
data communications (TS 24.282 clause 24), each with the transmission control of TS 24.282
clause 11.1 and the warning texts of TS 24.282 table 4.9.2-2.

Run against a fixture prepared with --mcdata (see add_mcdata_policy in
tools/prepare-prearranged-test.py). Check IDs match tests/mcdata/MCDATA_MEDIA_TEST.md.

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
DELIVERED, READ = 2, 3


# ------------------------------------------------------------------------------
# Run the scenario: check MP-01 to MP-24 and write the results file.
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
    checks, observations = [], {}
    result = dict(scenario='mcdata-media-plane', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the container of a role writes, or {} while it is missing or partly written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The status of every client and of the MCData server, attached to a failure.
    def snapshot():
        return {role: status(role) for role in roles + ['mcdata-server']}

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
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
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
    # The outcome of the last media plane request of a client.
    def media(role):
        return status(role).get('mcdata_media_result') or {}

    # ------------------------------------------------------------------------------
    # The messages a client received over the media plane that carry this text.
    def received(role, text):
        return [
            message
            for message in status(role).get('mcdata_media_received') or []
            if any(payload.get('text') == text for payload in message.get('payloads', []))
        ]

    # ------------------------------------------------------------------------------
    # The MCData server's counters.
    def counters():
        return status('mcdata-server').get('counters') or {}

    # ------------------------------------------------------------------------------
    # The client's media plane result once it is of a message other than the earlier one (each SDS and file offered
    # over the media plane has a new Message ID), else {}.
    def new_media(role, earlier):
        result = media(role)
        return result if result.get('message_id') not in (None, earlier) else {}

    # ------------------------------------------------------------------------------
    # Send a standalone SDS over the media plane (TS 24.282 clause 9.2.3.2.3) and wait for the expected
    # answer and warning text to this message.
    def send(role, target, text, expect=200, warning=None, label=None):
        earlier = media(role).get('message_id')
        command(role, f'sds-media {target} {text}')
        wait(
            label or f'{role}: media SDS -> {expect}',
            lambda: (
                new_media(role, earlier).get('status') == expect
                and (warning is None or warning in new_media(role, earlier).get('warning', ''))
            ),
        )

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(role).get('mcdata_authorized') and status(role).get('mcdata_affiliated') for role in roles
            ),
            90,
        )
        instance = status('mcdata-server')['instance_id']

        # MP-01 one-to-one standalone SDS over the media plane.
        text = f'media-{secrets.token_hex(4)}'
        before = counters().get('media_delivered', 0)
        send('client-a', ids['client-b'], text, label='MP-01 the INVITE offering the MSRP stream is accepted with 200')
        wait(
            'MP-01 the sender puts the payload on the MSRP connection and releases the session (TS 24.582 6.1.1.2.1)',
            lambda: media('client-a').get('state') in ('sent', 'delivered'),
        )
        wait('MP-01 the session ends once the SEND is answered', lambda: media('client-a').get('state') == 'delivered')
        wait(
            'MP-01 the recipient receives the message over the media plane with the same Message ID',
            lambda: (
                received('client-b', text)
                and received('client-b', text)[0]['message_id'] == media('client-a').get('message_id')
            ),
        )
        check(
            'MP-01 the recipient learns the originator from the second leg',
            received('client-b', text)[0]['from'] == ids['client-a'],
        )
        wait(
            'MP-01 the server counts the request and its delivery',
            lambda: counters().get('media_sds', 0) >= 1 and counters().get('media_delivered', 0) > before,
        )
        check('MP-01 no signalling plane SDS was used', not (status('client-b').get('mcdata_inbox') or []))

        # MP-02 the media plane applies the same transmission control as TS 24.282 clause 11.1.
        send(
            'client-d',
            ids['client-a'],
            'refused',
            403,
            '200',
            'MP-02 a user without <allow-transmit-data> is rejected with 200',
        )
        send(
            'client-a',
            ids['client-d'],
            'refused',
            403,
            '229',
            'MP-02 a target outside the one-to-one list is rejected with 229',
        )
        send(
            'client-c',
            ids['client-b'],
            'refused',
            403,
            '230',
            "MP-02 a sender outside the target's incoming list is rejected with 230",
        )

        # MP-04 group standalone SDS over the media plane: every affiliated member is
        # offered a leg of its own (TS 24.282 clause 9.2.3.4.4 with the group checks of TS 24.282
        # clause 9.2.2.4.2 step 6).
        text = f'group-media-{secrets.token_hex(4)}'
        before = counters().get('media_delivered', 0)
        send('client-a', f'group={group}', text, label='MP-04 the group media plane request is accepted with 200')
        wait(
            'MP-04 every other affiliated member receives it over its own MSRP leg',
            lambda: all(received(role, text) for role in ['client-b', 'client-c', 'client-d']),
        )
        check(
            'MP-04 the recipients learn the calling group and the originator',
            all(
                received(role, text)[0]['group'] == group and received(role, text)[0]['from'] == ids['client-a']
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        check('MP-04 the sender is not offered its own message', not received('client-a', text))
        wait(
            'MP-04 the server counts one delivery per recipient',
            lambda: counters().get('media_delivered', 0) >= before + 3,
        )
        send(
            'client-c',
            f'group={group}',
            'refused',
            403,
            '201',
            'MP-04 a member without transmit permission on the group is rejected with 201',
        )
        send(
            'client-a',
            f'group=sip:{group_user}-nosds@{domain}',
            'refused',
            403,
            '206',
            'MP-04 a group where SDS is not allowed is rejected with 206',
        )
        send(
            'client-a',
            f'group=sip:{group_user}-nosupport@{domain}',
            'refused',
            488,
            '207',
            'MP-04 a group without the SDS enabler is rejected with 488/207',
        )

        # ------------------------------------------------------------------------------
        # The messages a client sent on its SDS session.
        def sent(role):
            return status(role).get('mcdata_media_sent') or []

        # ------------------------------------------------------------------------------
        # The in-band disposition notifications a client received for one message (TS 24.582 clause 6.1.2.5).
        def notifications(role, message_id):
            return [
                notification
                for notification in status(role).get('mcdata_media_notifications') or []
                if notification['message_id'] == message_id
            ]

        # MP-05 an SDS session (TS 24.282 clause 9.2.4): the session stays open, both parties
        # send, and the disposition notifications travel in band (TS 24.582 clause 6.1.2.5).
        command('client-a', f'sds-session {ids["client-b"]}')
        wait(
            'MP-05 the SDS session is established and stays open',
            lambda: (
                media('client-a').get('state') == 'open'
                and status('client-a').get('mcdata_media_session')
                and status('client-b').get('mcdata_media_session')
            ),
        )
        first = f'session-a-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send delivery {first}')
        wait(
            'MP-05 the message reaches the other party with its sender named',
            lambda: received('client-b', first) and received('client-b', first)[0]['from'] == ids['client-a'],
        )
        wait(
            'MP-05 the in-band DELIVERED notification returns to the sender',
            lambda: (
                sent('client-a')
                and notifications('client-a', sent('client-a')[-1]['message_id'])
                and notifications('client-a', sent('client-a')[-1]['message_id'])[0]['type'] == DELIVERED
            ),
        )
        # The session is bidirectional: the invited party answers on the same session.
        reply = f'session-b-{secrets.token_hex(3)}'
        command('client-b', f'sds-session send {reply}')
        wait(
            'MP-05 the invited party sends on the same session',
            lambda: received('client-a', reply) and received('client-a', reply)[0]['from'] == ids['client-b'],
        )
        check(
            'MP-05 the session carried both messages on one MSRP connection',
            media('client-a').get('state') == 'open' and status('client-a').get('mcdata_media_session'),
        )
        command('client-a', 'sds-session close')
        wait(
            'MP-05 closing the session releases it at both ends',
            lambda: (
                not status('client-a').get('mcdata_media_session')
                and not status('client-b').get('mcdata_media_session')
            ),
        )

        # MP-06 emergency one-to-one communication (TS 24.282 clauses 6.2.8.3, 6.2.8.4.3, 6.2.8.4.4):
        # an ongoing session is upgraded, both parties follow, and it is cancelled.
        command('client-a', f'sds-session {ids["client-b"]}')
        wait(
            'MP-06 a session for the emergency upgrade is open',
            lambda: media('client-a').get('state') == 'open' and status('client-b').get('mcdata_media_session'),
        )
        check(
            'MP-06 the session starts as an ordinary communication',
            not status('client-a').get('mcdata_session_emergency')
            and status('client-a').get('mcdata_session_emergency_state', '').startswith('MDEPC 1'),
        )
        command('client-a', 'sds-session emergency')
        wait(
            'MP-06 the upgrade is accepted and the sender reaches MDEPC 3 (6.2.8.4.4)',
            lambda: (
                status('client-a').get('mcdata_session_emergency')
                and status('client-a').get('mcdata_session_emergency_state', '').startswith('MDEPC 3')
                and status('client-a').get('mcdata_emergency')
            ),
        )
        wait(
            'MP-06 the other party follows the emergency condition (6.2.8.4.2)',
            lambda: status('client-b').get('mcdata_session_emergency') and status('client-b').get('mcdata_emergency'),
        )
        wait(
            'MP-06 the server records the emergency condition on both legs',
            lambda: (
                len(
                    [
                        session
                        for session in status('mcdata-server').get('media_sessions') or []
                        if session.get('emergency')
                    ]
                )
                >= 2
            ),
        )
        urgent = f'urgent-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send {urgent}')
        wait(
            'MP-06 the session still carries messages while it is an emergency communication',
            lambda: received('client-b', urgent),
        )
        command('client-a', 'sds-session emergency cancel')
        wait(
            'MP-06 the cancellation returns both parties to MDEPC 1 (6.2.8.4.3)',
            lambda: (
                not status('client-a').get('mcdata_session_emergency')
                and status('client-a').get('mcdata_session_emergency_state', '').startswith('MDEPC 1')
                and not status('client-b').get('mcdata_session_emergency')
            ),
        )
        command('client-a', 'sds-session close')
        wait('MP-06 the session is closed', lambda: not status('client-a').get('mcdata_media_session'))
        # A user without <allow-emergency-private-call> in its MCData ruleset is refused.
        command('client-c', f'sds-session {ids["client-a"]}')
        wait('MP-06 client-c opens an ordinary session', lambda: media('client-c').get('state') == 'open')
        command('client-c', 'sds-session emergency')
        wait(
            'MP-06 an unauthorised emergency upgrade is rejected with 403/112',
            lambda: (
                media('client-c').get('emergency_status') == 403
                and '112' in media('client-c').get('emergency_warning', '')
            ),
        )
        check(
            'MP-06 the refused session stays an ordinary communication',
            not status('client-c').get('mcdata_session_emergency'),
        )
        command('client-c', 'sds-session close')
        wait('MP-06 the refused session is closed', lambda: not status('client-c').get('mcdata_media_session'))

        # ------------------------------------------------------------------------------
        # The MCData emergency (MDEG) or imminent peril (MDIG) group state of a client
        # (TS 24.282 clause 6.2.8.1).
        def group_state(role, which='emergency'):
            return status(role).get(f'mcdata_group_{which}_state', '')

        # ------------------------------------------------------------------------------
        # The MCData emergency (MDEGC) or imminent peril (MDIGC) group communication state of a
        # client (TS 24.282 clause 6.2.8.1).
        def communication_state(role, which='emergency'):
            return status(role).get(f'mcdata_group_{which}_communication_state', '')

        # ------------------------------------------------------------------------------
        # The in-progress emergency or imminent peril state the server holds for the group.
        def server_group():
            return (status('mcdata-server').get('group_priority') or {}).get(group) or {}

        # MP-09 an emergency group communication on a group SDS session (TS 24.282 clauses
        # 6.2.8.1.1, 6.3.7.1.11): the group enters an in-progress emergency state that every
        # member follows, and an authorised user cancels it (TS 24.282 clause 6.2.8.1.3).
        command('client-a', f'sds-session group={group} emergency')
        wait(
            'MP-09 the emergency group session is accepted and the originator reaches MDEGC 3 (6.2.8.1.4)',
            lambda: (
                media('client-a').get('state') == 'open'
                and communication_state('client-a').startswith('MDEGC 3')
                and group_state('client-a').startswith('MDEG 2')
            ),
        )
        wait(
            'MP-09 every other affiliated member joins the in-progress emergency state (9.2.4.2.4 step 4A)',
            lambda: all(group_state(role).startswith('MDEG 2') for role in ['client-b', 'client-c', 'client-d']),
        )
        wait(
            'MP-09 the server records the in-progress emergency state of the group (6.3.7)',
            lambda: server_group().get('emergency') and not server_group().get('imminent'),
        )
        check(
            'MP-09 the originator is in the MCData emergency state (6.2.8.1.1 step 1)',
            status('client-a').get('mcdata_emergency'),
        )
        urgent = f'group-urgent-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send {urgent}')
        wait('MP-09 the emergency group session carries messages', lambda: received('client-b', urgent))

        # MP-10 an imminent peril request on a group that is already in an
        # in-progress emergency state is answered 200 with warning 149, and a SIP
        # INFO request corrects the client (TS 24.282 clauses 6.3.7.1.10, 6.2.8.1.13).
        command('client-b', 'sds-session imminent')
        wait(
            'MP-10 the request is answered 200 with warning 149 (9.2.4.4.4 step 3)',
            lambda: (
                media('client-b').get('priority_status') == 200
                and '149' in media('client-b').get('priority_warning', '')
            ),
        )
        wait(
            'MP-10 the SIP INFO request leaves the client at the emergency level (6.2.8.1.13)',
            lambda: (
                group_state('client-b', 'imminent').startswith('MDIG 1')
                and communication_state('client-b', 'imminent').startswith('MDIGC 1')
                and group_state('client-b').startswith('MDEG 2')
                and status('client-b').get('mcdata_priority_corrections', 0) >= 1
            ),
        )
        check(
            'MP-10 the group stays in its emergency state',
            server_group().get('emergency') and not server_group().get('imminent'),
        )

        command('client-a', 'sds-session emergency cancel')
        wait(
            'MP-09 the cancellation returns every member to MDEG 1 (6.2.8.1.3, 6.3.7.1.14)',
            lambda: all(group_state(role).startswith('MDEG 1') for role in roles),
        )
        wait('MP-09 the server clears the in-progress emergency state of the group', lambda: not server_group())
        command('client-a', 'sds-session close')
        wait(
            'MP-09 the emergency group session is released at every member',
            lambda: not any(status(role).get('mcdata_media_session') for role in roles),
        )

        # MP-11 an imminent peril group communication (TS 24.282 clause 6.2.8.1.9), upgraded to
        # an emergency group communication (TS 24.282 clause 6.3.7.1.1) and then cancelled.
        command('client-a', f'sds-session group={group} imminent')
        wait(
            'MP-11 the imminent peril group session is accepted and the originator reaches MDIGC 3 (6.2.8.1.4)',
            lambda: (
                media('client-a').get('state') == 'open'
                and communication_state('client-a', 'imminent').startswith('MDIGC 3')
                and group_state('client-a', 'imminent').startswith('MDIG 2')
            ),
        )
        wait(
            'MP-11 every other affiliated member joins the in-progress imminent peril state (9.2.4.2.4 step 4B)',
            lambda: all(
                group_state(role, 'imminent').startswith('MDIG 2') for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        wait(
            'MP-11 the server records the in-progress imminent peril state',
            lambda: server_group().get('imminent') and not server_group().get('emergency'),
        )
        check(
            'MP-11 an imminent peril communication leaves the MCData emergency state clear (6.2.8.1.9)',
            not status('client-a').get('mcdata_emergency'),
        )
        command('client-a', 'sds-session emergency')
        wait(
            'MP-11 the group is upgraded to an emergency communication (6.3.7.1.1)',
            lambda: (
                server_group().get('emergency')
                and not server_group().get('imminent')
                and group_state('client-a').startswith('MDEG 2')
                and group_state('client-a', 'imminent').startswith('MDIG 1')
            ),
        )
        wait(
            'MP-11 the members follow the upgrade',
            lambda: all(
                group_state(role).startswith('MDEG 2') and group_state(role, 'imminent').startswith('MDIG 1')
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        command('client-a', 'sds-session emergency cancel')
        wait('MP-11 the group returns to no priority', lambda: not server_group())
        command('client-a', 'sds-session close')
        wait(
            'MP-11 the session is released at every member',
            lambda: not any(status(role).get('mcdata_media_session') for role in roles),
        )

        # ------------------------------------------------------------------------------
        # Run a command that the client may itself refuse; True if it did.
        def refused(role, text):
            try:
                command(role, text)
            except RuntimeError:
                return True
            return False

        # MP-12 the group document refuses priority group communications (warnings 233 and 236
        # of TS 24.282 table 4.9.2-2; TS 24.282 clauses 6.3.7.2.6 and 6.3.7.2.4).
        noemergency = f'sip:{group_user}-noemergency@{domain}'
        command('client-a', f'sds-session group={noemergency} emergency')
        wait(
            'MP-12 a group that does not allow emergency communications answers 403/233 (6.3.7.2.6)',
            lambda: media('client-a').get('status') == 403 and '233' in media('client-a').get('warning', ''),
        )
        command('client-a', f'sds-session group={noemergency} imminent')
        wait(
            'MP-12 a group that does not allow imminent peril communications answers 403/236 (6.3.7.2.4)',
            lambda: media('client-a').get('status') == 403 and '236' in media('client-a').get('warning', ''),
        )
        # The same rejections from the user profile rather than the group document.
        refused('client-c', f'sds-session group={group} emergency')
        wait(
            'MP-12 a user without <allow-emergency-group-call> is rejected with 403/233 (6.3.7.2.6)',
            lambda: media('client-c').get('status') == 403 and '233' in media('client-c').get('warning', ''),
        )
        refused('client-c', f'sds-session group={group} imminent')
        wait(
            'MP-12 a user without <allow-imminent-peril-call> is rejected with 403/236 (6.3.7.2.4)',
            lambda: media('client-c').get('status') == 403 and '236' in media('client-c').get('warning', ''),
        )
        check('MP-12 no in-progress state was raised by the refused requests', not server_group())

        # ------------------------------------------------------------------------------
        # The files a client sent or received over the media plane.
        def media_files(role):
            return status(role).get('mcdata_media_files') or []

        # ------------------------------------------------------------------------------
        # Create a file of random text of this size in the container of a role; return its path.
        def make_file(role, name, size):
            run = subprocess.run(
                cli
                + [
                    'exec',
                    '-T',
                    role,
                    'sh',
                    '-c',
                    f"head -c {size} /dev/urandom | base64 | head -c {size} > /tmp/{name}; wc -c < /tmp/{name}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if run.returncode:
                raise RuntimeError(f'{role} create {name}: {run.stderr.strip()}')
            return f'/tmp/{name}'

        # MP-13 file distribution over the media plane (TS 24.282 clause 10.2.5 with TS 24.582
        # clause 7): the file travels in MSRP SEND requests instead of being uploaded by URL.
        small = make_file('client-a', 'small.bin', 200)
        command('client-a', f'fd-media mandatory completed {ids["client-b"]} {small}')
        wait('MP-13 the one-to-one file offer is accepted with 200', lambda: media('client-a').get('status') == 200)
        wait(
            'MP-13 the recipient receives the file over MSRP with its hash verified',
            lambda: [
                file
                for file in media_files('client-b')
                if file.get('state') == 'received' and file.get('hash_verified') and file.get('received_bytes') == 200
            ],
        )
        check(
            'MP-13 the file names its originator and its metadata',
            media_files('client-b')[-1]['from'] == ids['client-a']
            and media_files('client-b')[-1]['name'] == 'small.bin'
            and media_files('client-b')[-1]['bytes'] == 200,
        )
        wait(
            'MP-13 the completion notification reaches the sender (12.2 over the signalling plane)',
            lambda: [
                notification
                for notification in status('client-a').get('mcdata_file_notifications') or []
                if notification.get('type') == 3
            ],
        )
        wait(
            'MP-13 the server counts the transfer and its delivery',
            lambda: (
                counters().get('media_files', 0) >= 1
                and counters().get('media_files_delivered', 0) >= 1
                and counters().get('media_file_bytes', 0) >= 200
            ),
        )
        wait(
            'MP-13 the sending leg is released once the file has been relayed (TS 24.582 7.1.2.1)',
            lambda: media('client-a').get('state') == 'delivered',
            40,
        )

        # MP-14 a group file distribution reaches every other affiliated member.
        group_file = make_file('client-a', 'group.bin', 1000)
        before = counters().get('media_files_delivered', 0)
        command('client-a', f'fd-media mandatory group={group} {group_file}')
        wait('MP-14 the group file offer is accepted with 200', lambda: media('client-a').get('status') == 200)
        wait(
            'MP-14 every other affiliated member receives the file',
            lambda: all(
                [
                    file
                    for file in media_files(role)
                    if file.get('name') == 'group.bin' and file.get('state') == 'received'
                ]
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        check(
            'MP-14 the recipients learn the calling group',
            all(
                [file for file in media_files(role) if file.get('name') == 'group.bin'][-1]['group'] == group
                for role in ['client-b', 'client-c', 'client-d']
            ),
        )
        wait(
            'MP-14 the server counts one delivery per recipient',
            lambda: counters().get('media_files_delivered', 0) >= before + 3,
        )

        # MP-15 a file that is neither mandatory nor small enough to be auto-received
        # is declined by the terminating client (TS 24.282 clause 10.2.5.2.4 step 7b, clause 11.2).
        big = make_file('client-b', 'big.bin', 1000)
        command('client-b', f'fd-media {ids["client-a"]} {big}')
        wait(
            'MP-15 the recipient declines the invitation with 480/110',
            lambda: [
                file
                for file in media_files('client-a')
                if file.get('name') == 'big.bin' and file.get('state') == 'declined'
            ],
        )
        check(
            'MP-15 the declined file was never transferred',
            not [
                file
                for file in media_files('client-a')
                if file.get('name') == 'big.bin' and file.get('state') == 'received'
            ],
        )

        # ------------------------------------------------------------------------------
        # Offer a mandatory file over the media plane and wait for the expected answer and warning text to this offer.
        def fd_send(role, target, path, expect, warning, label):
            earlier = media(role).get('message_id')
            command(role, f'fd-media mandatory {target} {path}')
            wait(
                label,
                lambda: (
                    new_media(role, earlier).get('status') == expect
                    and warning in new_media(role, earlier).get('warning', '')
                ),
            )

        # MP-16 transmission control and the size limits of TS 24.282 clause 11.1 for FD.
        over = make_file('client-a', 'over.bin', 500)
        fd_send(
            'client-a', ids['client-b'], over, 403, '202', 'MP-16 a file over the one-to-one limit is rejected with 202'
        )
        refused_file = make_file('client-d', 'refused.bin', 200)  # each file lives on its sender
        fd_send(
            'client-d',
            ids['client-a'],
            refused_file,
            403,
            '200',
            'MP-16 a user without <allow-transmit-data> is rejected with 200',
        )
        group_over = make_file('client-a', 'groupover.bin', 2500)
        fd_send(
            'client-a',
            f'group={group}',
            group_over,
            403,
            '208',
            'MP-16 a file over the group limit is rejected with 208',
        )
        fd_send(
            'client-a',
            f'group=sip:{group_user}-nosds@{domain}',
            small,
            403,
            '213',
            'MP-16 a group where FD is not allowed is rejected with 213',
        )
        fd_send(
            'client-a',
            f'group=sip:{group_user}-nosupport@{domain}',
            small,
            488,
            '214',
            'MP-16 a group without the FD enabler is rejected with 488/214',
        )
        observations['fd_counters'] = {key: value for key, value in counters().items() if key.startswith('media_file')}

        # MP-17 a group file distribution as an emergency group communication (TS 24.282 clause 6.2.8.1.8).
        command('client-a', f'sds-session group={group} emergency')
        wait('MP-17 the group is in an in-progress emergency state', lambda: server_group().get('emergency'))
        command('client-a', 'sds-session close')
        wait(
            'MP-17 the session is closed while the group keeps its state',
            lambda: not status('client-a').get('mcdata_media_session') and server_group().get('emergency'),
        )
        urgent_file = make_file('client-a', 'urgent.bin', 200)
        command('client-a', f'fd-media mandatory group={group} {urgent_file}')
        wait(
            'MP-17 the file is distributed at the emergency level of the group (6.3.7.1.11)',
            lambda: (
                media('client-a').get('status') == 200
                and all(
                    [
                        file
                        for file in media_files(role)
                        if file.get('name') == 'urgent.bin' and file.get('state') == 'received'
                    ]
                    for role in ['client-b', 'client-c', 'client-d']
                )
            ),
        )
        wait(
            'MP-17 the members are at MDEG 2 while it is distributed',
            lambda: all(group_state(role).startswith('MDEG 2') for role in ['client-b', 'client-c', 'client-d']),
        )
        command('client-a', f'sds-session group={group}')
        wait('MP-17 a session is open again for the cancellation', lambda: media('client-a').get('state') == 'open')
        command('client-a', 'sds-session emergency cancel')
        wait('MP-17 the in-progress emergency state is cancelled', lambda: not server_group())
        command('client-a', 'sds-session close')
        wait('MP-17 the session is released', lambda: not status('client-a').get('mcdata_media_session'))

        # ------------------------------------------------------------------------------
        # The emergency alerts a client was told of, by group and originator.
        def alerts(role):
            return status(role).get('mcdata_alerts_received') or {}

        # MP-18 an emergency alert sent inside the session request (TS 24.282 clause 6.2.8.1.1
        # step 3): the alert is authorised with the communication and the members are told.
        # client-d leaves the group first, so that it is a member which is affiliated
        # again later while the state is in progress, and never a participant.
        command('client-d', 'mcdata-deaffiliate')
        wait(
            'MP-18 a member de-affiliates from the group before the communication',
            lambda: group not in (status('client-d').get('mcdata_affiliations') or []),
        )
        command('client-a', f'sds-session group={group} emergency alert')
        wait(
            'MP-18 the emergency group session with an alert is accepted and the alert is initiated (6.2.8.1.4 step 1b)',
            lambda: (
                media('client-a').get('state') == 'open'
                and status('client-a').get('mcdata_alert_state', '').startswith('MDEA 3')
                and group_state('client-a').startswith('MDEG 2')
            ),
        )
        wait(
            'MP-18 the members learn of the alert with the originator and the location (6.3.7.1.3)',
            lambda: all(
                alerts(role).get(group, {}).get(ids['client-a'], {}).get('latitude') is not None
                for role in ['client-b', 'client-c']
            ),
        )
        wait(
            'MP-18 the server records the alert of the group (16.2.3.1)',
            lambda: ids['client-a'] in (status('mcdata-server').get('emergency_alerts') or {}).get(group, []),
        )

        # MP-19 a member that affiliates while the state is in progress is told by a SIP
        # MESSAGE, because it is not participating in the communication (TS 24.282 clause 6.3.7.1.2).
        command('client-d', 'mcdata-affiliate')
        wait(
            'MP-19 on affiliating again it is told of the in-progress emergency state',
            lambda: (
                [
                    notification
                    for notification in status('client-d').get('mcdata_group_notifications') or []
                    if notification.get('group') == group and notification.get('emergency')
                ]
                and group_state('client-d').startswith('MDEG 2')
            ),
        )
        check(
            'MP-19 the notification did not make it a participant', not status('client-d').get('mcdata_media_session')
        )
        check(
            'MP-19 it also learns of the outstanding alert of the group (16.2.3.3)',
            alerts('client-d').get(group, {}).get(ids['client-a']) is not None,
        )
        wait(
            'MP-19 the server counts the notifications it sent',
            lambda: counters().get('media_state_notifications', 0) >= 1,
        )
        command('client-a', 'sds-session emergency cancel')
        wait('MP-19 the cancellation reaches the participants', lambda: not server_group())
        command('client-a', 'mcdata-alert cancel')
        wait(
            'MP-19 the alert of the group is cancelled',
            lambda: not (status('mcdata-server').get('emergency_alerts') or {}).get(group),
        )
        command('client-a', 'sds-session close')
        wait('MP-19 the session is released', lambda: not status('client-a').get('mcdata_media_session'))

        # ------------------------------------------------------------------------------
        # The ad hoc groups the server holds, with their members.
        def adhoc_groups():
            return status('mcdata-server').get('adhoc_groups') or {}

        # ------------------------------------------------------------------------------
        # Wait until these clients hold no media plane session. A recipient holds its leg until
        # the server releases it; a client holds one media plane session at a time, so the next
        # case waits for that.
        def idle(label, roles_):
            wait(
                label,
                lambda: all(
                    media(role).get('state') in (None, 'released', 'delivered', 'closed', 'rejected')
                    and not status(role).get('mcdata_media_session')
                    for role in roles_
                ),
                40,
            )

        # MP-20 a standalone SDS to an ad hoc group over the media plane (TS 24.282 clause
        # 24.2.2.1.1 with clause 9.2.3): the participants are listed, the server creates the ad
        # hoc group, and a user without <allow-adhoc-group-data-comn-participation> is left out
        # (TS 24.282 clause 24.3.2.1.2 step 5).
        text = f'adhoc-media-{secrets.token_hex(4)}'
        before = counters().get('media_adhoc', 0)
        send(
            'client-a',
            f'adhoc={ids["client-b"]},{ids["client-c"]},{ids["client-d"]}',
            text,
            label='MP-20 the ad hoc group media plane request is accepted with 200',
        )
        wait(
            'MP-20 the 200 names the server-generated ad hoc group (24.4.2.2)',
            lambda: media('client-a').get('group', '').startswith('sip:adhoc-'),
        )
        adhoc = media('client-a')['group']
        wait(
            'MP-20 the participants receive it over their own MSRP legs with the ad hoc group',
            lambda: all(
                received(role, text)
                and received(role, text)[0]['from'] == ids['client-a']
                and received(role, text)[0]['group'] == adhoc
                for role in ['client-b', 'client-c']
            ),
        )
        check('MP-20 the user not allowed to participate receives nothing', not received('client-d', text))
        # The server's status file is written periodically: wait for it rather than read it once.
        wait(
            'MP-20 the ad hoc group holds the initiator and the two participants',
            lambda: (
                sorted(adhoc_groups().get(adhoc, [])) == sorted([ids['client-a'], ids['client-b'], ids['client-c']])
            ),
        )
        wait('MP-20 the server counts the ad hoc request', lambda: counters().get('media_adhoc', 0) == before + 1)
        wait('MP-20 the sending leg is released', lambda: media('client-a').get('state') == 'delivered')

        idle('MP-20 the delivery legs are released', ['client-b', 'client-c'])

        # MP-21 a follow-up names the ad hoc group in <mcdata-request-uri> (TS 24.282 clause
        # 24.2.2.1.1 step 5e-ii), so the same participants are reached without a list.
        text = f'adhoc-again-{secrets.token_hex(4)}'
        send(
            'client-b',
            f'adhoc=group={adhoc}',
            text,
            label='MP-21 a participant sends to the existing ad hoc group with 200',
        )
        wait(
            'MP-21 the other members of the ad hoc group receive it',
            lambda: all(
                received(role, text) and received(role, text)[0]['group'] == adhoc for role in ['client-a', 'client-c']
            ),
        )
        check('MP-21 no new ad hoc group was created', media('client-b').get('group') == adhoc)
        wait('MP-21 the sending leg is released', lambda: media('client-b').get('state') == 'delivered')

        idle('MP-21 the delivery legs are released', ['client-a', 'client-c'])

        # MP-22 an ad hoc group SDS session (TS 24.282 clause 24.2.2.1.1 with clause 9.2.4): the offer is
        # "a=sendrecv", the participants come from criteria, and any of them may send.
        command('client-a', f'sds-session adhoc=criteria=member:{group}')
        wait(
            'MP-22 the ad hoc SDS session is established at every participant',
            lambda: (
                media('client-a').get('state') == 'open'
                and all(status(role).get('mcdata_media_session') for role in ['client-a', 'client-b', 'client-c'])
            ),
        )
        session_group = status('client-a').get('mcdata_session_group', '')
        check(
            'MP-22 the initiator and the participants hold the same new ad hoc group',
            session_group.startswith('sip:adhoc-')
            and session_group != adhoc
            and all(status(role).get('mcdata_session_group') == session_group for role in ['client-b', 'client-c']),
        )
        check(
            'MP-22 the member without participation rights was not invited',
            not status('client-d').get('mcdata_media_session'),
        )
        first = f'adhoc-session-a-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send delivery {first}')
        wait(
            'MP-22 a message reaches both participants with its sender named',
            lambda: all(
                received(role, first) and received(role, first)[0]['from'] == ids['client-a']
                for role in ['client-b', 'client-c']
            ),
        )
        wait(
            'MP-22 the in-band DELIVERED notifications return to the sender',
            lambda: len(notifications('client-a', sent('client-a')[-1]['message_id'])) >= 2,
        )
        reply = f'adhoc-session-c-{secrets.token_hex(3)}'
        command('client-c', f'sds-session send {reply}')
        wait(
            'MP-22 a participant sends on the same session and every other one receives it',
            lambda: all(received(role, reply) for role in ['client-a', 'client-b']),
        )
        command('client-a', 'sds-session emergency')
        wait(
            'MP-22 the ad hoc group emergency communication is refused (not implemented)',
            lambda: (
                'not implemented' in status('client-a').get('last_error', '')
                and status('client-a').get('mcdata_media_session')
            ),
        )
        command('client-a', 'sds-session close')
        wait(
            'MP-22 closing the session releases it at every participant',
            lambda: not any(status(role).get('mcdata_media_session') for role in ['client-a', 'client-b', 'client-c']),
        )

        # MP-23 file distribution to an ad hoc group over the media plane (TS 24.282 clause
        # 24.2.2.1.1 step 6 with clause 10.2.5): "adhoc-group-fd-session".
        adhoc_file = make_file('client-a', 'adhoc.bin', 300)
        command('client-a', f'fd-media mandatory adhoc={ids["client-b"]},{ids["client-c"]} {adhoc_file}')
        wait(
            'MP-23 the ad hoc file offer is accepted with 200 naming a new ad hoc group',
            lambda: (
                media('client-a').get('name') == 'adhoc.bin'
                and media('client-a').get('status') == 200
                and media('client-a').get('group', '').startswith('sip:adhoc-')
            ),
        )
        fd_group = media('client-a')['group']
        wait(
            'MP-23 both participants receive the file with its hash verified and the ad hoc group',
            lambda: all(
                [
                    file
                    for file in media_files(role)
                    if file.get('name') == 'adhoc.bin'
                    and file.get('state') == 'received'
                    and file.get('hash_verified')
                    and file.get('group') == fd_group
                ]
                for role in ['client-b', 'client-c']
            ),
        )
        wait(
            'MP-23 the sending leg is released once the file has been relayed',
            lambda: media('client-a').get('state') == 'delivered',
            40,
        )

        idle('MP-23 the delivery legs are released', ['client-b', 'client-c'])

        # MP-24 the ad hoc rejections of TS 24.282 clauses 24.3.2.1.1 and 24.4.2.2.
        unknown = f'sip:nobody-{secrets.token_hex(3)}@{domain}'
        send(
            'client-c',
            f'adhoc={ids["client-a"]}',
            'refused',
            403,
            '238',
            'MP-24 a user without <allow-adhoc-group-data-comn> is rejected with 238',
        )
        send(
            'client-a',
            f'adhoc={ids["client-b"]},{ids["client-c"]},{ids["client-d"]},{unknown}',
            'refused',
            403,
            '242',
            'MP-24 more participants than <max-no-participants> are rejected with 242',
        )
        send(
            'client-a',
            f'adhoc={ids["client-d"]}',
            'refused',
            403,
            '241',
            'MP-24 a list of users none of whom may participate is rejected with 241',
        )
        send(
            'client-a',
            'adhoc=criteria=colour:red',
            'refused',
            403,
            '240',
            'MP-24 criteria that determine no participants are rejected with 240',
        )
        send(
            'client-a',
            f'adhoc=group=sip:adhoc-unknown@{domain}',
            'refused',
            403,
            '240',
            'MP-24 an ad hoc group that does not exist is rejected with 240',
        )

        # MP-03 the server releases the sessions it no longer needs.
        wait(
            'MP-03 the server releases the sessions it no longer needs',
            lambda: not (status('mcdata-server').get('media_sessions') or []),
            45,
        )

        observations['server_counters'] = counters()
        check('server instance unchanged', status('mcdata-server')['instance_id'] == instance)
        result['passed'] = True
    except (AssertionError, KeyError, IndexError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-media-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
