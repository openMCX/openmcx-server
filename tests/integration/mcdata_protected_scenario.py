#!/usr/bin/env python3
"""Exercise end-to-end protected MCData payloads (TS 33.180 clause 8, TS 24.282 clause 6.6): one-to-one
payloads under a PCK (TS 33.180 clause 8.3) and group payloads under the GMK (TS 33.180 clause 8.4), sent
as standalone SDS over signalling (TS 24.282 clauses 9.2.2.2.1 and 9.2.2.2.2) or the media plane
(TS 24.282 clauses 9.2.3 and 9.2.4) and as files over the media plane and HTTP (TS 24.282 clauses
10.2.5 and 10.2.4); signalling protected with the CSK (TS 33.180 clause 9.5), the sensitive XML
content of TS 24.282 clause 4.6 encrypted (TS 33.180 clause 9.3), and with --sign-payloads the payload
signatures (TS 33.180 clause 8.5.5).

Run against a fixture prepared with --mcdata --protected. Check IDs match
tests/mcdata/MCDATA_PROTECTED_TEST.md. Every text sent is recorded in the report
so that the wire verifier can check that none of them crosses the network in clear.

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
# Run the protected MCData scenario against the running lab and write integration/mcdata-protected-results.json; an
# AssertionError ends it at the first failed check.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-dpp')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    if not all(configs[role]['mcdata'].get('protect_payload') for role in roles):
        parser.error('the fixture must be prepared with --mcdata --protected')
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    group = configs['client-a']['mcdata']['group_id']
    checks, observations, texts = [], {}, []
    result = dict(scenario='mcdata-protected-sds', passed=False, checks=checks, observations=observations, texts=texts)

    # ------------------------------------------------------------------------------
    # The status.json the role last wrote, or {} while it has none.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # Every role's status, attached to a failure and to the results.
    def snapshot():
        return {role: status(role) for role in roles + ['mcdata-server']}

    # ------------------------------------------------------------------------------
    # Run one mcx-client console command in the role's container.
    def command(role, text):
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Poll the predicate until it holds (recorded as a passed check) or the timeout expires (AssertionError).
    def wait(label, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
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
    # The messages in the client's inbox that carry the text.
    def inbox(role, text):
        return [
            message
            for message in status(role).get('mcdata_inbox') or []
            if any(payload.get('text') == text for payload in message.get('payloads', []))
        ]

    # ------------------------------------------------------------------------------
    # The client's payload protection state (TS 24.282 clause 6.6).
    def protection(role):
        return status(role).get('mcdata_protection') or {}

    # ------------------------------------------------------------------------------
    # The client sends the text with the console command, records it for the wire verifier and waits for the 202
    # (Accepted); returns the sent message.
    def send(role, command_text, text, label):
        before = [message['message_id'] for message in status(role).get('mcdata_sent') or []]
        texts.append(text)
        command(role, command_text + ' ' + text)
        wait(
            label,
            lambda: (
                lambda messages: (
                    messages and messages[-1]['message_id'] not in before and messages[-1].get('status') == 202
                )
            )(status(role).get('mcdata_sent') or []),
        )
        return (status(role).get('mcdata_sent') or [])[-1]

    # ------------------------------------------------------------------------------
    # The label with a random suffix, so that the wire verifier can find each text.
    def unique(label):
        return f'{label}-{secrets.token_hex(6)}'

    try:
        wait(
            'four clients MCData-authorised, affiliated and holding the group key',
            lambda: all(
                status(role).get('mcdata_authorized')
                and status(role).get('mcdata_affiliated')
                and protection(role).get('enabled')
                and protection(role).get('group_keys')
                for role in roles
            ),
            120,
        )
        failures = {role: protection(role).get('failures', 0) for role in roles}

        # ------------------------------------------------------------------------------
        # DS-01 each client uploaded a CSK at service authorisation (TS 24.282 clause 7.2.2 step 3)
        # and the MCData server holds it (TS 33.180 clause 9.5.1).
        # The client's signalling protection state (TS 33.180 clause 9.5).
        def signalling(role):
            return status(role).get('mcdata_signalling_protection') or {}

        check(
            'DS-01 every client holds a CSK (purpose tag 2) that the MCData server accepted',
            all(
                signalling(role).get('enabled')
                and signalling(role).get('csk_id', 0) >> 28 == 2
                and status('mcdata-server').get('users', {}).get(ids[role], {}).get('csk_id')
                == signalling(role).get('csk_id')
                for role in roles
            ),
        )

        # DP-01 the first one-to-one message carries a new PCK in an application/mikey
        # body (TS 24.282 clause 9.2.2.2.1 step 2c); the payload is protected with it (TS 24.282 clause 6.6.3.2).
        text = unique('first')
        first = send('client-a', f'sds {ids["client-b"]}', text, 'DP-01 one-to-one protected SDS accepted with 202')
        pck = first.get('dppk_id')
        check('DP-01 the payload is protected with a PCK-ID (purpose tag 0001)', pck is not None and pck >> 28 == 1)
        wait(
            'DP-01 client-b authenticates the PCK, decrypts and renders the text',
            lambda: (
                inbox('client-b', text)
                and inbox('client-b', text)[0].get('protected')
                and inbox('client-b', text)[0].get('dppk_id') == pck
            ),
        )
        check(
            'DP-01 both clients hold one PCK context',
            protection('client-a').get('pck_contexts') == 1 and protection('client-b').get('pck_contexts') == 1,
        )
        observations['pck_id'] = hex(pck)

        # DP-02 later messages reuse the PCK and carry only the PCK-ID (TS 33.180 clause 8.3).
        text = unique('second')
        second = send('client-a', f'sds {ids["client-b"]}', text, 'DP-02 second message accepted')
        check('DP-02 the security context is reused', second.get('dppk_id') == pck)
        wait(
            'DP-02 client-b decrypts it with the stored PCK',
            lambda: inbox('client-b', text) and inbox('client-b', text)[0].get('dppk_id') == pck,
        )

        # DP-03 the reply from client-b uses the same context in the other direction.
        text = unique('reply')
        reply = send('client-b', f'sds {ids["client-a"]}', text, 'DP-03 reply accepted')
        check('DP-03 the reply is protected with the same PCK', reply.get('dppk_id') == pck)
        wait(
            'DP-03 client-a decrypts the reply',
            lambda: inbox('client-a', text) and inbox('client-a', text)[0].get('dppk_id') == pck,
        )

        # DP-04 a group message is protected with the GMK of the group (TS 33.180 clause 8.4).
        text = unique('group')
        grouped = send('client-a', f'sds-group {group}', text, 'DP-04 group protected SDS accepted')
        gmk = grouped.get('dppk_id')
        check(
            'DP-04 the payload is protected with the GMK-ID of the group',
            gmk is not None and gmk >> 28 == 0 and gmk == status('client-a').get('group_key_id'),
        )
        for role in ('client-b', 'client-c', 'client-d'):
            wait(
                f'DP-04 {role} decrypts the group message with the GMK',
                lambda role=role: (
                    inbox(role, text)
                    and inbox(role, text)[0].get('protected')
                    and inbox(role, text)[0].get('dppk_id') == gmk
                ),
            )

        # DP-05 an altered I_MESSAGE fails authentication: 606 with warning 136 at the
        # recipient, which never renders the message (TS 24.282 clause 9.2.2.2.2 step 3d).
        text = unique('tampered')
        send('client-a', f'sds tamper-key {ids["client-c"]}', text, 'DP-05 the server accepts the message for delivery')
        wait(
            'DP-05 client-c rejects the altered I_MESSAGE',
            lambda: protection('client-c').get('failures', 0) == failures['client-c'] + 1,
        )
        check('DP-05 client-c never renders the message', holds(lambda: not inbox('client-c', text), 1))

        # DP-06 a new context with client-c after the failure works.
        text = unique('fresh')
        fresh = send('client-a', f'sds {ids["client-c"]}', text, 'DP-06 a new PCK to client-c is accepted')
        wait(
            'DP-06 client-c decrypts with the new PCK',
            lambda: inbox('client-c', text) and inbox('client-c', text)[0].get('dppk_id') == fresh.get('dppk_id'),
        )
        check(
            'DP-06 client-a and client-c now share a different PCK than client-a and client-b',
            fresh.get('dppk_id') != pck and fresh.get('dppk_id') >> 28 == 1,
        )

        # DP-07 delivery notifications still reach the sender (clear signalling payloads).
        text = unique('notify')
        noted = send(
            'client-a', f'sds delivery {ids["client-b"]}', text, 'DP-07 protected SDS with a delivery request accepted'
        )
        wait(
            'DP-07 client-a receives the delivery notification',
            lambda: any(
                notification.get('message_id') == noted['message_id']
                for notification in status('client-a').get('mcdata_notifications') or []
            ),
        )
        check(
            'DP-07 no other decryption failures',
            all(
                protection(role).get('failures', 0) == failures[role] + (1 if role == 'client-c' else 0)
                for role in roles
            ),
        )

        # ------------------------------------------------------------------------------
        # ---- The media plane (TS 24.282 clauses 9.2.3, 9.2.4 and 10.2.5) and files over HTTP (TS 24.282
        # clause 10.2.4).
        # The result of the client's last media plane transaction.
        def media(role):
            return status(role).get('mcdata_media_result') or {}

        # ------------------------------------------------------------------------------
        # The messages the client received over the media plane that carry the text.
        def media_received(role, text):
            return [
                message
                for message in status(role).get('mcdata_media_received') or []
                if any(payload.get('text') == text for payload in message.get('payloads', []))
            ]

        # ------------------------------------------------------------------------------
        # Create a file of the given size in the role's container, starting with a unique marker the wire verifier looks
        # for; returns its path and SHA-256.
        def make_file(role, name, size):
            marker = unique('file')
            texts.append(marker)
            run = subprocess.run(
                cli
                + [
                    'exec',
                    '-T',
                    role,
                    'sh',
                    '-c',
                    f"(printf '{marker}'; head -c {size} /dev/urandom | base64) | head -c {size} > /tmp/{name};"
                    f" sha256sum /tmp/{name}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if run.returncode:
                raise RuntimeError(f'{role} create {name}: {run.stderr.strip()}')
            return f'/tmp/{name}', run.stdout.split()[0]

        # ------------------------------------------------------------------------------
        # A predicate that holds when the client has no media plane transaction in progress.
        def idle_media(role):
            return lambda: (
                not media(role) or media(role).get('state') in ('delivered', 'rejected', 'closed', 'released')
            )

        # DP-08 a one-to-one standalone SDS over the media plane between users with no
        # context: the PCK travels in a=key-mgmt of the SDP offer (TS 24.282 clause 9.2.3.2.1 step 2).
        text = unique('media-bc')
        texts.append(text)
        contexts = protection('client-b').get('pck_contexts', 0)
        command('client-b', f'sds-media {ids["client-c"]} {text}')
        wait('DP-08 the media plane offer with a PCK is accepted', lambda: media('client-b').get('status') == 200)
        check(
            'DP-08 the payload is protected with a new PCK',
            media('client-b').get('protected')
            and media('client-b').get('dppk_id') >> 28 == 1
            and protection('client-b').get('pck_contexts') == contexts + 1,
        )
        wait(
            'DP-08 client-c accepts the PCK from the SDP and decrypts the MSRP payload',
            lambda: (
                media_received('client-c', text)
                and media_received('client-c', text)[0].get('protected')
                and media_received('client-c', text)[0].get('dppk_id') == media('client-b').get('dppk_id')
            ),
        )

        # DP-09 a group standalone SDS over the media plane is protected with the GMK.
        text = unique('media-group')
        texts.append(text)
        wait('DP-09 client-a is idle on the media plane', idle_media('client-a'), 30)
        command('client-a', f'sds-media group={group} {text}')
        wait('DP-09 the group media plane request is accepted', lambda: media('client-a').get('status') == 200)
        check('DP-09 it is protected with the GMK-ID', media('client-a').get('dppk_id') == gmk)
        for role in ('client-b', 'client-c', 'client-d'):
            wait(
                f'DP-09 {role} decrypts the group payload from MSRP',
                lambda role=role: media_received(role, text) and media_received(role, text)[0].get('dppk_id') == gmk,
            )

        # DP-10 an SDS session: both parties send under the PCK they already share.
        wait('DP-10 client-a is idle on the media plane', idle_media('client-a'), 30)
        command('client-a', f'sds-session {ids["client-b"]}')
        wait('DP-10 the session opens', lambda: media('client-a').get('state') == 'open')
        check(
            'DP-10 the session reuses the PCK of client-a and client-b',
            media('client-a').get('dppk_id', pck) in (None, pck),
        )
        first, reply = unique('session-a'), unique('session-b')
        texts.extend([first, reply])
        command('client-a', f'sds-session send {first}')
        wait(
            'DP-10 client-b decrypts the session message',
            lambda: media_received('client-b', first) and media_received('client-b', first)[0].get('dppk_id') == pck,
        )
        command('client-b', f'sds-session send {reply}')
        wait(
            'DP-10 client-a decrypts the reply in the same session',
            lambda: media_received('client-a', reply) and media_received('client-a', reply)[0].get('dppk_id') == pck,
        )
        command('client-a', 'sds-session close')
        wait('DP-10 the session closes', lambda: not media('client-a') or media('client-a').get('state') != 'open', 20)

        # DP-11 a file over the media plane: a series of Protected Payload messages in
        # MSRP; the recipient stores the clear file, whose hash matches the original.
        path, digest = make_file('client-a', 'protected.bin', 200)
        wait('DP-11 client-a is idle on the media plane', idle_media('client-a'), 30)
        command('client-a', f'fd-media mandatory {ids["client-c"]} {path}')
        wait(
            'DP-11 the file offer is accepted',
            lambda: media('client-a').get('file') and media('client-a').get('status') == 200,
        )
        check(
            'DP-11 the file is protected with the PCK of client-a and client-c',
            media('client-a').get('protected')
            and media('client-a').get('dppk_id') == fresh.get('dppk_id')
            and media('client-a').get('bytes') > 200,
        )
        wait(
            'DP-11 client-c decrypts the file and stores the original',
            lambda: [
                file
                for file in status('client-c').get('mcdata_media_files') or []
                if file.get('protected') and file.get('plain_sha256') == digest and file.get('state') == 'received'
            ],
            40,
        )

        # DP-12 files over HTTP: a one-to-one file is protected before upload
        # (TS 24.282 clause 10.2.2.1 step 7); a group file is uploaded in clear (step 8b).
        path, digest = make_file('client-a', 'stored.bin', 200)
        command('client-a', f'fd-send mandatory {ids["client-b"]} {path}')
        wait(
            'DP-12 the one-to-one FD request is accepted',
            lambda: (status('client-a').get('mcdata_files_sent') or [{}])[-1].get('status') in (200, 202),
        )
        check(
            'DP-12 it names the PCK of client-a and client-b',
            (status('client-a').get('mcdata_files_sent') or [{}])[-1].get('dppk_id') == pck,
        )
        wait(
            'DP-12 client-b downloads and decrypts the stored file',
            lambda: [
                file
                for file in (status('client-b').get('mcdata_files') or [])
                if isinstance(file, dict) and file.get('protected') and file.get('plain_sha256') == digest
            ],
            40,
        )
        path, digest = make_file('client-a', 'shared.bin', 1200)
        texts.pop()  # the group file is uploaded in clear, as TS 24.282 clause 10.2.2.1 step 8b says
        command('client-a', f'fd-send mandatory group={group} {path}')
        wait(
            'DP-12 client-b downloads the clear group file',
            lambda: [
                file
                for file in (status('client-b').get('mcdata_files') or [])
                if isinstance(file, dict) and not file.get('protected') and file.get('plain_sha256') == digest
            ],
            40,
        )
        # DS-02 signalling bodies crossed sealed in both directions and nothing was refused.
        server = status('mcdata-server').get('signalling_protection') or {}
        check(
            'DS-02 the server opened and sealed signalling, and refused none',
            server.get('enabled')
            and server.get('opened', 0) > 0
            and server.get('sealed', 0) > 0
            and server.get('refused') == 0,
        )
        check(
            'DS-02 the senders sealed signalling, every client opened some, and none was refused',
            all(signalling(role).get('sealed', 0) > 0 for role in ('client-a', 'client-b'))
            and all(signalling(role).get('opened', 0) > 0 and signalling(role).get('refused') == 0 for role in roles),
        )

        # ------------------------------------------------------------------------------
        # DX-01 the sensitive XML content of TS 24.282 clause 4.6 is encrypted with each client's CSK.
        # The XML content protection counters of the client or server (TS 33.180 clause 9.3).
        def xml(role):
            return status(role).get('mcdata_xml_protection' if role != 'mcdata-server' else 'xml_protection') or {}

        check(
            'DX-01 every client and the server encrypted and decrypted XML content, and refused none',
            all(
                xml(role).get('enabled') and xml(role).get('encrypted', 0) > 0 and xml(role).get('decrypted', 0) > 0
                for role in roles
            )
            and xml('mcdata-server').get('encrypted', 0) > 0
            and xml('mcdata-server').get('decrypted', 0) > 0
            and xml('mcdata-server').get('refused') == 0,
        )
        observations['xml'] = {role: xml(role) for role in roles + ['mcdata-server']}
        # DA-01 with --sign-payloads, every DATA PAYLOAD was signed by its sender's MCData ID
        # and verified by its recipients (TS 33.180 clause 8.5.5).
        signing = all(configs[role]['mcdata'].get('authenticate_payload') for role in roles)
        observations['signed'] = signing
        if signing:
            # ------------------------------------------------------------------------------
            # The client's payload authentication counters (TS 33.180 clause 8.5.5).
            def auth(role):
                return status(role).get('mcdata_authentication') or {}

            received = [
                message
                for role in roles
                for message in (status(role).get('mcdata_inbox') or [])
                + (status(role).get('mcdata_media_received') or [])
            ]
            check(
                'DA-01 every received message carried a verified signature',
                received and all(message.get('authenticated') for message in received),
            )
            check(
                'DA-01 the senders signed, the recipients verified, nothing failed',
                auth('client-a').get('signed', 0) > 0
                and auth('client-b').get('verified', 0) > 0
                and all(auth(role).get('failures') == 0 for role in roles),
            )
            # DA-02 an altered signature is refused and the message never rendered.
            text = unique('forged')
            texts.append(text)
            send(
                'client-a',
                f'sds tamper-sig {ids["client-b"]}',
                text,
                'DA-02 the server accepts the forged message for delivery',
            )
            wait(
                'DA-02 client-b refuses the message whose signature fails',
                lambda: auth('client-b').get('failures') == 1,
            )
            check('DA-02 client-b never renders it', holds(lambda: not inbox('client-b', text), 1))
        observations['signalling'] = {role: signalling(role) for role in roles + ['mcdata-server']}
        observations['signalling']['mcdata-server'] = server
        observations['protection'] = {role: protection(role) for role in roles}
        result['passed'] = True
    finally:
        result['final_status'] = snapshot()
        output = args.artifacts / 'integration' / 'mcdata-protected-results.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], checks=len(checks)), indent=2))


if __name__ == '__main__':
    main()
