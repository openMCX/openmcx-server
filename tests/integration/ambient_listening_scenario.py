#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise ambient listening calls (TS 24.379 clause 11.1.6, TS 23.379 clause 10.14).

Run against a fixture prepared with --private-call: client-a may make both
ambient listening types (targets limited to b and c), client-b only locally
initiated ones, client-c neither, and client-d cannot be called. The server
private call timer is 30 s. Check IDs match tests/mcptt/AMBIENT_LISTENING_TEST.md.

The procedures under test: the client procedures of TS 24.379 clause 11.1.6.2.1 (on-demand
call, its release origination and termination), the participating function's of clause 11.1.6.3
(warnings 144 and 154 in clause 11.1.6.3.1.1, 127 at the terminating side), and the controlling
function's of clause 11.1.6.4 with the server initiated release of clause 11.1.6.4.3; floor control
gives the floor to the listened-to user and denies the listening user with cause #5 (Receive only,
TS 24.380 clause 8.2.6.2).

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
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
    """Run the ambient listening checks AL-01 to AL-13 and write integration/ambient-listening-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-ambient')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcptt']['user_id'] for client in roles}
    checks, observations = [], {}
    result = dict(scenario='ambient-listening-call', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """Every client's and the server's status, for the failure report."""
        return {client: status(client) for client in roles + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one command in the role's container (mcptt-server or mcx-client); a failure raises RuntimeError."""
        binary, config = (
            ('openmcx-mcptt-server', '/config/mcptt-server.json')
            if role == 'mcptt-server'
            else ('mcx-client', f'/config/{role}.json')
        )
        run = subprocess.run(
            cli + ['exec', '-T', role, binary, '--config', config, '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=15):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record the label as a passed check if the condition holds; raise with a snapshot otherwise."""
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot()))
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def sessions():
        """The server's call sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def ambient_sessions():
        """The server's ambient listening call sessions."""
        return [call for call in sessions() if call.get('call_type') == 'ambient']

    # ------------------------------------------------------------------------------
    def idle():
        """Every client idle with no ambient listening call, and the server holding no session."""
        return (
            all(status(client).get('call_state') == 'idle' and not status(client).get('ambient') for client in roles)
            and not sessions()
        )

    # ------------------------------------------------------------------------------
    def ambient(role):
        """The role's cached ambient listening call state, or {}."""
        return status(role).get('ambient') or {}

    # ------------------------------------------------------------------------------
    def last_ambient(role):
        """The role's cached state of its last, released, ambient listening call, or {}."""
        return status(role).get('last_ambient') or {}

    # ------------------------------------------------------------------------------
    def failure(role):
        """The role's last call failure, or {}."""
        return status(role).get('last_call_failure') or {}

    # ------------------------------------------------------------------------------
    def listen(listening, listened_to):
        """listening asks to listen to listened_to (remote-init) and waits for media (TS 24.379
        clause 11.1.6.2.1.1)."""
        command(listening, f'ambient remote {ids[listened_to]}')
        wait(
            f'{listening} listens to {listened_to}',
            lambda: (
                status(listening).get('call_state') == 'active'
                and any(
                    call.get('listened_to') == ids[listened_to] and call.get('floor_owner') == ids[listened_to]
                    for call in ambient_sessions()
                )
                and ambient(listened_to).get('transmitting')
            ),
        )

    # ------------------------------------------------------------------------------
    def hang_up_all():
        """Hang up on every client."""
        for role in roles:
            command(role, 'hangup')

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(client).get('authorized') and status(client).get('affiliated') for client in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        command('client-b', 'ambient-source /artifacts/speech/bravo.wav')
        command('client-a', 'ambient-source /artifacts/speech/alpha.wav')

        # AL-01 remotely initiated: a listens to b; b's user sees nothing.
        before = {client: status(client).get('received_packets', 0) for client in roles}
        listen('client-a', 'client-b')
        session = ambient_sessions()[0]
        check(
            'AL-01 server session: remote-init, a listening, b listened-to, floor with b',
            session.get('ambient_listening_type') == 'remote-init'
            and session.get('listening') == ids['client-a']
            and session.get('listened_to') == ids['client-b']
            and session.get('initiator') == ids['client-a'],
        )
        listening_ambient = ambient('client-a')
        check(
            'AL-01 listening user: role cached, release permitted (Feature-Caps), null alert in 183',
            listening_ambient.get('role') == 'listening'
            and listening_ambient.get('type') == 'remote-init'
            and listening_ambient.get('release_allowed')
            and listening_ambient.get('null_alert'),
        )
        listened_to_status = status('client-b')
        check(
            'AL-01 listened-to user shows no call: idle, no call type, not talking',
            listened_to_status.get('call_state') == 'idle'
            and listened_to_status.get('call_type') == ''
            and not listened_to_status.get('talking')
            and listened_to_status.get('private_peer') == '',
        )
        check(
            'AL-01 listened-to client: role cached, no release permission, null alert, transmitting',
            ambient('client-b').get('role') == 'listened-to'
            and not ambient('client-b').get('release_allowed')
            and ambient('client-b').get('null_alert')
            and ambient('client-b').get('transmitting'),
        )
        wait(
            'AL-01 listening user gets Floor Taken naming b without permission to request',
            lambda: (
                status('client-a').get('floor_owner') == ids['client-b']
                and status('client-a').get('permission_to_request') in (0, False)
            ),
        )

        # AL-02 media flows only from the listened-to user to the listening user.
        wait(
            'AL-02 listened-to speech reaches the listening user',
            lambda: status('client-a').get('received_packets', 0) >= before['client-a'] + 150,
            20,
        )
        check(
            'AL-02 no other client receives the ambient media',
            all(
                status(client).get('received_packets', 0) == before[client]
                for client in ['client-b', 'client-c', 'client-d']
            ),
        )
        observations['al02_sent_by_b'] = status('client-b').get('sent_packets')

        # AL-03 the listening user cannot take the floor (receive only, cause #5 of TS 24.380
        # clause 8.2.6.2).
        denials = status('client-a').get('floor_denials', 0)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'AL-03 listening user floor request denied with cause 5',
            lambda: (
                status('client-a').get('floor_denials', 0) > denials
                and status('client-a').get('last_floor_reject_cause') == 5
            ),
        )
        check(
            'AL-03 floor stays with the listened-to user', ambient_sessions()[0].get('floor_owner') == ids['client-b']
        )

        # AL-04 a remotely listened-to user cannot release the call it does not know about.
        command('client-b', 'hangup')
        check(
            'AL-04 hangup by the listened-to user of a remote-init call changes nothing',
            holds(
                lambda: (
                    ambient_sessions()
                    and status('client-a').get('call_state') == 'active'
                    and ambient('client-b').get('transmitting')
                ),
                2,
            ),
        )

        # AL-05 the listening user releases the call.
        command('client-a', 'hangup')
        wait('AL-05 listening user release ends the call for both', idle)
        check(
            'AL-05 client-initiated release carries no release reason; both caches cleared',
            last_ambient('client-a').get('release_reason') == ''
            and last_ambient('client-b').get('role') == 'listened-to',
        )

        # AL-06 locally initiated: b asks a to listen to it.
        before = status('client-a').get('received_packets', 0)
        command('client-b', f'ambient local {ids["client-a"]}')
        wait(
            'AL-06 local-init call: a listening and b transmitting',
            lambda: (
                status('client-a').get('call_state') == 'active'
                and ambient('client-b').get('transmitting')
                and any(
                    call.get('ambient_listening_type') == 'local-init' and call.get('listened_to') == ids['client-b']
                    for call in ambient_sessions()
                )
            ),
        )
        check(
            'AL-06 listening invitee is told and may release (Feature-Caps in INVITE)',
            ambient('client-a').get('role') == 'listening'
            and ambient('client-a').get('release_allowed')
            and not ambient('client-a').get('null_alert'),
        )
        check(
            'AL-06 listened-to originator gets no indication but may release (Feature-Caps in 200)',
            status('client-b').get('call_state') == 'idle'
            and ambient('client-b').get('role') == 'listened-to'
            and ambient('client-b').get('release_allowed'),
        )
        wait(
            'AL-06 local-init media reaches the listening user',
            lambda: status('client-a').get('received_packets', 0) >= before + 150,
            20,
        )

        # AL-07 the listened-to originator of a local-init call may release it.
        command('client-b', 'hangup')
        wait('AL-07 listened-to originator release ends the local-init call', idle)

        # AL-08 administrator release (TS 24.379 clause 11.1.6.4.3).
        listen('client-a', 'client-b')
        command('mcptt-server', f'ambient-release {ids["client-b"]}')
        wait('AL-08 administrator release ends the call', idle)
        check(
            'AL-08 listening user told "administrator-action"; listened-to BYE has no reason',
            last_ambient('client-a').get('release_reason') == 'administrator-action'
            and last_ambient('client-b').get('release_reason') == '',
        )

        # AL-09a a call command that fails before any INVITE is sent is no call
        # request: the listened-to client stays in the ambient call.
        listen('client-a', 'client-b')
        command('client-b', f'private {ids["client-b"]}')
        wait(
            'AL-09a failed call command reported by the listened-to client',
            lambda: 'another MCPTT ID' in status('client-b').get('last_error', ''),
        )
        sent = status('client-b').get('sent_packets', 0)
        wait(
            'AL-09a listened-to client still attached and transmitting',
            lambda: (
                ambient('client-b').get('attached')
                and ambient('client-b').get('transmitting')
                and status('client-b').get('sent_packets', 0) >= sent + 50
            ),
        )
        check(
            'AL-09a ambient call still held by the server and the listening user',
            ambient_sessions()
            and status('client-a').get('call_state') == 'active'
            and status('client-b').get('call_state') == 'idle',
        )

        # AL-09 a call request initiated by the listened-to user releases the ambient call.
        command('client-b', 'call')
        wait(
            'AL-09 listening user told "call-request-initiated-by-listened-to-client"',
            lambda: last_ambient('client-a').get('release_reason') == 'call-request-initiated-by-listened-to-client',
        )
        wait(
            'AL-09 the listened-to user group call proceeds',
            lambda: (
                status('client-b').get('call_state') == 'active'
                and status('client-b').get('call_type') == 'prearranged'
                and not ambient_sessions()
            ),
        )
        hang_up_all()
        wait('AL-09 calls released', idle)

        # AL-10 a call request targeted to the listened-to user releases the ambient call.
        listen('client-a', 'client-b')
        command('client-c', f'private {ids["client-b"]} auto')
        wait(
            'AL-10 listening user told "call-request-for-listened-to-client"',
            lambda: last_ambient('client-a').get('release_reason') == 'call-request-for-listened-to-client',
        )
        wait(
            'AL-10 the private call to the listened-to user is established',
            lambda: (
                status('client-b').get('call_state') == 'active'
                and status('client-b').get('private_peer') == ids['client-c']
                and status('client-c').get('call_state') == 'active'
            ),
        )
        command('client-c', 'hangup')
        wait('AL-10 calls released', idle)

        # AL-11 private call timer expiry (30 s in this fixture).
        started = time.monotonic()
        listen('client-a', 'client-b')
        wait(
            'AL-11 listening user told "private-call-expiry"',
            lambda: last_ambient('client-a').get('release_reason') == 'private-call-expiry',
            45,
        )
        observations['al11_seconds_to_expiry'] = round(time.monotonic() - started, 1)
        check(
            'AL-11 released no earlier than the 30 s private call timer', observations['al11_seconds_to_expiry'] >= 29
        )
        wait('AL-11 call released', idle)

        # AL-12 rejections; none creates a call.
        for label, role, text, status_code, warning in [
            (
                'AL-12 requester without the remote-init ruleset rejected with 154',
                'client-c',
                f'ambient remote {ids["client-b"]}',
                403,
                '154',
            ),
            (
                'AL-12 remote-init needs its own ruleset element (local-only user rejected with 154)',
                'client-b',
                f'ambient remote {ids["client-a"]}',
                403,
                '154',
            ),
            (
                'AL-12 target outside the <PrivateCall> list rejected with 144',
                'client-a',
                f'ambient remote {ids["client-d"]}',
                403,
                '144',
            ),
            ('AL-12 uncallable target rejected with 127', 'client-b', f'ambient local {ids["client-d"]}', 403, '127'),
        ]:
            command(role, text)
            wait(
                label,
                lambda: (
                    failure(role).get('status') == status_code
                    and warning in failure(role).get('warning', '')
                    and status(role).get('call_state') == 'idle'
                ),
            )
            check(label + ': no ambient session', not ambient_sessions())

        # AL-13 a listened-to target already in another call is busy: 480.
        command('client-c', f'private {ids["client-b"]} auto')
        wait('AL-13 target in a private call', lambda: status('client-b').get('call_state') == 'active')
        command('client-a', f'ambient remote {ids["client-b"]}')
        wait(
            'AL-13 ambient request to a busy user rejected with 480',
            lambda: failure('client-a').get('status') == 480 and status('client-a').get('call_state') == 'idle',
        )
        check(
            'AL-13 the busy user call is undisturbed',
            status('client-b').get('call_state') == 'active'
            and status('client-b').get('private_peer') == ids['client-c'],
        )
        command('client-c', 'hangup')
        wait('AL-13 call released', idle)

        check('server instance unchanged', status('mcptt-server')['instance_id'] == instance)
        result['passed'] = True
    except (
        AssertionError,
        KeyError,
        IndexError,
        OSError,
        RuntimeError,
        StopIteration,
        subprocess.SubprocessError,
    ) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/ambient-listening-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
