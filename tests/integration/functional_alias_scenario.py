#!/usr/bin/env python3
"""Exercise functional aliases (TS 24.379 clause 9A) and their use in calls.

Run against a separate four-client fixture prepared with
--private-call --adhoc --functional-alias. Each check records one assertion;
IDs match tests/mcptt/FUNCTIONAL_ALIAS_TEST.md.

The procedures under test: the functional alias status change by the client (TS 24.379 clause
9A.2.1.2) and at the MCPTT server owning the alias (clause 9A.2.2.3.3: activation, the
<mcptt-user-list>, the maximum simultaneous activations and take-over), the private call to an
alias redirected with 300 (Multiple Choices) (clauses 11.1.1.2.1.1 and 11.1.1.4.2), the calling
alias presented in calls (clause 10.1.1.3.1.1 step 6a), and ad hoc participant lists naming an
alias (clause 17.4.2.2 step 12b).

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the functional alias checks FA-01 to FA-11 and write integration/functional-alias-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-alias')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcptt']['user_id'] for client in roles}
    site = json.loads((generated / 'site.json').read_text())
    aliases = {alias['id'].split(':', 1)[1].split('.', 1)[0]: alias['id'] for alias in site['functional_aliases']}
    dispatcher, medic, reserve = aliases['dispatcher'], aliases['medic'], aliases['reserve']
    checks, observations = [], {}
    result = dict(scenario='functional-alias', passed=False, checks=checks, observations=observations)

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
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
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
    def sessions():
        """The server's call sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def idle(wanted=roles):
        """Every wanted client idle and the server holding no session."""
        return all(status(client).get('call_state') == 'idle' for client in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def active_aliases():
        """The server's activated functional aliases: alias to the MCPTT IDs that activated it."""
        return status('mcptt-server').get('functional_aliases', {})

    # ------------------------------------------------------------------------------
    def fa_result(role, action, code):
        """A predicate: the role's last functional alias request was the action and got the status code
        (TS 24.379 clause 9A.2.2.3.3)."""
        return lambda: (
            (status(role).get('last_fa_result') or {}).get('action') == action
            and (status(role).get('last_fa_result') or {}).get('status') == code
        )

    # ------------------------------------------------------------------------------
    def private_active(caller, callee):
        """Exactly one private call session, between caller and callee, both active."""
        current = [call for call in sessions() if call.get('call_type') == 'private']
        return (
            len(current) == 1
            and set(current[0].get('participants', [])) == {ids[caller], ids[callee]}
            and all(status(client).get('call_state') == 'active' for client in (caller, callee))
        )

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning=''):
        """A predicate: the role is idle and its last call failed with the code and the warning text."""

        # ------------------------------------------------------------------------------
        def check():
            """The role is idle and its last call failure carries the code and the warning."""
            failure = status(role).get('last_call_failure') or {}
            return (
                status(role).get('call_state') == 'idle'
                and failure.get('status') == code
                and warning in failure.get('warning', '')
            )

        return check

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(client).get('authorized') and status(client).get('affiliated') for client in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for role in roles:
            command(role, 'answer-mode auto')

        # FA-01 activation by permitted users (TS 24.379 clause 9A.2.2.3.3 steps 4a, 5 and 12).
        command('client-c', f'fa activate {medic}')
        wait('FA-01 first user activates the alias', fa_result('client-c', 'activate', 200))
        command('client-d', f'fa activate {medic}')
        wait(
            'FA-01 second user activates the same alias within its limit',
            lambda: active_aliases().get(medic) == [ids['client-c'], ids['client-d']],
        )

        # FA-02 a user outside <mcptt-user-list> is refused.
        command('client-c', f'fa activate {dispatcher}')
        wait(
            'FA-02 activation by a user not in the alias user list rejected with 403',
            fa_result('client-c', 'activate', 403),
        )

        # FA-03 <max-simultaneous-activations> and FA-04 take-over.
        command('client-a', f'fa activate {dispatcher}')
        wait('FA-03 dispatcher activated by client a', lambda: active_aliases().get(dispatcher) == [ids['client-a']])
        command('client-b', f'fa activate {dispatcher}')
        wait('FA-03 activation beyond the limit rejected with 403', fa_result('client-b', 'activate', 403))
        command('client-b', f'fa takeover {dispatcher}')
        wait(
            'FA-04 permitted take-over replaces the current holder',
            lambda: fa_result('client-b', 'takeover', 200)() and active_aliases().get(dispatcher) == [ids['client-b']],
        )
        command('client-a', f'fa takeover {dispatcher}')
        wait(
            'FA-04 take-over without <allow-takeover-functional-alias-other-user> rejected with 403',
            lambda: fa_result('client-a', 'takeover', 403)() and active_aliases().get(dispatcher) == [ids['client-b']],
        )

        # FA-05 private call to a functional alias: 300 redirect to an activated user.
        command('client-a', f'private-fa {medic} auto')
        wait(
            'FA-05 private call to the alias reaches its first activated user',
            lambda: private_active('client-a', 'client-c'),
            20,
        )
        redirect = status('client-a').get('functional_alias_redirect') or {}
        assert redirect.get('alias') == medic and redirect.get('selected') == ids['client-c'], 'redirect not recorded'
        checks.append('FA-05 caller followed a 300 Multiple Choices naming the selected MCPTT ID')
        assert status('client-c').get('called_functional_alias') == medic, 'callee not told the called alias'
        checks.append('FA-05 callee is told which alias was called')
        command('client-a', 'hangup')
        wait('FA-05 released', idle)

        # FA-06 presentation of the caller's alias only while activated (TS 24.379 clause
        # 10.1.1.3.1.1 step 6a).
        command('client-b', f'fa use {dispatcher}')
        command('client-b', f"private {ids['client-a']} auto")
        wait(
            'FA-06 private call presents the activated alias',
            lambda: (
                private_active('client-b', 'client-a')
                and status('client-a').get('calling_functional_alias') == dispatcher
            ),
        )
        command('client-b', 'hangup')
        wait('FA-06 released', idle)
        command('client-a', f'fa use {dispatcher}')
        command('client-a', f"private {ids['client-c']} auto")
        wait(
            'FA-06 an alias that is not activated for the caller is not presented',
            lambda: private_active('client-a', 'client-c') and status('client-c').get('calling_functional_alias') == '',
        )
        command('client-a', 'hangup')
        wait('FA-06 second call released', idle)
        command('client-b', 'call')
        wait(
            'FA-06 group call members see the initiator alias',
            lambda: (
                all(status(client).get('call_state') == 'active' for client in roles)
                and all(
                    status(client).get('calling_functional_alias') == dispatcher
                    for client in ['client-a', 'client-c', 'client-d']
                )
            ),
            20,
        )
        command('client-b', 'hangup')
        wait('FA-06 group call released', idle, 20)
        command('client-a', 'fa use none')
        command('client-b', 'fa use none')

        # FA-07 first-to-answer call to an alias invites every activated user.
        command('client-a', f'first-to-answer-fa {medic}')
        wait(
            'FA-07 every user that activated the alias rings',
            lambda: all(status(client).get('call_state') == 'ringing' for client in ['client-c', 'client-d']),
        )
        command('client-d', 'answer')
        wait(
            'FA-07 first answer selected',
            lambda: private_active('client-a', 'client-d') and status('client-c').get('call_state') == 'idle',
        )
        command('client-a', 'hangup')
        wait('FA-07 released', idle)

        # FA-08 ad hoc participant list naming an alias (TS 24.379 clause 17.4.2.2 step 12b).
        command('client-a', f'adhoc {medic}')
        wait(
            'FA-08 ad hoc call invites the users behind the alias',
            lambda: (
                all(
                    status(client).get('call_state') == 'active' and status(client).get('call_type') == 'adhoc'
                    for client in ['client-a', 'client-c', 'client-d']
                )
                and all(status(client).get('called_functional_alias') == medic for client in ['client-c', 'client-d'])
            ),
            20,
        )
        command('client-a', 'hangup')
        wait('FA-08 released', idle, 20)

        # FA-09 broadcast ad hoc call: receive-only invitees (cause #5, TS 24.380 clause 8.2.6.2),
        # release at transmission end.
        command('client-a', f"adhoc broadcast {ids['client-b']} {ids['client-c']}")
        wait(
            'FA-09 broadcast ad hoc call established',
            lambda: (
                all(
                    status(client).get('call_state') == 'active' and status(client).get('call_type') == 'adhoc'
                    for client in ['client-a', 'client-b', 'client-c']
                )
                and status('client-b').get('adhoc_broadcast')
            ),
        )
        denials = status('client-b').get('floor_denials', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'FA-09 receiver request denied with cause 5',
            lambda: (
                status('client-b').get('floor_denials', 0) > denials
                and status('client-b').get('last_floor_reject_cause') == 5
            ),
        )
        before = status('client-c').get('received_packets', 0)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'FA-09 receivers get the broadcast speech',
            lambda: status('client-c').get('received_packets', 0) >= before + 100,
            20,
        )
        wait('FA-09 broadcast ad hoc call released at transmission end', idle, 25)

        # FA-10 deactivation and FA-11 an alias nobody has activated.
        command('client-c', f'fa deactivate {medic}')
        wait(
            'FA-10 deactivation removes the user from the alias',
            lambda: active_aliases().get(medic) == [ids['client-d']],
        )
        # The redirected INVITE is an ordinary private call, so the caller's
        # <PrivateCall> list applies to the selected user: client-b may call anyone.
        command('client-b', f'private-fa {medic} auto')
        wait('FA-10 the alias now resolves to the remaining user', lambda: private_active('client-b', 'client-d'), 20)
        command('client-b', 'hangup')
        wait('FA-10 released', idle)
        command('client-b', f'private-fa {reserve} auto')
        wait(
            'FA-11 call to an alias with no activated user rejected with 403 warning 145',
            rejected('client-b', 403, '145 unable to determine called party'),
        )

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/functional-alias-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
