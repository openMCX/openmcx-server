#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise functional aliases (TS 24.379 clause 9A) and their use in calls.

Run against a separate four-client fixture prepared with
--private-call --adhoc --functional-alias. Each check records one assertion;
IDs match tests/mcptt/FUNCTIONAL_ALIAS_TEST.md.

The procedures under test: the functional alias status change by the client (TS 24.379 clause
9A.2.1.2) after its status subscription (clauses 9A.2.1.1 and 9A.2.1.3), at the participating
function (clause 9A.2.2.2.3: 200, or 403 with warning 201) and at the MCPTT server owning the alias
(clause 9A.2.2.3.3: activation, the <mcptt-user-list>, the maximum simultaneous activations and
take-over), its outcome in the status NOTIFY (clause 9A.2.2.2.5), the private call to an
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
    """Run the functional alias checks FA-01 to FA-17 and write integration/functional-alias-results.json."""
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
    duty_officer, patrol_car, incident_commander = aliases['duty-officer'], aliases['patrol-car-12'], aliases['incident-commander']
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
    def fa_result(role, action, code, alias=None, outcome=None, warning=''):
        """A predicate: the role's last functional alias request was the action and got the status code (TS 24.379
        clause 9A.2.2.2.3) with the warning, and the status NOTIFY with its p-id-fa gave the alias the outcome
        (clause 9A.2.2.2.5): activated, deactivated, take-over-possible or refused."""

        # ------------------------------------------------------------------------------
        def check():
            """The last request's action, status code, warning and the alias's outcome."""
            last = status(role).get('last_fa_result') or {}
            return (
                last.get('action') == action
                and last.get('status') == code
                and warning in last.get('warning', '')
                and (alias is None or (last.get('outcomes') or {}).get(alias) == outcome)
            )

        return check

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

        # FA-01 activation by permitted users (TS 24.379 clause 9A.2.2.3.3 steps 4a, 5 and 12): the client
        # subscribes to its own status first (clause 9A.2.1.1), the PUBLISH is answered 200 (clause
        # 9A.2.2.2.3 step 8) and the NOTIFY with its p-id-fa lists the alias "activated" (clause 9A.2.2.2.5).
        command('client-c', f'fa activate {patrol_car}')
        wait(
            'FA-01 the client subscribes to its functional alias status before the change (200)',
            lambda: status('client-c').get('functional_alias_subscription_result') == 200,
        )
        wait(
            'FA-01 first user activates the alias: 200, then NOTIFY "activated"',
            fa_result('client-c', 'activate', 200, patrol_car, 'activated'),
        )
        command('client-d', f'fa activate {patrol_car}')
        wait(
            'FA-01 second user activates the same alias within its limit',
            lambda: active_aliases().get(patrol_car) == [ids['client-c'], ids['client-d']],
        )

        # FA-02 an alias the user may not change (TS 24.379 clause 9A.2.2.2.3 steps 4A and 4B; OpenMCX's
        # <FunctionalAliasList> is the aliases whose <mcptt-user-list> names the user) is refused by the
        # participating function.
        command('client-c', f'fa activate {duty_officer}')
        wait(
            'FA-02 activation by a user not in the alias user list rejected with 403 warning 201',
            fa_result(
                'client-c', 'activate', 403, warning='201 user not authorized to change the functional alias status'
            ),
        )

        # FA-03 <max-simultaneous-activations> and FA-04 take-over.
        command('client-a', f'fa activate {duty_officer}')
        wait('FA-03 duty-officer activated by client a', lambda: active_aliases().get(duty_officer) == [ids['client-a']])
        # Beyond the limit the owning check refuses (clause 9A.2.2.3.3 step 5); client-b, which may take the alias
        # over, is told "take-over-possible" (clause 3.1, clause 9A.2.1.3).
        command('client-b', f'fa activate {duty_officer}')
        wait(
            'FA-03 activation beyond the limit: 200, then NOTIFY "take-over-possible"',
            lambda: (
                fa_result('client-b', 'activate', 200, duty_officer, 'take-over-possible')()
                and active_aliases().get(duty_officer) == [ids['client-a']]
            ),
        )
        # FA-04 the take-over request carries <take-over> after the offer (clause 9A.2.1.2 step 6 d)); client-a
        # learns from its NOTIFY that it lost the alias.
        command('client-b', f'fa takeover {duty_officer}')
        wait(
            'FA-04 permitted take-over replaces the current holder: NOTIFY "activated"',
            lambda: (
                fa_result('client-b', 'takeover', 200, duty_officer, 'activated')()
                and active_aliases().get(duty_officer) == [ids['client-b']]
            ),
        )
        wait(
            'FA-04 the previous holder is notified that it no longer holds the alias',
            lambda: duty_officer not in status('client-a').get('active_functional_aliases', [duty_officer]),
        )
        # client-a, without <allow-takeover-functional-alias-other-user>, is offered no take-over, so its
        # take-over goes as an activation without <take-over> and is refused in the NOTIFY.
        command('client-a', f'fa takeover {duty_officer}')
        wait(
            'FA-04 take-over without <allow-takeover-functional-alias-other-user>: 200, then refused in the NOTIFY',
            lambda: (
                fa_result('client-a', 'takeover', 200, duty_officer, 'refused')()
                and (status('client-a').get('last_fa_result') or {}).get('take_over') is False
                and active_aliases().get(duty_officer) == [ids['client-b']]
            ),
        )

        # FA-05 private call to a functional alias: 300 redirect to an activated user.
        command('client-a', f'private-fa {patrol_car} auto')
        wait(
            'FA-05 private call to the alias reaches its first activated user',
            lambda: private_active('client-a', 'client-c'),
            20,
        )
        redirect = status('client-a').get('functional_alias_redirect') or {}
        assert redirect.get('alias') == patrol_car and redirect.get('selected') == ids['client-c'], 'redirect not recorded'
        checks.append('FA-05 caller followed a 300 Multiple Choices naming the selected MCPTT ID')
        assert status('client-c').get('called_functional_alias') == patrol_car, 'callee not told the called alias'
        checks.append('FA-05 callee is told which alias was called')
        command('client-a', 'hangup')
        wait('FA-05 released', idle)

        # FA-06 presentation of the caller's alias only while activated (TS 24.379 clause
        # 10.1.1.3.1.1 step 6a).
        command('client-b', f'fa use {duty_officer}')
        command('client-b', f"private {ids['client-a']} auto")
        wait(
            'FA-06 private call presents the activated alias',
            lambda: (
                private_active('client-b', 'client-a')
                and status('client-a').get('calling_functional_alias') == duty_officer
            ),
        )
        command('client-b', 'hangup')
        wait('FA-06 released', idle)
        command('client-a', f'fa use {duty_officer}')
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
                    status(client).get('calling_functional_alias') == duty_officer
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
        command('client-a', f'first-to-answer-fa {patrol_car}')
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
        command('client-a', f'adhoc {patrol_car}')
        wait(
            'FA-08 ad hoc call invites the users behind the alias',
            lambda: (
                all(
                    status(client).get('call_state') == 'active' and status(client).get('call_type') == 'adhoc'
                    for client in ['client-a', 'client-c', 'client-d']
                )
                and all(status(client).get('called_functional_alias') == patrol_car for client in ['client-c', 'client-d'])
            ),
            20,
        )
        command('client-a', 'hangup')
        wait('FA-08 released', idle, 20)

        # FA-08b an alias in a change of the participants (TS 24.379 clause 17.4.5.1.1 step 3a): invited, the users
        # behind it join, each told the called alias; removed, they leave; an alias nobody holds alone is 403 145.
        command('client-a', f"adhoc {ids['client-b']}")
        wait('FA-08b ad hoc call with client-b', lambda: all(
            status(client).get('call_state') == 'active' for client in ['client-a', 'client-b']), 20)
        command('client-a', f'adhoc-modify add {patrol_car}')
        wait(
            'FA-08b the users behind the added alias join, told the called alias',
            lambda: all(
                status(client).get('call_state') == 'active' and status(client).get('called_functional_alias') == patrol_car
                for client in ['client-c', 'client-d']
            ),
            20,
        )
        command('client-a', f'adhoc-modify remove {patrol_car}')
        wait(
            'FA-08b the users behind the removed alias leave',
            lambda: all(status(client).get('call_state') == 'idle' for client in ['client-c', 'client-d'])
            and status('client-b').get('call_state') == 'active',
            20,
        )
        command('client-a', f'adhoc-modify add {incident_commander}')
        wait(
            'FA-08b an alias nobody holds, alone in the change: 403 with warning 145',
            lambda: (status('client-a').get('last_modify_result') or {}).get('status') == 403
            and '145 ' in (status('client-a').get('last_modify_result') or {}).get('warning', ''),
        )
        command('client-a', 'hangup')
        wait('FA-08b released', idle, 20)

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
        command('client-c', f'fa deactivate {patrol_car}')
        wait(
            'FA-10 deactivation removes the user from the alias: 200, then NOTIFY without it',
            lambda: (
                fa_result('client-c', 'deactivate', 200, patrol_car, 'deactivated')()
                and active_aliases().get(patrol_car) == [ids['client-d']]
            ),
        )
        # The redirected INVITE is an ordinary private call, so the caller's
        # <PrivateCall> list applies to the selected user: client-b may call anyone.
        command('client-b', f'private-fa {patrol_car} auto')
        wait('FA-10 the alias now resolves to the remaining user', lambda: private_active('client-b', 'client-d'), 20)
        command('client-b', 'hangup')
        wait('FA-10 released', idle)
        command('client-b', f'private-fa {incident_commander} auto')
        wait(
            'FA-11 call to an alias with no activated user rejected with 403 warning 145',
            rejected('client-b', 403, '145 unable to determine called party'),
        )

        # FA-12 to FA-15: a PUBLISH names the user's whole set (TS 24.379 clause 9A.2.2.2.3 steps 12 to 14, the client
        # listing every alias wanted active, clause 9A.2.1.2 step 6 a). client-b gives duty-officer up first.
        command('client-b', f'fa deactivate {duty_officer}')
        wait('FA-12 duty-officer released by client-b', lambda: duty_officer not in active_aliases())
        command('client-a', f'fa activate {duty_officer}')
        wait('FA-12 duty-officer activated by client-a', lambda: active_aliases().get(duty_officer) == [ids['client-a']])
        command('client-a', f'fa activate {incident_commander}')
        wait(
            'FA-12 a second alias activated: both stay active',
            lambda: (
                active_aliases().get(duty_officer) == [ids['client-a']]
                and active_aliases().get(incident_commander) == [ids['client-a']]
            ),
        )
        # The client deactivates one alias by listing the other (step 12 b), not by Expires 0.
        command('client-a', f'fa deactivate {duty_officer}')
        wait(
            'FA-13 one of two aliases deactivated, the other stays active',
            lambda: (
                fa_result('client-a', 'deactivate', 200, duty_officer, 'deactivated')()
                and duty_officer not in active_aliases()
                and active_aliases().get(incident_commander) == [ids['client-a']]
            ),
        )
        # Another client's PUBLISH: Expires 0 deactivates every alias of the user, whatever it lists (step 13).
        command('client-a', f'fa activate {duty_officer}')
        wait(
            'FA-14 both aliases active again',
            lambda: (
                active_aliases().get(duty_officer) == [ids['client-a']]
                and active_aliases().get(incident_commander) == [ids['client-a']]
            ),
        )
        command('client-a', f'fa publish 0 {incident_commander}')
        wait(
            'FA-14 Expires 0 listing one alias deactivates both',
            lambda: duty_officer not in active_aliases() and incident_commander not in active_aliases(),
        )
        # An alias listed again keeps its place among the alias's activations (step 12 a): client-c joins
        # patrol-car-12 after client-d, and client-d's PUBLISH listing it again leaves client-d first.
        command('client-c', f'fa activate {patrol_car}')
        wait(
            'FA-15 client-c activates patrol-car-12 after client-d',
            lambda: active_aliases().get(patrol_car) == [ids['client-d'], ids['client-c']],
        )
        command('client-d', f'fa publish 4294967295 {patrol_car}')
        time.sleep(2)
        wait(
            'FA-15 an alias listed again keeps its activation order',
            lambda: active_aliases().get(patrol_car) == [ids['client-d'], ids['client-c']],
        )

        # FA-16 and FA-17: TS 24.379 clause 9.2.2.3.3 step 10 a0, a de-affiliation refused while the group document
        # forbids it for an activated alias: incident-commander always (<forbidden-deaffiliation-FAs>), duty-officer
        # for the last user to have bound it to the group (<forbidden-deaffiliation-if-last-FAs>, clause 9A.4). The
        # PUBLISH is answered 200 all the same and the user stays affiliated. A single server only: on split servers
        # the controlling function never sees a per-group de-affiliation (docs/LIMITATIONS.md).
        split = (generated / 'mcptt-part-1.json').exists()
        group = configs['client-a']['mcptt']['group_id']

        def server_affiliated(role):
            return group in ((status('mcptt-server').get('affiliations') or {}).get(ids[role]) or [])

        def deaffiliation_kept(label):
            command('client-a', 'deaffiliate')
            time.sleep(2)
            wait(label, lambda: server_affiliated('client-a'), 5)

        def deaffiliation_done(label):
            command('client-a', 'deaffiliate')
            wait(label, lambda: not server_affiliated('client-a'))
            command('client-a', 'affiliate')
            wait(f'{label}: affiliated again', lambda: server_affiliated('client-a') and status('client-a').get('affiliated'))

        def binding(action):
            before = (status('client-a').get('alias_binding_result') or {}).get('request', 0)
            command('client-a', f'fa {action} {duty_officer} {group}')
            wait(
                f'FA-17 the {action} request is answered 200',
                lambda: (status('client-a').get('alias_binding_result') or {}).get('request', 0) > before
                and status('client-a')['alias_binding_result'].get('status') == 200,
            )

        def forbidden_deaffiliation():
            command('client-a', f'fa activate {incident_commander}')
            wait('FA-16 incident-commander activated by client-a', lambda: active_aliases().get(incident_commander) == [ids['client-a']])
            deaffiliation_kept('FA-16 de-affiliation refused while incident-commander is activated: still affiliated')
            command('client-a', f'fa deactivate {incident_commander}')
            wait('FA-16 incident-commander deactivated', lambda: incident_commander not in active_aliases())
            deaffiliation_done('FA-16 without the alias the de-affiliation takes effect')

            command('client-a', f'fa activate {duty_officer}')
            wait('FA-17 duty-officer activated by client-a', lambda: active_aliases().get(duty_officer) == [ids['client-a']])
            deaffiliation_done('FA-17 an activated alias not bound to the group does not hold the user')
            binding('bind')
            deaffiliation_kept('FA-17 de-affiliation refused for the last user to have bound duty-officer: still affiliated')
            binding('unbind')
            deaffiliation_done('FA-17 once unbound the de-affiliation takes effect')
            command('client-a', f'fa deactivate {duty_officer}')
            wait('FA-17 duty-officer deactivated', lambda: duty_officer not in active_aliases())

        if split:
            observations['forbidden_deaffiliation'] = 'skipped: split servers'
        else:
            forbidden_deaffiliation()

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
