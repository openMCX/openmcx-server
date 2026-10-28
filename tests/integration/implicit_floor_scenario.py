#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise MCPTT calls set up with an implicit floor request.

Run against a separate four-client fixture prepared with --private-call --chat --adhoc --priority (the priority
policy authorises client-a's emergency call, IF-04), with the speech fixtures copied. Check labels carry the IDs IF-01 to IF-09 (to be listed in
tests/mcptt/IMPLICIT_FLOOR_TEST.md).

The procedures under test: the client offers "mc_implicit_request" when the call command ends in implicit=<WAV>
(TS 24.380 clause 14.2.5, an implementation option; TS 24.379 clause 6.4), the controlling MCPTT function accepts
it in the 200 (OK) of an INVITE that initiates the call (TS 24.380 clause 14.3.5) and grants the floor once the leg
is active, as if a Floor Request was received (TS 24.380 clauses 6.3.4.2.2 step 3a-i and 6.3.5.2.2 items 1 and 3a);
the client waits in 'U: pending Request' with T101 running (TS 24.380 clause 6.2.4.2.2 step 4) and talks on Floor
Granted. A join of a chat group call that exists is not an implicit floor request (TS 24.380 clauses 6.3.2.2 and
14.3.5): no echo, Floor Taken or Floor Idle; a call request to a group whose call has a talker gets Floor Taken
without queueing (TS 24.380 clause 6.3.5.2.2 item 3c); the client refuses "rejoin implicit" (TS 24.380 clause 6.2.1
item 2). The wire checks are verify_implicit_floor.py.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds
from prearranged_floor_scenario import repeat_pcm

ROOT = Path(__file__).resolve().parents[2]
SPEECH = '/artifacts/speech/alpha.wav'


# ------------------------------------------------------------------------------
def main():
    """Run the implicit floor request checks IF-01 to IF-09 and write integration/implicit-floor-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-implicit')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcptt']['user_id'] for client in roles}
    site = json.loads((generated / 'site.json').read_text())
    chat = next(entry for entry in site['groups'] if entry.get('type') == 'chat')
    prearranged = configs['client-a']['mcptt']['group_id']
    checks = []
    result = dict(scenario='implicit-floor-request', passed=False, checks=checks)

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
    def command(role, text, refused=False):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError, or with refused the
        command must fail."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if refused != bool(run.returncode):
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip() or "accepted"}')

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
    def implicit(role, outcome):
        """A predicate: the role's last implicit floor request has the outcome ("accepted", "not accepted")."""
        return lambda: status(role).get('implicit_floor_request') == outcome

    # ------------------------------------------------------------------------------
    def talks(talker, listeners, before):
        """A predicate: the talker holds the floor and talks, and every listener received 100 more packets."""
        return lambda: (
            status(talker).get('talking')
            and status(talker).get('floor_state') == 'HasPermission'
            and all(status(role).get('received_packets', 0) >= before[role] + 100 for role in listeners)
        )

    # ------------------------------------------------------------------------------
    def received():
        """The received packet counters of every client."""
        return {role: status(role).get('received_packets', 0) for role in roles}

    # ------------------------------------------------------------------------------
    def on_group(group):
        """A predicate: every client affiliated to the group and on it."""
        return lambda: all(status(role).get('group_id') == group and status(role).get('affiliated') for role in roles)

    # ------------------------------------------------------------------------------
    def hangup_all(label):
        """Hang up every client still in a call and wait until the server holds no session."""
        for role in roles:
            if status(role).get('call_state') != 'idle':
                command(role, 'hangup')
        wait(label, idle, 30)

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(client).get('authorized') and status(client).get('affiliated') for client in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        assert (args.artifacts / 'speech' / 'alpha.wav').is_file(), 'missing speech fixture alpha.wav'
        for role in roles:
            command(role, 'answer-mode auto')

        # IF-01 prearranged group call with an implicit floor request: granted without a Floor Request.
        before = received()
        command('client-a', f'call implicit={SPEECH}')
        wait('IF-01 the 200 (OK) accepts the implicit floor request', implicit('client-a', 'accepted'))
        wait('IF-01 the originator is granted and the members hear it', talks('client-a', ['client-b'], before), 20)
        assert status('client-a').get('call_type') == 'prearranged'

        # IF-02 a call request to the group whose call has a talker: Floor Taken (no queueing negotiated). client-c
        # was invited to the call as a member, so it leaves first; once alpha.wav has ended, client-a talks again
        # with a fixture long enough to hold the floor through the check.
        command('client-c', 'hangup')
        wait('IF-02 the third member left', lambda: status('client-c').get('call_state') == 'idle')
        repeat_pcm(args.artifacts / 'speech/alpha.wav', args.artifacts / 'speech/implicit-hold.wav')
        wait('IF-02 the first talk burst ended', lambda: not status('client-a').get('talking'), 15)
        command('client-a', 'ptt /artifacts/speech/implicit-hold.wav')
        wait('IF-02 the originator talks again', lambda: status('client-a').get('talking'))
        command('client-c', f'call implicit={SPEECH}')
        wait(
            'IF-02 an implicit request into a call with a talker gets Floor Taken',
            lambda: (
                status('client-c').get('call_state') == 'active'
                and status('client-c').get('implicit_floor_request') == 'accepted'
                and status('client-c').get('floor_owner') == ids['client-a']
                and status('client-c').get('floor_state') == 'NoPermission'
                and not status('client-c').get('talking')
            ),
            20,
        )
        assert holds(lambda: status('client-a').get('talking'), 2), 'the implicit request pre-empted the talker'
        checks.append('IF-02 the talker keeps the floor (TS 24.380 clause 6.3.5.2.2 NOTE 5)')

        # IF-03 a rejoin is never an implicit floor request (TS 24.380 clause 6.2.1 item 2).
        command('client-c', 'hangup')
        wait('IF-03 the third member left', lambda: status('client-c').get('call_state') == 'idle')
        # The client reports a refused command in its status (last_error), not in the command's exit code.
        command('client-c', 'rejoin implicit')
        wait(
            'IF-03 the client refuses rejoin implicit',
            lambda: status('client-c').get('last_error') == 'a rejoin is not an implicit floor request'
            and status('client-c').get('call_state') == 'idle',
        )
        command('client-c', 'rejoin')
        wait('IF-03 the plain rejoin joins the call', lambda: status('client-c').get('call_state') == 'active')
        command('client-a', 'release')
        hangup_all('IF-03 prearranged call released')

        # IF-04 emergency group call with an implicit floor request.
        before = received()
        command('client-a', f'call emergency implicit={SPEECH}')
        wait('IF-04 the emergency call accepts the implicit floor request', implicit('client-a', 'accepted'))
        wait('IF-04 the emergency originator is granted', talks('client-a', ['client-b'], before), 20)
        command('client-a', 'release')
        command('client-a', 'emergency off')
        hangup_all('IF-04 emergency call released')

        # IF-05 the client's own default: without the word no implicit floor request is offered.
        command('client-a', 'call')
        wait('IF-05 a plain call is active', lambda: status('client-a').get('call_state') == 'active')
        assert holds(lambda: status('client-a').get('floor_state') == 'NoPermission', 2), 'plain call got the floor'
        checks.append('IF-05 a plain call stays in U: has no permission')
        hangup_all('IF-05 plain call released')

        # IF-06 private call with an implicit floor request: granted once the callee answers.
        before = received()
        command('client-a', f"private {ids['client-b']} auto implicit={SPEECH}")
        wait('IF-06 the private call accepts the implicit floor request', implicit('client-a', 'accepted'), 20)
        wait('IF-06 the private caller is granted', talks('client-a', ['client-b'], before), 20)
        hangup_all('IF-06 private call released')

        # IF-07 ad hoc group call with an implicit floor request.
        before = received()
        command('client-a', f"adhoc {ids['client-b']} {ids['client-c']} implicit={SPEECH}")
        wait('IF-07 the ad hoc call accepts the implicit floor request', implicit('client-a', 'accepted'), 20)
        wait('IF-07 the ad hoc initiator is granted', talks('client-a', ['client-b', 'client-c'], before), 20)
        hangup_all('IF-07 ad hoc call released')

        # IF-08 chat: the creator's implicit request is accepted, a joiner's is not (TS 24.380 clause 14.3.5).
        for role in roles:
            command(role, 'group ' + chat['id'])
        wait(
            'IF-08 all clients on the chat group',
            on_group(chat['id']),
            30,
        )
        command('client-a', f'chat implicit={SPEECH}')
        wait('IF-08 the chat creator is accepted', implicit('client-a', 'accepted'))
        wait('IF-08 the chat creator is granted', lambda: status('client-a').get('talking'), 20)
        command('client-b', f'chat implicit={SPEECH}')
        wait('IF-08 the chat joiner is not accepted', implicit('client-b', 'not accepted'), 20)
        wait(
            'IF-08 the chat joiner gets Floor Taken and does not talk',
            lambda: status('client-b').get('floor_owner') == ids['client-a'] and not status('client-b').get('talking'),
        )
        hangup_all('IF-08 chat call released')
        for role in roles:
            command(role, 'group ' + prearranged)
        wait(
            'IF-08 all clients back on the prearranged group',
            on_group(prearranged),
            30,
        )

        # IF-09 no-implicit overrides the configured default.
        command('client-a', 'call no-implicit')
        wait('IF-09 a call with no-implicit is active', lambda: status('client-a').get('call_state') == 'active')
        assert holds(lambda: status('client-a').get('floor_state') == 'NoPermission', 2), 'no-implicit got the floor'
        checks.append('IF-09 no-implicit stays in U: has no permission')
        hangup_all('IF-09 call released')

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError, StopIteration) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/implicit-floor-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
