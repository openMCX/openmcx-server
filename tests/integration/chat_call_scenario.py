#!/usr/bin/env python3
"""Exercise on-network, on-demand chat group calls.

Run against a separate four-client fixture prepared with --chat. Check labels
carry the IDs used in tests/mcptt/CHAT_CALL_TEST.md.

The procedures under test are the chat group call procedures of TS 24.379 clause 10.1.2: the
client joining and leaving (clauses 10.1.2.2.1.1 and 10.1.2.2.3.1), the controlling MCPTT
function's session establishment and join (clause 10.1.2.4.1.1, with warnings 117, 118, 120,
122, 148 and 167) and its release (clause 6.3.8.1 item 2), implicit affiliation (clauses
9.2.2.3.6 to 9.2.2.3.8), and floor control per TS 24.380 clause 6.3.4.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
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
    """Run the chat group call checks CH-01 to CH-16 and write integration/chat-call-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-chat')
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
    inactivity = chat['call_policy']['inactivity_timeout_ms'] / 1000
    checks, observations = [], {}
    result = dict(scenario='on-demand-chat-group-call', passed=False, checks=checks, observations=observations)

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
    def chat_sessions():
        """The server's chat group call sessions."""
        return [call for call in sessions() if call.get('call_type') == 'chat']

    # ------------------------------------------------------------------------------
    def idle(wanted=roles):
        """Every wanted client idle and the server holding no session."""
        return all(status(client).get('call_state') == 'idle' for client in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def chat_active(wanted):
        """Exactly one chat session, on the chat group, whose participants are the wanted users, each
        active in a chat call."""
        current = chat_sessions()
        return (
            len(current) == 1
            and current[0].get('group_id') == chat['id']
            and set(current[0].get('participants', [])) == {ids[client] for client in wanted}
            and all(
                status(client).get('call_state') == 'active' and status(client).get('call_type') == 'chat'
                for client in wanted
            )
        )

    # ------------------------------------------------------------------------------
    def roster(wanted):
        """Each wanted user's conference roster lists exactly the wanted users."""
        expected = {ids[client] for client in wanted}
        return all(
            status(client).get('conference_active')
            and set(status(client).get('conference_participants', [])) == expected
            for client in wanted
        )

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning):
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

    # ------------------------------------------------------------------------------
    def select(role, group):
        """Select (and affiliate the role to) the group."""
        command(role, 'group ' + group)

    # ------------------------------------------------------------------------------
    def on_group(wanted, group):
        """A predicate: every wanted client affiliated to the group and on it."""
        return lambda: all(
            status(client).get('affiliated') and status(client).get('group_id') == group for client in wanted
        )

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(client).get('authorized') and status(client).get('affiliated') for client in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
        for role in roles:
            select(role, chat['id'])
        wait('all clients affiliated to the chat group', on_group(roles, chat['id']), 30)

        # CH-01 the first member creates the session and nobody is invited.
        command('client-a', 'chat')
        wait('CH-01 first joiner creates a chat session alone', lambda: chat_active(['client-a']))
        assert holds(
            lambda: all(status(client).get('call_state') == 'idle' for client in ['client-b', 'client-c', 'client-d']),
            2,
        ), 'server invited chat members'
        checks.append('CH-01 no member is invited by the server')
        session = chat_sessions()[0]['session_uri']

        # CH-02 a second member joins the same session; rosters follow.
        command('client-b', 'chat')
        wait(
            'CH-02 second member joins the same chat session',
            lambda: chat_active(['client-a', 'client-b']) and chat_sessions()[0]['session_uri'] == session,
        )
        wait('CH-02 conference rosters list both members', lambda: roster(['client-a', 'client-b']))

        # CH-03 floor contention and two-way speech.
        denials = status('client-b').get('floor_denials', 0)
        before_b = status('client-b').get('received_packets', 0)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait('CH-03 first talker granted', lambda: status('client-a').get('talking'))
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('CH-03 competing request denied', lambda: status('client-b').get('floor_denials', 0) > denials)
        wait(
            'CH-03 listener receives speech',
            lambda: status('client-b').get('received_packets', 0) >= before_b + 100,
            20,
        )
        wait(
            'CH-03 floor released',
            lambda: not status('client-a').get('talking') and not chat_sessions()[0].get('floor_owner'),
            20,
        )
        before_a = status('client-a').get('received_packets', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('CH-03 second member granted', lambda: status('client-b').get('talking'))
        wait(
            'CH-03 first member receives speech',
            lambda: status('client-a').get('received_packets', 0) >= before_a + 100,
            20,
        )
        wait('CH-03 second floor released', lambda: not status('client-b').get('talking'), 20)

        # CH-04 third member joins; the fourth exceeds max_participants.
        command('client-c', 'chat')
        wait('CH-04 third member joins', lambda: chat_active(['client-a', 'client-b', 'client-c']))
        wait('CH-04 rosters list three members', lambda: roster(['client-a', 'client-b', 'client-c']))
        command('client-d', 'chat')
        wait(
            'CH-04 join beyond max_participants rejected with 486 warning 122',
            rejected('client-d', 486, '122 too many participants'),
        )

        # CH-05 the creator leaving does not end a chat session; it can rejoin.
        command('client-a', 'hangup')
        wait(
            'CH-05 session survives the creator leaving',
            lambda: (
                status('client-a').get('call_state') == 'idle'
                and chat_active(['client-b', 'client-c'])
                and chat_sessions()[0]['session_uri'] == session
            ),
        )
        wait('CH-05 rosters drop the departed member', lambda: roster(['client-b', 'client-c']))
        command('client-a', 'chat')
        wait(
            'CH-05 creator rejoins the same session',
            lambda: chat_active(['client-a', 'client-b', 'client-c']) and chat_sessions()[0]['session_uri'] == session,
        )

        # CH-06 release once only one participant remains (TS 24.379 clause 6.3.8.1 item 2).
        command('client-b', 'hangup')
        wait('CH-06 two members remain after one leaves', lambda: chat_active(['client-a', 'client-c']))
        command('client-c', 'hangup')
        wait('CH-06 last remaining participant released by the server', idle)

        # CH-07 a lone joiner is released by the inactivity timer.
        command('client-d', 'chat')
        wait('CH-07 lone joiner active', lambda: chat_active(['client-d']))
        started = time.monotonic()
        wait('CH-07 lone joiner released by inactivity timer', idle, inactivity + 10)
        observations['lone_joiner_release_seconds'] = round(time.monotonic() - started, 2)
        assert observations['lone_joiner_release_seconds'] >= inactivity - 3, 'released before inactivity timer'

        # CH-08 call type must match the group type.
        command('client-a', 'call')
        wait(
            'CH-08 prearranged request on a chat group rejected with 403 warning 118',
            rejected('client-a', 403, '118 the group identity indicated in the request is a chat group'),
        )
        select('client-a', prearranged)
        wait('CH-08 client a affiliated to the prearranged group', on_group(['client-a'], prearranged))
        command('client-a', 'chat')
        wait(
            'CH-08 chat request on a prearranged group rejected with 403 warning 117',
            rejected('client-a', 403, '117 the group identity indicated in the request is a prearranged group'),
        )

        # CH-09 a chat session and a prearranged group call run side by side.
        select('client-b', prearranged)
        wait('CH-09 clients a and b on the prearranged group', on_group(['client-a', 'client-b'], prearranged))
        command('client-c', 'chat')
        command('client-d', 'chat')
        wait('CH-09 chat session between c and d', lambda: chat_active(['client-c', 'client-d']))
        command('client-a', 'call')
        wait(
            'CH-09 prearranged call coexists with the chat session',
            lambda: (
                len(sessions()) == 2
                and chat_active(['client-c', 'client-d'])
                and any(
                    call.get('call_type') == 'prearranged'
                    and set(call.get('participants', [])) == {ids['client-a'], ids['client-b']}
                    for call in sessions()
                )
            ),
        )
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'CH-09 independent floors granted concurrently',
            lambda: (
                len(sessions()) == 2
                and all(
                    call.get('floor_owner') == (ids['client-c'] if call.get('call_type') == 'chat' else ids['client-a'])
                    for call in sessions()
                )
            ),
        )
        wait('CH-09 both floors released', lambda: all(not call.get('floor_owner') for call in sessions()), 20)
        command('client-a', 'hangup')
        wait(
            'CH-09 ending the group call leaves the chat session',
            lambda: len(sessions()) == 1 and chat_active(['client-c', 'client-d']),
        )
        command('client-d', 'hangup')
        wait('CH-09 chat session released when one participant remains', idle)

        # ------------------------------------------------------------------------------
        # CH-14 emergency and imminent peril chat group calls (TS 24.379 clause
        # 10.1.2.4.1.1 steps 14 and 15): entering either state invites affiliated
        # members that have not joined, up to max_participants.
        def chat_priority(value):
            """The one chat session runs at the priority value ('emergency', 'imminent' or 'normal')."""
            current = chat_sessions()
            return len(current) == 1 and current[0].get('priority') == value

        for role in roles:
            if status(role).get('group_id') != chat['id']:
                select(role, chat['id'])
        wait('CH-14 all clients on the chat group', on_group(roles, chat['id']), 30)
        command('client-d', 'chat emergency')
        wait(
            'CH-14 unauthorised emergency chat request rejected with 403',
            rejected('client-d', 403, 'emergency call not authorized'),
        )
        wait('CH-14 rejected request leaves no session', idle)
        command('client-c', 'chat emergency')
        wait(
            'CH-14 emergency join invites affiliated members up to the participant limit',
            lambda: chat_active(['client-c', 'client-a', 'client-b']) and chat_priority('emergency'),
        )
        wait(
            'CH-14 invited members learn the emergency state',
            lambda: all(
                status(client).get('priority') == 'emergency' for client in ['client-a', 'client-b', 'client-c']
            ),
        )
        assert status('client-d').get('call_state') == 'idle', 'member beyond max_participants invited'
        checks.append('CH-14 no invitation beyond max_participants')
        command('client-c', 'emergency off')
        wait(
            'CH-14 emergency cancellation returns every participant to normal',
            lambda: (
                chat_priority('normal')
                and all(status(client).get('priority') == 'normal' for client in ['client-a', 'client-b', 'client-c'])
            ),
        )
        for role in ['client-a', 'client-b', 'client-c']:
            command(role, 'hangup')
        wait('CH-14 emergency chat session released', idle)
        command('client-a', 'chat')
        command('client-b', 'chat')
        wait(
            'CH-14 normal chat session with two members',
            lambda: chat_active(['client-a', 'client-b']) and chat_priority('normal'),
        )
        command('client-a', 'imminent on')
        wait(
            'CH-14 imminent peril upgrade invites the next affiliated member',
            lambda: chat_active(['client-a', 'client-b', 'client-c']) and chat_priority('imminent'),
        )
        wait(
            'CH-14 joined and invited members learn imminent peril',
            lambda: all(
                status(client).get('priority') == 'imminent' for client in ['client-a', 'client-b', 'client-c']
            ),
        )
        command('client-a', 'imminent off')
        wait('CH-14 imminent peril cancelled', lambda: chat_priority('normal'))
        for role in ['client-a', 'client-b', 'client-c']:
            command(role, 'hangup')
        wait('CH-14 imminent chat session released', idle)

        # CH-15 implicit affiliation (TS 24.379 clauses 9.2.2.3.6 to 9.2.2.3.8): an
        # unaffiliated member joining a chat group is affiliated by the server;
        # a normal call is still refused with 120, and a rejected join undoes it.
        command('client-d', 'deaffiliate')
        wait('CH-15 client d deaffiliated', lambda: not status('client-d').get('affiliated'))
        command('client-d', 'call force')
        wait(
            'CH-15 unaffiliated normal call rejected with 403 warning 120',
            rejected('client-d', 403, '120 user is not affiliated to this group'),
        )
        command('client-d', 'chat')
        wait('CH-15 unaffiliated chat join is accepted', lambda: chat_active(['client-d']))
        wait('CH-15 join implicitly affiliates the member', lambda: status('client-d').get('affiliated'))
        command('client-d', 'hangup')
        wait('CH-15 implicit-affiliation session released', idle, 30)
        command('client-d', 'deaffiliate')
        wait('CH-15 client d deaffiliated again', lambda: not status('client-d').get('affiliated'))
        for role in ['client-a', 'client-b', 'client-c']:
            command(role, 'chat')
        wait('CH-15 chat session at max_participants', lambda: chat_active(['client-a', 'client-b', 'client-c']))
        command('client-d', 'chat')
        wait(
            'CH-15 join beyond the limit rejected with 486/122', rejected('client-d', 486, '122 too many participants')
        )
        wait('CH-15 rejected join undoes the implicit affiliation', lambda: not status('client-d').get('affiliated'), 5)
        assert holds(lambda: not status('client-d').get('affiliated'), 1), 'rejected join affiliated client d again'
        for role in ['client-a', 'client-b', 'client-c']:
            command(role, 'hangup')
        wait('CH-15 full session released', idle)
        command('client-d', 'affiliate')
        wait('CH-15 client d reaffiliated', lambda: status('client-d').get('affiliated'))

        # CH-16 chat group variants (TS 24.379 clause 10.1.2.4.1.1 steps 4b, 4c and 12a).
        site = json.loads((args.compose.resolve().parent / 'generated/site.json').read_text())
        restricted = {
            entry['id'].rsplit('-', 1)[-1].split('@')[0]: entry['id']
            for entry in site['groups']
            if entry.get('preconfigured_use_only') or entry.get('regrouped')
        }
        for kind, warning in [
            ('preconfigured', '167 call is not allowed on the preconfigured group'),
            ('regrouped', '148 group is regrouped'),
        ]:
            select('client-c', restricted[kind])
            wait(f'CH-16 client c on the {kind} chat group', on_group(['client-c'], restricted[kind]), 30)
            command('client-c', 'chat')
            wait(
                f'CH-16 chat on a {kind} group rejected with 403 warning {warning[:3]}',
                rejected('client-c', 403, warning),
            )
        select('client-c', chat['id'])
        wait('CH-16 client c back on the chat group', on_group(roles, chat['id']), 30)
        for role in ['client-a', 'client-b', 'client-d']:
            command(role, 'chat')
        wait('CH-16 chat session at max_participants', lambda: chat_active(['client-a', 'client-b', 'client-d']))
        command('client-c', 'chat')
        wait(
            'CH-16 higher-priority joiner displaces one participant at the limit',
            lambda: (
                len(chat_sessions()) == 1
                and ids['client-c'] in chat_sessions()[0].get('participants', [])
                and len(chat_sessions()[0].get('participants', [])) == 3
                and sum(status(client).get('call_state') == 'idle' for client in ['client-a', 'client-b', 'client-d'])
                == 1
            ),
            20,
        )
        for role in roles:
            if status(role).get('call_state') != 'idle':
                command(role, 'hangup')
        wait('CH-16 session released', idle, 30)

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError, StopIteration) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/chat-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
