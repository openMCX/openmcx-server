#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise mcx-agent, the MCData plumbing for AI agents (openmcx-client agent/), against the real servers: client-a
runs as the agent (the mcx-agent daemon with mcx-client as its engine) holding the functional alias front-desk; the
hello-world echo bot of agent/examples runs in client-b's container, as a third-party agent would, and reaches it
over MCP on HTTP with a bearer token; client-c is the field user who chats with it.

The client image must hold mcx-agent (the openmcx-agent image, FROM openmcx-client): without it the scenario reports
itself skipped. Run against a fixture prepared with --private-call --mcdata (add_mcdata_policy in
tools/prepare-prearranged-test.py): client-c may send to anyone and to front-desk, client-a may send to client-c, and
client-b may take front-desk over.

Checks:
  AG-01 the agent starts on client-a's identity and activates front-desk
  AG-02 a two-line SDS to the alias is answered by the echo bot, in the sender's conversation, presenting the
        alias, line breaks kept, asking for delivery and read reports; the agent learns the echo was delivered
  AG-03 the sender gets the read report the bot's mark_read sends
  AG-04 an SDS to the agent's MCData ID is answered too
  AG-05 a group SDS does not reach the agent
  AG-06 the agent may send only to users who wrote to it (allow_senders_hours): others are refused (not_allowed)
  AG-07 a file from the agent's outbox reaches the field user
  AG-08 a file from the field user is accepted and acknowledged by the bot
  AG-09 front-desk taken over: the agent refuses to send; given back, the agent activates it again
  AG-10 the MCP server lists the tools and answers a call
  AG-11 the audit log records the tool calls that acted on the network
  AG-12 MCP over HTTP from another container: refused without the token, answering with it

Specifications: TS 24.282 V19.7.0 (Rel-19) clauses 9.2.2 (SDS), 9.2.1.3 and 12.2 (disposition notifications),
10.2.4 (FD over HTTP), 22 (functional aliases).
"""

import argparse
import json
import secrets
import subprocess
import time
from pathlib import Path

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
READ, DELIVERED_AND_READ = 3, 4
AGENT_ROLE, USER_ROLE = 'client-a', 'client-c'
SOCKET = '/run/mcx/agent.sock'
BOT = '/usr/local/share/mcx-agent/examples/echo-bot.py'
BOT_ROLE = 'client-b'  # the third-party agent's container
MCP_URL = 'http://client-a:8765/mcp'


# ------------------------------------------------------------------------------
# Run the scenario and write the results file.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcdata-agent')
    parser.add_argument('--agent-image', help='the image client-a runs the agent in (default: the client image)')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    compose_file = args.compose.resolve()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(compose_file)]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = compose_file.parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    group = configs['client-a']['mcdata']['group_id']
    domain = group.split('@', 1)[1]
    front_desk = f'sip:front-desk.fa@{domain}'
    agent_id, user_id = ids[AGENT_ROLE], ids[USER_ROLE]
    checks, observations = [], {}
    result = dict(scenario='mcdata-agent', passed=False, checks=checks, observations=observations)

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
    # Poll a predicate until it holds (the check passes) or the timeout expires (the scenario fails).
    def wait(label, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.1)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    # Record a passed check, or fail the scenario with a snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    # Run a command in the container of a role; its completed process.
    def exec_in(role, command, stdin=None, timeout=30):
        return subprocess.run(
            cli + ['exec', '-T', role] + command, input=stdin, capture_output=True, text=True, timeout=timeout
        )

    # ------------------------------------------------------------------------------
    # Run one mcx-client command in the container of a role.
    def command(role, text):
        run = exec_in(role, ['mcx-client', '--config', f'/config/{role}.json', '--command', text], timeout=15)
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Call one mcx-agent tool through the CLI in the agent's container: (exit status, JSON result).
    def agent(tool, **arguments):
        line = ['mcx-agent', '--socket', SOCKET, tool]
        for name, value in arguments.items():
            line += [f'--{name}', str(value).lower() if isinstance(value, bool) else str(value)]
        run = exec_in(AGENT_ROLE, line, timeout=90)
        try:
            return run.returncode, json.loads(run.stdout)
        except json.JSONDecodeError:
            return run.returncode, {'error': run.stderr.strip() or run.stdout.strip()}

    # ------------------------------------------------------------------------------
    # The SDS messages a client received that carry this text.
    def inbox(role, text):
        return [
            message
            for message in status(role).get('mcdata_inbox') or []
            if any(payload.get('text') == text for payload in message.get('payloads', []))
        ]

    # ------------------------------------------------------------------------------
    # Send an SDS with a client command and return the record of the request the server accepted (202): for an
    # SDS to an alias, the follow-up request to the selected user (TS 24.282 clause 9.2.2.2.1).
    def send(role, text, label):
        before = [record['message_id'] for record in status(role).get('mcdata_sent') or []]
        command(role, text)
        wait(
            label,
            lambda: any(
                record['message_id'] not in before and record.get('status') == 202
                for record in status(role).get('mcdata_sent') or []
            ),
        )
        return next(
            record
            for record in status(role).get('mcdata_sent') or []
            if record['message_id'] not in before and record.get('status') == 202
        )

    # ------------------------------------------------------------------------------
    # The functional aliases the server holds, with the users that activated them.
    def aliases():
        return status('mcdata-server').get('functional_aliases') or {}

    # ------------------------------------------------------------------------------
    # A text that no earlier message carried.
    def unique(label):
        return f'{label}-{secrets.token_hex(4)}'

    def echo(text):
        return f'Hello {user_id}, you said: {text}'

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(role).get('mcdata_authorized') and status(role).get('mcdata_affiliated') for role in roles
            ),
            90,
        )
        if exec_in(AGENT_ROLE, ['sh', '-c', 'command -v mcx-agent']).returncode:
            result.update(passed=True, skipped='the client image has no mcx-agent (use the openmcx-agent image)')
            print(result['skipped'], flush=True)
            raise StopIteration

        # Client-a becomes the agent: the same container, configuration and identity, with the mcx-agent daemon as
        # its entry point; the daemon runs mcx-client as its engine with the lab's arguments (--disable-tls).
        service = json.loads(compose_file.read_text())['services'][AGENT_ROLE]
        engine_args = [
            argument
            for argument in service.get('command', [])
            if argument not in ('--config', f'/config/{AGENT_ROLE}.json')
        ]
        work = args.artifacts / 'agent'
        work.mkdir(parents=True, exist_ok=True)
        work.chmod(0o777)
        token = secrets.token_hex(24)
        (work / 'token').write_text(token + '\n')
        (work / 'agent.json').write_text(
            json.dumps(
                dict(
                    engine=dict(config=f'/config/{AGENT_ROLE}.json', args=engine_args),
                    socket=SOCKET,
                    data_dir='/artifacts/agent/data',
                    alias=front_desk,
                    alias_retry_s=3,
                    recipients=[],
                    allow_senders_hours=1,
                    rate_per_minute=30,
                    mcp_http=dict(listen='0.0.0.0:8765', token_file='/artifacts/agent/token'),
                ),
                indent=2,
            )
            + '\n'
        )
        override = dict(
            entrypoint=['/usr/local/bin/mcx-agent'],
            command=['daemon', '--config', '/artifacts/agent/agent.json'],
            environment=dict(MCX_AGENT_SOCKET=SOCKET),
        )
        if args.agent_image:
            override['image'] = args.agent_image
        override_file = compose_file.parent / 'agent-compose.json'
        override_file.write_text(json.dumps(dict(services={AGENT_ROLE: override}), indent=2) + '\n')
        up = subprocess.run(
            cli + ['-f', str(override_file), 'up', '-d', '--no-deps', '--wait', AGENT_ROLE],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if up.returncode:
            raise RuntimeError(f'the agent did not start: {up.stderr.strip()[-2000:]}')

        # AG-01 the daemon, its engine and the alias.
        wait(
            'AG-01 the agent can send as front-desk',
            lambda: (lambda state: state.get('can_send') is True)(agent('status')[1]),
            60,
        )
        code, state = agent('status')
        observations['agent_status'] = state
        check('AG-01 the agent runs on client-a\'s MCData ID', state['mcdata_id'] == agent_id)
        check(
            'AG-01 the agent holds front-desk',
            state['alias'] == dict(id=front_desk, state='active', active=True, required=True),
        )
        wait('AG-01 the server lists client-a on front-desk', lambda: aliases().get(front_desk) == [agent_id])
        bot = exec_in(
            BOT_ROLE,
            [
                'sh',
                '-c',
                f'nohup python3 {BOT} --mcp-url {MCP_URL} --token-file /artifacts/agent/token '
                '--cursor /artifacts/agent/echo.cursor > /artifacts/agent/echo-bot.log 2>&1 &',
            ],
        )
        if bot.returncode:
            raise RuntimeError(f'the echo bot did not start: {bot.stderr}')
        wait(
            'AG-01 the echo bot is ready',
            lambda: (
                'echo bot ready' in (work / 'echo-bot.log').read_text(errors='replace')
                if (work / 'echo-bot.log').exists()
                else False
            ),
        )

        # AG-02 the field user writes two lines to the alias (the escaped option of mcx-client); the server selects
        # client-a, and the bot answers.
        first = unique('to-alias')
        text = f'{first}\nsecond line'
        sent = send(
            USER_ROLE,
            f'sds-fa both escaped {front_desk} {first}\\nsecond line',
            'AG-02 the SDS to front-desk is accepted (202)',
        )
        wait('AG-02 the field user receives the echo', lambda: bool(inbox(USER_ROLE, echo(text))))
        answer = inbox(USER_ROLE, echo(text))[0]
        observations['alias_answer'] = answer
        check('AG-02 the echo comes from the agent', answer['from'] == agent_id)
        check('AG-02 the echo presents front-desk', answer['functional_alias'] == front_desk)
        check('AG-02 the echo is in the sender\'s conversation', answer['conversation_id'] == sent['conversation_id'])
        check('AG-02 the echo replies to the message (InReplyTo)', answer['in_reply_to'] == sent['message_id'])
        check('AG-02 the echo asks for delivery and read reports', answer['disposition'] == 3)
        wait(
            'AG-02 the agent learns the echo was delivered',
            lambda: (
                agent('message_status', message_id=answer['message_id'])[1].get('message', {}).get('delivered') is True
            ),
        )
        code, received = agent('inbox', kind='message')
        item = next((i for i in received['items'] if i['text'] == text), None)
        check('AG-02 the agent\'s inbox shows the message to front-desk', item and item['to_alias'] == front_desk)

        # AG-03 the bot marked it read: the read report reaches the sender.
        wait(
            'AG-03 the field user gets the read report',
            lambda: any(
                notification.get('message_id') == sent['message_id']
                and notification.get('type') in (READ, DELIVERED_AND_READ)
                for notification in status(USER_ROLE).get('mcdata_notifications') or []
            ),
        )

        # AG-04 the field user writes to the agent's own MCData ID.
        text = unique('direct')
        send(USER_ROLE, f'sds {agent_id} {text}', 'AG-04 the SDS to the agent is accepted (202)')
        wait('AG-04 the field user receives the echo', lambda: bool(inbox(USER_ROLE, echo(text))))

        # AG-05 a group SDS reaches client-a's engine but not the agent.
        text = unique('group')
        send('client-b', f'sds-group {group} {text}', 'AG-05 client-b sends a group SDS (202)')
        wait('AG-05 client-a\'s engine receives the group SDS', lambda: bool(inbox(AGENT_ROLE, text)))
        code, received = agent('inbox', kind='any', limit=200)
        check('AG-05 the group SDS is not in the agent\'s inbox', all(i.get('text') != text for i in received['items']))
        check(
            'AG-05 nobody is answered for it',
            holds(
                lambda: (
                    not any(
                        text in payload.get('text', '')
                        for role in ('client-b', 'client-c')
                        for message in status(role).get('mcdata_inbox') or []
                        for payload in message.get('payloads', [])
                        if message.get('from') == agent_id
                    )
                ),
                3,
            ),
        )

        # AG-06 no recipient list: the agent may send to client-c, who wrote to it, and not to client-b.
        code, refused = agent('send_message', to=ids['client-b'], text='not allowed')
        check(
            'AG-06 a user who never wrote to the agent is refused (not_allowed, exit status 3)',
            code == 3 and refused.get('code') == 'not_allowed',
        )

        # AG-07 a file from the agent's outbox.
        made = exec_in(
            AGENT_ROLE,
            [
                'sh',
                '-c',
                'mkdir -p /artifacts/agent/data/outbox && '
                'printf "Shift report: all units at their posts, gate 2 closed for works.\\n%.0s" 1 2 '
                '> /artifacts/agent/data/outbox/report.txt',
            ],
        )
        if made.returncode:
            raise RuntimeError(made.stderr)
        code, sent_file = agent('send_file', to=user_id, file='report.txt')
        check('AG-07 the agent offers the file', code == 0 and sent_file['message']['kind'] == 'file')
        observations['file_sent'] = sent_file
        wait(
            'AG-07 the field user receives the file offer',
            lambda: any(
                entry.get('from') == agent_id and entry.get('name') == 'report.txt'
                for entry in status(USER_ROLE).get('mcdata_files') or []
            ),
        )

        # AG-08 a file from the field user: the bot accepts it and says so.
        upload = args.artifacts / 'agent-test'
        upload.mkdir(parents=True, exist_ok=True)
        (upload / 'photo-note.txt').write_text('Broken fence at the north gate, photo to follow.\n' * 2)
        command(USER_ROLE, f'fd-send {agent_id} /artifacts/agent-test/photo-note.txt')
        wait(
            'AG-08 the bot acknowledges the file',
            lambda: any(
                'I got your file photo-note.txt' in payload.get('text', '')
                for message in status(USER_ROLE).get('mcdata_inbox') or []
                for payload in message.get('payloads', [])
            ),
            30,
        )
        code, received = agent('inbox', kind='file')
        item = next((i for i in received['items'] if i['file_name'] == 'photo-note.txt'), {})
        check('AG-08 the agent downloaded the file', item.get('file_state') == 'downloaded' and item.get('path'))

        # AG-09 client-b takes front-desk over; when it gives it back, the agent activates it again.
        command('client-b', f'mcdata-fa takeover {front_desk}')
        wait('AG-09 client-b holds front-desk', lambda: aliases().get(front_desk) == [ids['client-b']])
        wait('AG-09 the agent no longer sends', lambda: agent('status')[1].get('can_send') is False)
        code, refused = agent('send_message', to=user_id, text='without my alias')
        check(
            'AG-09 a message without the alias is refused (alias_inactive, exit status 3)',
            code == 3 and refused.get('code') == 'alias_inactive',
        )
        observations['alias_lost'] = agent('status')[1]
        command('client-b', f'mcdata-fa deactivate {front_desk}')
        wait('AG-09 the agent activates front-desk again', lambda: aliases().get(front_desk) == [agent_id], 30)
        wait('AG-09 the agent sends again', lambda: agent('status')[1].get('can_send') is True)

        # AG-10 the MCP server, over stdio.
        requests = (
            '\n'.join(
                json.dumps(message)
                for message in [
                    dict(
                        jsonrpc='2.0',
                        id=1,
                        method='initialize',
                        params=dict(
                            protocolVersion='2025-06-18', capabilities={}, clientInfo=dict(name='lab', version='1')
                        ),
                    ),
                    dict(jsonrpc='2.0', method='notifications/initialized'),
                    dict(jsonrpc='2.0', id=2, method='tools/list'),
                    dict(jsonrpc='2.0', id=3, method='tools/call', params=dict(name='status', arguments={})),
                ]
            )
            + '\n'
        )
        mcp = exec_in(AGENT_ROLE, ['mcx-agent', 'mcp', '--socket', SOCKET], stdin=requests)
        replies = {reply.get('id'): reply for reply in map(json.loads, mcp.stdout.splitlines())}
        names = sorted(tool['name'] for tool in replies.get(2, {}).get('result', {}).get('tools', []))
        observations['mcp_tools'] = names
        check(
            'AG-10 the MCP server names itself',
            replies.get(1, {}).get('result', {}).get('serverInfo', {}).get('name') == 'mcx-agent',
        )
        check('AG-10 the MCP server lists the tools', 'send_message' in names and 'wait_message' in names)
        check(
            'AG-10 an MCP tool call answers',
            replies.get(3, {}).get('result', {}).get('structuredContent', {}).get('mcdata_id') == agent_id,
        )

        # AG-11 the audit log.
        audit = exec_in(AGENT_ROLE, ['cat', '/artifacts/agent/data/audit.jsonl']).stdout
        tools = [json.loads(line)['tool'] for line in audit.splitlines() if line.strip()]
        observations['audit_tools'] = tools
        check(
            'AG-11 the audit log records sends, replies, reads and files',
            {'send_message', 'reply_message', 'mark_read', 'send_file', 'respond_file'} <= set(tools),
        )
        # AG-12 MCP over HTTP, from client-c's container: what an agent in another container sees.
        probe = (
            'import json, sys, urllib.request, urllib.error\n'
            'url, token = sys.argv[1], sys.argv[2]\n'
            'def post(body, auth=True):\n'
            '    headers = {"Content-Type": "application/json",\n'
            '               "Accept": "application/json, text/event-stream"}\n'
            '    if auth: headers["Authorization"] = "Bearer " + token\n'
            '    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")\n'
            '    try:\n'
            '        with urllib.request.urlopen(req, timeout=20) as r:\n'
            '            return r.status, json.loads(r.read() or b"null")\n'
            '    except urllib.error.HTTPError as e: return e.code, None\n'
            'init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",\n'
            '        "params": {"protocolVersion": "2025-06-18"}}\n'
            'status = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",\n'
            '          "params": {"name": "status", "arguments": {}}}\n'
            'print(json.dumps({"no_token": post(init, False)[0], "init": post(init), "status": post(status)}))\n'
        )
        run = exec_in(USER_ROLE, ['python3', '-c', probe, MCP_URL, token])
        seen = json.loads(run.stdout or '{}')
        observations['mcp_http'] = seen
        check('AG-12 MCP over HTTP refuses a request without the token (401)', seen.get('no_token') == 401)
        check(
            'AG-12 MCP over HTTP initializes with the token',
            seen['init'][0] == 200 and seen['init'][1]['result']['serverInfo']['name'] == 'mcx-agent',
        )
        check(
            'AG-12 an MCP tool call over HTTP answers',
            seen['status'][1]['result']['structuredContent']['mcdata_id'] == agent_id,
        )
        result['passed'] = True
    except StopIteration:
        pass
    except (AssertionError, KeyError, IndexError, TypeError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    for name in ('echo-bot.log',):
        path = args.artifacts / 'agent' / name
        if path.exists():
            observations[name] = path.read_text(errors='replace')[-3000:]
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-agent-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
