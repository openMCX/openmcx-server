#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise mcx-agent's voice (MCPTT) and video (MCVideo) plumbing for AI agents (openmcx-client agent/) against
the real servers: client-a runs as the agent (the mcx-agent daemon with mcx-client as its engine, voice and video
on, no MCData); in client-d's container, as third-party agents would, the hello-world voice bot (agent/examples/
voice-bot.py: it plays back every talk burst it hears) and the camera agent (video-feed.py: a generated test card
streamed to POST /video) reach it over MCP on HTTP with a bearer token. client-b and client-c are the users.

The client image must hold mcx-agent (the openmcx-agent image, FROM openmcx-client): without it the scenario reports
itself skipped. Run against a fixture prepared with --private-call --mcvideo (tools/prepare-prearranged-test.py):
client-b may make MCPTT and MCVideo private calls to anyone, client-c MCVideo private calls to anyone. The agent
makes no calls: users call it, or start group calls of its groups.

Checks:
  VA-01 the agent starts on client-a's identities with voice and video ready, MCData not enabled
  VA-02 client-b calls the agent (MCPTT private call): the agent answers at once
  VA-03 client-b talks: the voice bot hears the burst, with client-b as its talker, and answers it in the call;
        client-b hears the answer
  VA-04 a group call of client-c on the agent's group: the bot hears client-c and answers in the group call;
        client-b and client-c hear it
  VA-05 the agent makes no calls (no start_call or video_call tool); in a call client-b makes to it, it speaks a
        WAV of its outbox (CLI) and leaves the call
  VA-06 client-c calls the agent (MCVideo private call): the agent answers and transmits; client-c decodes the
        pictures the agent sent, and they come from the stream of pictures, not the test pattern
  VA-07 client-b starts an MCVideo group call of the agent's group: the agent joins and transmits; client-b and
        client-c decode its pictures
  VA-08 client-b calls the agent (MCVideo private call): the agent answers, transmits, and receives no video
        itself
  VA-09 the audit log records the voice and video tools that acted; MCData tools are refused (not_enabled)

Specifications: TS 24.379 V19.7.0 (Rel-19) clauses 10.1 (group calls), 11.1.1 (private calls); TS 24.380 V19.2.0
(Rel-19) clause 6.2.4 (floor participant); TS 24.281 V19.6.0 (Rel-19) clauses 9.2, 10.2; TS 24.581 V19.2.0
(Rel-19) clause 6.2.4 (transmission participant); TS 26.281 V19.0.0 (Rel-19) clause 4.1.1 (H.264).
"""

import argparse
import json
import secrets
import subprocess
import time
from pathlib import Path

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
AGENT_ROLE, BOT_ROLE = 'client-a', 'client-d'
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
SOCKET = '/run/mcx/agent.sock'
EXAMPLES = '/usr/local/share/mcx-agent/examples'
MCP_URL = 'http://client-a:8765/mcp'


# ------------------------------------------------------------------------------
# Run the scenario and write the results file.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-voice-video-agent')
    parser.add_argument('--agent-image', help='the image client-a runs the agent in (default: the client image)')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    compose_file = args.compose.resolve()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(compose_file)]
    generated = compose_file.parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    mcptt = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    mcvideo = {role: configs[role]['mcvideo']['user_id'] for role in ROLES}
    group = configs[AGENT_ROLE]['mcptt']['group_id']
    video_group = configs[AGENT_ROLE]['mcvideo']['group_id']
    checks, observations = [], {}
    result = dict(scenario='voice-video-agent', passed=False, checks=checks, observations=observations)
    work = args.artifacts / 'agent'

    # ------------------------------------------------------------------------------
    # The status.json the container of a role writes, or {} while it is missing or partly written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def snapshot():
        return {role: status(role) for role in ROLES}

    # ------------------------------------------------------------------------------
    # Poll a predicate until it holds (the check passes) or the timeout expires (the scenario fails).
    def wait(label, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(detail if detail is not None else snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    def exec_in(role, command, timeout=60):
        return subprocess.run(cli + ['exec', '-T', role] + command, capture_output=True, text=True, timeout=timeout)

    # ------------------------------------------------------------------------------
    # One mcx-client command in the container of a user.
    def command(role, text):
        run = exec_in(role, ['mcx-client', '--config', f'/config/{role}.json', '--command', text], timeout=15)
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # One mcx-agent tool through the CLI in the agent's container: (exit status, JSON result).
    def agent(tool, **arguments):
        line = ['mcx-agent', '--socket', SOCKET, tool]
        for name, value in arguments.items():
            line += [f'--{name}', str(value).lower() if isinstance(value, bool) else str(value)]
        run = exec_in(AGENT_ROLE, line, timeout=90)
        try:
            return run.returncode, json.loads(run.stdout)
        except json.JSONDecodeError:
            return run.returncode, {'error': run.stderr.strip() or run.stdout.strip()}

    def log(name):
        path = work / name
        return path.read_text(errors='replace') if path.exists() else ''

    # ------------------------------------------------------------------------------
    # Start an example agent in the bot's container, in the background, its output in <work>/<log>.
    def start_bot(script, log_name, *options):
        line = ' '.join(
            [f'nohup python3 {EXAMPLES}/{script} --mcp-url {MCP_URL} --token-file /artifacts/agent/token']
            + list(options)
            + [f'> /artifacts/agent/{log_name} 2>&1 &']
        )
        run = exec_in(BOT_ROLE, ['sh', '-c', line])
        if run.returncode:
            raise RuntimeError(f'{script} did not start: {run.stderr}')

    def packets(role):
        return status(role).get('received_packets', 0)

    # ------------------------------------------------------------------------------
    # Pictures the receiver decoded, and how many equal the agent's for the same SSRC and timestamp.
    def matching(receiver):
        sent = status(AGENT_ROLE).get('mcvideo_sent_frames') or {}
        received = status(receiver).get('mcvideo_received_frames') or {}
        return len(received), sum(1 for key in received if key in sent and sent[key] == received[key])

    def idle_all():
        for role in ('client-b', 'client-c', 'client-d'):
            if status(role).get('call_state') not in (None, 'idle'):
                command(role, 'hangup')
        wait('the MCPTT calls ended', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES), 30)

    try:
        wait(
            'four clients authorised for MCPTT and MCVideo and affiliated',
            lambda: all(
                status(role).get('authorized')
                and status(role).get('affiliated')
                and status(role).get('mcvideo_affiliated')
                for role in ROLES
            ),
            90,
        )
        if exec_in(AGENT_ROLE, ['sh', '-c', 'command -v mcx-agent']).returncode:
            result.update(passed=True, skipped='the client image has no mcx-agent (use the openmcx-agent image)')
            print(result['skipped'], flush=True)
            raise StopIteration

        # Client-a becomes the agent: the same container, configuration and identities, with the mcx-agent daemon
        # as its entry point running mcx-client with the lab's arguments.
        service = json.loads(compose_file.read_text())['services'][AGENT_ROLE]
        engine_args = [a for a in service.get('command', []) if a not in ('--config', f'/config/{AGENT_ROLE}.json')]
        work.mkdir(parents=True, exist_ok=True)
        work.chmod(0o777)
        token = secrets.token_hex(24)
        (work / 'token').write_text(token + '\n')
        # A voice and video agent: the engine configuration without its MCData part.
        engine = {key: value for key, value in configs[AGENT_ROLE].items() if key != 'mcdata'}
        (work / 'client.json').write_text(json.dumps(engine, indent=2) + '\n')
        (work / 'agent.json').write_text(
            json.dumps(
                dict(
                    engine=dict(config='/artifacts/agent/client.json', args=engine_args),
                    socket=SOCKET,
                    data_dir='/artifacts/agent/data',
                    voice=dict(enabled=True, max_speech_s=30),
                    video=dict(enabled=True),
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

        # VA-01 the daemon and its engine, voice and video ready.
        def services():
            return agent('status')[1].get('services') or {}

        wait(
            'VA-01 the agent has voice and video ready',
            lambda: services().get('mcptt', {}).get('ready') and services().get('mcvideo', {}).get('ready'),
            60,
        )
        state = agent('status')[1]
        observations['agent_status'] = state
        check('VA-01 the agent runs on client-a\'s MCPTT ID', state['services']['mcptt']['id'] == mcptt[AGENT_ROLE])
        check('VA-01 and its MCVideo ID', state['services']['mcvideo']['id'] == mcvideo[AGENT_ROLE])
        check('VA-01 MCData is not enabled', state['services']['mcdata']['enabled'] is False)
        wait(
            'VA-01 the agent is affiliated (MCPTT and MCVideo)',
            lambda: status(AGENT_ROLE).get('affiliated') and status(AGENT_ROLE).get('mcvideo_affiliated'),
            30,
        )
        start_bot('voice-bot.py', 'voice-bot.log')
        wait('VA-01 the voice bot is ready', lambda: 'voice bot ready' in log('voice-bot.log'), 30)

        # VA-02 client-b calls the agent.
        command('client-b', f"private {mcptt[AGENT_ROLE]} auto")
        wait(
            'VA-02 the agent answers client-b\'s private call',
            lambda: (lambda st: st.get('state') == 'active' and st.get('peer') == mcptt['client-b'])(
                agent('call_status')[1]
            ),
        )
        wait('VA-02 client-b is in the call', lambda: status('client-b').get('call_state') == 'active')

        # VA-03 client-b talks; the bot plays it back.
        before = packets('client-b')
        command('client-b', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'VA-03 the bot hears client-b',
            lambda: f"heard {mcptt['client-b']} in a private call" in log('voice-bot.log'),
            40,
        )
        code, got = agent('wait_speech', since=0, audio='none', timeout_s=5)
        observations['first_speech'] = got
        item = got.get('item') or {}
        check(
            'VA-03 the burst names client-b and the private call',
            item.get('from') == mcptt['client-b']
            and item.get('call_type') == 'private'
            and item.get('peer') == mcptt['client-b'],
            got,
        )
        check('VA-03 the burst holds the speech (over 3 s)', item.get('duration_ms', 0) > 3000, got)
        wait(
            'VA-03 the bot spoke its answer',
            lambda: 'spoke to ' + mcptt['client-b'] + ': spoken' in log('voice-bot.log'),
            60,
        )
        heard = packets('client-b') - before
        observations['client_b_heard_packets'] = heard
        check('VA-03 client-b heard the answer (over 3 s of speech)', heard > 150, heard)
        command('client-b', 'hangup')
        wait('VA-03 the call ends for the agent', lambda: agent('call_status')[1].get('state') == 'idle')

        # VA-04 a group call: client-c talks to the group, the agent answers everyone.
        command('client-c', 'call')
        wait(
            'VA-04 the agent joins client-c\'s group call',
            lambda: (lambda st: st.get('state') == 'active' and st.get('group') == group)(agent('call_status')[1]),
            30,
        )
        wait(
            'VA-04 client-b and client-c are in it',
            lambda: all(status(role).get('call_state') == 'active' for role in ('client-b', 'client-c')),
        )
        before = {role: packets(role) for role in ('client-b', 'client-c')}
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'VA-04 the bot hears client-c in the group call',
            lambda: f"heard {mcptt['client-c']} in a prearranged call ({group})" in log('voice-bot.log'),
            40,
        )
        wait('VA-04 the bot answers in the group call', lambda: f'spoke to {group}: spoken' in log('voice-bot.log'), 60)
        heard = {role: packets(role) - before[role] for role in before}
        observations['group_heard_packets'] = heard
        # client-b also heard client-c's own burst (about 5 s): the answer adds more than 150 packets to it.
        check('VA-04 client-c heard the agent', heard['client-c'] > 150, heard)
        check('VA-04 client-b heard client-c and the agent', heard['client-b'] > 300, heard)
        idle_all()
        if agent('call_status')[1].get('state') != 'idle':
            agent('hangup')
        wait('VA-04 the agent left the group call', lambda: agent('call_status')[1].get('state') == 'idle', 30)

        # VA-05 the agent makes no calls; in a call client-b makes to it, it speaks a file of its outbox (CLI).
        for tool in ('start_call', 'video_call'):
            code, refused = agent(tool, kind='private', to=mcptt['client-b'])
            check(
                f'VA-05 the agent has no {tool} tool', code == 2 and 'unknown tool' in refused.get('error', ''), refused
            )
        exec_in(
            AGENT_ROLE,
            [
                'sh',
                '-c',
                'mkdir -p /artifacts/agent/data/outbox && '
                'cp /artifacts/speech/alpha.wav /artifacts/agent/data/outbox/alpha.wav',
            ],
        )
        log_before = log('voice-bot.log')
        command('client-b', f"private {mcptt[AGENT_ROLE]} auto")
        wait('VA-05 the agent answers client-b again', lambda: agent('call_status')[1].get('state') == 'active')
        wait('VA-05 client-b is in the call', lambda: status('client-b').get('call_state') == 'active')
        before = packets('client-b')
        code, said = agent('speak', file='alpha.wav', timeout_s=20)
        observations['speak_file'] = said
        check('VA-05 the agent spoke the file', code == 0 and said.get('outcome') == 'spoken', said)
        wait('VA-05 client-b heard it', lambda: packets('client-b') - before > 150)
        check('VA-05 the bot heard nothing meanwhile', log('voice-bot.log') == log_before, log('voice-bot.log'))
        code, ended = agent('hangup')
        check('VA-05 the agent leaves the call', code == 0 and ended.get('state') == 'idle', ended)
        wait('VA-05 client-b\'s call ended', lambda: status('client-b').get('call_state') == 'idle')

        # The camera agent streams its pictures and transmits in every MCVideo call it is in.
        start_bot('video-feed.py', 'video-feed.log', '--seconds 180')
        wait('the camera agent is ready', lambda: 'video feed ready' in log('video-feed.log'), 30)

        # VA-06 client-c calls the agent with video.
        command('client-c', f"mcvideo-private {mcvideo[AGENT_ROLE]} auto")
        wait(
            'VA-06 the agent answers client-c\'s MCVideo call',
            lambda: (
                status(AGENT_ROLE).get('mcvideo_call_state') == 'active'
                and status(AGENT_ROLE).get('mcvideo_peer') == mcvideo['client-c']
            ),
            30,
        )
        wait('VA-06 the agent transmits in it', lambda: status(AGENT_ROLE).get('mcvideo_transmitting') is True, 30)
        wait('VA-06 client-c decodes the agent\'s pictures', lambda: matching('client-c')[1] >= 30, 30)
        observations['private_matching'] = matching('client-c')
        live = status(AGENT_ROLE).get('mcvideo_live') or {}
        observations['agent_live'] = live
        check(
            'VA-06 the pictures come from the stream (the engine took them)',
            live.get('pictures', 0) >= 30 and (live.get('age_ms') or 10**6) < 1000,
            live,
        )
        command('client-c', 'mcvideo-hangup')
        wait('VA-06 the call ended', lambda: status(AGENT_ROLE).get('mcvideo_call_state') == 'idle', 20)

        # VA-07 client-b starts an MCVideo group call of the agent's group: the agent joins and shows its video.
        command('client-b', 'mcvideo-call')
        wait(
            'VA-07 the agent joins client-b\'s group call',
            lambda: (
                status(AGENT_ROLE).get('mcvideo_call_state') == 'active'
                and status(AGENT_ROLE).get('mcvideo_group') == video_group
            ),
            30,
        )
        wait('VA-07 the agent transmits in it', lambda: status(AGENT_ROLE).get('mcvideo_transmitting') is True, 30)
        wait(
            'VA-07 client-b and client-c decode the agent\'s pictures',
            lambda: matching('client-b')[1] >= 30 and matching('client-c')[1] >= 30,
            30,
        )
        observations['group_matching'] = {role: matching(role) for role in ('client-b', 'client-c')}
        for role in ROLES[1:]:
            if status(role).get('mcvideo_call_state') not in (None, 'idle'):
                command(role, 'mcvideo-hangup')
        if status(AGENT_ROLE).get('mcvideo_call_state') not in (None, 'idle'):
            agent('video_hangup')
        wait(
            'VA-07 the call ended', lambda: all(status(role).get('mcvideo_call_state') == 'idle' for role in ROLES), 30
        )

        # VA-08 client-b calls the agent with video; the agent receives no video itself.
        command('client-b', f"mcvideo-private {mcvideo[AGENT_ROLE]} auto")
        wait(
            'VA-08 the agent answers client-b\'s MCVideo call',
            lambda: (
                status(AGENT_ROLE).get('mcvideo_call_state') == 'active'
                and status(AGENT_ROLE).get('mcvideo_peer') == mcvideo['client-b']
            ),
            30,
        )
        wait('VA-08 the agent transmits in it', lambda: status(AGENT_ROLE).get('mcvideo_transmitting') is True, 30)
        wait('VA-08 client-b decodes the agent\'s pictures', lambda: matching('client-b')[1] >= 30, 30)
        check(
            'VA-08 the agent decodes no video itself',
            holds(lambda: status(AGENT_ROLE).get('mcvideo_frames_received', 0) == 0, 1),
            status(AGENT_ROLE).get('mcvideo_frames_received'),
        )
        command('client-b', 'mcvideo-hangup')
        wait('VA-08 the call ended', lambda: status(AGENT_ROLE).get('mcvideo_call_state') == 'idle', 20)

        # VA-09 the audit log and the services left out.
        audit = exec_in(AGENT_ROLE, ['cat', '/artifacts/agent/data/audit.jsonl']).stdout
        tools = [json.loads(line)['tool'] for line in audit.splitlines() if line.strip()]
        observations['audit_tools'] = sorted(set(tools))
        check(
            'VA-09 the audit log records speech, leaving calls and video',
            {'speak', 'hangup', 'video_transmit'} <= set(tools),
            sorted(set(tools)),
        )
        check(
            'VA-09 the audit log leaves the audio out',
            all('UklGR' not in line for line in audit.splitlines()),  # base64 of "RIFF"
        )
        code, refused = agent('send_message', to=mcptt['client-b'], text='hello')
        check(
            'VA-09 MCData tools are refused (not_enabled)', code == 3 and refused.get('code') == 'not_enabled', refused
        )
        result['passed'] = True
    except StopIteration:
        pass
    except (AssertionError, KeyError, IndexError, TypeError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    for name in ('voice-bot.log', 'video-feed.log'):
        if (work / name).exists():
            observations[name] = log(name)[-3000:]
    result['status'] = snapshot()
    output = args.artifacts / 'integration/voice-video-agent-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
