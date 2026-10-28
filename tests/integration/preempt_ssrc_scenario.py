#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A join refused for its floor control SSRC preempts nobody.

At the participant limit of a chat group call, a joiner of higher <user-priority> displaces the lowest-priority
participant (TS 24.379 clause 10.1.2.4.1.1 step 12a). The SSRC the joiner allocates in its SDP ("mc_floor_ssrc", TS
24.380 clause 4.3.3.1) is checked first: under the joiner's CSK the server refuses one that already carried floor
control under it (McServer::offered_floor_ssrc_refused, RFC 7714 section 8.4), with 488 (Not Acceptable Here, RFC
3261 section 13.3.1.3), before the request changes anything. With the chat group protected (--protected
--chat-protected-floor: media under its GMK, floor control under each client's CSK), the scenario checks that
  - PS-01 client-c's floor control works under its CSK in a prearranged group call, which leaves the server a
    floor control context under client-c's CSK for client-c's floor SSRC;
  - PS-02 a chat call at the participant limit with client-a, client-b and client-d, floor control under the CSK;
  - PS-03 client-c, of higher priority, joins offering the floor SSRC of its previous call: refused with 488, and the
    three participants stay in the call (nobody preempted, no BYE) with floor control going on;
  - PS-04 client-c joins with a new SSRC: one participant is displaced (the preemption the refusal did not do).
PS-01, PS-03 and PS-04 run under the same CSK of client-c (its CSK-ID unchanged, no key download to it, the same
server instance), and PS-03 and PS-04 under the same priority, admission policy and membership (the same chat group
entry, the same join command, client-c on the same group).

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261,
RFC 7714.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run PS-01 to PS-04 against the lab of --compose; print the result and write
    integration/preempt-ssrc-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-preempt-ssrc')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    site = json.loads((generated / 'site.json').read_text())
    chat = next(entry for entry in site['groups'] if entry.get('type') == 'chat' and entry.get('user_priorities'))
    if not chat.get('protect_floor'):
        parser.error('the fixture must be prepared with --protected --chat-protected-floor')
    prearranged = configs['client-a']['mcptt']['group_id']
    checks, observations = [], {}
    result = dict(scenario='preempt-ssrc', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client and of the server, for failure messages."""
        return {role: status(role) for role in ROLES + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=20):
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.1)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:4000])

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label if condition holds, else raise with a snapshot."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot())[:4000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def sessions():
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def chat_participants():
        """The participants of the one chat session, or None."""
        current = [call for call in sessions() if call.get('call_type') == 'chat']
        return set(current[0].get('participants', [])) if len(current) == 1 else None

    # ------------------------------------------------------------------------------
    def idle():
        """Every client idle and no session at the server."""
        return all(status(role).get('call_state') == 'idle' for role in ROLES) and not sessions()

    # ------------------------------------------------------------------------------
    def on_group(roles, group):
        """The roles affiliated to and on the group."""
        return lambda: all(status(role).get('affiliated') and status(role).get('group_id') == group for role in roles)

    # ------------------------------------------------------------------------------
    def chat_entry():
        """The chat group's entry in the site configuration the server was started with."""
        current = json.loads((generated / 'site.json').read_text())
        return next(entry for entry in current['groups'] if entry['id'] == chat['id'])

    # ------------------------------------------------------------------------------
    def key_downloads(role):
        """The CSK downloads the server logged for the role (TS 33.180 clause 5.8.2): csk_download_sent events."""
        run = subprocess.run(cli + ['logs', '--no-color', 'mcptt-server'], capture_output=True, text=True, timeout=60)
        return [line for line in run.stdout.splitlines() if '"csk_download_sent"' in line and f'"{ids[role]}"' in line]

    # ------------------------------------------------------------------------------
    def same_conditions(label, reference):
        """client-c's CSK, the server instance, the chat group's entry and client-c's group are those of reference."""
        check(f'{label} client-c\'s CSK-ID is unchanged', status('client-c').get('csk_id') == reference['csk_id'])
        check(f'{label} no CSK download to client-c', not key_downloads('client-c'))
        check(f'{label} the same server instance', status('mcptt-server').get('instance_id') == reference['instance'])
        check(
            f'{label} the chat group\'s priority, admission policy and membership unchanged',
            chat_entry() == reference['chat'],
        )

    # ------------------------------------------------------------------------------
    def floor_works(sender, receivers, label, wav='alpha.wav'):
        """A burst from sender: the floor is granted over protected floor control and every receiver decrypts and
        decodes 100 packets of it; the floor is released."""
        before = {role: status(role).get('received_packets', 0) for role in receivers}
        command(sender, f'ptt /artifacts/speech/{wav}')
        wait(f'{label} {sender} granted the floor over protected floor control', lambda: status(sender).get('talking'))
        wait(
            f'{label} {", ".join(receivers)} decrypt and decode the burst',
            lambda: all(status(role).get('received_packets', 0) >= before[role] + 100 for role in receivers),
            20,
        )
        wait(f'{label} {sender} floor released', lambda: not status(sender).get('talking'), 30)

    try:
        wait(
            'four protected clients authorized, affiliated and holding a CSK',
            lambda: all(
                status(role).get('authorized') and status(role).get('affiliated') and status(role).get('csk_id')
                for role in ROLES
            ),
            120,
        )
        wait('fixture initially idle', idle, 30)
        for role in ROLES:
            command(role, 'answer-mode auto')
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name

        # PS-01 client-c's floor control under its CSK in a prearranged call.
        command('client-a', 'call')
        wait(
            'PS-01 prearranged group call with the four clients',
            lambda: all(status(role).get('call_state') == 'active' for role in ROLES),
        )
        floor_works('client-a', ['client-c'], 'PS-01')
        previous = status('client-c').get('floor_ssrc')
        check('PS-01 client-c\'s floor SSRC known', bool(previous))
        reference = dict(
            csk_id=status('client-c').get('csk_id'),
            instance=status('mcptt-server').get('instance_id'),
            chat=chat_entry(),
        )
        check('PS-01 client-c holds a CSK', bool(reference['csk_id']))
        observations.update(previous_floor_ssrc=previous, csk_id=reference['csk_id'])
        command('client-a', 'hangup')
        wait('PS-01 prearranged call released', idle, 30)

        # PS-02 the chat call at its participant limit.
        for role in ROLES:
            command(role, 'group ' + chat['id'])
        wait('PS-02 all clients on the chat group', on_group(ROLES, chat['id']), 30)
        three = ['client-a', 'client-b', 'client-d']
        for role in three:
            command(role, 'chat')
        expected = {ids[role] for role in three}
        wait('PS-02 chat call at max_participants', lambda: chat_participants() == expected)
        floor_works('client-a', ['client-b', 'client-d'], 'PS-02')

        # PS-03 client-c joins with the SSRC of its previous call.
        command('client-c', 'next-floor-ssrc previous')
        command('client-c', 'chat')
        wait(
            'PS-03 the join with a used floor SSRC is refused with 488',
            lambda: (
                status('client-c').get('call_state') == 'idle'
                and (status('client-c').get('last_call_failure') or {}).get('status') == 488
            ),
        )
        check(
            'PS-03 the refused join offered the previous floor SSRC', status('client-c').get('floor_ssrc') == previous
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if chat_participants() != expected or not all(status(role).get('call_state') == 'active' for role in three):
                raise AssertionError('PS-03 a participant left the call: ' + json.dumps(snapshot())[:4000])
            time.sleep(0.2)
        checks.append('PS-03 nobody preempted: the three participants stay in the call')
        print(checks[-1], flush=True)
        floor_works('client-b', ['client-a', 'client-d'], 'PS-03', 'bravo.wav')
        same_conditions('PS-03', reference)
        check('PS-03 client-c on the chat group', status('client-c').get('group_id') == chat['id'])

        # PS-04 a new SSRC: the higher-priority join displaces one participant. The same join command on the same
        # group under the same CSK; only the SSRC differs (the hook applied once, to PS-03).
        check('PS-04 the call is at its limit as for PS-03', chat_participants() == expected)
        command('client-c', 'chat')
        wait(
            'PS-04 client-c joins and displaces one participant',
            lambda: (
                (participants := chat_participants()) is not None
                and ids['client-c'] in participants
                and len(participants) == 3
                and sum(status(role).get('call_state') == 'idle' for role in three) == 1
            ),
        )
        check('PS-04 the join offered a new floor SSRC', status('client-c').get('floor_ssrc') != previous)
        same_conditions('PS-04', reference)
        for role in ROLES:
            if status(role).get('call_state') != 'idle':
                command(role, 'hangup')
        wait('PS-04 chat call released', idle, 30)
        for role in ROLES:
            command(role, 'group ' + prearranged)
        wait('back on the prearranged group', on_group(ROLES, prearranged), 30)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'preempt-ssrc-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
