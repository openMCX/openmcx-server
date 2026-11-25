#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCData SDS communications over pre-established sessions, and the sessions' life outside them.

client-a and client-b hold pre-established sessions with the combined MCData server (the lab prepared with --mcdata
--mcdata-pre-established); client-c and client-d use the media plane on demand. The scenario checks that
  - MDPE-01 the sessions are set up (TS 24.282 clause 18.3.2): the 200 (OK) names the session's URI and the server's
    MSRP media "passive"; the server confirms them;
  - MDPE-02 a one-to-one standalone SDS client-a sends goes over its session by REFER (clause 9.2.5.2.1.1:
    "establish-success", the MSRP connection to the session's media, the REFER "BYE" and "terminated"), and reaches
    client-b over client-b's session (clause 9.2.5.2.2.2: "establish-request", then "terminate-request");
  - MDPE-03 a group standalone SDS client-a sends over its session (clause 9.2.5.3) reaches client-b over its session
    and client-c and client-d on demand;
  - MDPE-04 a one-to-one SDS session client-a opens over its session with client-c (on demand) carries messages both
    ways and is left by client-a (REFER "BYE", "terminated");
  - MDPE-05 an SDS session client-c opens with client-a reaches client-a over its session (clause 9.2.5.2.2.2, the
    session "establish-request"), carries messages both ways and is released by the server when client-c leaves
    ("terminate-request", clause 9.2.5.4.2.2); every session stays established, free again;
  - MDPE-09 an emergency group SDS session with an emergency alert client-a opens over its session (clause 9.2.5.3:
    the indications in the REFER, the grant and the Resource-Priority in "establish-success", clause 6.2.8.1.16)
    reaches client-b over its session ("establish-request" with the indications) and the others on demand; every
    member enters the group's in-progress emergency state; client-a cancels it by a re-INVITE in its session;
  - MDPE-10 client-b, not authorised for emergency group communications, is refused at its REFER (403 with warning
    233, clause 9.2.5.3.2.1 step 6B a)); its session stays free;
  - MDPE-11 an imminent peril group SDS session over client-a's session (clause 6.2.8.1.9), upgraded to an emergency
    one by a re-INVITE in the session (clause 6.3.7.1.1; client-b told within its own session, clause 6.3.7.1.17) and
    cancelled;
  - MDPE-12 an emergency one-to-one SDS session from client-a to client-b, over both sessions (clauses 9.2.5.2.1.1 1a)
    and 9.2.5.2.2.1 step 4 ii), cancelled by client-a (clauses 9.2.5.2.2.3 and 6.3.7.1.18; client-b follows, clauses
    9.2.5.2.2.4 and 6.3.7.1.17);
  - MDPE-13 an ordinary one-to-one SDS session over client-a's session upgraded to an emergency one and cancelled;
    (MDPE-09 to MDPE-13 need a client that carries priority communications over its session; with one that does not,
    they are reported skipped)
  - MDPE-06 the participating function modifies client-a's session (operator "pre-session-modify", clause 18.3.4);
  - MDPE-07 client-a releases its session (clause 18.3.3.1.1); an SDS then goes on demand, with no REFER;
  - MDPE-08 the participating function releases client-b's session (clause 18.3.3.2.2: "pre-session-release").

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), RFC 3515, RFC 4488.
"""

import argparse
import json
import secrets
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/mcdata-pre-established-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcdata-pre-established')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcdata']['user_id'] for role in ROLES}
    group = configs['client-a']['mcdata']['group_id']
    server_cfg = json.loads((generated / 'mcdata-server.json').read_text())
    if server_cfg.get('mcdata', {}).get('resource_sharing', 'none') == 'none':
        parser.error('the fixture must be prepared with --mcdata --mcdata-pre-established')
    checks = []
    result = dict(scenario='mcdata-pre-established', passed=False, checks=checks)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one command in the role's container (the MCData server's or mcx-client's)."""
        binary = 'openmcx-mcdata-server' if role == 'mcdata-server' else 'mcx-client'
        run = subprocess.run(
            cli + ['exec', '-T', role, binary, '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def events(service, name):
        """The JSON log entries of the service whose 'event' is name."""
        run = subprocess.run(
            cli + ['logs', '--no-color', '--no-log-prefix', service], capture_output=True, text=True, timeout=30
        )
        found = []
        for line in run.stdout.splitlines():
            start = line.find('{"')
            try:
                entry = json.loads(line[start:]) if start >= 0 else {}
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and entry.get('event') == name:
                found.append(entry)
        return found

    # ------------------------------------------------------------------------------
    def snapshot():
        return {role: status(role) for role in ROLES + ['mcdata-server']}

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.1)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def pre(role):
        """The client's pre-established session in its status, or {}."""
        return status(role).get('mcdata_pre_session') or {}

    # ------------------------------------------------------------------------------
    def server_pre(role):
        """The MCData server's record of the role's session, or {}."""
        for entry in status('mcdata-server').get('pre_sessions') or []:
            if entry.get('user_id') == ids[role]:
                return entry
        return {}

    # ------------------------------------------------------------------------------
    def free(role):
        """The session is established on both sides and carries no communication."""
        return (
            pre(role).get('state') == 'established'
            and not pre(role).get('communication')
            and server_pre(role).get('confirmed')
            and not server_pre(role).get('communication')
        )

    # ------------------------------------------------------------------------------
    def counted(role, key, before):
        return lambda: pre(role).get(key, 0) > before

    # ------------------------------------------------------------------------------
    def received(role, text):
        """The messages the client received over the media plane that carry this text."""
        return [
            message
            for message in status(role).get('mcdata_media_received') or []
            if any(payload.get('text') == text for payload in message.get('payloads', []))
        ]

    # ------------------------------------------------------------------------------
    def media(role):
        return status(role).get('mcdata_media_result') or {}

    # ------------------------------------------------------------------------------
    def server_count(name, **fields):
        return len(
            [
                entry
                for entry in events('mcdata-server', name)
                if all(entry.get(key) == value for key, value in fields.items())
            ]
        )

    # ------------------------------------------------------------------------------
    def group_state(role, which='emergency'):
        """The client's MDEG or MDIG state (TS 24.282 clause 6.2.8.1)."""
        return status(role).get(f'mcdata_group_{which}_state', '')

    # ------------------------------------------------------------------------------
    def communication_state(role, which='emergency'):
        """The client's MDEGC or MDIGC state (TS 24.282 clause 6.2.8.1)."""
        return status(role).get(f'mcdata_group_{which}_communication_state', '')

    # ------------------------------------------------------------------------------
    def server_group():
        """The in-progress emergency or imminent peril state the server holds for the group."""
        return (status('mcdata-server').get('group_priority') or {}).get(group) or {}

    # ------------------------------------------------------------------------------
    def close_session(role, label):
        """The role leaves its SDS session over its pre-established session; both sessions are free again."""
        done = pre(role).get('terminated', 0)
        command(role, 'sds-session close')
        wait(
            f'{label} {role} leaves the communication ("terminated")',
            lambda: pre(role).get('terminated', 0) > done and pre(role).get('last_state') == 'terminated',
        )
        wait(f'{label} every session is free again', lambda: free('client-a') and free('client-b'))
        wait(
            f'{label} no member is left in the communication',
            lambda: not any(status(other).get('mcdata_media_session') for other in ROLES),
        )

    # ------------------------------------------------------------------------------
    def priority_scenarios():
        """MDPE-09 to MDPE-13."""
        # MDPE-09 an emergency group SDS session with an alert over client-a's session.
        b_offered = pre('client-b').get('established', 0)
        refers = server_count('mcdata_pre_refer', user_id=ids['client-a'], emergency=True)
        command('client-a', f'sds-session group={group} emergency alert')
        wait(
            'MDPE-09 the REFER carries the emergency indication',
            lambda: server_count('mcdata_pre_refer', user_id=ids['client-a'], emergency=True) > refers,
        )
        wait(
            'MDPE-09 "establish-success" grants it: client-a reaches MDEGC 3 and MDEG 2 (6.2.8.1.16)',
            lambda: (
                pre('client-a').get('communication') == 'established'
                and communication_state('client-a').startswith('MDEGC 3')
                and group_state('client-a').startswith('MDEG 2')
            ),
        )
        check(
            'MDPE-09 the re-INVITE "establish-success" carries a Resource-Priority',
            bool(media('client-a').get('resource_priority')),
        )
        wait(
            'MDPE-09 every other member enters the in-progress emergency state',
            lambda: all(group_state(role).startswith('MDEG 2') for role in ('client-b', 'client-c', 'client-d')),
        )
        check(
            'MDPE-09 client-b is offered the communication over its session',
            pre('client-b').get('established', 0) > b_offered,
        )
        wait('MDPE-09 the server records the group\'s emergency state', lambda: server_group().get('emergency'))
        urgent = f'pre-urgent-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send {urgent}')
        wait(
            'MDPE-09 the emergency session carries client-a\'s message to client-b',
            lambda: received('client-b', urgent),
        )
        command('client-a', 'sds-session emergency cancel alert')
        wait(
            'MDPE-09 the cancellation by a re-INVITE in the session returns every member to MDEG 1',
            lambda: all(group_state(role).startswith('MDEG 1') for role in ROLES),
        )
        wait('MDPE-09 the server clears the group\'s emergency state', lambda: not server_group())
        close_session('client-a', 'MDPE-09')

        # MDPE-10 an unauthorised emergency group request over client-b's session.
        command('client-b', f'sds-session group={group} emergency')
        wait(
            'MDPE-10 client-b\'s REFER is refused with 403 and warning 233',
            lambda: media('client-b').get('status') == 403 and '233' in media('client-b').get('warning', ''),
        )
        wait(
            'MDPE-10 client-b\'s session stays free and its group state MDEG 1',
            lambda: (
                free('client-b')
                and group_state('client-b').startswith('MDEG 1')
                and not status('client-b').get('mcdata_media_session')
            ),
        )

        # MDPE-11 an imminent peril group SDS session, upgraded to an emergency one, cancelled.
        command('client-a', f'sds-session group={group} imminent')
        wait(
            'MDPE-11 "establish-success" grants it: client-a reaches MDIGC 3 and MDIG 2',
            lambda: (
                pre('client-a').get('communication') == 'established'
                and communication_state('client-a', 'imminent').startswith('MDIGC 3')
                and group_state('client-a', 'imminent').startswith('MDIG 2')
            ),
        )
        check('MDPE-11 with a Resource-Priority', bool(media('client-a').get('resource_priority')))
        wait(
            'MDPE-11 every other member enters the in-progress imminent peril state',
            lambda: all(
                group_state(role, 'imminent').startswith('MDIG 2') for role in ('client-b', 'client-c', 'client-d')
            ),
        )
        wait('MDPE-11 the server records it', lambda: server_group().get('imminent'))
        command('client-a', 'sds-session emergency')
        wait(
            'MDPE-11 the upgrade by a re-INVITE in the session makes the group an emergency one (6.3.7.1.1)',
            lambda: (
                server_group().get('emergency')
                and not server_group().get('imminent')
                and group_state('client-a').startswith('MDEG 2')
            ),
        )
        wait(
            'MDPE-11 the members follow, client-b within its own session',
            lambda: all(
                group_state(role).startswith('MDEG 2') and group_state(role, 'imminent').startswith('MDIG 1')
                for role in ('client-b', 'client-c', 'client-d')
            ),
        )
        command('client-a', 'sds-session emergency cancel')
        wait(
            'MDPE-11 the cancellation returns the group to no priority',
            lambda: not server_group() and all(group_state(role).startswith('MDEG 1') for role in ROLES),
        )
        close_session('client-a', 'MDPE-11')

        # MDPE-12 an emergency one-to-one SDS session over both sessions, cancelled.
        b_offered = pre('client-b').get('established', 0)
        command('client-a', f'sds-session {ids["client-b"]} emergency')
        wait(
            'MDPE-12 "establish-success" grants the emergency one-to-one communication (MDEPC 3)',
            lambda: (
                pre('client-a').get('communication') == 'established'
                and status('client-a').get('mcdata_session_emergency')
                and status('client-a').get('mcdata_session_emergency_state', '').startswith('MDEPC 3')
            ),
        )
        check('MDPE-12 with a Resource-Priority', bool(media('client-a').get('resource_priority')))
        wait(
            'MDPE-12 client-b is offered the emergency communication over its session',
            lambda: (
                pre('client-b').get('established', 0) > b_offered and status('client-b').get('mcdata_session_emergency')
            ),
        )
        urgent = f'pre-urgent-1to1-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send {urgent}')
        wait('MDPE-12 the emergency session carries the message', lambda: received('client-b', urgent))
        command('client-a', 'sds-session emergency cancel')
        wait(
            'MDPE-12 the cancellation by a re-INVITE in the session returns client-a to MDEPC 1 (6.3.7.1.18)',
            lambda: (
                not status('client-a').get('mcdata_session_emergency')
                and status('client-a').get('mcdata_session_emergency_state', '').startswith('MDEPC 1')
            ),
        )
        wait(
            'MDPE-12 client-b follows within its own session (6.3.7.1.17)',
            lambda: not status('client-b').get('mcdata_session_emergency'),
        )
        close_session('client-a', 'MDPE-12')

        # MDPE-13 an ordinary one-to-one SDS session over client-a's session, upgraded and cancelled.
        command('client-a', f'sds-session {ids["client-c"]}')
        wait(
            'MDPE-13 the ordinary session is established over client-a\'s session',
            lambda: (
                pre('client-a').get('communication') == 'established'
                and status('client-c').get('mcdata_media_session')
                and not status('client-a').get('mcdata_session_emergency')
            ),
        )
        command('client-a', 'sds-session emergency')
        wait(
            'MDPE-13 the upgrade by a re-INVITE in the session is granted (MDEPC 3)',
            lambda: (
                status('client-a').get('mcdata_session_emergency')
                and status('client-a').get('mcdata_session_emergency_state', '').startswith('MDEPC 3')
            ),
        )
        wait('MDPE-13 client-c follows', lambda: status('client-c').get('mcdata_session_emergency'))
        command('client-a', 'sds-session emergency cancel')
        wait(
            'MDPE-13 the cancellation returns both to an ordinary communication',
            lambda: (
                not status('client-a').get('mcdata_session_emergency')
                and not status('client-c').get('mcdata_session_emergency')
            ),
        )
        close_session('client-a', 'MDPE-13')

    try:
        wait(
            'four clients MCData-authorised and affiliated',
            lambda: all(
                status(role).get('mcdata_authorized') and status(role).get('mcdata_affiliated') for role in ROLES
            ),
            90,
        )

        # MDPE-01 the sessions are established.
        for role in ('client-a', 'client-b'):
            command(role, 'mcdata-pre-establish')
            wait(
                f'MDPE-01 {role}\'s session is established with the server\'s media "passive"',
                lambda role=role: pre(role).get('state') == 'established' and pre(role).get('setup') == 'passive',
            )
            wait(f'MDPE-01 the participating function confirms {role}\'s session', lambda role=role: free(role))
            check(
                f'MDPE-01 {role}\'s session has the URI the server allocated',
                pre(role).get('uri')
                and ';mcdata-pre-session=' in pre(role)['uri']
                and pre(role)['uri'] == server_pre(role).get('uri'),
            )

        # MDPE-02 one-to-one standalone SDS: client-a over its session, client-b over its own.
        text = f'pre-1to1-{secrets.token_hex(3)}'
        a_done, b_done = pre('client-a').get('terminated', 0), pre('client-b').get('terminated', 0)
        refers = server_count('mcdata_pre_refer', user_id=ids['client-a'])
        command('client-a', f'sds-media {ids["client-b"]} {text}')
        wait(
            'MDPE-02 client-a\'s REFER reaches the participating function',
            lambda: server_count('mcdata_pre_refer', user_id=ids['client-a']) > refers,
        )
        wait(
            'MDPE-02 client-b receives the SDS over the media plane from client-a',
            lambda: received('client-b', text) and received('client-b', text)[0].get('from') == ids['client-a'],
        )
        wait(
            'MDPE-02 client-a\'s communication ends with "terminated" (REFER "BYE", clause 9.2.5.4.2.1)',
            lambda: pre('client-a').get('terminated', 0) > a_done and pre('client-a').get('last_state') == 'terminated',
        )
        wait(
            'MDPE-02 client-b\'s communication is released with "terminate-request" (clause 9.2.5.4.2.2)',
            lambda: (
                pre('client-b').get('terminated', 0) > b_done
                and pre('client-b').get('last_state') == 'terminate-request'
            ),
        )
        check('MDPE-02 client-a\'s SDS was delivered', media('client-a').get('pre_established') is True)
        wait('MDPE-02 both sessions are free again', lambda: free('client-a') and free('client-b'))

        # MDPE-03 group standalone SDS over client-a's session.
        text = f'pre-group-{secrets.token_hex(3)}'
        b_offered = pre('client-b').get('established', 0)
        command('client-a', f'sds-media group={group} {text}')
        for role in ('client-b', 'client-c', 'client-d'):
            wait(
                f'MDPE-03 {role} receives the group SDS with the group named',
                lambda role=role: received(role, text) and received(role, text)[0].get('group') == group,
            )
        check('MDPE-03 client-b received it over its session', pre('client-b').get('established', 0) > b_offered)
        check('MDPE-03 client-a is not offered its own message', not received('client-a', text))
        wait('MDPE-03 both sessions are free again', lambda: free('client-a') and free('client-b'))

        # MDPE-04 an SDS session client-a opens over its session with client-c.
        a_done = pre('client-a').get('terminated', 0)
        command('client-a', f'sds-session {ids["client-c"]}')
        wait(
            'MDPE-04 the SDS session is established over client-a\'s session',
            lambda: (
                pre('client-a').get('communication') == 'established' and status('client-c').get('mcdata_media_session')
            ),
        )
        first = f'pre-session-a-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send {first}')
        wait(
            'MDPE-04 client-c receives client-a\'s message',
            lambda: received('client-c', first) and received('client-c', first)[0].get('from') == ids['client-a'],
        )
        reply = f'pre-session-c-{secrets.token_hex(3)}'
        command('client-c', f'sds-session send {reply}')
        wait(
            'MDPE-04 client-a receives client-c\'s reply over its session',
            lambda: received('client-a', reply) and received('client-a', reply)[0].get('from') == ids['client-c'],
        )
        command('client-a', 'sds-session close')
        wait(
            'MDPE-04 client-a leaves: "terminated", and client-c\'s session ends',
            lambda: (
                pre('client-a').get('terminated', 0) > a_done
                and pre('client-a').get('last_state') == 'terminated'
                and not status('client-c').get('mcdata_media_session')
            ),
        )
        wait('MDPE-04 client-a\'s session is free again', lambda: free('client-a'))

        # MDPE-05 an SDS session client-c opens with client-a, offered over client-a's session.
        a_offered, a_done = pre('client-a').get('established', 0), pre('client-a').get('terminated', 0)
        command('client-c', f'sds-session {ids["client-a"]}')
        wait(
            'MDPE-05 client-a is offered the SDS session over its session ("establish-request")',
            lambda: (
                pre('client-a').get('established', 0) > a_offered
                and pre('client-a').get('last_state') == 'establish-request'
                and status('client-a').get('mcdata_media_session')
            ),
        )
        first = f'pre-ct-c-{secrets.token_hex(3)}'
        command('client-c', f'sds-session send {first}')
        wait(
            'MDPE-05 client-a receives client-c\'s message over its session',
            lambda: received('client-a', first) and received('client-a', first)[0].get('from') == ids['client-c'],
        )
        reply = f'pre-ct-a-{secrets.token_hex(3)}'
        command('client-a', f'sds-session send {reply}')
        wait(
            'MDPE-05 client-c receives client-a\'s reply',
            lambda: received('client-c', reply) and received('client-c', reply)[0].get('from') == ids['client-a'],
        )
        command('client-c', 'sds-session close')
        wait(
            'MDPE-05 client-c leaves; the server releases client-a\'s part with "terminate-request"',
            lambda: (
                pre('client-a').get('terminated', 0) > a_done
                and pre('client-a').get('last_state') == 'terminate-request'
                and not status('client-a').get('mcdata_media_session')
            ),
        )
        wait('MDPE-05 every session stays established and free', lambda: free('client-a') and free('client-b'))

        # MDPE-09 to MDPE-13: emergency and imminent peril communications over the sessions (TS 24.282 clause 9.2.5),
        # with a client that carries them there (its status names the priority states, annex G.4).
        if 'mcdata_priority_states' in status('client-a'):
            priority_scenarios()
        else:
            result['skipped'] = 'MDPE-09 to MDPE-13: the client carries no priority communication over its session'
            print(result['skipped'], flush=True)

        # MDPE-06 the participating function's modification.
        modified = server_count('mcdata_pre_session_modified_by_server', user_id=ids['client-a'], status=200)
        command('mcdata-server', f'pre-session-modify {ids["client-a"]}')
        wait(
            'MDPE-06 the participating function\'s re-INVITE is answered 200',
            lambda: (
                server_count('mcdata_pre_session_modified_by_server', user_id=ids['client-a'], status=200) > modified
            ),
        )
        wait('MDPE-06 the session stays established and free', lambda: free('client-a'))

        # MDPE-07 the user's release; an SDS then goes on demand.
        command('client-a', 'mcdata-pre-release')
        wait('MDPE-07 client-a has no session', lambda: status('client-a').get('mcdata_pre_session') is None)
        wait('MDPE-07 the participating function releases it', lambda: not server_pre('client-a'))
        refers = server_count('mcdata_pre_refer', user_id=ids['client-a'])
        text = f'demand-{secrets.token_hex(3)}'
        command('client-a', f'sds-media {ids["client-c"]} {text}')
        wait('MDPE-07 without a session the SDS reaches client-c on demand', lambda: received('client-c', text))
        check(
            'MDPE-07 and no REFER was sent',
            server_count('mcdata_pre_refer', user_id=ids['client-a']) == refers
            and media('client-a').get('pre_established') is not True,
        )

        # MDPE-08 the participating function's release.
        command('mcdata-server', f'pre-session-release {ids["client-b"]}')
        wait(
            'MDPE-08 the participating function releases client-b\'s session and client-b has none',
            lambda: status('client-b').get('mcdata_pre_session') is None and not server_pre('client-b'),
        )
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'mcdata-pre-established-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
