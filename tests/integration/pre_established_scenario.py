#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Calls over a pre-established session, and the session's life outside a call.

client-a holds a pre-established session with the combined MCPTT server (the lab prepared with --pre-established
--private-call); the others call the usual way. The scenario checks that
  - PE-01 client-a's session is set up with ICE and is confirmed on both sides (TS 24.379 clause 8.2);
  - PE-02 a group call client-a starts goes over the session by REFER, reaches the other three, and its speech flows;
    released, the session stays (TS 24.379 clause 10.1.1.2.2.1, TS 24.380 clause 9.2.2);
  - PE-03 a group call client-c starts reaches client-a over the session, and client-a hears it (TS 24.380 clause
    9.3.2.4);
  - PE-04 a private call client-a makes goes over the session by REFER (TS 24.379 clause 11.1.1.2.2.1);
  - PE-05 the user modifies the session outside a call, asking for implicit floor control (clause 8.3.1.1);
  - PE-06 the participating function modifies it (clause 8.3.2.2: the operator's "pre-session-modify");
  - PE-07 the user releases it (clause 8.4.1.1); a group call then goes the usual way, with no REFER;
  - PE-08 a new session is released by the participating function (clause 8.4.2.2: "pre-session-release").
  - PE-09 the client is killed with a session and starts again: the participating function releases the session
    (clause 8.4.2.2), and the next call to the user is offered on demand.
  - PE-10 (with --priority) client-b raises and then cancels the emergency of a group call client-a is in over its
    session: client-a learns of both in a re-INVITE in the session's dialog (TS 24.379 clauses 6.3.3.1.6 and
    10.1.1.3.6, the session being its only dialog), the group's in-progress emergency state is cleared, and client-a's
    next call is a normal one; in that call client-a itself raises and cancels the emergency, by a re-INVITE in its
    session's dialog with the MCPTT-Info and the session's SDP (TS 24.379 clauses 10.1.1.2.1.3 and 10.1.1.2.1.4,
    "covers both on-demand session and pre-established sessions"), which the participating function takes as the
    call's (clause 10.1.1.3.1.3), and the other clients are told of both; the upgrade carries an implicit floor
    request (clause 6.4), accepted in the answer ("mc_implicit_request", TS 24.380 clause 14.3.5) and granted (TS
    24.380 clause 6.3.4.3.6): client-b hears client-a.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 3515, RFC 8445.
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
    """Run the scenario against the lab of --compose; print the result and write
    integration/pre-established-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-pre-established')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    server_cfg = json.loads((generated / 'mcptt-server.json').read_text())
    if server_cfg.get('mcptt', {}).get('resource_sharing', 'none') == 'none':
        parser.error('the fixture must be prepared with --pre-established --private-call')
    checks = []
    result = dict(scenario='pre-established', passed=False, checks=checks)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one command in the role's container (the MCPTT server's or mcx-client's)."""
        binary = 'openmcx-mcptt-server' if role == 'mcptt-server' else 'mcx-client'
        run = subprocess.run(
            cli + ['exec', '-T', role, binary, '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
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
            if entry.get('event') == name:
                found.append(entry)
        return found

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        snapshot = {role: status(role) for role in ROLES}
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot)[:4000])

    # ------------------------------------------------------------------------------
    def session():
        """client-a's pre-established session in its status, or {}."""
        return status('client-a').get('pre_session') or {}

    # ------------------------------------------------------------------------------
    def established():
        return session().get('state') == 'established' and session().get('ice') == 'completed'

    # ------------------------------------------------------------------------------
    def in_call(roles):
        return lambda: all(status(role).get('call_state') not in (None, 'idle') for role in roles)

    # ------------------------------------------------------------------------------
    def idle():
        return all(status(role).get('call_state') == 'idle' for role in ROLES)

    # ------------------------------------------------------------------------------
    def server_event(name, **fields):
        """A predicate: the MCPTT server logged event name for client-a, with fields, more than before times."""
        before = len(matching(name, fields))
        return lambda: len(matching(name, fields)) > before

    # ------------------------------------------------------------------------------
    def matching(name, fields):
        return [
            entry
            for entry in events('mcptt-server', name)
            if entry.get('user_id', ids['client-a']) == ids['client-a']
            and all(entry.get(key) == value for key, value in fields.items())
        ]

    # ------------------------------------------------------------------------------
    def speech(talker, listener, label):
        """talker sends speech; listener receives at least 100 packets; the floor is released."""
        before = status(listener).get('received_packets', 0)
        command(talker, 'ptt /artifacts/speech/alpha.wav')
        wait(f'{label} {talker} granted the floor', lambda: status(talker).get('talking'))
        wait(
            f'{label} {listener} receives the speech',
            lambda: status(listener).get('received_packets', 0) >= before + 100,
            20,
        )
        wait(f'{label} {talker} releases the floor', lambda: not status(talker).get('talking'), 30)

    try:
        wait(
            'four clients authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )

        # PE-01 setup with ICE, confirmed on both sides.
        started = server_event('pre_established_session_started')
        command('client-a', 'pre-establish')
        wait('PE-01 client-a\'s session is established and its ICE checks completed', established)
        wait('PE-01 the participating function confirms the session', started)
        uri = session().get('uri', '')
        wait('PE-01 the session has its own URI', lambda: bool(uri))

        # PE-02 an originated group call over the session.
        refers = len(events('client-a', 'pre_session_refer_sent'))
        over = server_event('pre_session_call')
        command('client-a', 'call')
        wait(
            'PE-02 client-a sends the group call REFER over the session',
            lambda: len(events('client-a', 'pre_session_refer_sent')) > refers,
        )
        wait('PE-02 the participating function sets up the call over the session', over)
        wait('PE-02 the group call reaches the four clients', in_call(ROLES))
        speech('client-a', 'client-b', 'PE-02')
        command('client-a', 'hangup')
        wait('PE-02 the call is released', idle)
        wait('PE-02 the session stays, not in use', established, 10)

        # PE-03 a terminating group call over the session.
        controls = len(events('client-a', 'pre_session_control_received'))
        command('client-c', 'call')
        wait('PE-03 the group call client-c starts reaches the four clients', in_call(ROLES))
        wait(
            'PE-03 client-a is told of the call over the session',
            lambda: len(events('client-a', 'pre_session_control_received')) > controls,
        )
        speech('client-c', 'client-a', 'PE-03')
        command('client-c', 'hangup')
        wait('PE-03 the call is released', idle)
        wait('PE-03 the session stays, not in use', established, 10)

        # PE-04 a private call over the session.
        refers = len(events('client-a', 'pre_session_refer_sent'))
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'PE-04 client-a sends the private call REFER over the session',
            lambda: len(events('client-a', 'pre_session_refer_sent')) > refers,
        )
        wait('PE-04 the private call connects client-a and client-b', in_call(['client-a', 'client-b']))
        speech('client-a', 'client-b', 'PE-04')
        command('client-a', 'hangup')
        wait('PE-04 the call is released', idle)
        wait('PE-04 the session stays, not in use', established, 10)

        # PE-10 the emergency state of a call client-a is in over its session, raised and cancelled by client-b.
        site = json.loads((generated / 'site.json').read_text())
        if any(group.get('priority_policy') for group in site.get('groups', [])):
            notified = len(events('client-a', 'pre_session_priority_reinvite'))
            command('client-b', 'call')
            wait('PE-10 client-b\'s group call reaches the four clients', in_call(ROLES))
            command('client-b', 'emergency on')
            wait(
                'PE-10 client-b\'s call is an emergency call', lambda: status('client-b').get('priority') == 'emergency'
            )
            wait(
                'PE-10 client-a is told of the emergency in its session\'s dialog',
                lambda: (
                    status('client-a').get('priority') == 'emergency'
                    and len(events('client-a', 'pre_session_priority_reinvite')) > notified
                ),
            )
            notified = len(events('client-a', 'pre_session_priority_reinvite'))
            cancelled = len([e for e in events('mcptt-server', 'priority_changed') if e.get('priority') == 'normal'])
            command('client-b', 'emergency off')
            wait(
                'PE-10 the group\'s in-progress emergency state is cleared',
                lambda: (
                    len([e for e in events('mcptt-server', 'priority_changed') if e.get('priority') == 'normal'])
                    > cancelled
                ),
            )
            wait(
                'PE-10 client-a is told of the cancel in its session\'s dialog',
                lambda: (
                    status('client-a').get('priority') == 'normal'
                    and len(events('client-a', 'pre_session_priority_reinvite')) > notified
                ),
            )
            command('client-b', 'hangup')
            wait('PE-10 the call is released', idle)
            wait('PE-10 the session stays, not in use', established, 10)
            # The next call over the session is a normal one: it reaches client-b by the usual INVITE, not as an
            # emergency call.
            over = server_event('pre_session_call')
            command('client-a', 'call')
            wait('PE-10 client-a\'s next call goes over its session', over)
            wait('PE-10 and reaches the four clients', in_call(ROLES))
            wait('PE-10 as a normal call', lambda: status('client-b').get('priority') == 'normal', 5)
            wait(
                'PE-10 client-a\'s call over its session is active',
                lambda: status('client-a').get('call_state') == 'active',
            )
            # client-a, in its call over the session, raises the emergency itself (TS 24.379 clause 10.1.1.2.1.3): a
            # re-INVITE in the session's dialog (the call has no other), answered 200 (OK) for the call. It asks for
            # the floor with it (step 7: an implicit floor request, clause 6.4): the answer echoes
            # "mc_implicit_request" (TS 24.380 clause 14.3.5) and the floor control server grants the floor (TS 24.380
            # clause 6.3.4.3.6), so client-a's speech reaches client-b.
            reinvite = server_event('pre_session_call_reinvite')
            answered = server_event('pre_session_call_reinvite_answered', status=200)
            accepted = server_event('upgrade_implicit_floor_request_accepted')
            heard = status('client-b').get('received_packets', 0)
            command('client-a', 'emergency on implicit=/artifacts/speech/alpha.wav')
            wait('PE-10 client-a\'s emergency re-INVITE goes in its session\'s dialog', reinvite)
            wait('PE-10 and is answered 200 (OK) for the call', answered)
            wait(
                'PE-10 client-a\'s call over its session is an emergency call',
                lambda: status('client-a').get('priority') == 'emergency',
            )
            wait(
                'PE-10 client-b is told of client-a\'s emergency',
                lambda: status('client-b').get('priority') == 'emergency',
            )
            wait('PE-10 the controlling function accepts the upgrade\'s implicit floor request', accepted)
            wait(
                'PE-10 the answer in the session\'s dialog echoes mc_implicit_request',
                lambda: status('client-a').get('implicit_floor_request') == 'accepted',
            )
            wait('PE-10 client-a is granted the floor with its upgrade', lambda: status('client-a').get('talking'))
            wait(
                'PE-10 client-b receives client-a\'s speech',
                lambda: status('client-b').get('received_packets', 0) >= heard + 100,
                20,
            )
            wait('PE-10 client-a releases the floor', lambda: not status('client-a').get('talking'), 30)
            # And cancels it (clause 10.1.1.2.1.4), the same way: the group's in-progress emergency state is cleared.
            reinvite = server_event('pre_session_call_reinvite')
            answered = server_event('pre_session_call_reinvite_answered', status=200)
            cancelled = len([e for e in events('mcptt-server', 'priority_changed') if e.get('priority') == 'normal'])
            command('client-a', 'emergency off')
            wait('PE-10 client-a\'s cancel re-INVITE goes in its session\'s dialog', reinvite)
            wait('PE-10 and the cancel is answered 200 (OK) for the call', answered)
            wait(
                'PE-10 the group\'s in-progress emergency state is cleared by client-a',
                lambda: (
                    len([e for e in events('mcptt-server', 'priority_changed') if e.get('priority') == 'normal'])
                    > cancelled
                ),
            )
            wait(
                'PE-10 client-a\'s call is a normal call again', lambda: status('client-a').get('priority') == 'normal'
            )
            wait('PE-10 client-b is told of client-a\'s cancel', lambda: status('client-b').get('priority') == 'normal')
            command('client-a', 'hangup')
            wait('PE-10 that call is released', idle)
            wait('PE-10 the session stays again', established, 10)

        # PE-05 the user's modification.
        modified = len(events('client-a', 'pre_session_modified'))
        command('client-a', 'pre-session-modify implicit')
        wait(
            'PE-05 the user\'s re-INVITE is answered 200 and the session asks for implicit floor control',
            lambda: (
                any(e.get('status') == 200 for e in events('client-a', 'pre_session_modified')[modified:])
                and session().get('implicit') is True
            ),
        )

        # PE-06 the participating function's modification.
        server_modified = server_event('pre_established_session_modified', status=200)
        command('mcptt-server', f"pre-session-modify {ids['client-a']} priority=5")
        wait('PE-06 the participating function\'s re-INVITE is answered 200', server_modified)
        wait('PE-06 the session stays established', established, 10)

        # PE-07 the user's release; calls then go the usual way.
        released = server_event('pre_established_session_released')
        command('client-a', 'pre-session-release')
        wait('PE-07 client-a has no session', lambda: status('client-a').get('pre_session') is None)
        wait('PE-07 the participating function releases it', released)
        refers = len(events('client-a', 'pre_session_refer_sent'))
        command('client-a', 'call')
        wait('PE-07 without a session the group call reaches the four clients', in_call(ROLES))
        wait(
            'PE-07 and no REFER is sent',
            lambda: len(events('client-a', 'pre_session_refer_sent')) == refers,
            1,
        )
        command('client-a', 'hangup')
        wait('PE-07 the call is released', idle)

        # PE-08 the participating function's release.
        command('client-a', 'pre-establish')
        wait('PE-08 client-a sets up a new session', established)
        command('mcptt-server', f"pre-session-release {ids['client-a']}")
        wait(
            'PE-08 the participating function releases it and client-a has none',
            lambda: status('client-a').get('pre_session') is None,
        )

        # PE-09 the client dies with its session and starts again (a new registration and an initial service
        # authorisation): the participating function releases the old session (clause 8.4.2.2), and a call to the user
        # is then offered on demand, not over the dead session.
        command('client-a', 'pre-establish')
        wait('PE-09 client-a sets up a new session', established)
        ended = server_event('pre_established_session_ended')
        subprocess.run(cli + ['kill', '-s', 'SIGKILL', 'client-a'], capture_output=True, text=True, timeout=30)
        (args.artifacts / 'client-a' / 'status.json').unlink(missing_ok=True)
        subprocess.run(cli + ['start', 'client-a'], capture_output=True, text=True, timeout=60, check=True)
        wait(
            'PE-09 client-a is authorised and affiliated again',
            lambda: status('client-a').get('authorized') and status('client-a').get('affiliated'),
            90,
        )
        wait('PE-09 the participating function releases the session of the dead client', ended)
        over_session = {'pre_established': True}
        over_before = len(matching('call_fanout', over_session))
        command('client-c', 'call')
        wait('PE-09 the group call client-c starts reaches the four clients on demand', in_call(ROLES))
        if len(matching('call_fanout', over_session)) != over_before or status('client-a').get('pre_session'):
            raise AssertionError('PE-09 the call went over a pre-established session')
        checks.append('PE-09 no call is offered over the released session')
        command('client-c', 'hangup')
        wait('PE-09 the call is released', idle)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'pre-established-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
