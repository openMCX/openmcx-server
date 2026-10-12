#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise private call services: call-back, remotely initiated call, transfer and forwarding.

The procedures under test, all of TS 24.379: private call call-back (clause 11.1.5, the client side of clause
11.1.5.2.1), remotely initiated private call (clause 11.1.7, with <ric-app-level-priority> of clause 11.1.7.2.2 step 3
b)), unannounced and announced private call transfer (clause 11.1.8, clause 11.1.8.2.3), private call forwarding on
manual input (clause 11.1.9.2.1), immediate and no-answer forwarding at the terminating participating function (clause
11.1.1.3.2 steps 4 and 6) and the no answer timer TNP1 (clause 6.3.2.5), with the warning texts 151, 158, 170 and 175 of
table 4.4.2-2.

Run against a separate four-client fixture prepared with --private-call --private-services. IDs match
tests/mcptt/PRIVATE_CALL_TEST.md.

Specifications: TS 24.379 V19.7.0 (Rel-19).
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
    """Run the checks PS-01 to PS-13 (and PS-06b) and write integration/private-services-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-services')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcptt']['user_id'] for role in roles}
    checks, observations = [], {}
    result = dict(scenario='private-call-services', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client and of the server, for failure messages and the result file."""
        return {role: status(role) for role in roles + ['mcptt-server']}

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
    def wait(label, predicate, timeout=15):
        """Poll predicate every 50 ms until it holds (record label) or timeout seconds pass (raise)."""
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
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def idle(wanted=roles):
        """The wanted clients are idle and the server has no session."""
        return all(status(role).get('call_state') == 'idle' for role in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def private_active(caller, callee):
        """Exactly one private call between caller and callee, started by caller, active at both."""
        current = [session for session in sessions() if session.get('call_type') == 'private']
        return (
            len(current) == 1
            and set(current[0].get('participants', [])) == {ids[caller], ids[callee]}
            and current[0].get('calling_user') == ids[caller]
            and all(status(role).get('call_state') == 'active' for role in (caller, callee))
        )

    # ------------------------------------------------------------------------------
    def service_rejected(role, code, warning):
        """A predicate: the role's last service request was answered with code and the warning text."""
        return lambda: (
            (status(role).get('last_service_result') or {}).get('status') == code
            and warning in (status(role).get('last_service_result') or {}).get('warning', '')
        )

    # ------------------------------------------------------------------------------
    def outcome(role, kind, value='success'):
        """A predicate: the role received the service response kind with value."""
        return lambda: (status(role).get('service_outcomes') or {}).get(kind) == value

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

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for role in roles:
            command(role, 'answer-mode auto')

        # PS-01 call-back request, confirmation and fulfilment (TS 24.379 clause 11.1.5).
        command('client-a', f"callback {ids['client-b']} high")
        wait(
            'PS-01 target stores the call-back request with its urgency',
            lambda: (
                (status('client-b').get('callback_requests_received') or {}).get(ids['client-a'], {}).get('urgency')
                == 'high'
            ),
        )
        wait(
            'PS-01 requester entry confirmed (PCCB-I3)',
            lambda: (
                (status('client-a').get('callback_requests_sent') or {}).get(ids['client-b']) == 'PCCB-I3: confirmed'
            ),
        )
        command('client-b', f"callback-fulfil {ids['client-a']}")
        wait(
            'PS-01 fulfilment rings the requester in manual commencement',
            lambda: status('client-a').get('call_state') == 'ringing',
        )
        command('client-a', 'answer')
        wait('PS-01 call-back call established', lambda: private_active('client-b', 'client-a'))
        wait(
            'PS-01 both call-back entries deleted after fulfilment',
            lambda: (
                not status('client-a').get('callback_requests_sent')
                and not status('client-b').get('callback_requests_received')
            ),
        )
        command('client-b', 'hangup')
        wait('PS-01 released', idle)

        # PS-02 call-back cancellation and PS-03 authorisation (warning 151). Warning 152 (cancel not authorised) is not
        # provoked: the client cancels only a confirmed request, and no user of the fixture may request a call-back
        # without being allowed to cancel it.
        command('client-a', f"callback {ids['client-b']}")
        wait(
            'PS-02 second request confirmed',
            lambda: (
                (status('client-a').get('callback_requests_sent') or {}).get(ids['client-b']) == 'PCCB-I3: confirmed'
            ),
        )
        command('client-a', f"callback-cancel {ids['client-b']}")
        wait(
            'PS-02 cancellation removes both entries',
            lambda: (
                not status('client-a').get('callback_requests_sent')
                and not status('client-b').get('callback_requests_received')
            ),
        )
        command('client-c', f"callback {ids['client-a']}")
        wait(
            'PS-03 unauthorised call-back request rejected with 403 warning 151',
            service_rejected('client-c', 403, '151 user not authorised to make a private call call-back request'),
        )

        # PS-04 remotely initiated private call (TS 24.379 clause 11.1.7) and PS-05 warning 158.
        command('client-a', f"remote-call {ids['client-b']} {ids['client-d']} auto")
        wait('PS-04 remote user places the requested private call', lambda: private_active('client-b', 'client-d'), 20)
        wait(
            'PS-04 requester told of the successful outcome',
            outcome('client-a', 'remotely-initiated-private-call-response'),
        )
        command('client-b', 'hangup')
        wait('PS-04 released', idle)
        # PS-04a <ric-app-level-priority> (TS 24.379 clause 11.1.7.2.2 step 3 b)): the remote user's
        # INVITE carries it as Resource-Priority, accepted for that call only.
        command('client-a', f"remote-call {ids['client-b']} {ids['client-d']} auto priority=mcpttp.6")
        wait(
            'PS-04a remote user places the prioritised private call', lambda: private_active('client-b', 'client-d'), 20
        )
        wait(
            'PS-04a the server accepted Resource-Priority mcpttp.6 for that call',
            lambda: any(
                event.get('user_id') == ids['client-b']
                and event.get('target') == ids['client-d']
                and event.get('resource_priority') == 'mcpttp.6'
                for event in events('mcptt-server', 'ric_priority_accepted')
            ),
        )
        command('client-b', 'hangup')
        wait('PS-04a released', idle)
        command('client-b', f"remote-call {ids['client-c']} {ids['client-a']}")
        wait(
            'PS-05 unauthorised remote call request rejected with 403 warning 158',
            service_rejected('client-b', 403, '158 user not authorised to request a remotely initiated private call'),
        )

        # PS-06 unannounced transfer (TS 24.379 clause 11.1.8) and PS-07 warning 170.
        command('client-a', f"private {ids['client-b']} auto")
        wait('PS-06 call to be transferred established', lambda: private_active('client-a', 'client-b'))
        command('client-a', f"transfer {ids['client-d']}")
        wait(
            'PS-06 transferred user now in a private call with the target',
            lambda: private_active('client-b', 'client-d'),
            20,
        )
        wait(
            'PS-06 the transferred user kept its call with the requester while it called the target',
            lambda: bool(events('client-b', 'transferred_call_kept')),
        )
        wait(
            'PS-06 requester told of success and out of the call',
            lambda: (
                outcome('client-a', 'transfer-private-call-response')()
                and status('client-a').get('call_state') == 'idle'
            ),
            20,
        )
        command('client-b', f"transfer {ids['client-a']}")
        wait(
            'PS-07 unauthorised transfer rejected with 403 warning 170',
            service_rejected('client-b', 403, '170 user not authorised to make a private call transfer request'),
        )
        command('client-b', 'hangup')
        wait('PS-07 released', idle)

        # PS-06b failed transfer (TS 24.379 clauses 11.1.8.2.1 and 11.1.8.2.2): the transferred user keeps its call
        # with the requester while it calls the target, so when that call fails the two stay in their call.
        command('client-a', f"private {ids['client-b']} auto")
        wait('PS-06b call to be transferred established', lambda: private_active('client-a', 'client-b'))
        unknown = 'sip:nobody.mcptt@' + ids['client-d'].split('@', 1)[1]
        command('client-a', f'transfer {unknown}')
        wait(
            'PS-06b requester told of failure, and the call with the transferred user goes on',
            lambda: (
                outcome('client-a', 'transfer-private-call-response', 'fail')()
                and outcome('client-b', 'transfer', 'fail')()
                and private_active('client-a', 'client-b')
            ),
            20,
        )
        command('client-a', 'hangup')
        wait('PS-06b released', idle)

        # PS-08 manual forwarding of a ringing call (TS 24.379 clause 11.1.9.2.1).
        command('client-a', f"private {ids['client-b']} manual")
        wait('PS-08 callee ringing', lambda: status('client-b').get('call_state') == 'ringing')
        command('client-b', f"forward {ids['client-d']}")
        wait(
            'PS-08 caller receives 480 with warning 175',
            lambda: (
                (status('client-a').get('last_call_failure') or {}).get('status') == 480
                and '175 call is forwarded' in (status('client-a').get('last_call_failure') or {}).get('warning', '')
            ),
            20,
        )
        wait('PS-08 caller reaches the forwarding target', lambda: private_active('client-a', 'client-d'), 20)
        wait('PS-08 forwarding user told of success', outcome('client-b', 'forward-private-call-response'))
        command('client-a', 'hangup')
        wait('PS-08 released', idle)

        # PS-09 immediate forwarding configured for the called user (TS 24.379 clause 11.1.1.3.2 step 4).
        # Every look at the caller also looks at the forwarding user, which must stay idle throughout (a status that
        # cannot be read says nothing).
        forwarding_states = set()

        def watching(predicate):
            def watched():
                forwarding_states.add(status('client-c').get('call_state', 'idle'))
                return predicate()

            return watched

        command('client-a', f"private {ids['client-c']} auto")
        wait(
            'PS-09 original attempt answered 480 with warning 175',
            watching(
                lambda: (
                    '175 call is forwarded' in (status('client-a').get('last_call_failure') or {}).get('warning', '')
                )
            ),
        )
        wait(
            'PS-09 call to a user with immediate forwarding reaches the forwarding target',
            watching(lambda: private_active('client-a', 'client-b')),
            20,
        )
        assert holds(lambda: status('client-c').get('call_state') == 'idle', 1) and forwarding_states == {'idle'}, (
            f'forwarding user was called: {sorted(map(str, forwarding_states))}'
        )
        checks.append('PS-09 the forwarding user is never rung')
        command('client-a', 'hangup')
        wait('PS-09 released', idle)

        # PS-10 client-side profile authorisation (TS 24.379 clause 11.1.5.2.1): client-d enforces
        # its downloaded <ruleset>, which grants no call-back, so nothing is sent.
        assert status('client-d').get('enforce_profile_ruleset') and 'allow-private-call' not in status('client-d').get(
            'profile_actions', []
        ), 'client-d fixture does not enforce a restrictive profile'
        command('client-d', f"callback {ids['client-a']}")
        wait(
            'PS-10 client refuses a call-back request its profile does not grant',
            lambda: 'not authorised by the user profile' in status('client-d').get('last_error', ''),
        )
        assert holds(lambda: ids['client-d'] not in (status('client-a').get('callback_requests_received') or {}), 1), (
            'refused request reached the target'
        )
        checks.append('PS-10 the refused request never reaches the target')

        # PS-11 forwarding on no answer (TS 24.379 clause 6.3.2.5): client-d forwards to client-a
        # when it does not answer within TNP1 (3 s in this fixture).
        command('client-b', f"private {ids['client-d']} manual")
        wait('PS-11 callee rings', lambda: status('client-d').get('call_state') == 'ringing')
        started = time.monotonic()
        wait(
            'PS-11 after TNP1 the caller gets 480 with warning 175 and a no-answer forwarding request',
            lambda: (
                (status('client-b').get('last_forwarding') or {}).get('reason') == 'no-answer'
                and '175 call is forwarded' in (status('client-b').get('last_call_failure') or {}).get('warning', '')
            ),
            20,
        )
        observations['tnp1_seconds'] = round(time.monotonic() - started, 1)
        assert observations['tnp1_seconds'] >= 2, 'forwarded before TNP1 expired'
        checks.append('PS-11 the forwarding waited for TNP1')
        wait(
            'PS-11 the unanswered invitation to the callee is cancelled',
            lambda: status('client-d').get('call_state') == 'idle',
        )
        wait('PS-11 caller reaches the no-answer forwarding target', lambda: private_active('client-b', 'client-a'), 20)
        wait(
            'PS-11 the server reports the TNP1 expiry',
            lambda: any(
                event.get('user_id') == ids['client-d'] for event in events('mcptt-server', 'no_answer_timer_expired')
            ),
        )
        command('client-b', 'hangup')
        wait('PS-11 released', idle)

        # PS-12 a user with forwarding on no answer who is not registered is
        # forwarded at once (TS 24.379 clause 11.1.1.3.2 step 6), without waiting for TNP1.
        offline = ids['client-d'].replace('client-d', 'offline')
        command('client-b', f"private {offline} auto")
        wait(
            'PS-12 a call to the unregistered user is forwarded with reason no-answer',
            lambda: any(
                event.get('by') == offline and event.get('reason') == 'no-answer'
                for event in events('mcptt-server', 'private_call_forwarded')
            ),
            10,
        )
        wait('PS-12 caller reaches the forwarding target', lambda: private_active('client-b', 'client-a'), 20)
        command('client-b', 'hangup')
        wait('PS-12 released', idle)

        # PS-13 announced transfer (TS 24.379 clause 11.1.8.2.3): client-a holds its call with
        # client-b, calls client-d to announce the transfer, then asks client-b to
        # call client-d with Replaces; client-d's call with client-a is replaced.
        command('client-a', f"private {ids['client-b']} auto")
        wait('PS-13 call to be transferred established', lambda: private_active('client-a', 'client-b'))
        command('client-a', f"transfer {ids['client-d']} announced")
        wait(
            'PS-13 the requester holds the call and reaches the target, which returns its dialog',
            lambda: (
                (status('client-a').get('announced_transfer') or {}).get('state') == 'announcing'
                and (status('client-a').get('announced_transfer') or {}).get('replaces') is True
                and status('client-d').get('call_state') == 'active'
            ),
            20,
        )
        wait(
            'PS-13 the server holds the transferred user\'s leg',
            lambda: any(
                event.get('user_id') == ids['client-a'] for event in events('mcptt-server', 'private_call_held')
            ),
        )
        wait(
            'PS-13 the held call and the announcing call coexist',
            lambda: len([session for session in sessions() if session.get('call_type') == 'private']) == 2,
        )
        command('client-a', f"transfer {ids['client-d']} complete")
        wait(
            'PS-13 the transferred user\'s call replaces the announcing call at the target',
            lambda: private_active('client-b', 'client-d'),
            20,
        )
        wait('PS-13 the target reports the replaced dialog', lambda: bool(events('client-d', 'private_call_replaced')))
        wait(
            'PS-13 the requester is told of success and has left both calls',
            lambda: (
                outcome('client-a', 'transfer-private-call-response')()
                and status('client-a').get('call_state') == 'idle'
                and (status('client-a').get('announced_transfer') or {}).get('state') == 'completed'
            ),
            20,
        )
        command('client-b', 'hangup')
        wait('PS-13 released', idle)

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/private-services-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
