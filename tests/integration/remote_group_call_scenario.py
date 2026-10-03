#!/usr/bin/env python3
"""Exercise remotely initiated group calls (TS 24.379 clause 10.1.5).

A requesting user asks a remote user, by SIP MESSAGE, to place a group call to a targeted group (TS 24.379 clause
10.1.5.2.1); the remote user places it and reports the outcome (clause 10.1.5.2.2), with the requested
<ric-app-level-priority> as Resource-Priority (clause 10.1.5.2.1 step 3 d) D), clause 10.1.5.2.2 step 2 b)). The
controlling function refuses an unauthorised requester (warning 157), a remote user not affiliated to the group (clause
10.1.5.4 step 3, warning 120) and a preconfigured-use-only group (clause 10.1.5.4 step 2A, warning 167); a client
refuses the latter itself (clause 10.1.5.2.1 step 1A).

Run against a fixture prepared with --private-call, where client-a holds <allow-request-remote-init-group-call> and the
preconfigured-use-only group <group>-ric-preconf has members b, c and d. Check IDs match
tests/mcptt/REMOTE_INITIATED_TEST.md.

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
    """Run the checks RG-01 to RG-11 and write integration/remote-group-call-results.json.

    RG-07 and RG-08 are not checks of this scenario: they are the wire verifier and regression rows of
    tests/mcptt/REMOTE_INITIATED_TEST.md.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-remote')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    group = configs['client-a']['mcptt']['group_id']
    preconf = group.replace('@', '-ric-preconf@')
    checks, observations = [], {}
    result = dict(scenario='remotely-initiated-group-call', passed=False, checks=checks, observations=observations)

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
    def sessions():
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def idle():
        """Every client is idle and the server has no session."""
        return all(status(role).get('call_state') == 'idle' for role in roles) and not sessions()

    # ------------------------------------------------------------------------------
    def outcome(role, key):
        """The value the role recorded for the service response key."""
        return (status(role).get('service_outcomes') or {}).get(key)

    # ------------------------------------------------------------------------------
    def service_status(role):
        """The response to the role's last service request (status and warning)."""
        return status(role).get('last_service_result') or {}

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in roles),
            90,
        )
        # In a split system the participating servers report the affiliations to the controlling server by peer
        # registration (TS 24.379 clause 9.2.2.3.3), a moment after the clients see them: wait for that too.
        wait(
            'the controlling server knows every affiliation',
            lambda: all(
                group in (status('mcptt-server').get('affiliations') or {}).get(ids[role], []) for role in roles
            ),
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']

        # RG-01 authorised remote group call: a asks b, b places the group call, everyone joins.
        command('client-a', f'remote-group-call {ids["client-b"]} {group}')
        wait(
            'RG-01 remote user places the group call and all members join',
            lambda: (
                all(status(role).get('call_state') == 'active' for role in roles)
                and any(call.get('call_type') == 'prearranged' and call.get('group_id') == group for call in sessions())
            ),
        )
        session = next(call for call in sessions() if call.get('group_id') == group)
        assert session['initiator'] == ids['client-b'], 'the remote user is the call initiator'
        checks.append('RG-01 the remote user, not the requester, is the initiator')
        wait(
            'RG-01 requester is told the remote call succeeded',
            lambda: outcome('client-a', 'remotely-initiated-group-call-response') == 'success',
        )
        assert outcome('client-b', 'remote-group') == 'success', 'remote user did not record success'
        checks.append('RG-01 remote user recorded the outcome it reported')

        # RG-02 speech works in the resulting call, then teardown.
        before = status('client-c').get('received_packets', 0)
        command('client-b', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'RG-02 initiator speech reaches the other members',
            lambda: status('client-c').get('received_packets', 0) >= before + 100,
            20,
        )
        wait('RG-02 floor released', lambda: not status('client-b').get('talking'), 20)
        command('client-b', 'hangup')
        wait('RG-02 call released', idle)

        # RG-03 silent request (notify-remote-user=false) still places the call.
        command('client-a', f'remote-group-call {ids["client-b"]} {group} silent')
        wait(
            'RG-03 a silent remote request establishes the call',
            lambda: all(status(role).get('call_state') == 'active' for role in roles),
        )
        wait(
            'RG-03 requester told the silent remote call succeeded',
            lambda: outcome('client-a', 'remotely-initiated-group-call-response') == 'success',
        )
        command('client-a', 'hangup')  # requester is a participant; leaving follows initiator policy of b's call
        command('client-b', 'hangup')
        wait('RG-03 call released', idle)

        # RG-04 unauthorised requester: client-c has no group_call ruleset -> 403 with warning 157.
        command('client-c', f'remote-group-call {ids["client-b"]} {group}')
        wait(
            'RG-04 unauthorised remote group request rejected with 157',
            lambda: (
                service_status('client-c').get('status') == 403
                and '157' in service_status('client-c').get('warning', '')
            ),
        )
        assert idle(), 'rejected request must not create a call'
        checks.append('RG-04 rejected request created no call')

        # RG-05 remote user not affiliated to the named group -> 403 with warning 120
        # (TS 24.379 clause 10.1.5.4 step 3).
        bogus = 'sip:no-such-group@' + group.split('@', 1)[1]
        command('client-a', f'remote-group-call {ids["client-b"]} {bogus}')
        wait(
            'RG-05 request for a group the remote user is not affiliated to rejected with 120',
            lambda: (
                service_status('client-a').get('status') == 403
                and '120' in service_status('client-a').get('warning', '')
            ),
        )

        # RG-06 the remote user is busy: it reports failure without disturbing its call.
        command('client-b', 'call')
        wait('RG-06 remote user is in a call', lambda: status('client-b').get('call_state') == 'active')
        command('client-a', f'remote-group-call {ids["client-b"]} {group}')
        wait(
            'RG-06 requester told the busy remote user could not place the call',
            lambda: outcome('client-a', 'remotely-initiated-group-call-response') == 'fail',
        )
        assert status('client-b').get('call_state') == 'active', 'the remote user call was disturbed'
        checks.append('RG-06 busy remote user call undisturbed')
        command('client-b', 'hangup')
        wait('RG-06 call released', idle)

        # RG-09 application priority (TS 24.379 clause 10.1.5.2.1 step 3 d) D), clause 10.1.5.2.2 step 2 b)): the
        # remote user's INVITE carries the requested value as Resource-Priority,
        # which the server accepts for that follow-up call only.
        command('client-a', f'remote-group-call {ids["client-b"]} {group} priority=mcptt.5')
        wait(
            'RG-09 a request with ric-app-level-priority establishes the call',
            lambda: all(status(role).get('call_state') == 'active' for role in roles),
        )
        wait(
            'RG-09 requester told the prioritised remote call succeeded',
            lambda: outcome('client-a', 'remotely-initiated-group-call-response') == 'success',
        )
        wait(
            'RG-09 the remote user placed the call with Resource-Priority mcptt.5',
            lambda: any(
                event.get('resource_priority') == 'mcptt.5' and event.get('target') == group
                for event in events('client-b', 'ric_priority_applied')
            ),
        )
        wait(
            'RG-09 the server accepted it for the remote user and the group',
            lambda: any(
                event.get('user_id') == ids['client-b']
                and event.get('target') == group
                and event.get('resource_priority') == 'mcptt.5'
                for event in events('mcptt-server', 'ric_priority_accepted')
            ),
        )
        command('client-b', 'hangup')
        wait('RG-09 call released', idle)

        # RG-10 preconfigured-use-only group, server check (TS 24.379 clause 10.1.5.4 step 2A):
        # client-a is not a member, so its GMS withholds the document and the
        # server refuses the request with 167.
        command('client-a', f'remote-group-call {ids["client-b"]} {preconf}')
        wait(
            'RG-10 a request for a preconfigured-use-only group rejected with 167',
            lambda: (
                service_status('client-a').get('status') == 403
                and '167' in service_status('client-a').get('warning', '')
            ),
        )
        assert idle(), 'rejected request must not create a call'
        checks.append('RG-10 rejected request created no call')

        # RG-11 client check (TS 24.379 clause 10.1.5.2.1 step 1A): member client-c reads the
        # document's <preconfigured-group-use-only> and sends no request.
        before = service_status('client-c')
        command('client-c', f'remote-group-call {ids["client-b"]} {preconf}')
        wait(
            'RG-11 a member refuses a remote request for a preconfigured-use-only group itself',
            lambda: 'preconfigured group' in status('client-c').get('last_error', ''),
        )
        # The server keeps no count of these requests: the client's own last result stands for it here, and the
        # wire verifier (verify_remote_group_call.py) counts the requests for the group on the wire.
        assert holds(lambda: service_status('client-c') == before, 1), 'client-c sent a MESSAGE'
        checks.append('RG-11 no request reached the server')

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, StopIteration, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/remote-group-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
