#!/usr/bin/env python3
"""The MCPTT server restarts: its clients learn it and are authorised and affiliated again.

The MCPTT server keeps its bindings in memory, so a restarted server knows nobody. The scenario checks that
  - a call from a client the restarted server does not know is refused with 404 (Not Found) and Warning
    "141 user unknown to the participating function" (TS 24.379 clause 10.1.1.3.1.1 step 2a);
  - the client's next service authorisation PUBLISH, a refresh with SIP-If-Match, gets 412 (Conditional Request
    Failed) after the server bound the user (TS 24.379 clause 7.3.3 steps 5 and 7); the client considers itself not
    authorised (TS 24.379 clause 7.2.2) and publishes anew without SIP-If-Match (RFC 3903 section 5), and so is
    authorised again, subscribes to its affiliation status and affiliates again (TS 24.379 clauses 9.2.1.3 and
    9.2.1.2), without restarting;
  - a group call with the four clients works afterwards.

Run in a lab with two-minute access tokens (--token-ttl 120), so that each client renews its token, and
refreshes its service authorisation, within about a minute.

Specifications: TS 24.379 V19.7.0 (Rel-19); RFC 3903.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/server-restart-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-server-restart')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    checks, observations = [], {}
    result = dict(scenario='server-restart', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Send a command to a role's running mcx-client."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

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
        raise AssertionError(
            label + ' timed out: ' + json.dumps({role: status(role) for role in roles + ['mcptt-server']})[:4000]
        )

    # ------------------------------------------------------------------------------
    def signed_in(role):
        """The role is authorised and affiliated."""
        client = status(role)
        return bool(client.get('authorized') and client.get('affiliated'))

    # ------------------------------------------------------------------------------
    def sessions():
        """The MCPTT server's group sessions."""
        value = status('mcptt-server').get('sessions') or []
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def server_events(names):
        """The MCPTT server's JSON log entries whose 'event' is one of names, in log order."""
        run = subprocess.run(
            cli + ['logs', '--no-color', '--no-log-prefix', 'mcptt-server'], capture_output=True, text=True, timeout=30
        )
        found = []
        for line in run.stdout.splitlines():
            start = line.find('{"')
            try:
                entry = json.loads(line[start:]) if start >= 0 else {}
            except json.JSONDecodeError:
                continue
            if entry.get('event') in names:
                found.append(entry)
        return found

    # ------------------------------------------------------------------------------
    def server_knows(count):
        """The MCPTT server holds count authorised and count affiliated users."""
        server = status('mcptt-server')
        return server.get('authorized_users') == count and server.get('affiliated_users') == count

    try:
        wait(
            'four clients authorised and affiliated',
            lambda: all(signed_in(role) for role in roles) and server_knows(4),
            90,
        )
        # Restart just after client-a renewed its token: its next renewal is a minute away, which leaves time for
        # the refused call below.
        renewed = status('client-a').get('token_renewals', 0)
        wait('client-a renewed its token', lambda: status('client-a').get('token_renewals', 0) > renewed, 90)
        instance = status('mcptt-server').get('instance_id')
        subprocess.run(cli + ['restart', 'mcptt-server'], check=True, capture_output=True, timeout=120)
        wait(
            'a new MCPTT server instance, nobody authorised',
            lambda: (
                status('mcptt-server').get('ready')
                and status('mcptt-server').get('instance_id') not in (None, '', instance)
                and status('mcptt-server').get('authorized_users') == 0
            ),
            60,
        )
        renewals = {role: status(role).get('token_renewals', 0) for role in roles}

        # TS 24.379 clause 10.1.1.3.1.1 step 2a: no binding at the participating function.
        command('client-a', 'call')
        wait(
            'client-a call refused',
            lambda: (
                status('client-a').get('call_state') == 'idle'
                and (status('client-a').get('last_call_failure') or {}).get('status')
            ),
            15,
        )
        failure = status('client-a').get('last_call_failure') or {}
        observations['refused_call'] = failure
        assert failure.get('status') == 404, f'call from an unknown user answered {failure.get("status")}, not 404'
        assert '141 ' in (failure.get('warning') or '') and 'user unknown to the participating function' in (
            failure.get('warning') or ''
        ), f'404 without Warning 141: {failure.get("warning")!r}'
        checks.append('a call from a user the server does not know: 404 with Warning 141')

        # TS 24.379 clause 7.2.2 and RFC 3903 section 5: the refresh fails with 412, a new publication follows.
        wait(
            'every client renewed its token after the restart',
            lambda: all(status(role).get('token_renewals', 0) > renewals[role] for role in roles),
            150,
        )
        wait(
            'every client authorised and affiliated again, without a restart',
            lambda: all(signed_in(role) for role in roles) and server_knows(4),
            30,
        )
        # TS 24.379 clause 7.3.3: each user is bound (step 5) before its refresh is answered 412 (step 7), and its
        # new publication, without SIP-If-Match, then succeeds.
        entries = server_events({'service_publication_unknown', 'service_authorized'})
        unknown = [entry for entry in entries if entry['event'] == 'service_publication_unknown']
        observations['publication_unknown'] = [entry.get('user_id') for entry in unknown]
        users = {entry.get('user_id') for entry in unknown}
        assert len(users) == len(roles), f'412 after binding for {sorted(users)}, not for the {len(roles)} users'
        for user in users:
            last = max(i for i, entry in enumerate(entries) if entry.get('user_id') == user)
            assert entries[last]['event'] == 'service_authorized', f'{user}: no new publication after the 412'
        checks.append('each refresh answered 412 after the binding, then a new publication authorised')
        observations['clients'] = {
            role: {key: status(role).get(key) for key in ('instance_id', 'token_renewals', 'authorized', 'affiliated')}
            for role in roles
        }

        command('client-a', 'call')
        wait(
            'client-a to client-d in a group call',
            lambda: (
                all(status(role).get('call_state') == 'active' for role in roles)
                and sum(len(session.get('participants', [])) for session in sessions()) == 4
            ),
            30,
        )
        command('client-a', 'hangup')
        wait(
            'every client idle, no session on the server',
            lambda: all(status(role).get('call_state') == 'idle' for role in roles) and not sessions(),
            30,
        )
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)[:4000]
    output = args.artifacts / 'integration/server-restart-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
