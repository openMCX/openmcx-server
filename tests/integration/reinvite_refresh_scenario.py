#!/usr/bin/env python3
"""A session refresh by re-INVITE without MC service information keeps the call.

A third-party client may refresh its session with a re-INVITE carrying its current offer and no mcptt-info (RFC 4028
section 7.4); the lab clients refresh with UPDATE and send one only on the refresh-reinvite command. The scenario
checks that
  - RR-01 in a group call, client-b's refresh re-INVITE is answered 200 (OK) and the call goes on for all four;
  - RR-02 in a private call, client-a's refresh re-INVITE is answered 200 (OK) and the call goes on.

Specifications: RFC 4028, RFC 3264 section 8, TS 24.379 V19.7.0 (Rel-19).
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
    integration/reinvite-refresh-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-reinvite-refresh')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    checks = []
    result = dict(scenario='reinvite-refresh', passed=False, checks=checks)

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
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps({role: status(role) for role in ROLES})[:3000])

    # ------------------------------------------------------------------------------
    def in_call(roles):
        return lambda: all(status(role).get('call_state') not in (None, 'idle') for role in roles)

    # ------------------------------------------------------------------------------
    def idle():
        return all(status(role).get('call_state') == 'idle' for role in ROLES)

    try:
        wait(
            'four clients authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        command('client-a', 'call')
        wait('RR-01 a group call with the four clients', in_call(ROLES))
        command('client-b', 'refresh-reinvite')
        wait('RR-01 client-b\'s refresh re-INVITE is answered 200', lambda: status('client-b').get('last_refresh') == 200)
        time.sleep(2)
        wait('RR-01 the call goes on for all four', in_call(ROLES), 5)
        command('client-a', 'hangup')
        wait('RR-01 the call is released', idle)
        command('client-a', 'private sip:bob.mcptt@mcx.test')
        wait('RR-02 a private call between client-a and client-b', in_call(['client-a', 'client-b']))
        command('client-a', 'refresh-reinvite')
        wait(
            'RR-02 client-a\'s refresh re-INVITE is answered 200',
            lambda: status('client-a').get('last_refresh') == 200,
        )
        time.sleep(2)
        wait('RR-02 the call goes on', in_call(['client-a', 'client-b']), 5)
        command('client-a', 'hangup')
        wait('RR-02 the call is released', idle)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'reinvite-refresh-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
