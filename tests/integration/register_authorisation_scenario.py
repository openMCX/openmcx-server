#!/usr/bin/env python3
"""Service authorisation by REGISTER through the SIP core's third-party REGISTER.

Run in a lab prepared with --register-auth: the four clients send their access token and client ID in a REGISTER
(TS 24.379 clause 7.2.1) instead of the PUBLISH of clause 7.2.2. The scenario checks that
  - RA-01 each client is authorised and affiliated;
  - RA-02 the MCPTT server authorised each user from a third-party REGISTER (clause 7.3.2);
  - RA-03 a group call with the four clients is set up and released;
  - RA-04 a client's log-off de-registers it, and the SIP core's third-party REGISTER with Expires 0 removes its
    binding at the MCPTT server.
The wire verifier (verify_third_party_register.py) checks the third-party REGISTER itself.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.229 (clause 5.4.1.7).
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
    integration/register-authorisation-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-register-authorisation')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    checks = []
    result = dict(scenario='register-authorisation', passed=False, checks=checks)

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
    def server_events(names):
        """The MCPTT server's JSON log entries whose 'event' is one of names."""
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

    try:
        wait(
            'RA-01 four clients authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        by_register = {entry.get('user') for entry in server_events({'service_authorized_by_register'})}
        if len(by_register) < 4:
            raise AssertionError(f'RA-02 authorised by third-party REGISTER: {sorted(by_register)}')
        checks.append('RA-02 the MCPTT server authorised the four users from third-party REGISTERs')
        print(checks[-1], flush=True)
        result['users'] = sorted(by_register)
        command('client-a', 'call')
        wait(
            'RA-03 a group call with the four clients',
            lambda: all(status(role).get('call_state') not in (None, 'idle') for role in ROLES),
        )
        command('client-a', 'hangup')
        wait('RA-03 the call is released', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))
        command('client-d', 'log-off')
        wait(
            'RA-04 the log-off of client-d removes its binding by a third-party REGISTER with Expires 0',
            lambda: any(
                entry.get('reason') == 'deregistration' for entry in server_events({'service_binding_removed'})
            ),
        )
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'register-authorisation-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
