#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A refresh of the affiliation status subscription keeps the affiliation and the call.

The client asks for Expires 4294967295 (TS 24.379 clause 9.2.1.3 step 4) and re-subscribes in the dialog before the
duration the server grants ends (RFC 6665 section 4.1.2.1); the refresh-affiliation command does it at once. The
scenario checks that
  - AR-01 during a group call, client-b's in-dialog re-SUBSCRIBE is answered, client-b stays affiliated and the call
    goes on for all four;
  - AR-02 after the refresh, a new group call still reaches client-b.

Specifications: RFC 6665, TS 24.379 V19.7.0 (Rel-19).
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
    integration/affiliation-refresh-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-affiliation-refresh')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    checks = []
    result = dict(scenario='affiliation-refresh', passed=False, checks=checks)

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

    # ------------------------------------------------------------------------------
    def logged(role, name, since):
        """True once the role's log since `since` has the event `name`."""
        out = subprocess.run(cli + ['logs', '--no-color', '--since', since, role], capture_output=True, text=True)
        return f'"event":"{name}"' in out.stdout

    try:
        wait(
            'four clients authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        command('client-a', 'call')
        wait('AR-01 a group call with the four clients', in_call(ROLES))
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 1))
        command('client-b', 'refresh-affiliation')
        wait(
            'AR-01 client-b\'s affiliation status subscription is refreshed in its dialog',
            lambda: logged('client-b', 'affiliation_subscription_refreshed', since),
        )
        if logged('client-b', 'affiliation_subscription_refresh_failed', since):
            raise AssertionError('AR-01 client-b\'s refresh was refused')
        time.sleep(2)
        wait('AR-01 client-b stays affiliated', lambda: status('client-b').get('affiliated'), 5)
        wait('AR-01 the call goes on for all four', in_call(ROLES), 5)
        command('client-a', 'hangup')
        wait('AR-01 the call is released', idle)
        command('client-a', 'call')
        wait('AR-02 a new group call still reaches client-b', in_call(ROLES))
        command('client-a', 'hangup')
        wait('AR-02 the call is released', idle)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'affiliation-refresh-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
