#!/usr/bin/env python3
"""Service authorisation by REGISTER through the SIP core's third-party REGISTER.

Run in a lab prepared with --register-auth --mcvideo: the four clients send their access token and client ID for
MCPTT, MCData and MCVideo each in a REGISTER of its own (TS 24.379, TS 24.282 and TS 24.281 clause 7.2.1) instead of
the PUBLISH of clause 7.2.2. The scenario checks that
  - RA-01 each client is authorised for the three services and affiliated;
  - RA-02 the MCPTT, MCData and MCVideo servers authorised each user from a third-party REGISTER (clause 7.3.2);
  - RA-03 a group call with the four clients is set up and released;
  - RA-05 with a short token lifetime (--token-ttl), each client renews its token and authorises again by REGISTER,
    at each of the three servers;
  - RA-04 a client's log-off de-registers it, and the SIP core's third-party REGISTER with Expires 0 removes its
    binding at the three servers.
The wire verifier (verify_third_party_register.py) checks the third-party REGISTERs at the MCPTT server.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.229
(clause 5.4.1.7).
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
    site = json.loads((args.compose.resolve().parent / 'generated' / 'site.json').read_text())
    ttl = site.get('token_ttl_seconds', 3600)

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
    def server_events(names, server='mcptt-server'):
        """A server's JSON log entries whose 'event' is one of names."""
        run = subprocess.run(
            cli + ['logs', '--no-color', '--no-log-prefix', server], capture_output=True, text=True, timeout=30
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
            'RA-01 four clients authorised for MCPTT, MCData and MCVideo, and affiliated',
            lambda: all(
                status(role).get('authorized')
                and status(role).get('mcdata_authorized')
                and status(role).get('mcvideo_authorized')
                and status(role).get('affiliated')
                for role in ROLES
            ),
            90,
        )
        for server, name in (
            ('mcptt-server', 'service_authorized_by_register'),
            ('mcdata-server', 'mcdata_authorised_by_register'),
            ('mcvideo-server', 'service_authorized_by_register'),
        ):
            by_register = {entry.get('user') for entry in server_events({name}, server)}
            if len(by_register) < 4:
                raise AssertionError(f'RA-02 {server} authorised by third-party REGISTER: {sorted(by_register)}')
            checks.append(f'RA-02 the {server} authorised the four users from third-party REGISTERs')
            print(checks[-1], flush=True)
            result[server] = sorted(by_register)
        command('client-a', 'call')
        wait(
            'RA-03 a group call with the four clients',
            lambda: all(status(role).get('call_state') not in (None, 'idle') for role in ROLES),
        )
        command('client-a', 'hangup')
        wait('RA-03 the call is released', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))
        if ttl <= 300:
            # RA-05: the renewal of the token before it expires is a new REGISTER per service (clause 7.2.1).
            for server, name in (
                ('mcptt-server', 'service_authorized_by_register'),
                ('mcdata-server', 'mcdata_authorised_by_register'),
                ('mcvideo-server', 'service_authorized_by_register'),
            ):
                wait(
                    f'RA-05 the four users renewed their authorisation at the {server} by REGISTER',
                    lambda server=server, name=name: all(
                        [entry.get('user') for entry in server_events({name}, server)].count(user) >= 2
                        for user in result[server]
                    ),
                    ttl + 60,
                )
            wait(
                'RA-05 the four clients are still authorised for the three services after the renewal',
                lambda: all(
                    status(role).get('token_renewals', 0) >= 1
                    and status(role).get('authorized')
                    and status(role).get('mcdata_authorized')
                    and status(role).get('mcvideo_authorized')
                    for role in ROLES
                ),
            )
        command('client-d', 'log-off')
        wait(
            'RA-04 the log-off of client-d removes its binding by a third-party REGISTER with Expires 0',
            lambda: all(
                any(
                    entry.get('reason') == 'deregistration'
                    for entry in server_events({'service_binding_removed'}, server)
                )
                for server in ('mcptt-server', 'mcvideo-server')
            )
            and bool(server_events({'mcdata_logged_off'}, 'mcdata-server')),
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
