#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Clients renew their IdMS access token before it expires and stay service authorised.

They renew it with the refresh token IdMS issued at sign-in (TS 33.180 annex B.5), not by signing in again with the
password: one password sign-in each, then only refreshes.

Run on a lab prepared with a short token lifetime (--token-ttl 120). Service authorisation carries the access token in
SIP PUBLISH (TS 24.379 clause 7.2.2, TS 24.282 clause 7.2.2), and the servers hold the authorisation only until the
token expires. The clients renew the token and PUBLISH it again, so past the first token's expiry they are still
authorised and a private call with speech still works.

Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import POLL_INTERVAL_S

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Watch both clients past their first token expiry, then place a private call with speech; write
    integration/token-refresh-results.json.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-token-refresh')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    site = json.loads((generated / 'site.json').read_text())
    checks = []

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container (raises on failure)."""
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Poll predicate every 0.1 s until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                return
            time.sleep(0.1)
        raise AssertionError(label + ': ' + json.dumps({role: status(role) for role in roles}))

    # ------------------------------------------------------------------------------
    def authorised(role):
        """The role is authorised for MCPTT and MCData and affiliated."""
        state = status(role)
        return bool(state.get('authorized') and state.get('affiliated') and state.get('mcdata_authorized'))

    result = dict(scenario='token-refresh', passed=False, checks=checks)
    try:
        ttl = site['token_ttl_seconds']
        assert ttl <= 300, f'lab token lifetime {ttl} s is too long for this scenario (prepare with --token-ttl 120)'
        wait(
            'both clients authorised for MCPTT and MCData and affiliated',
            lambda: all(authorised(role) for role in roles),
            90,
        )
        # A client that does not report its token expiry is judged by the lab's lifetime.
        started = time.time()
        first = {role: status(role).get('token_expires_at') or int(started + ttl) for role in roles}
        assert all(0 < first[role] - time.time() <= ttl + 5 for role in roles), f'unexpected token expiry {first}'
        checks.append(f'first tokens expire within {ttl} s')
        # Past the first token's expiry (plus margin), authorisation must never have lapsed. The clients write their
        # status every 200 ms, so each status is looked at once per write.
        until = max(first.values()) + 15
        lapses = {role: 0 for role in roles}
        while time.time() < until:
            for role in roles:
                if not authorised(role):
                    lapses[role] += 1
            time.sleep(POLL_INTERVAL_S)
        assert not any(lapses.values()), f'service authorisation lapsed {lapses}'
        checks.append('authorisation held past the first token expiry')
        for role in roles:
            state = status(role)
            assert state.get('token_renewals', 0) >= 1, f'{role} did not renew its token: {state.get("token_renewals")}'
            assert state.get('token_expires_at', 0) > first[role], (
                f'{role} token expiry did not move: {state.get("token_expires_at")} <= {first[role]}'
            )
            assert not state.get('last_error'), f'{role} reported an error: {state.get("last_error")}'
            assert state.get('token_refreshes', 0) >= 1 and state.get('password_logins') == 1, (
                f'{role} renewed by refresh token {state.get("token_refreshes")} times, signed in with the password {state.get("password_logins")} times'
            )
        checks.append('both clients renewed their tokens with the refresh token, signing in with the password once')
        target = configs['client-b']['mcptt']['user_id']
        command('client-a', f'private {target} auto')
        wait(
            'private call set up after the first token expired',
            lambda: all(status(role).get('call_state') == 'active' for role in roles),
            30,
        )
        before = status('client-b').get('received_packets', 0)
        assert (args.artifacts / 'speech' / 'alpha.wav').is_file(), 'missing speech fixture alpha.wav'
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait('speech delivered after renewal', lambda: status('client-b').get('received_packets', 0) >= before + 50, 30)
        wait('floor released', lambda: not status('client-a').get('talking'), 30)
        command('client-a', 'hangup')
        wait('call released', lambda: all(status(role).get('call_state') == 'idle' for role in roles), 30)
        result['token_renewals'] = {role: status(role).get('token_renewals') for role in roles}
        result['token_expires_at'] = {role: [first[role], status(role).get('token_expires_at')] for role in roles}
        result['passed'] = True
    except (AssertionError, KeyError, OSError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = {role: status(role) for role in roles}
    output = args.artifacts / 'integration/token-refresh-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
