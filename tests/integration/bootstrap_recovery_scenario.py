#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A sign-in that fails for want of a document or a key recovers on a later attempt; nothing goes out unprotected.

Run with XML protection and mcptt.documents_on_notify (the MCPTT service configuration document comes with the
configuration subscription, TS 24.484 clause 6.3.13.2.2, before the service authorisation). client-c is logged off
(TS 24.379 clause 7.2.1A, so that the server holds no authorisation for it) and restarted while a server it needs
is stopped. client-c restarts as an MCPTT-only client (its generated configuration without "mcdata"), so that its first
read from the CMS is the one the configuration NOTIFY prompts (an MCData user profile would be read before it):
  BR-01 CMS stopped: the configuration subscription stands (TS 24.484 clause 6.3.13.3.2.2 step c: authenticated by
        the access token) but its documents cannot be read, so the protection of the authorisation is not known and
        no authorisation is sent; each later sign-in attempt refreshes the subscription in its dialog while the user
        is not authorised (RFC 6665 section 4.1.2.2; verify_subscription_protection.py: unauthorised-refresh);
  BR-02 the CMS back: a later attempt reads the document and authorises;
  BR-03 KMS stopped: the document is read but the keys cannot be provisioned, so no authorisation is sent; the KMS
        back: a later attempt authorises;
  BR-04 CMS stopped, client-c logged off before any authorisation: its configuration subscription ends with Expires
        0 in its dialog (RFC 6665 section 4.1.2.3; unauthorised-termination); the CMS back, "log-on" signs in again
        and authorises.
No clear or unsigned service authorisation goes out meanwhile (verify_subscription_protection.py and the lab's other
wire checks).

Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.379 V19.8.0 (Rel-19), TS 33.180 V19.5.0 (Rel-19), RFC 6665.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ['client-a', 'client-b', 'client-c', 'client-d']
ROLE = 'client-c'
UNREAD = 'service configuration document could not be read'


# ------------------------------------------------------------------------------
def main():
    """Run the checks BR-01 to BR-04 and write bootstrap-recovery.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-bootstrap-recovery')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    config_path = args.compose.resolve().parent / 'generated' / f'{ROLE}.json'
    original_config = config_path.read_text()
    checks, observations = [], {}
    result = dict(scenario='bootstrap-recovery', passed=False, checks=checks, observations=observations)

    def status(role=ROLE):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def snapshot():
        """The sign-in and authorisation state of every client, for failure messages."""
        keys = ('authorized', 'signed_in', 'sign_in_failures', 'sign_in_error', 'logged_off', 'configuration')
        return {role: {key: status(role).get(key) for key in keys} for role in CLIENTS}

    def command(text, role=ROLE):
        """Run one mcx-client command in the role's container."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    def compose(*words):
        """One docker compose command of the lab."""
        subprocess.run(cli + list(words), check=True, capture_output=True, timeout=120)

    def wait(label, predicate, timeout=30):
        """Poll predicate every 0.2 s until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    def restart_without(service):
        """Log client-c off, then restart it while the service is stopped: a fresh sign-in the server does not
        hold an authorisation for."""
        command('log-off')
        wait(f'{ROLE} logged off', lambda: status().get('logged_off') is True, 30)
        compose('stop', ROLE)
        config = json.loads(original_config)
        config.pop('mcdata', None)
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        compose('stop', service)
        # Not "start": it would start the stopped service again, a dependency of the client.
        compose('up', '-d', '--no-deps', ROLE)

    def failing(reason):
        """The fresh process has failed its sign-in at least twice for the reason (or for another than UNREAD)."""
        state = status()
        error = state.get('sign_in_error') or ''
        return (
            not state.get('authorized')
            and not state.get('logged_off')
            and (state.get('sign_in_failures') or 0) >= 2
            and (UNREAD in error if reason == UNREAD else bool(error) and UNREAD not in error)
        )

    try:
        wait('BR-00 every client authorised', lambda: all(status(role).get('authorized') for role in CLIENTS), 120)

        restart_without('cms')
        wait(
            'BR-01 CMS stopped: sign-in attempts fail on the unread document, no authorisation sent',
            lambda: failing(UNREAD),
            120,
        )
        compose('start', 'cms')
        wait('BR-02 the CMS back: a later attempt authorises', lambda: status().get('authorized') is True, 120)

        restart_without('kms')
        wait('BR-03 KMS stopped: sign-in attempts fail on the keys, no authorisation sent', lambda: failing('keys'), 120)
        compose('start', 'kms')
        wait('BR-03 the KMS back: a later attempt authorises', lambda: status().get('authorized') is True, 120)

        restart_without('cms')
        wait(
            'BR-04 CMS stopped: subscribed, sign-in failing',
            lambda: (status().get('configuration') or {}).get('subscription_status') == 200
            and (status().get('sign_in_failures') or 0) >= 1
            and not status().get('authorized')
            and not status().get('logged_off'),
            120,
        )
        command('log-off')
        wait('BR-04 logged off before any authorisation', lambda: status().get('logged_off') is True, 30)
        compose('start', 'cms')
        command('log-on')
        wait('BR-04 log-on signs in again and authorises', lambda: status().get('authorized') is True, 120)
        observations['clients'] = snapshot()
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        observations['clients'] = snapshot()
    finally:
        # The lab stays whole for the wire checks and the teardown.
        config_path.write_text(original_config)
        for service in ('cms', 'kms'):
            subprocess.run(cli + ['start', service], capture_output=True, timeout=120)
    (args.artifacts / 'bootstrap-recovery.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'scenario': 'bootstrap-recovery', 'passed': result['passed'], 'error': result.get('error')}),
          flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
