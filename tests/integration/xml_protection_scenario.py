#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCPTT XML confidentiality and integrity protection.

Sensitive MCPTT XML (the access token of service authorisation, mcptt-info of group and private calls) is encrypted and
decrypted by every client and server (TS 24.379 clause 6.6.2, TS 33.180 clause 9.3.4) and, with integrity protection
configured, signed and verified (TS 24.379 clause 6.6.3, TS 33.180 clause 9.3.5); nothing is refused.

Run against a fixture prepared with prepare-prearranged-test.py --protected --key-parameters-iei N --xml-protection
(optionally --split and --private-call), after or instead of the call scenarios: it places a group call and, with
--private-call, a private call, then checks that every client and server encrypted and decrypted MCPTT XML and refused
none. Check IDs match tests/mcptt/XML_PROTECTION_TEST.md.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run the checks XP-00 to XP-06 and write xml-protection.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-xml')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in CLIENTS}
    ids = {role: configs[role]['mcptt']['user_id'] for role in CLIENTS}
    servers = [
        path.stem for path in generated.glob('mcptt-*.json') if path.stem.startswith(('mcptt-server', 'mcptt-part'))
    ]
    private = bool(configs['client-a'].get('mcptt', {}).get('private_call')) or bool(
        json.loads((generated / 'site.json').read_text())['users'][0].get('private_call')
    )
    checks, observations = [], {}
    result = dict(scenario='xml-protection', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def counters(role):
        """The role's XML protection counters (enabled, encrypted, decrypted, signed, verified, refused)."""
        return status(role).get('xml_protection') or {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The XML protection counters and call state of every client and server, for failure messages."""
        return {
            role: {
                'xml_protection': counters(role),
                'call_state': status(role).get('call_state'),
                'authorized': status(role).get('authorized'),
                'last_error': status(role).get('last_error'),
            }
            for role in CLIENTS + servers
        }

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
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

    # ------------------------------------------------------------------------------
    def active(roles):
        """Every one of roles is in an active call."""
        return all(status(role).get('call_state') == 'active' for role in roles)

    # ------------------------------------------------------------------------------
    def idle():
        """Every client is idle (or reports no call state)."""
        return all(status(role).get('call_state') in ('idle', None) for role in CLIENTS)

    try:
        wait(
            'XP-00 the clients are authorised with XML protection enabled',
            lambda: all(status(role).get('authorized') and counters(role).get('enabled') for role in CLIENTS),
            120,
        )
        # The client starts a group call only once it is affiliated to the group, and its affiliation PUBLISH follows
        # its authorisation: wait for it before XP-02.
        wait('XP-00 the clients are affiliated', lambda: all(status(role).get('affiliated') for role in CLIENTS), 60)
        wait(
            'XP-01 the service authorisation was protected: each server decrypted the access token',
            lambda: sum(counters(server).get('decrypted', 0) for server in servers) >= len(CLIENTS),
        )
        command('client-a', 'call')
        wait('XP-02 a group call is set up with protected mcptt-info', lambda: active(['client-a', 'client-b']), 30)
        command('client-a', 'hangup')
        wait('XP-02 released', idle, 30)
        if private:
            command('client-a', f"private {ids['client-b']} auto")
            wait(
                'XP-03 a private call is set up with the protected called party',
                lambda: active(['client-a', 'client-b']),
                30,
            )
            command('client-a', 'hangup')
            wait('XP-03 released', idle, 30)
        wait(
            'XP-04 every client encrypted and decrypted MCPTT XML',
            lambda: all(
                counters(role).get('encrypted', 0) > 0 and counters(role).get('decrypted', 0) > 0 for role in CLIENTS
            ),
        )
        wait(
            'XP-04 every server encrypted and decrypted MCPTT XML',
            lambda: all(
                counters(server).get('encrypted', 0) > 0 and counters(server).get('decrypted', 0) > 0
                for server in servers
            ),
        )
        if configs['client-a'].get('security', {}).get('integrity_protection'):
            wait(
                'XP-06 every client and server signed its XML bodies and verified those it received (6.6.3)',
                lambda: all(
                    counters(role).get('signed', 0) > 0 and counters(role).get('verified', 0) > 0
                    for role in CLIENTS + servers
                ),
            )
        if not all(counters(role).get('refused', 0) == 0 for role in CLIENTS + servers):
            raise AssertionError('XP-05 content was refused: ' + json.dumps(snapshot()))
        checks.append('XP-05 no protected content was refused')
        print(checks[-1], flush=True)
        observations['counters'] = {role: counters(role) for role in CLIENTS + servers}
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:3000], flush=True)
    finally:
        (args.artifacts / 'xml-protection.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
