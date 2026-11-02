#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The KMS exchange protected with the pre-provisioned TrK and InK (prepare-prearranged-test.py --transport-keys).

client-a holds an InK and a TrK, client-b a TrK only, both shared with the KMS (TS 33.180 clause 5.3.2); client-c and
client-d hold none:
  TK-01 client-a and client-b are service authorised and hold their MCPTT CSK: the identity keys came through the
        signed KMS exchange with the key set wrapped under the TrK (annexes D.2.2, D.3.1 and D.3.3.2);
  TK-02 the KMS verified a signed KMS Initialize and KeyProvision request of each of them and answered each with a
        protected response (signed under the InK, else the TrK, its key set wrapped under the TrK), and refused none;
  TK-03 client-c and client-d are authorised over the TLS profile: no signed request, no protected response;
  TK-04 the status of client-a shows a TrK and an InK, that of client-b a TrK only.
The protected group call of prearranged_scenario then uses the keys.

Specifications: TS 33.180 V19.5.0 (Rel-19) clause 5.3.2, annexes D.2.2, D.3.1 and D.3.3.2.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ['client-a', 'client-b', 'client-c', 'client-d']
PROTECTED = {'client-a': {'trk': True, 'ink': True}, 'client-b': {'trk': True, 'ink': False}}


# ------------------------------------------------------------------------------
def main():
    """Run the checks TK-01 to TK-04 and write kms-transport-keys.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-kms-transport-keys')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    users = {role: json.loads((generated / f'{role}.json').read_text())['mcptt']['user_id'] for role in CLIENTS}
    checks, observations = [], {}
    result = dict(scenario='kms-transport-keys', passed=False, checks=checks, observations=observations)

    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def snapshot():
        """The authorisation and key state of every client, for failure messages."""
        return {
            role: {
                key: status(role).get(key)
                for key in ('authorized', 'xml_protection', 'sign_in_error', 'last_error', 'transport_keys')
            }
            for role in CLIENTS
        }

    def kms_events():
        """The JSON events of the KMS's log."""
        run = subprocess.run(cli + ['logs', '--no-color', '--no-log-prefix', 'kms'], capture_output=True, text=True,
                             timeout=60)
        events = []
        for line in run.stdout.splitlines():
            start = line.find('{')
            if start < 0:
                continue
            try:
                events.append(json.loads(line[start:]))
            except json.JSONDecodeError:
                continue
        return [event for event in events if str(event.get('event', '')).startswith('kms_')]

    def wait(label, predicate, timeout=30):
        """Poll predicate every 0.5 s until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.5)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    try:
        wait(
            'TK-01 client-a (InK and TrK) and client-b (TrK only) are authorised and hold their MCPTT CSK',
            lambda: all(
                status(role).get('authorized') and (status(role).get('xml_protection') or {}).get('csk_held')
                for role in PROTECTED
            ),
            120,
        )
        events = kms_events()
        observations['kms_events'] = events
        for role in PROTECTED:
            for event in ('kms_signed_request', 'kms_protected_response'):
                for operation in ('init', 'keyprov'):
                    if not any(e['event'] == event and e.get('user') == users[role] and e.get('operation') == operation
                               for e in events):
                        raise AssertionError(f'TK-02 no {event} for the {operation} of {role}: {events}')
        refused = [e for e in events if e['event'] == 'kms_signed_request_refused']
        if refused:
            raise AssertionError(f'TK-02 the KMS refused signed requests: {refused}')
        checks.append('TK-02 signed KmsInit and KeyProvision requests verified, protected responses, none refused')
        print(checks[-1], flush=True)
        wait('TK-03 client-c and client-d authorised',
             lambda: all(status(role).get('authorized') for role in ('client-c', 'client-d')), 120)
        events = kms_events()
        others = [e for e in events if e.get('user') in (users['client-c'], users['client-d'])]
        if others:
            raise AssertionError(f'TK-03 clients without keys used the protected exchange: {others}')
        checks.append('TK-03 the clients without keys use the TLS profile')
        print(checks[-1], flush=True)
        for role, expected in PROTECTED.items():
            shown = ((status(role).get('transport_keys') or {}).get('users') or {}).get(users[role])
            if shown != expected:
                raise AssertionError(f'TK-04 {role} status shows {shown}, expected {expected}')
        checks.append('TK-04 the status shows the configured TrK and InK')
        print(checks[-1], flush=True)
        observations['clients'] = snapshot()
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        observations['clients'] = snapshot()
    (args.artifacts / 'kms-transport-keys.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'scenario': 'kms-transport-keys', 'passed': result['passed'], 'error': result.get('error')}),
          flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
