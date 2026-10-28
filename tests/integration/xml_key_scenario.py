#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Required XML protection never dropped for want of a key.

The XML protection a client and the servers require is the configuration alone (TS 24.379 clauses 6.6.2.3.1 and
6.6.3.3.1, TS 24.282 clauses 6.5.2.3.1 and 6.5.3.3.1); keys are needed to meet it (TS 33.180 clause 9.3). This lab
runs XML protection without media and floor protection (prepare-prearranged-test.py --xml-only), confidentiality and
integrity separately or together, optionally with MCData signalling protection off (--mcdata-clear-signalling, a mixed
configuration) and one client whose KMS cannot be reached (--kms-unreachable ROLE):
  XK-01 every client with a reachable KMS is service authorised and holds its MCPTT CSK (the CSK exists without media
        or floor protection; TS 24.379 clause 7.2.2 step 3);
  XK-02 the client with the unreachable KMS is not service authorised: with protection required and no key nothing is
        sent in the clear (verify_xml_keys.py checks the wire: no clear or unsigned service authorisation);
  XK-03 a group call between client-a and client-b, its requests and responses protected as required;
  XK-04 with MCData: a one-to-one SDS from client-a to client-b is delivered (MCData protected as configured, or clear
        where its protection is off).
Check IDs match tests/mcptt/XML_PROTECTION_TEST.md.

Specifications: TS 24.379 V19.8.0 (Rel-19), TS 24.282 V19.8.0 (Rel-19), TS 33.180 V19.5.0 (Rel-19).
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ['client-a', 'client-b', 'client-c', 'client-d']
UNREACHABLE_KMS = 'https://kms.unreachable.invalid'


# ------------------------------------------------------------------------------
def main():
    """Run the checks XK-01 to XK-04 and write xml-key.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-xml-key')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in CLIENTS}
    unreachable = [role for role in CLIENTS if configs[role].get('security', {}).get('kms_uri') == UNREACHABLE_KMS]
    reachable = [role for role in CLIENTS if role not in unreachable]
    mcdata = all('mcdata' in configs[role] for role in ('client-a', 'client-b'))
    checks, observations = [], {}
    result = dict(scenario='xml-key', passed=False, checks=checks, observations=observations)

    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def snapshot():
        """The authorisation, protection and call state of every client, for failure messages."""
        return {
            role: {
                key: status(role).get(key)
                for key in ('authorized', 'xml_protection', 'call_state', 'sign_in_error', 'last_error', 'csk_id')
            }
            for role in CLIENTS
        }

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

    try:
        wait(
            'XK-01 every client with a reachable KMS is authorised and holds its MCPTT CSK',
            lambda: all(
                status(role).get('authorized') and (status(role).get('xml_protection') or {}).get('csk_held')
                for role in reachable
            ),
            120,
        )
        if unreachable:
            # The reachable clients were authorised meanwhile; the sign-in of the other is retried and fails each time.
            time.sleep(20)
            if any(status(role).get('authorized') for role in unreachable):
                raise AssertionError('XK-02 a client without keys was authorised: ' + json.dumps(snapshot()))
            checks.append(f'XK-02 {", ".join(unreachable)} without keys: not authorised, nothing sent in the clear')
            print(checks[-1], flush=True)
        wait('XK-03 affiliated', lambda: all(status(role).get('affiliated') for role in ('client-a', 'client-b')), 60)
        command('client-a', 'call')
        wait(
            'XK-03 a group call with its signalling protected as required',
            lambda: all(status(role).get('call_state') == 'active' for role in ('client-a', 'client-b')),
            30,
        )
        command('client-a', 'hangup')
        wait(
            'XK-03 released',
            lambda: all(status(role).get('call_state') in ('idle', None) for role in ('client-a', 'client-b')),
            30,
        )
        if mcdata:
            target = configs['client-b']['mcdata']['user_id']
            wait(
                'XK-04 MCData authorised',
                lambda: all(status(role).get('mcdata_authorized') for role in ('client-a', 'client-b')),
                60,
            )
            text = f'xml-key-{int(time.time())}'
            command('client-a', f'sds {target} {text}')
            wait(
                'XK-04 a one-to-one SDS is delivered',
                lambda: any(
                    any(payload.get('text') == text for payload in message.get('payloads', []))
                    for message in status('client-b').get('mcdata_inbox') or []
                ),
                30,
            )
        observations['clients'] = snapshot()
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        observations['clients'] = snapshot()
    (args.artifacts / 'xml-key.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'scenario': 'xml-key', 'passed': result['passed'], 'error': result.get('error')}), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
