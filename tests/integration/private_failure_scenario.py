#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Private call refusals and the commencement modes the server must not refuse, checked on the wire.

The lab is generated with --private-call --manual-only-caller: client-a may call client-b and client-c, client-d may
make private calls with manual commencement only and cannot be called. private_probe.py, run in client-a's
container, sends raw requests as client-a. The scenario checks that
  - PF-01: an INVITE with an Answer-Mode value RFC 5373 does not define is not refused for it (RFC 5373 section 2),
    nor one with Priv-Answer-Mode "Manual" (TS 24.379 clause 11.1.1.3.1.1 step 18 a): to client-d, both get the
    refusal of the target, 403 (Forbidden) with warning 144 (step 11 e), and client-d is not called;
  - PF-02: a BYE and a re-INVITE in a dialog the server does not have get 481 (Call/Transaction Does Not Exist)
    (RFC 3261 sections 15.1.2 and 12.2.2);
  - PF-03: client-d's private call with automatic commencement is refused with 403 (Forbidden) and warning 125
    (step 11 a);
  - PF-04: with client-a in a private call with client-b, the limit of the lab (one call), a further private call
    of client-a is refused with 486 (Busy Here) and warning 124, client-c is not called and the call goes on.

Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 3261, RFC 5373.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/private-failure-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-private-failure')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    compose = json.loads(args.compose.read_text())
    services = compose.get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    generated = args.compose.resolve().parent / 'generated'
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcptt']['user_id'] for role in ROLES}
    checks, observations = [], {}
    result = dict(scenario='private-failure', passed=False, checks=checks, observations=observations)

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
    def check(label, condition, detail=''):
        """Record label when condition holds; fail otherwise."""
        if not condition:
            raise AssertionError(f'{label}: {detail}')
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def probe(phase, target):
        """private_probe.py in client-a's container: {check: [status, warning]}."""
        run = subprocess.run(
            cli + ['exec', '-T', 'client-a', 'python3', '/tmp/private_probe.py', '--config', '/config/client-a.json',
                   '--phase', phase, '--target', target] + ([] if tls else ['--disable-tls']),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if run.returncode:
            raise RuntimeError(f'private_probe.py {phase}: {run.stderr.strip()[-2000:]}')
        outcomes = json.loads(run.stdout.strip().splitlines()[-1])
        observations[phase] = outcomes
        return outcomes

    # ------------------------------------------------------------------------------
    def idle(roles=ROLES):
        return all(status(role).get('call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning):
        """A predicate: role is idle and its last call failed with the SIP status code and the Warning text."""
        return lambda: (
            status(role).get('call_state') == 'idle'
            and (status(role).get('last_call_failure') or {}).get('status') == code
            and warning in (status(role).get('last_call_failure') or {}).get('warning', '')
        )

    try:
        wait(
            'four clients authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        for name in ('sip_negative.py', 'private_probe.py'):
            subprocess.run(cli + ['cp', str(HERE / name), f'client-a:/tmp/{name}'], check=True, capture_output=True)

        outcomes = probe('idle', ids['client-d'])
        warning = '144 user not authorised to call this particular user'
        for name in ('answer_mode_unknown', 'priv_answer_mode_manual'):
            code, text = outcomes[name]
            check(f'PF-01 {name}: 403 with warning 144, not a commencement refusal', code == 403 and warning in text,
                  f'{code} {text}')
        check('PF-01 client-d is not called', idle(['client-d']))
        for name in ('bye_unknown_dialog', 'reinvite_unknown_dialog'):
            check(f'PF-02 {name}: 481', outcomes[name][0] == 481, str(outcomes[name]))

        command('client-d', f"private {ids['client-b']} auto")
        wait(
            'PF-03 client-d\'s automatic commencement call refused with 403 and warning 125',
            rejected('client-d', 403, '125 user not authorised to make private call with automatic commencement'),
        )
        check('PF-03 client-b is not called', idle(['client-b']))

        command('client-a', f"private {ids['client-b']} auto")
        wait('PF-04 a private call between client-a and client-b',
             lambda: all(status(role).get('call_state') not in (None, 'idle') for role in ('client-a', 'client-b')))
        outcomes = probe('busy', ids['client-c'])
        code, text = outcomes['private_call_limit']
        check('PF-04 a further private call of client-a: 486 with warning 124',
              code == 486 and '124 maximum number of private calls reached' in text, f'{code} {text}')
        check('PF-04 client-c is not called', idle(['client-c']))
        check('PF-04 the call goes on',
              all(status(role).get('call_state') not in (None, 'idle') for role in ('client-a', 'client-b')))
        command('client-a', 'hangup')
        wait('PF-04 the call is released', idle)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'private-failure-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
