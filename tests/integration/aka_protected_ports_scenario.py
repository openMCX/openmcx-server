#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""AKA-06 (aka_protected_ports.py) in a running aka lab, from client-a's container (an IMS AKA UE).

Once client-a is authorised over its IPsec security associations, aka_protected_ports.py runs in its container (its
network namespace, its address): plaintext requests to the P-CSCF's protected ports from a port outside the security
associations shall go unanswered (TS 33.203 clause 7.1). Its result is written as
integration/aka-protected-ports-results.json.

Specifications: TS 33.203 V19.1.0 (Rel-19).
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


# ------------------------------------------------------------------------------
def main():
    """Run the probe in client-a against the lab of --compose; print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-protected-ports')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    out = args.artifacts / 'integration' / 'aka-protected-ports-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-protected-ports', passed=False)
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                status = json.loads((args.artifacts / 'client-a' / 'status.json').read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                status = {}
            if status.get('authorized') and (status.get('sip_security') or {}).get('port_ps'):
                break
            if time.monotonic() > deadline:
                raise AssertionError('client-a not authorised over IMS AKA')
            time.sleep(0.5)
        subprocess.run(
            cli + ['cp', str(HERE / 'aka_protected_ports.py'), 'client-a:/tmp/aka_protected_ports.py'],
            check=True,
            capture_output=True,
        )
        probe = ['python3', '/tmp/aka_protected_ports.py', '--config', '/config/client-a.json', '--status',
                 '/artifacts/client-a/status.json']
        run = subprocess.run(cli + ['exec', '-T', 'client-a'] + probe, capture_output=True, text=True, timeout=120)
        probes = json.loads(run.stdout.strip().splitlines()[-1])
        result.update(probes)
        failed = [check['name'] + ' (' + check['detail'] + ')' for check in probes.get('checks', [])
                  if not check['passed']]
        if failed or not probes.get('passed'):
            result['error'] = 'failed: ' + '; '.join(failed or ['unknown'])
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
