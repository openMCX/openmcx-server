#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""AKA-10 (aka_refusals.py) in a running aka-udp lab, on client-a (an IMS AKA UE registered over UDP).

Once client-a is authorised over its IPsec security associations, aka_refusals.py runs in a privileged helper container
joined to client-a's network and PID namespaces: it sends two requests the P-CSCF refuses from client-a's protected
client port, through client-a's security associations, and checks that each refusal comes back over the set (ESP to
port_us) and never unprotected (TS 33.203 clause 7.1, UDP case). Its result is written as
integration/aka-refusals-results.json.

Specifications: TS 33.203 V19.1.0 (Rel-19).
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TOOLS = 'openmcx-dev:0.4'


# ------------------------------------------------------------------------------
def main():
    """Run the probe beside client-a against the lab of --compose; print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-refusals')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    out = args.artifacts / 'integration' / 'aka-refusals-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-refusals', passed=False)
    try:
        status_file = args.artifacts / 'client-a' / 'status.json'
        deadline = time.monotonic() + 90
        while True:
            try:
                status = json.loads(status_file.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                status = {}
            if status.get('authorized') and (status.get('sip_security') or {}).get('port_uc'):
                break
            if time.monotonic() > deadline:
                raise AssertionError('client-a not authorised over IMS AKA')
            time.sleep(0.5)
        cfg = json.loads((args.compose.resolve().parent / 'generated' / 'client-a.json').read_text())
        cid = subprocess.run(cli + ['ps', '-q', 'client-a'], capture_output=True, text=True, check=True).stdout.strip()
        pid = subprocess.run(cli + ['exec', '-T', 'client-a', 'sh', '-c', 'pidof mcx-client'], capture_output=True,
                             text=True, check=True).stdout.split()[0]
        hosts = subprocess.run(cli + ['exec', '-T', 'client-a', 'getent', 'hosts', 'pcscf'], capture_output=True,
                               text=True, check=True).stdout.split()
        ue = subprocess.run(cli + ['exec', '-T', 'client-a', 'sh', '-c', 'hostname -i'], capture_output=True,
                            text=True, check=True).stdout.split()[0]
        run = subprocess.run(
            ['docker', 'run', '--rm', '--privileged', '--network', f'container:{cid}', '--pid', f'container:{cid}',
             '-v', f'{HERE / "aka_refusals.py"}:/probe/aka_refusals.py:ro', '-v', f'{status_file}:/probe/status.json:ro',
             TOOLS, 'python3', '/probe/aka_refusals.py', '--pid', pid, '--pcscf', hosts[0], '--ue', ue, '--status',
             '/probe/status.json', '--identity', cfg['sip']['identity']],
            capture_output=True, text=True, timeout=120,
        )
        lines = run.stdout.strip().splitlines()
        if not lines:
            raise AssertionError(f'probe failed: {run.stderr.strip()[-400:]}')
        probes = json.loads(lines[-1])
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
