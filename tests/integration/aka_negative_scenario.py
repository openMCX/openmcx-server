#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA refusals (aka_negative.py) in a running aka lab, from client-c's container (a SIP digest client).

Once client-c is authorised, aka_negative.py runs in its container, on the lab's network and with its
credentials: the P-CSCF's 421 (Extension Required) without a Security-Client (RFC 3329 clause 2.3.1), the refusal
of a SIP digest identity through the P-CSCF and of a SIP digest REGISTER of an IMS AKA identity at the SIP core
(TS 29.228 clause 6.3.1 step 4, TS 33.180 clause 6.2.1), and the IMS AKA challenge as the UE receives it (TS 24.229
clauses 5.2.2.2 and 5.4.1.2.1A), and that a new challenge deletes the IMPI's registration SAs (TS 33.203 clauses
7.3.1.4 and 7.4.2a; AKA-09: at the P-CSCF only the last challenge's set, protected client port 40130, is left, none of
the earlier ones of ports 40100, 40110 and 40120). Its result is written as integration/aka-negative-results.json.

Specifications: TS 24.229 V19.7.0, TS 29.228 V19.2.0, TS 33.180 V19.4.0, TS 33.203 V19.1.0 (Rel-19); RFC 3329.
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
def xfrm(cli, service, port):
    """The SA and policy lines of service's network namespace that name port (ip xfrm state/policy)."""
    cid = subprocess.run(cli + ['ps', '-q', service], capture_output=True, text=True, check=True).stdout.strip()
    out = subprocess.run(
        ['docker', 'run', '--rm', '--cap-add', 'NET_ADMIN', '--network', f'container:{cid}', TOOLS, 'bash', '-c',
         'ip xfrm state; ip xfrm policy'],
        capture_output=True, text=True, timeout=60,
    ).stdout
    return [line.strip() for line in out.splitlines() if f'port {port} ' in line + ' ']


# ------------------------------------------------------------------------------
def main():
    """Run the probes against the lab of --compose; print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-negative')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    services = json.loads(args.compose.read_text()).get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-c', {}).get('command', []))
    out = args.artifacts / 'integration' / 'aka-negative-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-negative', passed=False)
    # The lab's IMS AKA identity that no client registers with (tools/provision.py aka_probes).
    aka = json.loads((args.compose.resolve().parent / 'generated' / 'aka-probe-aka-probe.json').read_text())
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                status = json.loads((args.artifacts / 'client-c' / 'status.json').read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                status = {}
            if status.get('authorized'):
                break
            if time.monotonic() > deadline:
                raise AssertionError('client-c not authorised')
            time.sleep(0.5)
        subprocess.run(
            cli + ['cp', str(HERE / 'aka_negative.py'), 'client-c:/tmp/aka_negative.py'],
            check=True,
            capture_output=True,
        )
        probe = [
            'python3',
            '/tmp/aka_negative.py',
            '--config',
            '/config/client-c.json',
            '--aka-identity',
            aka['identity'],
            '--aka-impi',
            aka['isim']['impi'],
        ]
        probe += [] if tls else ['--disable-tls']
        run = subprocess.run(cli + ['exec', '-T', 'client-c'] + probe, capture_output=True, text=True, timeout=120)
        probes = json.loads(run.stdout.strip().splitlines()[-1])
        # AKA-09 at the P-CSCF: the registration SAs of the earlier challenges are gone, the last one's are there.
        left = {port: xfrm(cli, 'pcscf', port) for port in (40100, 40110, 40120, 40130)}
        probes.setdefault('checks', []).append(dict(
            name='AKA-09 a new challenge deletes the registration SAs of the IMPI (TS 33.203 clause 7.4.2a)',
            passed=not any(left[port] for port in (40100, 40110, 40120)) and bool(left[40130]),
            detail='; '.join(f'{port}: {len(lines)} lines' for port, lines in left.items()),
        ))
        probes['passed'] = probes.get('passed', False) and probes['checks'][-1]['passed']
        result.update(probes)
        failed = [check['name'] for check in probes.get('checks', []) if not check['passed']]
        if failed or not probes.get('passed'):
            result['error'] = 'failed: ' + ', '.join(failed or [probes.get('error_type', 'unknown')])
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
