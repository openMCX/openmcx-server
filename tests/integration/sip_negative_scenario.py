#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Wire-level authorisation probes (sip_negative.py) in a running lab, from client-a's container.

Once the clients are authorised, sip_negative.py runs in client-a's container, on the lab's network and with
client-a's credentials, and checks the SIP core's digest challenges and refusals (RFC 3261 section 22), the service
authorisation refusal of an invalid access token, 403 with warning "101 service authorisation failed" (TS 24.379
clause 7.3.3 step 6 and, in a lab with MCData, TS 24.282 clause 7.3.3), the authentication of a forged in-dialog
request, and the CMS and IdMS refusals (TS 33.180 annexes B.4.2.2 and B.10). Its result is written as
integration/security-results.json.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
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
    """Run the probes against the lab of --compose; print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-sip-negative')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    services = json.loads(args.compose.read_text()).get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    out = args.artifacts / 'integration' / 'security-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='sip-negative', passed=False)
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                status = json.loads((args.artifacts / 'client-a' / 'status.json').read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                status = {}
            if status.get('authorized'):
                break
            if time.monotonic() > deadline:
                raise AssertionError('client-a not authorised')
            time.sleep(0.5)
        subprocess.run(cli + ['cp', str(HERE / 'sip_negative.py'), 'client-a:/tmp/sip_negative.py'], check=True,
                       capture_output=True)
        probe = ['python3', '/tmp/sip_negative.py', '--config', '/config/client-a.json', '--output',
                 '/tmp/security-results.json']
        probe += [] if tls else ['--disable-tls']
        probe += ['--mcdata'] if 'mcdata-server' in services else []
        run = subprocess.run(cli + ['exec', '-T', 'client-a'] + probe, capture_output=True, text=True, timeout=180)
        probes = json.loads(run.stdout.strip().splitlines()[-1])
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
