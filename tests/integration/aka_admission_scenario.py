#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA admission and temporary sets at the P-CSCF (aka_admission.py) in a running aka lab, from client-c's
container, after aka_negative_scenario (same IMS AKA identity of no client).

- Lost challenges (TS 33.203 clauses 7.3.1.4 and 7.4.2a): two REGISTERs challenged without SM7, a third one is
  challenged too; at the P-CSCF only the third challenge's set is left (ip xfrm).
- Concurrent admission (clause 7.1 rule 3): six REGISTERs of the IMPI at once: each answered 401 or 400, every 400
  logged by the P-CSCF as an admission refused, and never more than three sets of these ports stored.
- Temporary expiry (TS 24.229 clause 5.2.2.2, 401 item 4: reg-await-auth, 4 minutes; TS 33.203 clause 7.4.2a): the
  set of the last challenge, never completed, is gone after 240 s, and not before 230 s; the P-CSCF looks every
  second (polling), the check every 2 s.
The result is written as integration/aka-admission-results.json. The scenario takes about five minutes.

Specifications: TS 24.229 V19.7.0, TS 33.203 V19.1.0 (Rel-19).
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TOOLS = 'openmcx-dev:0.4'
LIFETIME = 240  # docker/pcscf.cfg ipsec_temp_set_lifetime (reg-await-auth)


def xfrm(cli, service, port):
    """The SA and policy lines of service's network namespace that name port (ip xfrm state/policy)."""
    cid = subprocess.run(cli + ['ps', '-q', service], capture_output=True, text=True, check=True).stdout.strip()
    out = subprocess.run(
        ['docker', 'run', '--rm', '--cap-add', 'NET_ADMIN', '--network', f'container:{cid}', TOOLS, 'bash', '-c',
         'ip xfrm state; ip xfrm policy'],
        capture_output=True, text=True, timeout=60,
    ).stdout
    return [line.strip() for line in out.splitlines() if f'port {port} ' in line + ' ']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-admission')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    out = args.artifacts / 'integration' / 'aka-admission-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-admission', passed=False, checks=[])
    aka = json.loads((args.compose.resolve().parent / 'generated' / 'aka-probe-aka-probe.json').read_text())

    def check(name, passed, detail):
        result['checks'].append(dict(name=name, passed=bool(passed), detail=detail))

    def probe(step):
        run = subprocess.run(
            cli + ['exec', '-T', 'client-c', 'python3', '/tmp/aka_admission.py', '--config', '/config/client-c.json',
                   '--aka-identity', aka['identity'], '--aka-impi', aka['isim']['impi'], '--step', step],
            capture_output=True, text=True, timeout=120,
        )
        return {int(port): code for port, code in json.loads(run.stdout.strip().splitlines()[-1])['codes'].items()}

    def refusals():
        logs = subprocess.run(cli + ['logs', 'pcscf'], capture_output=True, text=True, timeout=60).stdout
        return logs.count('would hold more than 6 SAs per direction')

    try:
        subprocess.run(cli + ['cp', str(HERE / 'aka_admission.py'), 'client-c:/tmp/aka_admission.py'],
                       check=True, capture_output=True)
        codes = probe('lost')
        challenged = time.monotonic()
        left = {port: bool(xfrm(cli, 'pcscf', port)) for port in codes}
        check('lost challenges: the third registration is challenged', list(codes.values()) == [401, 401, 401],
              f'{codes}')
        check('lost challenges: only the last challenge set is left', left == {40200: False, 40210: False, 40220: True},
              f'{left}')
        before = refusals()
        codes = probe('parallel')
        stored = sum(bool(xfrm(cli, 'pcscf', port)) for port in codes)
        check('concurrent admission: each REGISTER answered 401 or 400',
              all(code in (401, 400) for code in codes.values()), f'{codes}')
        check('concurrent admission: every 400 is a refused admission',
              refusals() - before == list(codes.values()).count(400), f'{refusals() - before} refusals logged')
        check('concurrent admission: at most three sets stored', stored <= 3, f'{stored} sets')
        last = [port for port, code in codes.items() if code == 401]
        if not last:
            raise AssertionError('no challenged REGISTER for the expiry check')
        # The expiry check follows the last set challenged in the lost step if no parallel one stayed.
        watch = next((port for port in reversed(last) if xfrm(cli, 'pcscf', port)), None)
        start = time.monotonic() if watch else challenged
        watch = watch or 40220
        gone = None
        while time.monotonic() - start < LIFETIME + 20:
            if not xfrm(cli, 'pcscf', watch):
                gone = time.monotonic() - start
                break
            time.sleep(2)
        check('temporary expiry: the uncompleted set goes after reg-await-auth',
              gone is not None and LIFETIME - 10 <= gone <= LIFETIME + 10, f'port {watch}, gone after {gone} s')
        failed = [c['name'] + ' (' + c['detail'] + ')' for c in result['checks'] if not c['passed']]
        if failed:
            result['error'] = 'failed: ' + '; '.join(failed)
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
