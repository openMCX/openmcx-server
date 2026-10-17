#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""One service authorisation per user (TS 24.379 and TS 24.282 clause 7.3.3 steps 3a and 3b) in an admin lab.

The IdMS binds an access token to the account's first MC client ID. MCX Admin gives alice a new first client ID while
her device, client-a, is authorised with the old one: a client with the new one (service_logoff.py --phase other, with
client-a's configuration) is answered 486 with "164 maximum number of service authorizations reached" (MCData: "228
..."), the service configuration document's <max-simultaneous-authorizations> being 1. Once client-a logs off with its
"log-off" command (clause 7.2.1A step 4), the new client is authorised (--phase other-free) and logs off. The account
gets its client ID back and client-a's "log-on" authorises it again. The result is written as
integration/service-limit-results.json.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
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
    """Run the scenario against the lab of --compose; print the result."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', required=True)
    args = parser.parse_args()
    generated = args.compose.resolve().parent / 'generated'
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    compose = json.loads(args.compose.read_text())
    services = compose.get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    mcdata = 'mcdata-server' in services
    extra = ([] if tls else ['--disable-tls']) + (['--mcdata'] if mcdata else [])
    oauth = json.loads((generated / 'client-a.json').read_text())['oauth']
    status_file = args.artifacts / 'client-a' / 'status.json'
    out = args.artifacts / 'integration' / 'service-limit-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='service-limit', passed=False, phases=[], checks=[])

    # ------------------------------------------------------------------------------
    def helper(*words):
        """admin_helper.py with the words in a container of the MCX Admin image on the lab network; its result."""
        run = subprocess.run(
            ['docker', 'run', '--rm', '--network', compose['networks']['mcx']['name'],
             '-v', f'{generated / "tls/ca.crt"}:/ca.crt:ro', '-v', f'{HERE / "admin_helper.py"}:/admin_helper.py:ro',
             '--entrypoint', 'python3', services['mcxadmin']['image'], '/admin_helper.py', *words],
            capture_output=True, text=True, timeout=60)
        if run.returncode:
            raise AssertionError(f'helper {words[0]}: {run.stderr.strip()[-500:]}')
        return json.loads(run.stdout.strip().splitlines()[-1])

    # ------------------------------------------------------------------------------
    def status():
        try:
            return json.loads(status_file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                result['checks'].append(label)
                return
            time.sleep(0.5)
        raise AssertionError(label)

    # ------------------------------------------------------------------------------
    def command(text):
        run = subprocess.run(cli + ['exec', '-T', 'client-a', 'mcx-client', '--config', '/config/client-a.json',
                                    '--command', text], capture_output=True, text=True, timeout=15)
        if run.returncode:
            raise RuntimeError(f'client-a {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def probe(phase_name):
        run = subprocess.run(cli + ['exec', '-T', 'client-a', 'python3', '/tmp/service_logoff.py', '--config',
                                    '/config/client-a.json', '--phase', phase_name] + extra,
                             capture_output=True, text=True, timeout=180)
        probes = json.loads(run.stdout.strip().splitlines()[-1])
        result['phases'].append(probes)
        failed = [check['name'] for check in probes.get('checks', []) if not check['passed']]
        if failed or not probes.get('passed'):
            raise AssertionError(f'{phase_name}: ' + ', '.join(failed or [probes.get('error', 'unknown')]))

    # ------------------------------------------------------------------------------
    def client_ids(token, ids):
        """Set alice's MC client IDs in MCX Admin."""
        current = helper('api', token, 'GET', '/v1/users/alice')
        user = current['body']['user']
        user['client_ids'] = ids
        saved = helper('api', token, 'PUT', '/v1/users/alice', current['etag'], json.dumps(user))
        if saved['status'] != 200:
            raise AssertionError(f'client IDs not saved: {saved}')
        return current['body']['user'].get('client_ids', [])

    try:
        wait('client-a is authorised', lambda: status().get('authorized'), 90)
        for name in ('sip_negative.py', 'service_logoff.py'):
            subprocess.run(cli + ['cp', str(HERE / name), f'client-a:/tmp/{name}'], check=True, capture_output=True)
        token = helper('login', oauth['username'], oauth['password'], oauth['client_id'], oauth['redirect_uri'])['token']
        current = helper('api', token, 'GET', '/v1/users/alice')['body']['user'].get('client_ids', [])
        client_ids(token, ['urn:uuid:7e1f0a52-3c6d-4b8e-9f21-00000000a11c'] + current)
        result['checks'].append('MCX Admin gives alice a new first client ID')
        probe('other')
        command('log-off')
        wait('client-a logs off', lambda: status().get('logged_off') and status().get('deregistered') == 200)
        probe('other-free')
        client_ids(token, current)
        logged_on = time.time()
        command('log-on')
        wait('client-a logs on again',
             lambda: status_file.stat().st_mtime > logged_on and status().get('authorized')
             and not status().get('logged_off'), 90)
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
