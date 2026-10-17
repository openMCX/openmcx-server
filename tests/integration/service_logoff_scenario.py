#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Log-off and the end of a binding (TS 24.379 and TS 24.282 clauses 7.2.1A, 7.3.3 and 7.3.5) in a running lab.

1. client-a logs off with its "log-off" command (TS 24.379 clause 7.2.1A step 4): each server answers its PUBLISH with
   Expires 0 with 200, and the client de-registers; a probe with client-a's configuration (service_logoff.py --phase
   free) is then authorised at once and logs off; client-a's "log-on" authorises it again.
2. service_logoff.py --phase live in client-a's container: log-offs naming no publication are answered 400 or 412 (RFC
   3903), a restarted device's initial publication is authorised and its log-off answered 200 with Expires 0 and the
   entity tag, then 412 (clause 7.3.5).
3. A phone that dies: client-a, authorised again, is killed without logging off. When its service authorisation ends
   (the lab's token lifetime is short), each server removes its binding (clause 7.3.3 step 8: events
   service_binding_removed and mcdata_binding_removed, "service authorisation ended"); client-a, started again, is
   authorised again.
The result is written as integration/service-logoff-results.json.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), IETF RFC 3903.
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
    parser.add_argument('--project', default='openmcx-service-logoff')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    services = json.loads(args.compose.read_text()).get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    mcdata = 'mcdata-server' in services
    extra = ([] if tls else ['--disable-tls']) + (['--mcdata'] if mcdata else [])
    status_file = args.artifacts / 'client-a' / 'status.json'
    out = args.artifacts / 'integration' / 'service-logoff-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='service-logoff', passed=False, phases=[], checks=[])

    # ------------------------------------------------------------------------------
    def status():
        try:
            return json.loads(status_file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                result['checks'].append(label)
                return
            time.sleep(0.5)
        raise AssertionError(label)

    # ------------------------------------------------------------------------------
    def authorised_after(since):
        try:
            return status_file.stat().st_mtime > since and status().get('authorized') and not status().get('logged_off')
        except FileNotFoundError:
            return False

    # ------------------------------------------------------------------------------
    def command(text):
        """Send a command to client-a's running mcx-client."""
        run = subprocess.run(cli + ['exec', '-T', 'client-a', 'mcx-client', '--config', '/config/client-a.json',
                                    '--command', text], capture_output=True, text=True, timeout=15)
        if run.returncode:
            raise RuntimeError(f'client-a {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def probe(phase_name):
        """service_logoff.py in client-a's container: its checks, or the failure."""
        run = subprocess.run(cli + ['exec', '-T', 'client-a', 'python3', '/tmp/service_logoff.py', '--config',
                                    '/config/client-a.json', '--phase', phase_name] + extra,
                             capture_output=True, text=True, timeout=180)
        probes = json.loads(run.stdout.strip().splitlines()[-1])
        result['phases'].append(probes)
        failed = [check['name'] for check in probes.get('checks', []) if not check['passed']]
        if failed or not probes.get('passed'):
            raise AssertionError(f'{phase_name}: ' + ', '.join(failed or [probes.get('error', 'unknown')]))

    # ------------------------------------------------------------------------------
    def removed(service, event_name, user):
        """Whether the service's log has the end of the user's binding at the end of its service authorisation."""
        logs = subprocess.run(cli + ['logs', '--no-log-prefix', service], capture_output=True, text=True).stdout
        for line in logs.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if (entry.get('event') == event_name and entry.get('user_id') == user
                    and entry.get('reason') == 'service authorisation ended'):
                return True
        return False

    try:
        wait('client-a is authorised', lambda: authorised_after(0), 90)
        config = json.loads((args.compose.resolve().parent / 'generated' / 'client-a.json').read_text())
        for name in ('sip_negative.py', 'service_logoff.py'):
            subprocess.run(cli + ['cp', str(HERE / name), f'client-a:/tmp/{name}'], check=True, capture_output=True)

        # 1. The client's log-off and log-on.
        command('log-off')
        wanted = {'mcptt': 200, **({'mcdata': 200} if mcdata else {})}
        wait('client-a logs off: 200 from each server, then its de-REGISTER 200',
             lambda: status().get('logged_off') and status().get('log_off') == wanted
             and status().get('deregistered') == 200)
        probe('free')
        logged_on = time.time()
        command('log-on')
        wait('client-a logs on again', lambda: authorised_after(logged_on), 90)

        # 2. Log-off on the wire.
        probe('live')

        # 3. A phone that dies.
        restarted = time.time()
        subprocess.run(cli + ['restart', 'client-a'], check=True, capture_output=True, timeout=60)
        wait('client-a, restarted, is authorised', lambda: authorised_after(restarted), 90)
        subprocess.run(cli + ['kill', 'client-a'], check=True, capture_output=True, timeout=60)
        wait('the MCPTT server removes client-a\'s binding when its service authorisation ends',
             lambda: removed('mcptt-server', 'service_binding_removed', config['mcptt']['user_id']), 240)
        if mcdata:
            wait('the MCData server removes client-a\'s binding when its service authorisation ends',
                 lambda: removed('mcdata-server', 'mcdata_binding_removed', config['mcdata']['user_id']), 60)
        started = time.time()
        subprocess.run(cli + ['start', 'client-a'], check=True, capture_output=True, timeout=60)
        wait('client-a, started again, is authorised', lambda: authorised_after(started), 90)
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
