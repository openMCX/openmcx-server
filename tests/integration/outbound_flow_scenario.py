#!/usr/bin/env python3
"""Reach an MC UE that has no SIP listener over the flow it registered on (RFC 5626).

client-b's listening mcx-client is stopped, and outbound_flow_client.py takes its identity
in a container of its own: one connection to the SIP core, never a listener, and a
.invalid host in Via and Contact. The scenario checks that
  - the core refuses a Contact with an alias parameter, and records the flow as the
    binding's received address;
  - an in-dialog request (the MCPTT server's affiliation status NOTIFY) reaches it over
    the flow;
  - an initial request to its AoR (the INVITE of client-a's private call) reaches it over
    the flow;
  - after it closes the flow, the next private call to it fails at once, and the core
    does not dial the binding;
  - client-a, a listening client, keeps its binding without a received address.

The flow is the SIP Outbound flow of RFC 5626 section 4.2 (registrations); the requests over
it are the MCPTT affiliation status determination procedure (TS 24.379 clause 9.2.1.3) and
the on-demand private call setup (TS 24.379 clause 11.1.1.2.1.1 for the calling client).

Specifications: TS 24.379 V19.7.0 (Rel-19); RFC 5626.
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/outbound-flow-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-outbound-flow')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    compose = json.loads(args.compose.read_text())
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    flow_role = 'client-b'  # client-a's profile may call client-b privately
    debug = '--disable-tls' in compose['services'][flow_role]['command']
    probe_dir = args.artifacts / 'outbound-flow'
    checks, observations = [], {}
    result = dict(scenario='outbound-flow', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def probe():
        """The status.json of outbound_flow_client.py, or {} while it has none."""
        try:
            return json.loads((probe_dir / 'status.json').read_text())
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
        """Record label once predicate() holds; fail on timeout or when the flow client failed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            if probe().get('phase') == 'failed':
                break
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps({'probe': probe(), 'client-a': status('client-a')}))

    # ------------------------------------------------------------------------------
    def failed_call():
        """The SIP status of client-a's last failed call once it is idle again, else a false value."""
        client = status('client-a')
        return client.get('call_state') == 'idle' and (client.get('last_call_failure') or {}).get('status')

    process = None
    try:
        wait('four clients authorized', lambda: all(status(role).get('authorized') for role in roles), 90)
        subprocess.run(cli + ['stop', flow_role], check=True, capture_output=True, timeout=60)
        checks.append(f'listening {flow_role} stopped')
        probe_dir.mkdir(parents=True, exist_ok=True)
        for name in ('status.json', 'stop'):
            (probe_dir / name).unlink(missing_ok=True)
        script = Path(__file__).resolve().parent / 'outbound_flow_client.py'
        process = subprocess.Popen(
            cli
            + [
                'run',
                '--rm',
                '-T',
                '--no-deps',
                '--entrypoint',
                'python3',
                '-v',
                f'{script}:/outbound_flow_client.py:ro',
                flow_role,
                '/outbound_flow_client.py',
                '--config',
                f'/config/{flow_role}.json',
                '--output',
                '/artifacts/outbound-flow',
            ]
            + (['--disable-tls'] if debug else []),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait(
            'flow client registered, authorised and notified over its flow',
            lambda: probe().get('phase') == 'waiting-invite',
            60,
        )

        command('client-a', f"private {configs[flow_role]['mcptt']['user_id']} manual")
        wait('flow client closed its flow after the private call INVITE', lambda: probe().get('phase') == 'closed', 30)
        wait('client-a call refused by the flow client', lambda: failed_call() == 486, 15)
        observations['first_failure'] = status('client-a').get('last_call_failure')

        started = time.monotonic()
        command('client-a', f"private {configs[flow_role]['mcptt']['user_id']} manual")
        wait('client-a call to the closed flow fails', lambda: failed_call() and failed_call() != 486, 15)
        observations['closed_flow_failure'] = status('client-a').get('last_call_failure')
        observations['closed_flow_failure_seconds'] = round(time.monotonic() - started, 2)
        assert observations['closed_flow_failure_seconds'] < 5, 'the call to the closed flow did not fail at once'
        checks.append('the call to the closed flow failed at once')

        (probe_dir / 'stop').write_text('')
        output, _ = process.communicate(timeout=30)
        observations['flow_client'] = probe()
        assert process.returncode == 0 and probe().get('passed'), 'flow client: ' + output[-2000:]
        checks.extend(check['name'] for check in probe()['checks'])

        # The core's log about the flow, and client-a's binding: a listening client's
        # has no received address.
        logs = subprocess.run(
            cli + ['logs', '--no-color', 'sip-core'], capture_output=True, text=True, timeout=60
        ).stdout
        flow = probe()['flow']
        observations['core_log_lines'] = [line.strip() for line in logs.splitlines() if flow in line][-10:]
        # Kamailio logs each connection it opens ("pending outbound connect initialized").
        assert not any('outbound connect' in line and f'remote={flow}' in line for line in logs.splitlines()), (
            'the core opened a connection to the flow client'
        )
        checks.append('the core log shows no connection opened to the flow client')
        query = subprocess.run(
            cli
            + ['exec', '-T', 'client-a', 'python3', '-', '--config', '/config/client-a.json', '--query']
            + (['--disable-tls'] if debug else []),
            input=script.read_text(),
            capture_output=True,
            text=True,
            timeout=60,
        )
        bindings = json.loads(query.stdout.strip().splitlines()[-1])['bindings'] if query.returncode == 0 else None
        observations['client_a_bindings'] = bindings
        assert bindings and not any('received=' in binding or 'alias=' in binding for binding in bindings), (
            f'listening client-a binding changed: {bindings} {query.stderr[-500:]}'
        )
        checks.append('listening client-a binding has no received address')
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)[:4000]
    finally:
        if process and process.poll() is None:
            (probe_dir / 'stop').write_text('')
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
    output = args.artifacts / 'integration/outbound-flow-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
