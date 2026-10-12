#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The MCData server as an MCS server subscribing to group documents
(TS 24.481 V19.3.0 clause 6.3.13.2.2).

Run against a four-client fixture prepared with --private-call --mcdata
--group-management: the MCData server subscribes, at the MCPTT server's PSI,
to the documents of the groups it reads, keeps them, and drops a kept document
when a NOTIFY reports it changed. Check IDs match
tests/mcptt/GROUP_MANAGEMENT_TEST.md.

Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the MCS server subscription checks MCS-01 to MCS-03 and write
    integration/mcdata-group-subscription-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcs-subscription')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {client: json.loads((generated / f'{client}.json').read_text()) for client in roles}
    ids = {client: configs[client]['mcptt']['user_id'] for client in roles}
    group = configs['client-a']['mcptt']['group_id']
    data_server = json.loads((generated / 'mcdata-server.json').read_text())['mcdata']['service_uri']
    checks, observations = [], {}
    result = dict(scenario='mcdata-group-subscription', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The container's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def documents():
        """The MCData server's group document state, or {}."""
        return status('mcdata-server').get('group_documents') or {}

    # ------------------------------------------------------------------------------
    def counter(name):
        """One group document counter of the MCData server."""
        return (documents().get('counters') or {}).get(name, 0)

    # ------------------------------------------------------------------------------
    def snapshot():
        """The MCData server's documents, the MCPTT server's subscriptions and client-b's last XCAP answer,
        for the failure report."""
        return {
            'mcdata-server': documents(),
            'mcptt-server': status('mcptt-server').get('group_document_subscriptions'),
            'client-b': status('client-b').get('xcap_last'),
        }

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=20):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    def sds(text):
        """Send a group SDS from client-a and wait until client-b has received a new message."""
        before = len(status('client-b').get('mcdata_inbox') or [])
        command('client-a', f'sds-group {group} {text}')
        wait(f'SDS "{text}" reaches client-b', lambda: len(status('client-b').get('mcdata_inbox') or []) > before)

    try:
        wait(
            'four clients authorised for MCPTT and MCData',
            lambda: all(
                status(client).get('authorized') and status(client).get('mcdata_authorized') for client in roles
            ),
            90,
        )
        # MCS-01: the first group SDS reads the group, and the MCData server
        # subscribes to its document at the MCPTT server's PSI.
        sds('first')
        wait(
            'MCS-01 the MCData server subscribes to the group document',
            lambda: (documents().get('subscriptions') or {}).get(group) is True,
        )
        wait(
            'MCS-01 the MCPTT server accepted the MCData server\'s subscription and notified the full state',
            lambda: (
                any(
                    subscription.get('subscriber') == data_server
                    for subscription in (status('mcptt-server').get('group_document_subscriptions') or {}).get(
                        'subscriptions', []
                    )
                )
                and counter('notifies') >= 1
            ),
        )
        # MCS-02: later reads are answered from the kept document.
        sds('second')
        sds('third')
        wait('MCS-02 the kept group document answers later reads', lambda: counter('hits') >= 1)
        reads, changes = counter('reads'), counter('changes')
        observations['reads_before_change'] = reads
        # MCS-03: a change written through XCAP (client-b manages the group) is
        # notified, and the kept copy is dropped; the member is restored after.
        command('client-b', f"group-member remove {group} {ids['client-d']}")
        wait(
            'MCS-03 the MCData server is notified of the change and drops its copy',
            lambda: counter('changes') > changes,
            30,
        )
        sds('fourth')
        wait('MCS-03 the next group SDS reads the changed document again', lambda: counter('reads') > reads)
        command('client-b', f"group-member add {group} {ids['client-d']}")
        observations['counters'] = documents().get('counters')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-group-subscription-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
