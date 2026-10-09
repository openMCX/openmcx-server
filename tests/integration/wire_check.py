#!/usr/bin/env python3
"""Capture a scenario's traffic at its server and check it with the scenario's wire verifier.

The scenarios check the state the clients and servers report; the wire verifiers (verify_*.py) check the messages
themselves, independently of the C++ implementation: their order, their bodies and the messages that must not be
sent. tools/regress.py and run_all_call_types.sh use this module to run both:

  wire_check.py start  --compose C --project P --artifacts A --scenario S [--lab-flags "..."]
  ... the scenario ...
  wire_check.py finish --compose C --project P --artifacts A --scenario S [--lab-flags "..."]

start captures in the network namespace of the scenario's server (the participating and controlling function of a
single-server lab, or the MCData server) and returns once tcpdump listens; finish stops the capture, runs the
verifier and prints one JSON line {"scenario": "S/wire", "passed": ..., "error": ...}; its exit status is that of the
verifier. A scenario without a verifier, a lab with SIP over TLS (the SIP is not readable) and a split lab (the
verifiers read a single server's capture) are skipped: finish prints "skipped" and exits 0.

The capture and the verifier's report are kept as integration/<scenario>-wire.pcap and -wire.json.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MCPTT = 'sip:mcptt@mcx.test'
MCDATA = 'sip:mcdata@mcx.test'


# ------------------------------------------------------------------------------
def verifiers(scenario, flags):
    """The server to capture at and the verifier command lines (without capture and output) of a scenario in a lab
    with flags; None when the scenario has no wire verifier."""
    protected = '--protected' in flags
    if scenario == 'prearranged_scenario':
        if '--mcvideo' in flags or '--admin' in flags:
            return None
        if protected:
            return 'mcptt-server', [['verify_protected.py']]
        return 'mcptt-server', [['verify_prearranged.py']]
    table = {
        'private_call_scenario': ('mcptt-server', [['verify_private_call.py', '--service', MCPTT]]),
        'broadcast_call_scenario': ('mcptt-server', [['verify_broadcast_call.py', '--service', MCPTT]]),
        'chat_call_scenario': (
            'mcptt-server',
            [['verify_chat_call.py', '--service', MCPTT, '--chat-group', 'sip:operations-chat@mcx.test']],
        ),
        'adhoc_call_scenario': ('mcptt-server', [['verify_adhoc_call.py', '--service', MCPTT]]),
        'remote_group_call_scenario': (
            'mcptt-server',
            [['verify_remote_group_call.py', '--service', MCPTT, '--group', 'sip:operations@mcx.test']],
        ),
        'ambient_listening_scenario': ('mcptt-server', [['verify_ambient_listening.py', '--service', MCPTT]]),
        'first_to_answer_emergency_scenario': (
            'mcptt-server',
            [['verify_first_to_answer_emergency.py', '--service', MCPTT, '--emergency-priority', 'mcpttp.15']],
        ),
        'prearranged_priority_scenario': (
            'mcptt-server',
            [
                [
                    'verify_group_priority.py',
                    '--service',
                    MCPTT,
                    '--emergency-priority',
                    'mcpttp.15',
                    '--imminent-priority',
                    'mcpttp.10',
                ]
            ],
        ),
        'functional_alias_scenario': ('mcptt-server', [['verify_functional_alias.py', '--service', MCPTT]]),
        'regroup_scenario': ('mcptt-server', [['verify_regroup.py', '--service', MCPTT]]),
        'location_scenario': ('mcptt-server', [['verify_location.py', '--service', MCPTT]]),
        'protected_private_scenario': ('mcptt-server', [['verify_protected_private.py']]),
        'mcdata_location_scenario': (
            'mcdata-server',
            [['verify_location.py', '--service', MCDATA, '--mcdata'] + (['--protected'] if protected else [])],
        ),
        'mcdata_sds_scenario': ('mcdata-server', [['verify_mcdata_sds.py', '--service', MCDATA]]),
        'mcdata_fd_scenario': ('mcdata-server', [['verify_mcdata_fd.py', '--service', MCDATA]]),
        'mcdata_release_scenario': ('mcdata-server', [['verify_mcdata_release.py', '--service', MCDATA]]),
        'mcdata_status_scenario': ('mcdata-server', [['verify_mcdata_status.py', '--service', MCDATA]]),
        'mcdata_media_scenario': ('mcdata-server', [['verify_mcdata_media.py', '--service', MCDATA]]),
        'mcdata_ipconn_scenario': ('mcdata-server', [['verify_mcdata_ipconn.py', '--service', MCDATA]]),
        'mcdata_protected_scenario': ('mcdata-server', [['verify_mcdata_protected.py', '--results', '{results}']]),
    }
    return table.get(scenario)


# ------------------------------------------------------------------------------
def applicable(args, cli):
    """The server to capture at and the verifiers, or the reason the scenario is skipped."""
    found = verifiers(args.scenario, args.lab_flags.split())
    if not found:
        return None, 'no wire verifier'
    if '--split' in args.lab_flags.split():
        return None, 'split lab'
    # The MCData verifiers decode the clause 15 binary bodies, which protected signalling encrypts (TS 33.180 clause
    # 9.5); a protected lab is checked by verify_mcdata_protected.py and verify_location.py --protected instead.
    clear_only = {
        'mcdata_sds_scenario',
        'mcdata_fd_scenario',
        'mcdata_release_scenario',
        'mcdata_status_scenario',
        'mcdata_media_scenario',
        'mcdata_ipconn_scenario',
    }
    if args.scenario in clear_only and '--protected' in args.lab_flags.split():
        return None, 'protected MCData signalling'
    compose = json.loads(Path(args.compose).read_text())
    services = compose.get('services', {})
    command = ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    if '--disable-tls' not in command:
        return None, 'SIP over TLS'
    if found[0] not in services:
        return None, f'no {found[0]} in the lab'
    return found, ''


# ------------------------------------------------------------------------------
def paths(args):
    """The capture and report of the scenario."""
    base = Path(args.artifacts) / 'integration' / args.scenario.removesuffix('_scenario').replace('_', '-')
    return base.with_name(base.name + '-wire.pcap'), base.with_name(base.name + '-wire.json')


# ------------------------------------------------------------------------------
def start(args, cli):
    """Start the capture in the server's network namespace; return once tcpdump listens."""
    found, reason = applicable(args, cli)
    if not found:
        return 0
    server = subprocess.run(cli + ['ps', '-q', found[0]], capture_output=True, text=True).stdout.strip()
    if not server:
        subprocess.run(cli + ['up', '-d', '--wait', found[0]], capture_output=True, timeout=300)
        server = subprocess.run(cli + ['ps', '-q', found[0]], capture_output=True, text=True).stdout.strip()
    pcap, _ = paths(args)
    pcap.parent.mkdir(parents=True, exist_ok=True)
    name = f'{args.project}-wire'
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    log = pcap.with_suffix('.log')
    with open(pcap, 'wb') as out, open(log, 'wb') as err:
        subprocess.Popen(
            ['docker', 'run', '--rm', '--name', name, '--network', f'container:{server}', '--cap-drop', 'ALL']
            + ['--cap-add', 'NET_RAW', 'openmcx-dev:0.1', 'tcpdump', '-Z', 'root', '-i', 'eth0', '-U']
            + ['--immediate-mode', '-s', '0', '-w', '-', 'tcp or (udp and not port 53)'],
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if b'listening on' in log.read_bytes():
            return 0
        time.sleep(0.2)
    print(f'wire capture of {args.scenario} did not start: {log.read_text(errors="replace")[:300]}', file=sys.stderr)
    return 1


# ------------------------------------------------------------------------------
def finish(args, cli):
    """Stop the capture and run the scenario's verifiers; print one JSON result line."""
    found, reason = applicable(args, cli)
    label = f'{args.scenario}/wire'
    if not found:
        print(json.dumps(dict(scenario=label, passed=True, skipped=reason)))
        return 0
    pcap, report = paths(args)
    # Buffered final packets: tcpdump writes each packet at once (-U, --immediate-mode); a short grace still lets
    # the last responses of the scenario arrive.
    time.sleep(2)
    subprocess.run(['docker', 'stop', '-t', '2', f'{args.project}-wire'], capture_output=True)
    results = (
        Path(args.artifacts)
        / 'integration'
        / f'{args.scenario.removesuffix("_scenario").replace("_", "-")}-results.json'
    )
    errors, reports = [], []
    for index, verifier in enumerate(found[1]):
        output = report if index == 0 else report.with_name(f'{report.stem}-{index}.json')
        command = [sys.executable, str(HERE / verifier[0]), str(pcap)] + [
            str(results) if part == '{results}' else part for part in verifier[1:]
        ]
        command += ['--output', str(output)]
        # tshark reads its preferences from the user's configuration directory; a fresh one keeps them default.
        environment = dict(os.environ, WIRESHARK_CONFIG_DIR=str(pcap.parent / '.wireshark'))
        Path(environment['WIRESHARK_CONFIG_DIR']).mkdir(exist_ok=True)
        run = subprocess.run(command, capture_output=True, text=True, timeout=600, env=environment)
        reports.append(str(output))
        if run.returncode:
            text = (run.stdout + run.stderr).strip().splitlines()
            errors.append(f'{verifier[0]}: ' + ' | '.join(text[-3:])[:400])
    print(json.dumps(dict(scenario=label, passed=not errors, error='; '.join(errors), reports=reports)))
    return 1 if errors else 0


# ------------------------------------------------------------------------------
def main():
    """Parse the command line and start or finish the wire check."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['start', 'finish'])
    parser.add_argument('--compose', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--scenario', required=True)
    parser.add_argument('--lab-flags', default='')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', args.compose]
    return (start if args.action == 'start' else finish)(args, cli)


if __name__ == '__main__':
    raise SystemExit(main())
