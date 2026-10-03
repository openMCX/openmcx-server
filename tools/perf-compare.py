#!/usr/bin/env python3
# Lab tooling, no 3GPP behaviour: compares the resource use of two regression runs.
"""Compare the resource use of two regression runs (tools/regress.py --output DIR).

For each server role (mcptt-server, mcdata-server, mcvideo-server, the common services, the
clients) it sums the CPU time and takes the peak memory the containers used over the same
labs, from the resources.jsonl files regress.py writes, and compares the lab durations.
Used to show that a refactoring does not cost performance:

  tools/perf-compare.py artifacts/perf-before artifacts/perf-after [--threshold 10]

Prints a table; exits 1 when a role uses more than --threshold percent more CPU time or
peak memory in the second run than in the first.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROLES = {
    'mcptt-server': 'MCPTT server',
    'mcx-server': 'MCPTT server',  # the container's name in runs before 2026-10-01
    'mcdata-server': 'MCData server',
    'mcvideo-server': 'MCVideo server',
    'sip-core': 'SIP core',
}


# ------------------------------------------------------------------------------
def role_of(service):
    """The role a lab service belongs to: a server by name, the clients and the common services grouped."""
    if service in ROLES:
        return ROLES[service]
    if service.startswith('client-'):
        return 'clients'
    if service in (
        'idms',
        'gms',
        'cms',
        'kms',
        'lms',
        'credentials',
        'content-server',
        'message-store',
        'notification-server',
        'http-proxy',
        'mcx-user-db',
    ):
        return 'common services'
    return None


# ------------------------------------------------------------------------------
def labs_of(run_directory):
    """The labs (directories holding a resources.jsonl, relative to the run) a run measured."""
    return {path.parent.relative_to(run_directory) for path in Path(run_directory).rglob('resources.jsonl')}


# ------------------------------------------------------------------------------
def load(run_directory, labs):
    """CPU seconds (summed) and peak memory (max) per role, and the minutes per lab."""
    cpu, memory = defaultdict(float), defaultdict(int)
    for path in Path(run_directory).rglob('resources.jsonl'):
        if path.parent.relative_to(run_directory) not in labs:
            continue
        for line in path.read_text().splitlines():
            sample = json.loads(line)
            role = role_of(sample['service'])
            if role:
                cpu[role] += sample['cpu_usec'] / 1e6
                memory[role] = max(memory[role], sample['memory_peak'])
    minutes = {}
    for path in Path(run_directory).rglob('summary.json'):
        for result in json.loads(path.read_text()).get('results', []):
            lab = result.get('unit', result.get('lab'))
            if Path(path.parent.relative_to(run_directory), lab) in labs:
                minutes[(path.parent.name, lab)] = result.get('minutes', 0)
    return cpu, memory, minutes


# ------------------------------------------------------------------------------
def change(before, after):
    """The change from before to after in percent of before; 0 when before is 0."""
    return (after - before) * 100 / before if before else 0.0


# ------------------------------------------------------------------------------
def main():
    """Compare the two runs, print the table and return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument('--threshold', type=float, default=10.0, help='percent worse that fails (default 10)')
    args = parser.parse_args()
    # Only the labs both runs measured count, so that a full regression compares with a smaller baseline.
    labs = labs_of(args.before) & labs_of(args.after)
    print(f'{len(labs)} labs measured in both runs')
    cpu_before, memory_before, minutes_before = load(args.before, labs)
    cpu_after, memory_after, minutes_after = load(args.after, labs)
    worse = []
    print(
        f'{"role":18} {"CPU s before":>13} {"after":>9} {"change":>8}   {"peak MB before":>15} {"after":>8} {"change":>8}'
    )
    for role in sorted(set(cpu_before) | set(cpu_after)):
        cpu_change = change(cpu_before[role], cpu_after[role])
        memory_change = change(memory_before[role], memory_after[role])
        print(
            f'{role:18} {cpu_before[role]:13.1f} {cpu_after[role]:9.1f} {cpu_change:+7.1f}%   '
            f'{memory_before[role] / 2**20:15.1f} {memory_after[role] / 2**20:8.1f} {memory_change:+7.1f}%'
        )
        if cpu_change > args.threshold or memory_change > args.threshold:
            worse.append(role)
    total_before, total_after = sum(minutes_before.values()), sum(minutes_after.values())
    print(f'{"lab minutes":18} {total_before:13.1f} {total_after:9.1f} {change(total_before, total_after):+7.1f}%')
    if worse:
        print(f'more than {args.threshold:.0f} % worse: {", ".join(worse)}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
