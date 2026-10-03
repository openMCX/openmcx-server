#!/usr/bin/env python3
# Lab tooling: runs the integration scenarios of the lab matrix below. It implements no 3GPP
# procedure; the comments of the matrix name the clauses each lab exercises.
#
# Specifications: TS 24.281 V19.6.0, TS 24.379 V19.7.0, TS 24.481 V19.3.0, TS 24.484 V19.6.0,
# TS 33.180 V19.4.0 (all Rel-19); RFC 4825, RFC 5626.
"""Run the lab regression matrix: prepare each lab, run its scenarios, tear it down.

Each lab is a separate Docker Compose project, so labs run in parallel (--jobs);
the call-type labs, whose timers are sensitive to load, run alone afterwards
(--alone-jobs at a time). Every scenario starts on a freshly started lab, and
every lab is torn down after its last scenario, whatever the outcome; its logs are
kept. The summary is printed as a table and written to <output>/summary.json and
summary.md.

To keep the run short, a lab with several scenarios is prepared once per scenario
(unit <lab>.<n>, reported under the lab), so its scenarios run in parallel, and the
longest units start first, by the durations of earlier runs kept in
artifacts/.regress-timings.json (units not timed yet first). --whole-labs runs each
lab's scenarios one after the other on one prepared lab instead. At the end,
tools/lab-clean removes lab containers and volumes left by interrupted runs
(--no-clean to skip it).

Examples:
  tools/regress.py --list
  tools/regress.py --images 0.72 --client-image openmcx-client:0.72 --select smoke    # per-program images
  tools/regress.py --image openmcx:0.72 --client-image openmcx-client:0.72 --select smoke
  tools/regress.py --image openmcx:0.72 --client-image openmcx-client:0.72 --all --jobs 6
  tools/regress.py --image openmcx:0.72 --client-image openmcx-client:0.72 --select mcdata --tls
  tools/regress.py --image openmcx:0.72 --client-image openmcx-client:0.72 --select smoke,mcdata --duration 4h   # soak

The client image is built from the openmcx-client repository (linux/tools/build-image).
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

import lab_images

ROOT = Path(__file__).resolve().parents[1]
# The lab's SIP database with a data directory initialised at build time
# (docker/Dockerfile.sipdb): about 20 s less per lab than the official image.
FAST_DB_IMAGE = 'openmcx-sipdb:8.0-1'
COMPOSE = ROOT / '.cache/deps/docker-compose-linux-x86_64'

MCDATA_SIX = [
    'mcdata_sds_scenario',
    'mcdata_fd_scenario',
    'mcdata_release_scenario',
    'mcdata_status_scenario',
    'mcdata_media_scenario',
]
KEYS = ['--protected', '--key-parameters-iei', '0x79']


# ------------------------------------------------------------------------------
def lab(name, kind, flags, scenarios, tags, call_types=False, no_payload=False):
    """One lab of the matrix: its prepare tool kind ("single"), flags, scenarios and tags."""
    # The call-type runner's timers (the failure scenario's hold and session timers)
    # are sensitive to load, so those labs run alone after the parallel ones.
    return dict(
        name=name,
        kind=kind,
        flags=flags,
        scenarios=scenarios,
        tags=set(tags) | {name},
        call_types=call_types,
        no_payload=no_payload,
        alone=call_types,
    )


# The matrix. The labs come from prepare-prearranged-test.py. --mcdata-release is left out of
# the IP connectivity labs (its tunnel limits), and --priority needs --floor-queue.
LABS = [
    lab('smoke', 'single', [], ['prearranged_scenario'], ['smoke', 'mcptt']),
    # outbound_flow_scenario: a client without a SIP listener, reached over its RFC 5626 flow.
    # MCX Admin (slices B2, C): the accounts managed by MCX Admin; needs --admin-image.
    lab('admin', 'single', ['--admin'], ['prearranged_scenario', 'admin_scenario'], ['admin']),
    # MCX Admin with MCData rights: a user created there uses MCData (ADM-13).
    lab('admin-mcdata', 'single', ['--admin', '--private-call', '--mcdata'], ['admin_scenario'], ['admin']),
    # MCX Admin with protected groups: membership changes re-key the group (ADM-14).
    lab('admin-protected', 'single', ['--admin'] + KEYS, ['admin_scenario'], ['admin', 'protected']),
    lab(
        'smoke-mcdata',
        'single',
        ['--private-call', '--mcdata'],
        ['mcdata_sds_scenario', 'outbound_flow_scenario'],
        ['smoke', 'mcdata'],
    ),
    # Two-minute tokens: the clients renew them before expiry and keep their service authorisation.
    lab(
        'token-refresh',
        'single',
        ['--private-call', '--mcdata', '--token-ttl', '120'],
        ['token_refresh_scenario'],
        ['mcptt', 'mcdata', 'common'],
    ),
    lab(
        'smoke-mcvideo',
        'single',
        ['--mcvideo'],
        ['mcvideo_server_scenario', 'prearranged_scenario'],
        ['smoke', 'mcvideo'],
    ),
    lab(
        'mcvideo',
        'single',
        ['--mcvideo'],
        ['mcvideo_affiliation_scenario', 'mcvideo_group_call_scenario', 'mcvideo_private_call_scenario'],
        ['mcvideo'],
    ),
    lab('mcvideo-emergency', 'single', ['--mcvideo'], ['mcvideo_emergency_scenario'], ['mcvideo']),
    # TS 24.281 clauses 6.3.2, 6.3.3: participating and controlling MCVideo functions on different servers.
    lab(
        'mcvideo-split',
        'single',
        ['--split', '--mcvideo'],
        [
            'mcvideo_affiliation_scenario',
            'mcvideo_group_call_scenario',
            'mcvideo_private_call_scenario',
            'mcvideo_emergency_scenario',
        ],
        ['mcvideo', 'split'],
    ),
    lab('mcvideo-pull-push', 'single', ['--mcvideo'], ['mcvideo_pull_push_scenario'], ['mcvideo']),
    lab('mcvideo-ambient', 'single', ['--mcvideo'], ['mcvideo_ambient_scenario'], ['mcvideo']),
    lab('mcvideo-adhoc', 'single', ['--mcvideo'], ['mcvideo_adhoc_scenario'], ['mcvideo']),
    lab('mcvideo-regroup', 'single', ['--mcvideo'], ['mcvideo_regroup_scenario'], ['mcvideo']),
    lab('mcvideo-functional-alias', 'single', ['--mcvideo'], ['mcvideo_functional_alias_scenario'], ['mcvideo']),
    lab('mcvideo-group-selection', 'single', ['--mcvideo'], ['mcvideo_group_selection_scenario'], ['mcvideo']),
    lab(
        'mcvideo-location',
        'single',
        ['--mcvideo', '--location'],
        ['mcvideo_location_scenario'],
        ['mcvideo', 'location'],
    ),
    lab('mcvideo-protected', 'single', ['--mcvideo'] + KEYS, ['mcvideo_protected_scenario'], ['mcvideo', 'protected']),
    # TS 33.180 clause 9.4.5: an SPK between each pair of MCVideo servers protects the transmission
    # control between them; SRTP video passes the participating servers unchanged.
    lab(
        'mcvideo-protected-split',
        'single',
        ['--split', '--mcvideo'] + KEYS,
        ['mcvideo_protected_scenario'],
        ['mcvideo', 'protected', 'split'],
    ),
    lab(
        'mcvideo-xml',
        'single',
        ['--mcvideo'] + KEYS + ['--xml-protection'],
        ['mcvideo_xml_scenario'],
        ['mcvideo', 'protected'],
    ),
    lab(
        'mcvideo-integrity',
        'single',
        ['--mcvideo'] + KEYS + ['--xml-protection', '--integrity-protection'],
        ['mcvideo_xml_scenario'],
        ['mcvideo', 'protected'],
    ),
    lab('call-types', 'single', ['--private-call', '--broadcast', '--chat', '--adhoc'], [], ['mcptt'], call_types=True),
    lab(
        'call-types-split',
        'single',
        ['--split', '--private-call', '--broadcast', '--chat', '--adhoc'],
        [],
        ['mcptt', 'split'],
        call_types=True,
    ),
    lab('floor-queue', 'single', ['--floor-queue'], ['prearranged_floor_scenario'], ['mcptt']),
    lab('priority', 'single', ['--priority', '--floor-queue'], ['prearranged_priority_scenario'], ['mcptt']),
    lab('first-to-answer', 'single', ['--private-call'], ['first_to_answer_emergency_scenario'], ['mcptt']),
    lab('private-no-floor', 'single', ['--private-call'], ['private_no_floor_scenario'], ['mcptt']),
    lab(
        'private-no-floor-split',
        'single',
        ['--split', '--private-call'],
        ['private_no_floor_scenario'],
        ['mcptt', 'split'],
    ),
    lab(
        'functional-alias',
        'single',
        ['--private-call', '--adhoc', '--functional-alias'],
        ['functional_alias_scenario'],
        ['mcptt'],
    ),
    lab(
        'private-services', 'single', ['--private-call', '--private-services'], ['private_services_scenario'], ['mcptt']
    ),
    lab('regroup', 'single', ['--regroup'], ['regroup_scenario', 'temporary_group_scenario'], ['mcptt']),
    # RFC 4825 section 8.2.5 with TS 24.481 clause 7.2.4 and TS 24.484 clause 8.3.2.3: schema validation of the documents.
    lab(
        'group-management',
        'single',
        ['--group-management'],
        ['group_management_scenario', 'xcap_schema_scenario'],
        ['mcptt', 'common'],
    ),
    # TS 24.481 clause 6.3.13.2.2: the MCData server subscribing to group documents.
    lab(
        'group-management-mcdata',
        'single',
        ['--private-call', '--mcdata', '--group-management'],
        ['mcdata_group_subscription_scenario'],
        ['common', 'mcdata'],
    ),
    lab('location', 'single', ['--priority', '--location'], ['location_scenario'], ['mcptt', 'location']),
    lab('protected-prearranged', 'single', KEYS, ['prearranged_scenario'], ['mcptt', 'protected']),
    lab(
        'protected-private', 'single', ['--private-call'] + KEYS, ['protected_private_scenario'], ['mcptt', 'protected']
    ),
    lab(
        'xml-protection',
        'single',
        ['--private-call'] + KEYS + ['--xml-protection'],
        ['xml_protection_scenario', 'protected_private_scenario', 'prearranged_scenario'],
        ['mcptt', 'protected'],
    ),
    lab(
        'xml-protection-split',
        'single',
        ['--split', '--private-call'] + KEYS + ['--xml-protection'],
        ['xml_protection_scenario', 'prearranged_scenario'],
        ['mcptt', 'protected', 'split'],
    ),
    lab(
        'xml-integrity',
        'single',
        ['--private-call'] + KEYS + ['--xml-protection', '--integrity-protection'],
        ['xml_protection_scenario', 'protected_private_scenario', 'prearranged_scenario'],
        ['mcptt', 'protected'],
    ),
    lab(
        'xml-integrity-split',
        'single',
        ['--split', '--private-call'] + KEYS + ['--xml-protection', '--integrity-protection'],
        ['xml_protection_scenario', 'prearranged_scenario'],
        ['mcptt', 'protected', 'split'],
    ),
    lab('mcdata', 'single', ['--private-call', '--mcdata', '--mcdata-release'], MCDATA_SIX, ['mcdata']),
    lab('mcdata-ipconn', 'single', ['--private-call', '--mcdata'], ['mcdata_ipconn_scenario'], ['mcdata']),
    lab(
        'mcdata-xml',
        'single',
        ['--private-call', '--mcdata', '--mcdata-release'] + KEYS,
        MCDATA_SIX,
        ['mcdata', 'protected'],
        no_payload=True,
    ),
    lab(
        'mcdata-xml-ipconn',
        'single',
        ['--private-call', '--mcdata'] + KEYS,
        ['mcdata_ipconn_scenario'],
        ['mcdata', 'protected'],
        no_payload=True,
    ),
    lab(
        'mcdata-protected',
        'single',
        ['--private-call', '--mcdata'] + KEYS + ['--sign-payloads'],
        ['mcdata_protected_scenario'],
        ['mcdata', 'protected'],
    ),
    lab('mcdata-location', 'single', ['--mcdata', '--location'], ['mcdata_location_scenario'], ['mcdata', 'location']),
    lab(
        'mcdata-location-protected',
        'single',
        ['--mcdata', '--location'] + KEYS,
        ['mcdata_location_scenario'],
        ['mcdata', 'location', 'protected'],
    ),
    lab('msgstore', 'single', ['--mcdata', '--msgstore'], ['mcdata_msgstore_scenario'], ['mcdata']),
]

print_lock = threading.Lock()


# ------------------------------------------------------------------------------
def say(text):
    """Print one line, whole, from any of the lab threads."""
    with print_lock:
        print(text, flush=True)


# ------------------------------------------------------------------------------
def run(command, log=None, timeout=None, check=False):
    """Run command in the repository root with its output appended to log (discarded without one);
    returns the exit status, and raises RuntimeError on failure when check is set."""
    with open(log, 'a') if log else open('/dev/null', 'w') as out:
        result = subprocess.run(command, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        where = f'see {log}' if log else 'its output was discarded'
        raise RuntimeError(f'{command[0]} failed ({result.returncode}), {where}')
    return result.returncode


# ------------------------------------------------------------------------------
def scenario_result(log):
    """The scenario's closing JSON line: its name, verdict and check count."""
    try:
        lines = Path(log).read_text(errors='replace').splitlines()
    except FileNotFoundError:
        return {}
    for line in reversed(lines):
        line = line.strip()
        if line.startswith('{') and '"passed"' in line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
    return {}


# ------------------------------------------------------------------------------
def first_error(log):
    """The first error a log shows: the scenario's JSON error, an exception or a FAIL line."""
    try:
        text = Path(log).read_text(errors='replace')
    except FileNotFoundError:
        return ''
    for pattern in (
        r'"error": "([^"]{0,300})',
        r'((?:AssertionError|RuntimeError|Traceback)[^\n]{0,300})',
        r'(FAIL[^\n]{0,200})',
    ):
        found = re.search(pattern, text)
        if found:
            return found.group(1)
    return ''


# ------------------------------------------------------------------------------
def resource_snapshot(project, path, label):
    """Append each running container's CPU time and peak memory (cgroup v2) to path, for
    tools/perf-compare.py: one JSON line per container, after a scenario or a call-types run."""
    ids = subprocess.run(
        ['docker', 'ps', '-q', '--no-trunc', '--filter', f'label=com.docker.compose.project={project}'],
        capture_output=True,
        text=True,
    ).stdout.split()
    with path.open('a') as out:
        for container_id in ids:
            service = subprocess.run(
                ['docker', 'inspect', '-f', '{{index .Config.Labels "com.docker.compose.service"}}', container_id],
                capture_output=True,
                text=True,
            ).stdout.strip()
            cgroup = Path(f'/sys/fs/cgroup/system.slice/docker-{container_id}.scope')
            try:
                usage = next(
                    int(line.split()[1])
                    for line in (cgroup / 'cpu.stat').read_text().splitlines()
                    if line.startswith('usage_usec')
                )
                peak = int((cgroup / 'memory.peak').read_text())
            except (OSError, StopIteration, ValueError):
                continue
            out.write(json.dumps(dict(run=label, service=service, cpu_usec=usage, memory_peak=peak)) + '\n')


# ------------------------------------------------------------------------------
def run_lab(spec, args, output, stamp):
    """Prepare, run and tear down one lab. Returns one result per scenario."""
    name, lab_name = spec['name'], spec.get('lab', spec['name'])
    directory = output / name
    project = re.sub(r'[^a-z0-9-]', '-', f'rg-{name}-{spec["transport"]}-{stamp}'.lower())[:60]
    compose = [str(COMPOSE), '-p', project, '-f', str(directory / 'compose.json')]
    log = directory.parent / f'{name}.lab.log'
    results = []
    tool = 'prepare-prearranged-test.py'
    flags = list(spec['flags']) + ([] if spec['transport'] == 'tls' else ['--debug-sip'])
    started = time.monotonic()
    say(f'[start] {name} ({" ".join(flags)})')
    try:
        if directory.exists():
            shutil.rmtree(directory)
        if '--admin' in flags:
            if not args.admin_image:
                raise RuntimeError('an admin lab needs --admin-image')
            flags += ['--admin-image', args.admin_image]
        run(
            [
                'python3',
                f'tools/{tool}',
                '--directory',
                str(directory),
                '--project',
                project,
                *(['--images', args.images] if args.images else ['--image', args.image]),
                '--client-image',
                args.client_image,
            ]
            + flags,
            log,
            timeout=600,
            check=True,
        )
        if not args.standard_db:
            path = directory / 'compose.json'
            fixture = json.loads(path.read_text())
            for service_name, service in fixture.get('services', {}).items():
                if service_name.endswith('sip-db') and str(service.get('image', '')).startswith('mysql'):
                    service['image'] = FAST_DB_IMAGE
            path.write_text(json.dumps(fixture, indent=2) + '\n')
        if spec['no_payload']:
            for path in (directory / 'generated').glob('client-*.json'):
                cfg = json.loads(path.read_text())
                cfg['mcdata']['protect_payload'] = False
                path.write_text(json.dumps(cfg, indent=2) + '\n')
        speech = directory / 'artifacts/speech'
        speech.mkdir(parents=True, exist_ok=True)
        for wav in (ROOT / 'artifacts/speech').glob('*.wav'):
            shutil.copy(wav, speech)
        if spec['call_types']:
            run(compose + ['up', '-d', '--wait'], log, timeout=600)
            script = directory / 'call-types.log'
            code = run(
                ['bash', 'tests/integration/run_all_call_types.sh', str(directory), project],
                script,
                timeout=args.timeout * 8,
            )
            resource_snapshot(project, directory / 'resources.jsonl', 'call-types')
            text = script.read_text(errors='replace') if script.exists() else ''
            for line in text.splitlines():
                found = re.match(r'([a-z-]+): (PASS|FAIL.*)$', line.strip())
                if found:
                    results.append(
                        dict(
                            lab=lab_name,
                            scenario=f'call-types/{found.group(1)}',
                            passed=found.group(2) == 'PASS',
                            checks=None,
                            error='' if found.group(2) == 'PASS' else found.group(2),
                            log=str(directory / f'{found.group(1)}.log'),
                        )
                    )
            if not results:
                results.append(
                    dict(
                        lab=lab_name,
                        scenario='call-types',
                        passed=False,
                        checks=None,
                        error=f'runner exited {code}',
                        log=str(script),
                    )
                )
        for entry in spec['scenarios']:
            # A scenario may carry its own arguments.
            scenario, *extra = entry.split()
            run(compose + ['down', '-v', '--remove-orphans'], log, timeout=300)
            for status in (directory / 'artifacts').glob('*/status.json'):
                status.unlink()
            run(compose + ['up', '-d', '--wait'], log, timeout=600)
            scenario_log = directory / f'{"_".join([scenario] + [argument.strip("-") for argument in extra])}.log'
            try:
                code = run(
                    [
                        'python3',
                        f'tests/integration/{scenario}.py',
                        '--compose',
                        str(directory / 'compose.json'),
                        '--artifacts',
                        str(directory / 'artifacts'),
                        '--project',
                        project,
                    ]
                    + extra,
                    scenario_log,
                    timeout=args.timeout,
                )
            except subprocess.TimeoutExpired:
                code = 'timeout'
            # Each scenario's container logs and resource use, before the lab is restarted for the next.
            run(compose + ['logs', '--no-color'], directory / f'{scenario_log.stem}.lab.log', timeout=300)
            resource_snapshot(project, directory / 'resources.jsonl', entry)
            outcome = scenario_result(scenario_log)
            passed = code == 0 and outcome.get('passed', True) is not False
            checks = outcome.get('checks')
            results.append(
                dict(
                    lab=lab_name,
                    scenario=entry,
                    passed=passed,
                    checks=checks if isinstance(checks, int) else (len(checks) if isinstance(checks, list) else None),
                    error='' if passed else (first_error(scenario_log) or f'exit {code}'),
                    log=str(scenario_log),
                )
            )
    except Exception as error:  # preparation or startup failure
        results.append(
            dict(lab=lab_name, scenario='(lab)', passed=False, checks=None, error=str(error)[:300], log=str(log))
        )
    finally:
        run(compose + ['logs', '--no-color'], directory / 'lab.log', timeout=300) if (
            directory / 'compose.json'
        ).exists() else None
        run(compose + ['down', '-v', '--remove-orphans'], log, timeout=300) if (
            directory / 'compose.json'
        ).exists() else None
    minutes = (time.monotonic() - started) / 60
    for result in results:
        result['unit'], result['minutes'] = name, round(minutes, 2)
    say(f'[done]  {name}: {sum(result["passed"] for result in results)}/{len(results)} passed in {minutes:.1f} min')
    return results


TIMINGS = ROOT / 'artifacts/.regress-timings.json'


# ------------------------------------------------------------------------------
def units(labs, whole):
    """The units to run: a lab, or with several scenarios one unit per scenario."""
    out = []
    for spec in labs:
        if whole or spec['call_types'] or len(spec['scenarios']) < 2:
            out.append(dict(spec, lab=spec['name'], key=spec['name']))
            continue
        for index, entry in enumerate(spec['scenarios'], 1):
            out.append(
                dict(
                    spec,
                    name=f'{spec["name"]}.{index}',
                    lab=spec['name'],
                    scenarios=[entry],
                    key=f'{spec["name"]}|{entry}',
                )
            )
    return out


# ------------------------------------------------------------------------------
def load_timings(mode):
    """The unit durations in minutes of earlier runs over transport mode (tcp or tls)."""
    try:
        return json.loads(TIMINGS.read_text()).get(mode, {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ------------------------------------------------------------------------------
def save_timings(mode, finished):
    """Record the durations of the units finished over transport mode, keeping the others."""
    try:
        timings = json.loads(TIMINGS.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        timings = {}
    timings.setdefault(mode, {}).update(finished)
    TIMINGS.parent.mkdir(parents=True, exist_ok=True)
    TIMINGS.write_text(json.dumps(timings, indent=2, sort_keys=True) + '\n')


# ------------------------------------------------------------------------------
def select(names):
    """The labs a --select list names: lab names or tags, "=name" for that lab alone; exits on an
    unknown name."""
    if not names:
        return LABS
    wanted = {name.strip() for name in names.split(',') if name.strip()}
    # "=name" selects that lab alone, where a tag of the same name would select more.
    exact = {name[1:] for name in wanted if name.startswith('=')}
    wanted -= {'=' + name for name in exact}
    chosen = [spec for spec in LABS if spec['tags'] & wanted or spec['name'] in exact]
    unknown = (wanted - set().union(*(spec['tags'] for spec in LABS))) | (exact - {spec['name'] for spec in LABS})
    if unknown:
        sys.exit(f'unknown lab or tag: {", ".join(sorted(unknown))} (see --list)')
    return chosen


# ------------------------------------------------------------------------------
def duration(text):
    """Parse a --duration such as 90m, 4h or 300s (minutes without a unit) into seconds."""
    found = re.fullmatch(r'(\d+(?:\.\d+)?)([smh]?)', text or '')
    if not found:
        raise argparse.ArgumentTypeError('a duration such as 90m or 4h')
    return float(found.group(1)) * {'': 60, 's': 1, 'm': 60, 'h': 3600}[found.group(2)]


# ------------------------------------------------------------------------------
def main():
    """Parse the command line, run the selected labs and write the summaries; returns the exit status."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--image', help='One application image with every program (docker/Dockerfile target openmcx-all)'
    )
    parser.add_argument(
        '--images',
        metavar='TAG',
        help='per-program images openmcx-<program>:TAG instead of --image (tools/build-images TAG)',
    )
    parser.add_argument(
        '--client-image', help='mcx-client image (built by linux/tools/build-image in the openmcx-client repository)'
    )
    parser.add_argument(
        '--select',
        help='Comma-separated lab names or tags, or =name for one lab only (smoke, mcptt, mcdata, protected, '
        'location, common, split)',
    )
    parser.add_argument('--all', action='store_true', help='Every lab in the matrix')
    parser.add_argument(
        '--jobs',
        type=int,
        default=3,
        help='Labs run at once (each is a few to 26 containers); 2 when other labs share the host',
    )
    parser.add_argument(
        '--alone-jobs',
        type=int,
        default=1,
        help='Call-type labs run at once, after the others (default 1; at 2 their timers fail under the load)',
    )
    parser.add_argument(
        '--whole-labs', action='store_true', help='Run a lab\'s scenarios on one prepared lab, one after the other'
    )
    parser.add_argument('--no-clean', action='store_true', help='Skip tools/lab-clean at the end')
    parser.add_argument('--tls', action='store_true', help='SIP over TLS instead of the --debug-sip TCP labs')
    parser.add_argument(
        '--transport',
        choices=['tcp', 'tls', 'both'],
        help='debug TCP (default), TLS, or both at once in one pool (results under <output>/tcp and /tls)',
    )
    parser.add_argument(
        '--admin-image', help='the MCX Admin image, for the admin labs (built from the openmcx-admin repository)'
    )
    parser.add_argument(
        '--standard-db',
        action='store_true',
        help=f'the official MySQL image for the SIP database instead of {FAST_DB_IMAGE}',
    )
    parser.add_argument('--timeout', type=int, default=1500, help='Seconds allowed per scenario')
    parser.add_argument('--duration', type=duration, help='Soak: repeat the selection until this much time has passed')
    parser.add_argument('--output', type=Path, help='Directory for the lab fixtures, logs and summary')
    parser.add_argument('--list', action='store_true', help='List the labs and exit')
    args = parser.parse_args()
    if args.list:
        for spec in LABS:
            print(
                f'{spec["name"]:28} {spec["kind"]:6} {" ".join(spec["flags"]) or "-":55} '
                f'{"run_all_call_types.sh" if spec["call_types"] else " ".join(spec["scenarios"])}'
            )
            print(f'{"":28} tags: {", ".join(sorted(spec["tags"] - {spec["name"]}))}')
        return 0
    if not (args.image or args.images) or not args.client_image:
        parser.error('--image or --images, and --client-image, are required')
    if args.image and args.images:
        parser.error('choose --image or --images')
    if not args.all and not args.select:
        parser.error('choose --all or --select')
    if not COMPOSE.exists():
        parser.error(f'{COMPOSE} is missing: run tools/fetch-dependencies.py')
    labs = LABS if args.all else select(args.select)
    stamp = datetime.datetime.now().strftime('%m%d%H%M%S')
    output = (args.output or ROOT / f'artifacts/regress-{stamp}').resolve()
    output.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------------------
    def inspect(image):
        """The short ID of a local image; a command-line error when it is missing."""
        found = subprocess.run(
            ['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], capture_output=True, text=True
        )
        if found.returncode:
            parser.error(f'image {image} not found')
        return found.stdout.strip().removeprefix('sha256:')[:12]

    if args.images:
        # The run is identified by the per-program images of the servers and common services.
        image_id = '/'.join(inspect(f'{name}:{args.images}') for name in lab_images.SUMMARY_IMAGES)
        args.image = f'openmcx-*:{args.images}'
    else:
        image_id = inspect(args.image)
    client_image_id = inspect(args.client_image)
    transports = {'both': ['tcp', 'tls'], 'tls': ['tls'], 'tcp': ['tcp']}[
        args.transport or ('tls' if args.tls else 'tcp')
    ]
    if not args.standard_db:
        found = subprocess.run(['docker', 'image', 'inspect', FAST_DB_IMAGE], capture_output=True)
        if found.returncode:
            say(f'building {FAST_DB_IMAGE}')
            subprocess.run(
                ['docker', 'build', '-q', '-t', FAST_DB_IMAGE, '-f', 'docker/Dockerfile.sipdb', '.'],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
    timings = {transport: load_timings(transport) for transport in transports}
    plan = [dict(unit, transport=transport) for transport in transports for unit in units(labs, args.whole_labs)]
    # Longest first, across both transports; units without a timing yet are started first.
    plan.sort(key=lambda planned: timings[planned['transport']].get(planned['key'], float('inf')), reverse=True)
    say(
        f'image {args.image} ({image_id}), client {args.client_image} ({client_image_id}), '
        f'{len(labs)} labs in {len(plan)} units ({", ".join(transports)}), {args.jobs} at a time, output {output}'
    )
    results, rounds, deadline = [], 0, time.monotonic() + (args.duration or 0)
    while True:
        rounds += 1
        started = time.monotonic()
        round_output = output / f'round-{rounds}' if args.duration else output

        # ------------------------------------------------------------------------------
        def place(unit):
            """The directory of a unit's results: per transport when several run."""
            where = round_output / unit['transport'] if len(transports) > 1 else round_output
            where.mkdir(parents=True, exist_ok=True)
            return where

        parallel = [unit for unit in plan if not unit['alone']]
        alone = [unit for unit in plan if unit['alone']]
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            batches = list(pool.map(lambda unit: run_lab(unit, args, place(unit), f'{stamp}{rounds}'), parallel))
        with ThreadPoolExecutor(max_workers=max(1, args.alone_jobs)) as pool:
            batches += list(pool.map(lambda unit: run_lab(unit, args, place(unit), f'{stamp}{rounds}'), alone))
        # A unit that could not even start says nothing about its duration.
        for transport in transports:
            save_timings(
                transport,
                {
                    unit['key']: batch[0]['minutes']
                    for unit, batch in zip(parallel + alone, batches)
                    if unit['transport'] == transport and batch and batch[0]['scenario'] != '(lab)'
                },
            )
        for unit, batch in zip(parallel + alone, batches):
            for entry in batch:
                entry['round'], entry['transport'] = rounds, unit['transport']
            results.extend(batch)
        if not args.duration or time.monotonic() >= deadline:
            break
        # A soak whose labs cannot even start would otherwise repeat at once until
        # the deadline: a round in which everything failed within a minute ends it.
        if all(not entry['passed'] for batch in batches for entry in batch) and time.monotonic() - started < 60:
            say(f'round {rounds}: every scenario failed within a minute; stopping the soak')
            break
    headlines = []
    for transport in transports:
        where = output / transport if len(transports) > 1 else output
        where.mkdir(parents=True, exist_ok=True)
        mine = [result for result in results if result['transport'] == transport]
        failed = [result for result in mine if not result['passed']]
        summary = dict(
            image=args.image,
            image_id=image_id,
            client_image=args.client_image,
            client_image_id=client_image_id,
            date=datetime.date.today().isoformat(),
            tls=transport == 'tls',
            rounds=rounds,
            passed=len(mine) - len(failed),
            failed=len(failed),
            results=mine,
        )
        (where / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        headline = (
            f'Image `{args.image}` (`{image_id}`), client `{args.client_image}` (`{client_image_id}`), '
            f'{"TLS" if transport == "tls" else "debug TCP"} SIP, {rounds} round(s): '
            f'**{summary["passed"]} passed, {summary["failed"]} failed**.'
        )
        headlines.append(headline)
        lines = [
            f'# Regression {summary["date"]}',
            '',
            headline,
            '',
            '| Round | Lab | Scenario | Result | Checks | Failure | Log |',
            '|---|---|---|---|---|---|---|',
        ]
        for result in mine:
            lines.append(
                f'| {result["round"]} | {result["lab"]} | {result["scenario"]} | {"PASS" if result["passed"] else "FAIL"} | '
                f'{result["checks"] if result["checks"] is not None else ""} | {result["error"].replace("|", "/")[:160]} | {result["log"]} |'
            )
        (where / 'summary.md').write_text('\n'.join(lines) + '\n')
        say(
            '\n'.join(
                lines[2:3]
                + [f'  FAIL {result["lab"]} {result["scenario"]}: {result["error"][:120]}' for result in failed]
            )
        )
    if len(transports) > 1:
        (output / 'summary.md').write_text(
            '# Regression '
            + datetime.date.today().isoformat()
            + '\n\n'
            + '\n\n'.join(
                f'{transport}: {transport_headline}' for transport, transport_headline in zip(transports, headlines)
            )
            + '\n'
        )
    failed = [result for result in results if not result['passed']]
    leftover = subprocess.run(
        ['docker', 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, text=True
    ).stdout.split()
    left = [container for container in leftover if container.startswith('rg-') and stamp in container]
    if left:
        say(f'warning: containers left behind: {" ".join(left)}')
    if not args.no_clean:
        # Lab projects no longer running (an interrupted run's); images stay.
        run(['python3', 'tools/lab-clean', '--yes', '--no-images'], output / 'lab-clean.log', timeout=900)
    say(f'summary: {output / "summary.md"}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
