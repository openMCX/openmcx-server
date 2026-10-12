#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Affiliation PUBLISH refusals and per-group outcomes, checked on the wire.

Once the clients are authorised and affiliated, affiliation_probe.py, run in client-a's container, sends raw
affiliation PUBLISH requests as client-a to the MCPTT server and, in a lab with MCData, to the MCData server. The
scenario checks that
  - a PUBLISH without Expires, or with Expires 3600, is answered 423 (Interval Too Brief) with Min-Expires
    4294967295 (TS 24.379 clause 9.2.2.2.3 step 5, TS 24.282 clause 8.3.2.3 step 5);
  - an initial publication naming a group the user is a member of and one it is not is answered 200 (OK)
    (step 8), and the server affiliates the user to the member group only: the controlling function refuses the
    other (TS 24.379 clause 9.2.2.3.3 step 5) and the participating function removes it (clause 9.2.2.2.6);
  - a SIP-If-Match with an entity tag the server never issued gets 412 (Conditional Request Failed), the current
    one 200 (OK) (RFC 3903 section 6).

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 3903.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MEMBER = 'sip:operations@mcx.test'
NON_MEMBER = 'sip:operations-parallel@mcx.test'
MAX = '4294967295'


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/affiliation-publish-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-affiliation-publish')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    compose = json.loads(args.compose.read_text())
    services = compose.get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    mcdata = 'mcdata-server' in services
    checks, observations = [], {}
    result = dict(scenario='affiliation-publish', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out')

    # ------------------------------------------------------------------------------
    def expect(label, condition, detail=None):
        """Record label if condition holds; fail with detail otherwise."""
        if not condition:
            raise AssertionError(f'{label}: {json.dumps(detail)[:2000]}')
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def events(server, names):
        """A server's JSON log entries whose 'event' is one of names, in log order."""
        run = subprocess.run(
            cli + ['logs', '--no-color', '--no-log-prefix', server], capture_output=True, text=True, timeout=30
        )
        found = []
        for line in run.stdout.splitlines():
            start = line.find('{"')
            try:
                entry = json.loads(line[start:]) if start >= 0 else {}
            except json.JSONDecodeError:
                continue
            if entry.get('event') in names:
                found.append(entry)
        return found

    try:
        wait(
            'client-a authorised and affiliated',
            lambda: status('client-a').get('authorized') and status('client-a').get('affiliated')
            and (not mcdata or status('client-a').get('mcdata_affiliated', True)),
            90,
        )
        for name in ('affiliation_probe.py', 'sip_negative.py'):
            subprocess.run(cli + ['cp', str(HERE / name), f'client-a:/tmp/{name}'], check=True, capture_output=True)
        probe = ['python3', '/tmp/affiliation_probe.py', '--config', '/config/client-a.json', '--member', MEMBER,
                 '--non-member', NON_MEMBER]
        probe += [] if tls else ['--disable-tls']
        probe += ['--mcdata'] if mcdata else []
        run = subprocess.run(cli + ['exec', '-T', 'client-a'] + probe, capture_output=True, text=True, timeout=120)
        if run.returncode:
            raise AssertionError('affiliation probe: ' + (run.stderr.strip() or run.stdout.strip())[-2000:])
        outcomes = json.loads(run.stdout.strip().splitlines()[-1])
        observations['responses'] = outcomes
        for service, seen in outcomes.items():
            for name in ('no_expires', 'expires_3600'):
                code, headers = seen[name]
                expect(f'{service}: {name} -> 423 with Min-Expires {MAX}',
                       code == 423 and headers.get('min-expires') == MAX, seen[name])
            code, headers = seen['initial_member_and_non_member']
            expect(f'{service}: initial publication with a non-member group -> 200 with SIP-ETag and Expires {MAX}',
                   code == 200 and headers.get('sip-etag') and headers.get('expires') == MAX, seen)
            expect(f'{service}: unknown SIP-If-Match -> 412', seen['unknown_etag'][0] == 412, seen['unknown_etag'])
            expect(f'{service}: current SIP-If-Match -> 200', seen['current_etag'][0] == 200, seen['current_etag'])

        # The per-group outcome: the member group affiliated, the other refused.
        for server, refused, affiliated, prefix in (
            ('mcptt-server', 'affiliation_refused', 'affiliated', 'mcptt'),
        ) + ((('mcdata-server', 'mcdata_affiliation_refused', 'mcdata_affiliated', 'mcdata'),) if mcdata else ()):
            found = events(server, {refused, affiliated})
            refusals = [entry for entry in found if entry['event'] == refused and entry.get('group_id') == NON_MEMBER]
            expect(f'{prefix}: the non-member group refused', refusals, found[-6:])
            exact = [entry for entry in found if entry['event'] == affiliated and entry.get('groups') == [MEMBER]]
            expect(f'{prefix}: affiliated to the member group only', exact, found[-6:])
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'affiliation-publish-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
