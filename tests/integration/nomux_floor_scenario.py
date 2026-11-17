#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A private call without multiplexing: no "mc_floor_ssrc" in the offer, floor control with the client's own SSRC.

TS 24.380 clause 14.2.7: an endpoint includes "mc_floor_ssrc" in an SDP offer only "if multiplexing is supported";
clause 14.3.8: the answer includes it only if the offer did; clause 4.3.3.1: the SSRC it carries is the one the
receiving entity expects in the floor control messages it receives, so without it each side sends with its own SSRC
("SSRC of floor participant sending", "SSRC of floor control server", clauses 8.2.4 to 8.2.13).

The lab is generated with --private-call. nomux_probe.py, run in client-a's container, calls client-b as client-a
with such an offer and runs floor control on its own UDP port. The scenario checks that
  - NM-01: the MCPTT server accepts the offer (200 OK, not 488) and answers with a media plane control channel without
    "mc_floor_ssrc" (clause 14.3.8), once client-b answered;
  - NM-02: a Floor Request with the probe's own SSRC is answered with Floor Granted carrying the server's SSRC, not
    the probe's (clause 8.2.5), the one of every message the server sends; the server learned the probe's SSRC
    (floor_ssrc_learned);
  - NM-03: the probe's Floor Ack, with its own SSRC, is matched: Floor Granted is not sent again (clause 8.2.13);
  - NM-04: a first message carrying the server's own SSRC (both directions on one SSRC, RFC 3550 section 8.2) gets
    no answer and is not learned, when the server sent a message the probe could take it from; and once the probe's
    SSRC is learned a message with another SSRC is not taken as the probe's (no Floor Idle for it);
  - NM-05: the probe's Floor Release is answered with Floor Idle; the BYE ends the call and client-b is idle again.

Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 3550.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ROLES = ['client-a', 'client-b']


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab of --compose; print the result and write
    integration/nomux-floor-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-nomux-floor')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    compose = json.loads(args.compose.read_text())
    services = compose.get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-a', {}).get('command', []))
    generated = args.compose.resolve().parent / 'generated'
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcptt']['user_id'] for role in ROLES}
    checks, observations = [], {}
    result = dict(scenario='nomux-floor', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The status.json of a lab role, or {} while it has none."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
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
        """Record label once predicate() holds; fail on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps({role: status(role) for role in ROLES})[:3000])

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=''):
        """Record label when condition holds; fail otherwise."""
        if not condition:
            raise AssertionError(f'{label}: {json.dumps(detail)[:2000]}')
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def events(names):
        """The MCPTT server's JSON log entries whose 'event' is one of names, in log order."""
        run = subprocess.run(
            cli + ['logs', '--no-color', '--no-log-prefix', 'mcptt-server'], capture_output=True, text=True, timeout=30
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
            'client-a and client-b authorised and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        command('client-b', 'answer-mode auto')
        for name in ('sip_negative.py', 'nomux_probe.py'):
            subprocess.run(cli + ['cp', str(HERE / name), f'client-a:/tmp/{name}'], check=True, capture_output=True)
        run = subprocess.run(
            cli + ['exec', '-T', 'client-a', 'python3', '/tmp/nomux_probe.py', '--config', '/config/client-a.json',
                   '--target', ids['client-b']] + ([] if tls else ['--disable-tls']),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if run.returncode:
            raise RuntimeError(f'nomux_probe.py: {run.stderr.strip()[-2000:]}')
        outcomes = json.loads(run.stdout.strip().splitlines()[-1])
        observations['probe'] = outcomes
        probe_ssrc = outcomes['ssrc']

        answer = outcomes['answer']
        check('NM-01 the offer without mc_floor_ssrc is accepted: 200 (OK)', answer['status'] == 200, answer)
        check('NM-01 the answer has a media plane control channel without mc_floor_ssrc (TS 24.380 clause 14.3.8)',
              answer['floor_control'] and not answer['mc_floor_ssrc'], answer)

        granted = outcomes.get('granted') or {}
        check('NM-02 Floor Request with the probe\'s own SSRC: Floor Granted', granted.get('type') == 'Granted',
              outcomes)
        check('NM-02 Floor Granted carries the server\'s SSRC, not the probe\'s',
              granted.get('ssrc') not in (None, 0, probe_ssrc), granted)
        joined = outcomes.get('joined')
        if joined:
            check('NM-02 the server sends every message with one SSRC of its own', joined['ssrc'] == granted['ssrc'],
                  outcomes)
        learned = [entry for entry in events({'floor_ssrc_learned'}) if entry.get('user_id') == ids['client-a']]
        check('NM-02 the server learned the probe\'s SSRC', [entry.get('ssrc') for entry in learned] == [probe_ssrc],
              learned)
        if granted.get('ack'):
            check('NM-03 the probe\'s Floor Ack, with its own SSRC, is matched: no Floor Granted again',
                  granted.get('repeated') == 0, granted)
        timeouts = [entry for entry in events({'floor_ack_timeout'}) if entry.get('user_id') == ids['client-a']
                    and entry.get('type') == 1]
        check('NM-03 no Floor Granted went unacknowledged', not timeouts, timeouts)

        if joined:
            check('NM-04 a first message with the server\'s own SSRC gets no answer', not outcomes.get('collision'),
                  outcomes)
            # floor_receive_ok drops it before learned_floor_ssrc_refused: the SSRC learned is the probe's (NM-02).
        else:
            observations['collision'] = 'not checked: the server sent no message before the probe\'s first'
        check('NM-04 a Floor Release with another SSRC is not taken as the probe\'s',
              not any(message['type'] in ('Idle', 'Taken') for message in outcomes.get('stranger', [])), outcomes)

        released = outcomes.get('released') or {}
        check('NM-05 the probe\'s Floor Release: Floor Idle with the server\'s SSRC',
              released.get('type') == 'Idle' and released.get('ssrc') == granted.get('ssrc'), outcomes)
        check('NM-05 BYE: 200 (OK)', outcomes.get('bye') == 200, outcomes)
        wait('NM-05 client-b is idle again', lambda: status('client-b').get('call_state') == 'idle')
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'nomux-floor-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
