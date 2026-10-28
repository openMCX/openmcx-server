#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A participating function's relay refuses a floor control SSRC it may not send with under the client's CSK.

In a system of a controlling function and participating functions, a participating function relays floor control
re-protected (TS 33.180 clauses 9.4.2 and 9.4.5): towards its client under the client's CSK with the SSRC the client
allocated in its SDP (TS 24.380 clause 4.3.3.1), towards the controlling function under their SPK. An offer whose
SSRC already carried floor control under the client's CSK is answered 488 (Not Acceptable Here, RFC 3261 section
13.3.1.3) by the relay itself, before anything goes to the controlling function (McServer::relay_floor_ssrc_refused).
The relay passes each side's SSRC on to the other side, so under each key it also refuses the opposite direction's
SSRC (both senders would form the same SRTCP IVs, RFC 7714 sections 8.4 and 9.4): in a re-INVITE before the relay
changes (488, the call going on as it was, RFC 3261 section 14.2), in an answer by ending the relayed call (RFC 3261
section 13.2.2.4). With protected floor control (--split --protected), the scenario checks that
  - SR-01 a group call through the relays works under the CSK, client-c receiving floor control from its relay;
  - SR-02 client-c calls offering the floor SSRC of that call: 488 at client-c, the refusal logged by its relay with
    the CSK (relay_floor_ssrc_refused), and no call created at the controlling function;
  - SR-03 client-c calls with a new SSRC: the call is set up and floor control works;
  - SR-04 in that call, client-c's re-INVITEs (no MC service information): with the opposite direction's SSRC and
    with the SSRC of SR-01 488 at the relay, with a new SSRC passed on to the controlling function, which refuses it
    (488); with its own SSRC a refresh answered 200; the call goes on with its SSRCs and floor control works;
  - SR-05 client-c answers a group call with the SSRC its offer allocated: its relay refuses the answer under the CSK
    and ends client-c's part of the call; the call goes on for the others.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
RELAYS = ['mcptt-part-1', 'mcptt-part-2']


# ------------------------------------------------------------------------------
def main():
    """Run SR-01 to SR-03 against the lab of --compose; print the result and write
    integration/split-ssrc-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-split-ssrc')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    if not all(configs[role].get('security', {}).get('protect_media') for role in ROLES):
        parser.error('the fixture must be prepared with --split --protected')
    checks, observations = [], {}
    result = dict(scenario='split-ssrc', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client and of the controlling function, for failure messages."""
        return {role: status(role) for role in ROLES + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container."""
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
            time.sleep(0.1)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:4000])

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label if condition holds, else raise with a snapshot."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot())[:4000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def events(service, name):
        """The JSON log events called name of a service."""
        run = subprocess.run(cli + ['logs', '--no-color', service], capture_output=True, text=True, timeout=60)
        found = []
        for line in run.stdout.splitlines():
            text = line.split('|', 1)[-1].strip()
            if f'"event":"{name}"' in text:
                try:
                    found.append(json.loads(text))
                except json.JSONDecodeError:
                    continue
        return found

    # ------------------------------------------------------------------------------
    def sessions():
        """The controlling function's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def idle():
        """Every client idle and no session at the controlling function."""
        return all(status(role).get('call_state') == 'idle' for role in ROLES) and not sessions()

    # ------------------------------------------------------------------------------
    def floor_works(sender, receivers, label, wav='alpha.wav'):
        """A burst from sender: the floor is granted over protected floor control and every receiver decrypts and
        decodes 100 packets of it; the floor is released."""
        before = {role: status(role).get('received_packets', 0) for role in receivers}
        command(sender, f'ptt /artifacts/speech/{wav}')
        wait(f'{label} {sender} granted the floor over protected floor control', lambda: status(sender).get('talking'))
        wait(
            f'{label} {", ".join(receivers)} decrypt and decode the burst',
            lambda: all(status(role).get('received_packets', 0) >= before[role] + 100 for role in receivers),
            20,
        )
        wait(f'{label} {sender} floor released', lambda: not status(sender).get('talking'), 30)

    try:
        wait(
            'four protected clients authorized, affiliated and holding a CSK',
            lambda: all(
                status(role).get('authorized') and status(role).get('affiliated') and status(role).get('csk_id')
                for role in ROLES
            ),
            120,
        )
        wait('fixture initially idle', idle)
        for role in ROLES:
            command(role, 'answer-mode auto')

        # SR-01 a protected group call through the relays.
        command('client-a', 'call')
        wait(
            'SR-01 group call with the four clients',
            lambda: all(status(role).get('call_state') == 'active' for role in ROLES),
        )
        floor_works('client-a', ['client-c'], 'SR-01')
        previous = status('client-c').get('floor_ssrc')
        check('SR-01 client-c\'s floor SSRC known', bool(previous))
        observations['previous_floor_ssrc'] = previous
        command('client-a', 'hangup')
        wait('SR-01 call released', idle)
        created = len(events('mcptt-server', 'call_created'))

        # SR-02 client-c offers the SSRC of that call.
        command('client-c', 'next-floor-ssrc previous')
        command('client-c', 'call')
        wait(
            'SR-02 the call with a used floor SSRC is refused with 488',
            lambda: (
                status('client-c').get('call_state') == 'idle'
                and (status('client-c').get('last_call_failure') or {}).get('status') == 488
            ),
        )
        check(
            'SR-02 the refused call offered the previous floor SSRC', status('client-c').get('floor_ssrc') == previous
        )
        refusals = [event for relay in RELAYS for event in events(relay, 'relay_floor_ssrc_refused')]
        observations['relay_refusals'] = refusals
        check(
            'SR-02 client-c\'s relay refused the SSRC under the CSK',
            any(
                event.get('ssrc') == previous and event.get('key') == 'csk' and event.get('user_id') == ids['client-c']
                for event in refusals
            ),
        )
        check(
            'SR-02 nothing reached the controlling function',
            len(events('mcptt-server', 'call_created')) == created and idle(),
        )

        # SR-03 a new SSRC.
        command('client-c', 'call')
        wait(
            'SR-03 client-c\'s call with a new SSRC is set up',
            lambda: all(status(role).get('call_state') == 'active' for role in ROLES),
        )
        check('SR-03 the call offered a new floor SSRC', status('client-c').get('floor_ssrc') != previous)
        floor_works('client-c', ['client-a', 'client-b', 'client-d'], 'SR-03', 'bravo.wav')

        # SR-04 re-INVITEs in that call.
        ssrcs = {key: status('client-c').get(key) for key in ('floor_ssrc', 'remote_floor_ssrc')}
        observations['sr04_call'] = ssrcs
        refused_before = {relay: len(events(relay, 'relay_floor_ssrc_refused')) for relay in RELAYS}

        def refresh(option, label, expected):
            sequence = (status('client-c').get('last_refresh_offer') or {}).get('sequence', 0) + 1
            command('client-c', f'refresh-reinvite {option}'.strip())
            wait(
                f'SR-04 {label}: {expected}',
                lambda: (status('client-c').get('last_refresh') or {}) == {'sequence': sequence, 'status': expected},
            )
            check(
                f'SR-04 {label}: the call goes on with its SSRCs',
                status('client-c').get('call_state') == 'active'
                and {key: status('client-c').get(key) for key in ssrcs} == ssrcs,
            )

        refresh('floor-ssrc colliding', 'the opposite direction\'s SSRC', 488)
        refresh(f'floor-ssrc {previous}', 'the SSRC of SR-01', 488)
        refusals = [
            event for relay in RELAYS for event in events(relay, 'relay_floor_ssrc_refused')[refused_before[relay] :]
        ]
        observations['sr04_refusals'] = refusals
        check(
            'SR-04 the relay refused both under the CSK, the first as the opposite direction\'s',
            [(event.get('ssrc'), event.get('key'), event.get('opposite')) for event in refusals]
            == [(ssrcs['remote_floor_ssrc'], 'csk', True), (previous, 'csk', False)],
        )
        refresh('floor-ssrc changed', 'a new SSRC, refused by the controlling function', 488)
        refresh('', 'a refresh with its own SSRC', 200)
        floor_works('client-c', ['client-a', 'client-b', 'client-d'], 'SR-04', 'bravo.wav')
        floor_works('client-a', ['client-b', 'client-c', 'client-d'], 'SR-04')
        command('client-c', 'hangup')
        wait('SR-04 call released', idle)

        # SR-05 an answer with the offer's SSRC.
        def answer_refusals():
            return [
                event
                for relay in RELAYS
                for event in events(relay, 'relay_floor_ssrc_refused')
                if event.get('user_id') == ids['client-c'] and event.get('key') == 'csk' and event.get('opposite')
            ]

        refused_before = len(answer_refusals())
        command('client-c', 'next-answer-floor-ssrc offered')
        command('client-a', 'call')
        wait(
            'SR-05 client-c\'s relay refuses its answer with the offer\'s SSRC',
            lambda: len(answer_refusals()) > refused_before,
        )
        wait('SR-05 client-c\'s part of the call ends', lambda: status('client-c').get('call_state') == 'idle')
        wait(
            'SR-05 the call goes on for the others',
            lambda: all(status(role).get('call_state') == 'active' for role in ('client-a', 'client-b', 'client-d')),
        )
        floor_works('client-a', ['client-b', 'client-d'], 'SR-05')
        check('SR-05 client-c stays out of the call', status('client-c').get('call_state') == 'idle')
        command('client-a', 'hangup')
        wait('SR-05 call released', idle)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'split-ssrc-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
