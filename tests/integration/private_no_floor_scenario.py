#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCPTT private calls without floor control (TS 24.379 clause 11.1.2).

Run against a fixture prepared with --private-call: client-a may call client-b in every commencement mode, and the
server's private call timer (maximum_duration_ms) is 30 s. An offer without a media-level section for a media-floor
control entity makes a private call without floor control (TS 24.379 clause 11.1.2.2 for the client, clauses 11.1.2.3.2
and 11.1.2.4.2 for the participating and controlling functions). Both parties speak at once, each with the SSRC of its
SDP, and only the clients end the call (TS 24.379 clause 11.1.4.1 NOTE). The next private call is floor-controlled again
(TS 24.379 clause 11.1.1). Check IDs match tests/mcptt/PRIVATE_NO_FLOOR_TEST.md.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import time

import capture
from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
# PNF-03 waits out the server's private call timer (maximum_duration_ms) only when it is this short, and then this
# long beyond it.
SHORT_PRIVATE_CALL_TIMER_MS = 40000
PRIVATE_CALL_TIMER_MARGIN_S = 5


# ------------------------------------------------------------------------------
def main():
    """Run the checks PNF-01 to PNF-07 and write integration/private-no-floor-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-no-floor')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    compose = json.loads(args.compose.read_text())
    # Over TLS the captured SIP is encrypted: the SIP wire checks need a --debug-sip lab.
    sip_on_wire = '--disable-tls' in compose['services']['client-a']['command']
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcptt']['user_id'] for role in ROLES}
    timers = json.loads((generated / 'mcptt-server.json').read_text())['mcptt'].get('private_call', {})
    checks, observations = [], {}
    result = dict(scenario='private-call-without-floor-control', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/private-no-floor.pcap'
    capture_name = f'{args.project}-no-floor-capture'

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The call and floor fields of client-a and client-b, for failure messages."""
        keys = (
            'call_state',
            'call_type',
            'private_peer',
            'floor_control',
            'talking',
            'sent_packets',
            'received_packets',
            'floor_state',
            'last_call_failure',
            'last_error',
        )
        return {role: {key: status(role).get(key) for key in keys} for role in ('client-a', 'client-b')}

    # ------------------------------------------------------------------------------
    def wait(label, condition, timeout=20):
        """Poll condition every 0.1 s until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.1)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=None):
        """Record label if condition holds, else raise with detail."""
        if not condition:
            raise AssertionError(f'{label}: {json.dumps(detail) if detail is not None else "failed"}')
        checks.append(label)
        print(label, flush=True)

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
    def active(*roles):
        """Every role is in an active private call."""
        return all(
            status(role).get('call_state') == 'active' and status(role).get('call_type') == 'private' for role in roles
        )

    # ------------------------------------------------------------------------------
    def idle(*roles):
        """Every role is idle."""
        return all(status(role).get('call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    def counter(role, key):
        """A numeric status counter of the role, 0 when absent."""
        return status(role).get(key, 0) or 0

    # ------------------------------------------------------------------------------
    def start_capture():
        """Start tcpdump of SIP (TCP 5060 and 5061) in the server's network namespace and wait until it listens."""
        server = subprocess.run(
            cli + ['ps', '-q', 'mcptt-server'], check=True, capture_output=True, text=True
        ).stdout.strip()
        capture_file.parent.mkdir(parents=True, exist_ok=True)
        log = capture_file.with_suffix('.log')
        with open(capture_file, 'wb') as out, open(log, 'wb') as err:
            subprocess.Popen(
                [
                    'docker',
                    'run',
                    '--rm',
                    '--name',
                    capture_name,
                    '--network',
                    f'container:{server}',
                    '--cap-drop',
                    'ALL',
                    '--cap-add',
                    'NET_RAW',
                    'openmcx-dev:0.1',
                    'tcpdump',
                    '-Z',
                    'root',
                    '-i',
                    'eth0',
                    '-U',
                    '-s',
                    '0',
                    '-w',
                    '-',
                    'tcp port 5060 or tcp port 5061',
                ],
                stdout=out,
                stderr=err,
            )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and b'listening on' not in log.read_bytes():
            time.sleep(0.1)

    # ------------------------------------------------------------------------------
    def sip_text():
        """The SIP messages of the capture as text."""
        return capture.sip_text(capture_file)

    try:
        wait('four clients authorised', lambda: all(status(role).get('authorized') for role in ROLES), 90)
        wait('fixture initially idle', lambda: idle(*ROLES))
        assert (args.artifacts / 'speech' / 'alpha.wav').is_file(), 'missing speech fixture'
        for role in ROLES:
            command(role, 'answer-mode auto')
        start_capture()

        # PNF-01, TS 24.379 clause 11.1.2.2: an offer without a media-floor control section is a private
        # call without floor control; the callee answers without one.
        command('client-a', f"private {ids['client-b']} auto no-floor")
        wait('PNF-01 client-a and client-b in a private call', lambda: active('client-a', 'client-b'))
        established = time.monotonic()
        wait(
            'PNF-01 neither side has floor control',
            lambda: all(status(role).get('floor_control') is False for role in ('client-a', 'client-b')),
        )
        check(
            'PNF-01 each side knows the other',
            status('client-a').get('private_peer') == ids['client-b']
            and status('client-b').get('private_peer') == ids['client-a'],
            {role: status(role).get('private_peer') for role in ('client-a', 'client-b')},
        )
        check('PNF-01 nobody else is in the call', idle('client-c', 'client-d'))

        # PNF-02 both parties speak at the same time, and each hears the other.
        before = {
            role: (counter(role, 'sent_packets'), counter(role, 'received_packets'), counter(role, 'floor_denials'))
            for role in ('client-a', 'client-b')
        }
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'PNF-02 both talk at once',
            lambda: all(status(role).get('talking') is True for role in ('client-a', 'client-b')),
        )
        wait(
            'PNF-02 each receives the other\'s speech while both talk',
            lambda: (
                all(counter(role, 'received_packets') - before[role][1] >= 100 for role in ('client-a', 'client-b'))
                and all(status(role).get('talking') is True for role in ('client-a', 'client-b'))
            ),
        )
        wait(
            'PNF-02 the speech runs to its end at both',
            lambda: all(status(role).get('talking') is False for role in ('client-a', 'client-b')),
            20,
        )
        time.sleep(1)
        exchanged = {
            role: dict(
                sent=counter(role, 'sent_packets') - before[role][0],
                received=counter(role, 'received_packets') - before[role][1],
            )
            for role in ('client-a', 'client-b')
        }
        observations['speech'] = exchanged
        # alpha.wav is 6.7 s and bravo.wav 7.1 s: 336 and 354 frames of 20 ms.
        check('PNF-02 client-a sent its whole phrase', exchanged['client-a']['sent'] >= 330, exchanged)
        check('PNF-02 client-b sent its whole phrase', exchanged['client-b']['sent'] >= 350, exchanged)
        check(
            'PNF-02 client-b received client-a\'s phrase',
            exchanged['client-b']['received'] >= 0.95 * exchanged['client-a']['sent'],
            exchanged,
        )
        check(
            'PNF-02 client-a received client-b\'s phrase',
            exchanged['client-a']['received'] >= 0.95 * exchanged['client-b']['sent'],
            exchanged,
        )
        check(
            'PNF-02 no floor request was denied',
            all(counter(role, 'floor_denials') == before[role][2] for role in ('client-a', 'client-b')),
        )
        check('PNF-02 the call is still up after the speech', active('client-a', 'client-b'), snapshot())

        # PNF-03, TS 24.379 clause 11.1.4.1 NOTE: only the clients end the call, so the private call timer
        # (maximum_duration_ms) does not.
        limit = timers.get('maximum_duration_ms', 0)
        observations['private_call_timer_ms'] = limit
        if limit and limit <= SHORT_PRIVATE_CALL_TIMER_MS:
            remaining = limit / 1000 + PRIVATE_CALL_TIMER_MARGIN_S - (time.monotonic() - established)
            stayed = holds(lambda: active('client-a', 'client-b'), max(remaining, 0))
            observations['held_for_s'] = round(time.monotonic() - established, 1)
            check('PNF-03 the call stays up past the private call timer', stayed, snapshot())
        else:
            observations['private_call_timer_check'] = 'skipped: no short private call timer in this fixture'
            print(f'PNF-03 skipped: the private call timer ({limit} ms) is not short', flush=True)

        # PNF-04 the called user ends the call; both are idle.
        command('client-b', 'hangup')
        wait('PNF-04 the call ended at both', lambda: idle('client-a', 'client-b'))

        # PNF-05 manual commencement: client-b rings until it answers, then speaks at once.
        command('client-a', f"private {ids['client-b']} manual no-floor")
        wait('PNF-05 client-b rings', lambda: status('client-b').get('call_state') == 'ringing')
        command('client-b', 'answer')
        wait(
            'PNF-05 answered: both active without floor control',
            lambda: (
                active('client-a', 'client-b')
                and all(status(role).get('floor_control') is False for role in ('client-a', 'client-b'))
            ),
        )
        heard = counter('client-a', 'received_packets')
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'PNF-05 client-a hears client-b without any floor request',
            lambda: counter('client-a', 'received_packets') - heard >= 50,
        )
        command('client-a', 'hangup')
        wait('PNF-05 the call ended at both', lambda: idle('client-a', 'client-b'))

        # PNF-06 the next private call is floor-controlled again (TS 24.379 clause 11.1.1).
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'PNF-06 a private call with floor control',
            lambda: (
                active('client-a', 'client-b')
                and all(status(role).get('floor_control') is True for role in ('client-a', 'client-b'))
            ),
        )
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait('PNF-06 client-a is granted the floor', lambda: status('client-a').get('floor_state') == 'HasPermission')
        command('client-a', 'hangup')
        wait('PNF-06 the call ended at both', lambda: idle('client-a', 'client-b'))
        time.sleep(1)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)

        # PNF-07 the wire: offers and answers without m=application, and floor control
        # back in the following call.
        if sip_on_wire:
            sip = sip_text()
            messages = capture.split(sip)
            private = [
                message
                for message in messages
                if message.startswith('INVITE sip:') and '<session-type>private</session-type>' in message
            ]
            answers = [
                message
                for message in messages
                if message.startswith('SIP/2.0 200 ')
                and re.search(r'(?im)^CSeq:\s*\d+\s+INVITE\s*$', message)
                and 'm=audio' in message
            ]
            observations['private_invites'] = len(private)
            without = [message for message in private if 'm=audio' in message and 'm=application' not in message]
            originating = [message for message in without if message.startswith('INVITE sip:mcptt@')]
            terminating = [message for message in without if not message.startswith('INVITE sip:mcptt@')]
            observations['without_floor'] = dict(originating=len(originating), terminating=len(terminating))
            check(
                'PNF-07 client offers without a floor control section',
                len(originating) >= 2,
                observations['without_floor'],
            )
            check(
                'PNF-07 the controlling function invites the callee without one',
                len(terminating) >= 2,
                observations['without_floor'],
            )
            check(
                'PNF-07 200 answers without a floor control section',
                sum('m=application' not in message for message in answers) >= 4,
                len(answers),
            )
            check(
                'PNF-07 client offers announce the SSRC they speak with',
                all(re.search(r'a=ssrc:\d+ cname:mcptt', message) for message in originating),
            )
            check('PNF-07 the following call offers floor control', any('udp MCPTT' in message for message in private))
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, RuntimeError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/private-no-floor-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
