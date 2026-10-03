#!/usr/bin/env python3
"""Exercise end-to-end protected private calls.

The caller generates a PCK, encapsulates it in a MIKEY-SAKKE I_MESSAGE to the callee and both protect the call with it
(TS 33.180 clause 7.2.1, TS 24.379 clause 11.1.1.2.1.1 step 11, its PCK-ID beginning with the bits 0001); speech uses
SRTP under CS-ID 0 and 1 (TS 33.180 clause 7.4.1, table E.1.3-1), floor control SRTCP under each client's CSK (TS 33.180
clause 9.4.2). A tampered I_MESSAGE is rejected with 488 and warning 136 (TS 24.379 table 4.4.2-2). First-to-answer
calls carry the PCK in the answer (TS 33.180 clause 7.2.4), ambient listening calls are keyed by the listening user (TS
33.180 clause 7.2.5); emergency private calls keep the PCK (TS 24.379 clause 11.1).

Run against a four-client fixture prepared with --private-call --protected. Each check records one assertion; IDs match
tests/mcptt/PROTECTED_PRIVATE_CALL_TEST.md. Speech counts only packets the receiving client decrypted with the PCK and
decoded.

Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the checks PP-01 to PP-07 and write integration/protected-private-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-pck')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcptt']['user_id'] for role in roles}
    if not all(configs[role].get('security', {}).get('protect_media') for role in roles):
        parser.error('the fixture must be prepared with --protected')
    checks, observations = [], {}
    result = dict(scenario='protected-private-call', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client and of the server, for failure messages and the result file."""
        return {role: status(role) for role in roles + ['mcptt-server']}

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
    def wait(label, predicate, timeout=15):
        """Poll predicate every 50 ms until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label if condition holds, else raise with a snapshot."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot()))
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def sessions():
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def private_sessions(kind='private'):
        """The server's sessions of call type kind."""
        return [session for session in sessions() if session.get('call_type') == kind]

    # ------------------------------------------------------------------------------
    def idle(wanted=roles):
        """The wanted clients are idle and the server has no session."""
        return all(status(role).get('call_state') == 'idle' for role in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def key_id(role):
        """The PCK-ID the role's current private call uses, or None."""
        return status(role).get('private_key_id')

    # ------------------------------------------------------------------------------
    def shared_key(first, second):
        """Both parties use the same PCK-ID, whose four most significant bits are 0001 (TS 24.379 clause 11.1.1.2.1.1
        step 11 c)).
        """
        return key_id(first) is not None and key_id(first) == key_id(second) and key_id(first) >> 28 == 1

    # ------------------------------------------------------------------------------
    def active(caller, callee, kind='private'):
        """Exactly one protected call of kind between caller and callee, active at the caller, both on one PCK."""
        current = private_sessions(kind)
        return (
            len(current) == 1
            and current[0].get('protected') is True
            and set(current[0].get('participants', [])) == {ids[caller], ids[callee]}
            and status(caller).get('call_state') == 'active'
            and shared_key(caller, callee)
        )

    # ------------------------------------------------------------------------------
    def speech(sender, receiver, label, wav):
        """Send the wav from sender, wait until receiver decrypted and decoded 100 of its packets; return the count."""
        before = status(receiver).get('received_packets', 0)
        command(sender, f'ptt /artifacts/speech/{wav}')
        wait(f'{label} {sender} granted floor over protected floor control', lambda: status(sender).get('talking'))
        wait(
            f'{label} {receiver} decrypts and decodes {sender} speech',
            lambda: status(receiver).get('received_packets', 0) >= before + 100,
            20,
        )
        wait(f'{label} {sender} floor released', lambda: not status(sender).get('talking'), 20)
        return status(receiver).get('received_packets', 0) - before

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning):
        """A predicate: the role is idle after its call was refused with code and the warning text."""

        # ------------------------------------------------------------------------------
        def predicate():
            """The role is idle after its call was refused with code and the warning text."""
            failure = status(role).get('last_call_failure') or {}
            return (
                status(role).get('call_state') == 'idle'
                and failure.get('status') == code
                and warning in failure.get('warning', '')
            )

        return predicate

    try:
        wait(
            'four protected clients authorized, affiliated and holding a CSK',
            lambda: all(
                status(role).get('authorized') and status(role).get('affiliated') and status(role).get('csk_id')
                for role in roles
            ),
            120,
        )
        wait('fixture initially idle', idle)
        for role in roles:
            command(role, 'answer-mode auto')
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name
        bystanders = {role: status(role).get('received_packets', 0) for role in ('client-c', 'client-d')}

        # PP-01 automatic commencement: the caller's PCK reaches the callee, which
        # authenticates it; both select the same PCK-ID and the call is protected.
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'PP-01 protected private call established with one PCK-ID at both parties',
            lambda: active('client-a', 'client-b'),
        )
        observations['pck_id'] = hex(key_id('client-a'))
        check(
            'PP-01 group key is not used: the call is protected by the PCK',
            status('client-a').get('protected_ready') and status('client-b').get('protected_ready'),
        )

        # PP-02 SRTP both ways under CS-ID 0 (caller) and 1 (callee), floor under each CSK.
        observations['speech_packets'] = {
            'client-b': speech('client-a', 'client-b', 'PP-02', 'alpha.wav'),
            'client-a': speech('client-b', 'client-a', 'PP-02', 'bravo.wav'),
        }
        check(
            'PP-02 non-participants received no private speech',
            all(status(role).get('received_packets', 0) == bystanders[role] for role in bystanders),
        )
        first_key = key_id('client-a')
        command('client-b', 'hangup')
        wait(
            'PP-02 release clears the call and its PCK',
            lambda: idle() and key_id('client-a') is None and key_id('client-b') is None,
        )

        # PP-03 a new call has a new PCK; manual commencement answered later.
        command('client-a', f"private {ids['client-b']} manual")
        wait('PP-03 manual protected call rings the callee', lambda: status('client-b').get('call_state') == 'ringing')
        command('client-b', 'answer')
        wait('PP-03 answered manual call shares the PCK', lambda: active('client-a', 'client-b'))
        check('PP-03 every call has its own PCK', key_id('client-a') != first_key)
        command('client-a', 'hangup')
        wait('PP-03 caller hangup releases both parties', idle)

        # PP-04 an altered I_MESSAGE fails authentication at the callee: 488 with warning 136, whose text is the one of
        # TS 24.379 table 4.4.2-2 ("MIKEY-SAKKE"; clause 11.1.1.2.1.2 step 4 d) misspells it "MIKEY-SAKE").
        command('client-a', f"private {ids['client-b']} auto tamper-key")
        wait(
            'PP-04 tampered I_MESSAGE rejected with 488 and warning 136',
            rejected('client-a', 488, '136 authentication of the MIKEY-SAKKE I_MESSAGE failed'),
        )
        check(
            'PP-04 callee never joined the call',
            status('client-b').get('call_state') == 'idle' and key_id('client-b') is None,
        )
        wait('PP-04 rejected call cleaned up', idle)

        # PP-05 first-to-answer: no key in the request; the invitee that answers
        # sends a PCK encapsulated to the caller in its SDP answer (TS 33.180 clause 7.2.4).
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']}")
        wait(
            'PP-05 both invitees ring',
            lambda: all(status(role).get('call_state') == 'ringing' for role in ('client-b', 'client-c')),
        )
        check(
            'PP-05 no PCK before an answer',
            key_id('client-a') is None and key_id('client-b') is None and key_id('client-c') is None,
        )
        command('client-c', 'answer')
        wait(
            'PP-05 the answering invitee and the caller share its PCK',
            lambda: active('client-a', 'client-c') and status('client-a').get('private_peer') == ids['client-c'],
        )
        wait(
            'PP-05 the other invitee is cancelled without a key',
            lambda: status('client-b').get('call_state') == 'idle' and key_id('client-b') is None,
        )
        observations['first_to_answer_packets'] = speech('client-a', 'client-c', 'PP-05', 'alpha.wav')
        command('client-a', 'hangup')
        wait('PP-05 first-to-answer call released', idle)

        # PP-06 ambient listening (TS 33.180 clause 7.2.5): a listens to b; the listened-to
        # client's speech reaches a under the PCK a generated.
        command('client-b', 'ambient-source /artifacts/speech/bravo.wav')
        before = status('client-a').get('received_packets', 0)
        command('client-a', f"ambient remote {ids['client-b']}")
        wait(
            'PP-06 protected ambient listening call established',
            lambda: (
                private_sessions('ambient')
                and private_sessions('ambient')[0].get('protected') is True
                and shared_key('client-a', 'client-b')
            ),
        )
        wait(
            'PP-06 listening user decrypts the listened-to user\'s speech',
            lambda: status('client-a').get('received_packets', 0) >= before + 100,
            30,
        )
        command('client-a', 'hangup')
        wait('PP-06 ambient listening call released with its PCK', lambda: idle() and key_id('client-b') is None)

        # PP-07 emergency private call keeps the PCK through the priority upgrade.
        command('client-a', f"private {ids['client-b']} auto emergency")
        wait('PP-07 protected emergency private call established', lambda: active('client-a', 'client-b'))
        observations['emergency_packets'] = speech('client-a', 'client-b', 'PP-07', 'alpha.wav')
        command('client-a', 'hangup')
        wait('PP-07 emergency call released', idle)
        result['passed'] = True
    finally:
        result['final_status'] = snapshot()
        output = args.artifacts / 'integration' / 'protected-private-results.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], checks=len(checks)), indent=2))


if __name__ == '__main__':
    main()
