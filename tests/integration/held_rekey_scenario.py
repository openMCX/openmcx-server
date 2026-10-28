#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A held call's floor control goes on under a new CSK with its SRTCP index.

During an announced transfer (TS 24.379 clause 11.1.8.2.3) the requester holds its call with the transferred user
while it calls the target. A key download (TS 33.180 clause 5.8.2) then gives the requester a new CSK; the streams of
every call kept, the held one too, go on under it: RFC 3711 section 3.4, "after a re-key, the SRTCP index MUST NOT be
reset to zero again". With protected floor control (--private-call --private-services --protected --xml-protection:
the key download needs XML protection), the scenario checks, within the lab's 30-second private call duration (the
server ends a longer private call), that
  - HR-01 client-a's protected private call with client-b carries floor control under client-a's CSK;
  - HR-02 client-a holds that call for an announced transfer to client-d and is in the call with client-d;
  - HR-03 the MCPTT server downloads a new CSK to client-a, which takes it while the call with client-b is held;
  - HR-04 the transfer is cancelled, the held call is resumed and its floor control works in both directions.
The wire verifier (verify_held_rekey.py) checks that the held call's floor control SRTCP changed its MKI to the new
CSK-ID with its index growing in both directions, never starting again.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3711,
RFC 5359.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run HR-01 to HR-04 against the lab of --compose; print the result and write
    integration/held-rekey-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-held-rekey')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    if not all(configs[role].get('security', {}).get('protect_media') for role in ROLES):
        parser.error('the fixture must be prepared with --private-call --private-services --protected --xml-protection')
    checks, observations = [], {}
    result = dict(scenario='held-rekey', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client and of the server, for failure messages."""
        return {role: status(role) for role in ROLES + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one command in the role's container (the MCPTT server's or mcx-client's)."""
        binary = 'openmcx-mcptt-server' if role == 'mcptt-server' else 'mcx-client'
        run = subprocess.run(
            cli + ['exec', '-T', role, binary, '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=20,
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
    def sessions():
        """The server's sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def idle():
        """Every client idle and no session at the server."""
        return all(status(role).get('call_state') == 'idle' for role in ROLES) and not sessions()

    # ------------------------------------------------------------------------------
    def floor_works(sender, receivers, label, wav='alpha.wav'):
        """A burst from sender: the floor is granted over protected floor control (floor control both ways: the
        request and release from sender, the grant and idle to it), every receiver decrypts and decodes 100 packets of
        it, and sender releases the floor."""
        before = {role: status(role).get('received_packets', 0) for role in receivers}
        command(sender, f'ptt /artifacts/speech/{wav}')
        wait(f'{label} {sender} granted the floor over protected floor control', lambda: status(sender).get('talking'))
        wait(
            f'{label} {", ".join(receivers)} decrypt and decode the burst',
            lambda: all(status(role).get('received_packets', 0) >= before[role] + 100 for role in receivers),
            20,
        )
        command(sender, 'release')
        wait(f'{label} {sender} floor released', lambda: not status(sender).get('talking'), 30)

    try:
        wait(
            'four protected clients authorized and holding a CSK',
            lambda: all(status(role).get('authorized') and status(role).get('csk_id') for role in ROLES),
            120,
        )
        wait('fixture initially idle', idle)
        for role in ROLES:
            command(role, 'answer-mode auto')

        # HR-01 the call to be held.
        command('client-a', f"private {ids['client-b']} auto")
        wait(
            'HR-01 protected private call between client-a and client-b',
            lambda: all(status(role).get('call_state') == 'active' for role in ('client-a', 'client-b')),
        )
        floor_works('client-a', ['client-b'], 'HR-01')
        held = {key: status('client-a').get(key) for key in ('session_uri', 'floor_ssrc', 'remote_floor_ssrc')}
        observations['held_call'] = held

        # HR-02 announced transfer: the call is held while client-a calls client-d.
        command('client-a', f"transfer {ids['client-d']} announced")
        wait(
            'HR-02 client-a holds the call and is in the call with client-d',
            lambda: (
                (status('client-a').get('announced_transfer') or {}).get('state') == 'announcing'
                and status('client-d').get('call_state') == 'active'
            ),
        )

        # HR-03 a key download to client-a while the call is held.
        old = status('client-a').get('csk_id')
        observations['old_csk_id'] = old
        command('mcptt-server', f"csk-download {ids['client-a']}")
        wait('HR-03 client-a takes the downloaded CSK', lambda: status('client-a').get('csk_id') not in (None, old))
        observations['new_csk_id'] = status('client-a').get('csk_id')

        # HR-04 the held call is resumed and its floor control goes on.
        command('client-a', f"transfer {ids['client-d']} cancel")
        wait(
            'HR-04 the held call is resumed',
            lambda: (
                (status('client-a').get('announced_transfer') or {}).get('state') == 'cancelled'
                and status('client-a').get('call_state') == 'active'
                and status('client-a').get('session_uri') == held['session_uri']
            ),
        )
        wait(
            'HR-04 the resumed call keeps its floor SSRCs',
            lambda: all(status('client-a').get(key) == held[key] for key in ('floor_ssrc', 'remote_floor_ssrc')),
        )
        floor_works('client-a', ['client-b'], 'HR-04')
        command('client-a', 'hangup')
        wait('HR-04 released', idle)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'held-rekey-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
