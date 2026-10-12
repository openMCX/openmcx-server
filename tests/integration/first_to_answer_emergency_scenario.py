#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise emergency first-to-answer calls (TS 24.379 clauses 11.1.1 and 6.2.8.3).

Run against a fixture prepared with --private-call (client-a may originate
first-to-answer and emergency private calls to anyone). Recipient filtering is
exercised by temporarily narrowing client-a's ruleset in the CMS; the original
site configuration is always restored. Check IDs match tests/mcptt/FIRST_TO_ANSWER_TEST.md.

The procedures under test: the client originating and terminating procedures of TS 24.379
clauses 11.1.1.2.1.1 and 11.1.1.2.1.2 (the MEPC, MEPP and MPEA states), the in-dialog emergency
cancel of clause 11.1.1.2.1.4, the controlling function's of clause 11.1.1.4, and the emergency
private call authorisations of clause 6.2.8.3.1; the emergency call's Floor Taken carries the D-bit
(TS 24.380 table 8.2.3.15-2).

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
# Floor Indicator bit D (emergency call): TS 24.380 table 8.2.3.15-2.
EMERGENCY_BIT = 0x1000


# ------------------------------------------------------------------------------
def main():
    """Run the emergency first-to-answer checks FE-01 to FE-08 and write
    integration/first-to-answer-emergency-results.json; restore the site configuration if it changed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-fta')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    ids = {client: json.loads((generated / f'{client}.json').read_text())['mcptt']['user_id'] for client in roles}
    site_file = generated / 'site.json'
    original_site = site_file.read_text()
    checks, observations = [], {}
    result = dict(scenario='emergency-first-to-answer-call', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """Every client's and the server's status, for the failure report."""
        return {client: status(client) for client in roles + ['mcptt-server']}

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in the role's container; a failure raises RuntimeError."""
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
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def sessions():
        """The server's call sessions as a list."""
        value = status('mcptt-server').get('sessions', [])
        return list(value.values()) if isinstance(value, dict) else value

    # ------------------------------------------------------------------------------
    def idle():
        """Every client idle and the server holding no session."""
        return all(status(client).get('call_state') == 'idle' for client in roles) and not sessions()

    # ------------------------------------------------------------------------------
    def state(role, key):
        """One field of the role's status, '' when absent."""
        return status(role).get(key, '')

    # ------------------------------------------------------------------------------
    def active_pair(caller, callee):
        """Caller and callee both active, the caller's private call peer being the callee."""
        return (
            all(status(client).get('call_state') == 'active' for client in (caller, callee))
            and status(caller).get('private_peer') == ids[callee]
        )

    # ------------------------------------------------------------------------------
    def set_policy(**changes):
        """Rewrite client-a's private-call ruleset and restart the CMS."""
        site = json.loads(original_site)
        for user in site['users']:
            if user['mcptt_id'] == ids['client-a']:
                user['private_call'].update(changes)
        site_file.write_text(json.dumps(site, indent=2) + '\n')
        restart_cms()

    # ------------------------------------------------------------------------------
    def restart_cms():
        """Restart the CMS and wait until it is healthy."""
        subprocess.run(cli + ['restart', 'cms'], check=True, capture_output=True, timeout=120)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            health = subprocess.run(cli + ['ps', '--format', '{{.Health}}', 'cms'], capture_output=True, text=True)
            if health.stdout.strip() == 'healthy':
                return
            time.sleep(0.5)
        raise AssertionError('CMS did not become healthy')

    policy_changed = False
    try:
        wait('four clients authorized', lambda: all(status(client).get('authorized') for client in roles), 90)
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        assert (args.artifacts / 'speech' / 'alpha.wav').is_file(), 'missing speech fixture'
        for role in roles:
            command(role, 'answer-mode auto')

        # FE-01 emergency first-to-answer setup: both invitees ring with MEPP 2 (TS 24.379 clause
        # 11.1.1.2.1.2 step 3c).
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']} emergency alert")
        wait(
            'FE-01 both invitees ring despite automatic local answer mode',
            lambda: all(state(client, 'call_state') == 'ringing' for client in ['client-b', 'client-c']),
        )
        wait(
            'FE-01 invitees enter MEPP 2 while ringing',
            lambda: all(
                state(client, 'private_priority_state') == 'MEPP 2: in-progress' for client in ['client-b', 'client-c']
            ),
        )
        # Each client writes its status every 200 ms, so the caller's may lag the invitees'.
        wait(
            'FE-01 caller in MEPC 2',
            lambda: state('client-a', 'private_emergency_state') == 'MEPC 2: emergency-pc-requested',
        )

        # FE-02 the first answerer is selected; the other is cancelled and restores MEPP.
        command('client-b', 'answer')
        wait('FE-02 first answerer becomes the emergency peer', lambda: active_pair('client-a', 'client-b'))
        wait(
            'FE-02 caller reaches MEPC 3 / MEPP 2 / MPEA 3',
            lambda: (
                state('client-a', 'private_emergency_state') == 'MEPC 3: emergency-pc-granted'
                and state('client-a', 'private_priority_state') == 'MEPP 2: in-progress'
                and state('client-a', 'private_alert_state') == 'MPEA 3: emergency-alert-initiated'
            ),
        )
        wait(
            'FE-02 unselected invitee cancelled and its MEPP restored',
            lambda: (
                state('client-c', 'call_state') == 'idle'
                and state('client-c', 'private_priority_restored') == 'MEPP 1: no-emergency'
            ),
        )
        wait(
            'FE-02 selected invitee keeps MEPP 2 and the caller alert',
            lambda: (
                state('client-b', 'private_priority_state') == 'MEPP 2: in-progress'
                and ids['client-a'] in status('client-b').get('private_alerts', [])
            ),
        )
        session = next(call for call in sessions())
        assert session.get('priority') == 'emergency', 'server session not in emergency state'
        checks.append('FE-02 server keeps the in-progress emergency state for the call')

        # FE-03 the emergency floor D-bit reaches the peer.
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'FE-03 peer sees Floor Taken with the emergency D-bit',
            lambda: status('client-b').get('floor_indicator') == EMERGENCY_BIT,
        )
        wait('FE-03 floor released', lambda: not status('client-a').get('talking'), 20)

        # FE-04 after selection, the caller cancels the emergency and alert in-dialog.
        command('client-a', 'emergency off alert')
        wait(
            'FE-04 in-dialog cancellation returns both parties to MEPP 1',
            lambda: (
                all(
                    state(client, 'private_priority_state') == 'MEPP 1: no-emergency'
                    for client in ['client-a', 'client-b']
                )
                and active_pair('client-a', 'client-b')
            ),
        )
        command('client-a', 'hangup')
        wait('FE-04 released', idle)

        # FE-05 the other invitee may win; the first is then cancelled and restored.
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']} emergency")
        wait(
            'FE-05 both invitees ringing',
            lambda: all(state(client, 'call_state') == 'ringing' for client in ['client-b', 'client-c']),
        )
        command('client-c', 'answer')
        wait('FE-05 second invitee selected', lambda: active_pair('client-a', 'client-c'))
        wait(
            'FE-05 first invitee cancelled and its MEPP restored',
            lambda: (
                state('client-b', 'call_state') == 'idle'
                and state('client-b', 'private_priority_restored') == 'MEPP 1: no-emergency'
            ),
        )
        command('client-a', 'hangup')
        wait('FE-05 released', idle)

        # FE-06 an invitee declining an emergency first-to-answer call leaves the other ringing.
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']} emergency")
        wait(
            'FE-06 both invitees ringing',
            lambda: all(state(client, 'call_state') == 'ringing' for client in ['client-b', 'client-c']),
        )
        command('client-b', 'reject')
        wait(
            'FE-06 decline restores the decliner and the other invitee keeps ringing',
            lambda: (
                state('client-b', 'call_state') == 'idle'
                and state('client-b', 'private_priority_restored') == 'MEPP 1: no-emergency'
                and state('client-c', 'call_state') == 'ringing'
            ),
        )
        command('client-a', 'hangup')
        wait('FE-06 caller CANCEL clears the remaining invitee', idle)

        # FE-07 emergency recipients filter the invitees; none authorised -> 403 with emergency-ind false.
        policy_changed = True
        set_policy(emergency_any=False, emergency_recipients=[ids['client-c']])
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']} emergency")
        wait(
            'FE-07 only the authorised emergency recipient is invited',
            lambda: state('client-c', 'call_state') == 'ringing',
        )
        assert holds(lambda: state('client-b', 'call_state') == 'idle', 2), (
            'unauthorised emergency recipient was invited'
        )
        checks.append('FE-07 unauthorised recipient not invited')
        command('client-a', 'hangup')
        wait('FE-07 released', idle)
        set_policy(emergency_any=False, emergency_recipients=[])
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']} emergency")
        wait(
            'FE-07 no authorised recipient rejected with 403',
            lambda: (
                state('client-a', 'call_state') == 'idle'
                and (status('client-a').get('last_call_failure') or {}).get('status') == 403
                and 'emergency private call not authorized'
                in (status('client-a').get('last_call_failure') or {}).get('warning', '')
                and state('client-a', 'private_emergency_state') == 'MEPC 1: emergency-pc-capable'
            ),
        )

        # FE-08 an alert not authorised for every invitee is withdrawn; the emergency call proceeds.
        set_policy(alert_any=False, alert_recipients=[ids['client-b']])
        command('client-a', f"first-to-answer {ids['client-b']} {ids['client-c']} emergency alert")
        wait(
            'FE-08 both invitees ringing',
            lambda: all(state(client, 'call_state') == 'ringing' for client in ['client-b', 'client-c']),
        )
        command('client-b', 'answer')
        wait(
            'FE-08 call proceeds as an emergency call with the alert withdrawn (MPEA 1)',
            lambda: (
                active_pair('client-a', 'client-b')
                and state('client-a', 'private_priority_state') == 'MEPP 2: in-progress'
                and state('client-a', 'private_alert_state') == 'MPEA 1: no-alert'
            ),
        )
        command('client-a', 'hangup')
        wait('FE-08 released', idle)

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, StopIteration, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    finally:
        if policy_changed:
            site_file.write_text(original_site)
            try:
                restart_cms()
            except (AssertionError, subprocess.SubprocessError) as exc:
                result['restore_error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/first-to-answer-emergency-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
