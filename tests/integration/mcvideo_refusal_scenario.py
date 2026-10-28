#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""An MCVideo call refused for its transmission control SSRC ends only itself, while an MCPTT call goes on.

A client refuses the SSRC the MCVideo server allocates in its answer for the client's transmission control messages
when it may not use it (TS 24.581 clause 4.3.3.1, under the CSK RFC 7714 section 8.4); an answer cannot be rejected,
so the client acknowledges it and ends the dialog with BYE (RFC 3261 section 13.2.2.4). The MCVideo dialog stays the
MCVideo service's until the SIP stack reports its end: its CONFIRMED, which the stack reports after the media of the
answer, must not reach the MCPTT call. The lab clients refuse the next answer's SSRC on the
mcvideo-refuse-control-ssrc command. With protected media and floor control (--mcvideo --protected), the scenario
checks that
  - MR-01 an MCPTT group call is active and its floor control works under the CSK;
  - MR-02 client-a's MCVideo group call with the refused SSRC ends at client-a, its dialog is closed (no MCVideo
    dialog left in teardown), and client-a's MCPTT call goes on with its dialog, session and floor SSRCs unchanged;
    floor control of the MCPTT call still works in both directions;
  - MR-03 an MCVideo call without the refusal is set up and hung up, the MCPTT call going on as well.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 3261.
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
    """Run MR-01 to MR-03 against the lab of --compose; print the result and write
    integration/mcvideo-refusal-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo-refusal')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    if not all(configs[role].get('security', {}).get('protect_media') for role in ROLES):
        parser.error('the fixture must be prepared with --mcvideo --protected')
    checks, observations = [], {}
    result = dict(scenario='mcvideo-refusal', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The status of every client, for failure messages."""
        return {role: status(role) for role in ROLES}

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
    def mcptt(role):
        """The MCPTT call at the role: state, dialog, session and floor SSRCs."""
        current = status(role)
        return {
            key: current.get(key)
            for key in ('call_state', 'call_dialog', 'session_uri', 'floor_ssrc', 'remote_floor_ssrc')
        }

    # ------------------------------------------------------------------------------
    def floor_works(sender, receivers, label, wav='alpha.wav'):
        """A burst from sender in the MCPTT call: the floor is granted and every receiver decrypts and decodes 100
        packets of it; the floor is released."""
        before = {role: status(role).get('received_packets', 0) for role in receivers}
        command(sender, f'ptt /artifacts/speech/{wav}')
        wait(f'{label} {sender} granted the floor over protected floor control', lambda: status(sender).get('talking'))
        wait(
            f'{label} {", ".join(receivers)} decrypt and decode the burst',
            lambda: all(status(role).get('received_packets', 0) >= before[role] + 100 for role in receivers),
            20,
        )
        wait(f'{label} {sender} floor released', lambda: not status(sender).get('talking'), 30)

    # ------------------------------------------------------------------------------
    def unchanged(before, label, hold=3):
        """For hold seconds client-a's MCPTT call stays as before."""
        deadline = time.monotonic() + hold
        while time.monotonic() < deadline:
            if mcptt('client-a') != before:
                raise AssertionError(f'{label} the MCPTT call changed: {mcptt("client-a")} != {before}')
            time.sleep(0.2)
        checks.append(f'{label} client-a\'s MCPTT call goes on with its dialog, session and floor SSRCs')
        print(checks[-1], flush=True)

    try:
        wait(
            'four protected clients authorized, affiliated and holding a CSK',
            lambda: all(
                status(role).get('authorized') and status(role).get('affiliated') and status(role).get('csk_id')
                for role in ROLES
            ),
            120,
        )
        wait(
            'fixture initially idle',
            lambda: all(
                status(role).get('call_state') == 'idle' and status(role).get('mcvideo_call_state') in (None, 'idle')
                for role in ROLES
            ),
        )
        for role in ROLES:
            command(role, 'answer-mode auto')

        # MR-01 the MCPTT call.
        command('client-a', 'call')
        wait(
            'MR-01 MCPTT group call with the four clients',
            lambda: all(status(role).get('call_state') == 'active' for role in ROLES),
        )
        others = ['client-b', 'client-c', 'client-d']
        floor_works('client-a', others, 'MR-01')
        before = mcptt('client-a')
        check_ok = before['call_dialog'] and before['floor_ssrc'] and before['remote_floor_ssrc']
        if not check_ok:
            raise AssertionError('MR-01 the MCPTT call\'s parameters are not reported: ' + json.dumps(before))
        observations['mcptt_call'] = before

        # MR-02 the refused MCVideo call.
        command('client-a', 'mcvideo-refuse-control-ssrc')
        command('client-a', 'mcvideo-call')
        wait(
            'MR-02 client-a ends the MCVideo call for its transmission control SSRC',
            lambda: (
                status('client-a').get('mcvideo_call_state') in (None, 'idle')
                and 'SSRC collision' in str((status('client-a').get('mcvideo_last_call') or {}).get('reason', ''))
            ),
        )
        wait('MR-02 the MCVideo dialog is closed', lambda: status('client-a').get('mcvideo_closing_dialogs') == 0)
        unchanged(before, 'MR-02')
        floor_works('client-a', others, 'MR-02')
        floor_works('client-b', ['client-a', 'client-c', 'client-d'], 'MR-02', 'bravo.wav')
        unchanged(before, 'MR-02 after floor control', 1)

        # MR-03 an MCVideo call that is not refused.
        command('client-a', 'mcvideo-call')
        wait('MR-03 MCVideo call active at client-a', lambda: status('client-a').get('mcvideo_call_state') == 'active')
        command('client-a', 'mcvideo-hangup')
        wait(
            'MR-03 MCVideo call ended and its dialog closed',
            lambda: (
                status('client-a').get('mcvideo_call_state') in (None, 'idle')
                and status('client-a').get('mcvideo_closing_dialogs') == 0
            ),
        )
        for role in others:
            if status(role).get('mcvideo_call_state') not in (None, 'idle'):
                command(role, 'mcvideo-hangup')
        unchanged(before, 'MR-03')
        floor_works('client-a', others, 'MR-03')
        command('client-a', 'hangup')
        wait('MR-03 MCPTT call released', lambda: all(status(role).get('call_state') == 'idle' for role in ROLES))
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'mcvideo-refusal-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
