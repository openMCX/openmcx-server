#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise the location sent with an implicit floor request, with separate participating and controlling servers.

Run against a split fixture prepared with --split --private-call --chat --adhoc --location-when-talking client-a
--location-when-talking-always client-c. Check labels carry the IDs LWF-01 to LWF-06.

The procedures under test (TS 24.379 V19.8.0, TS 24.484 V19.6.0 clause 8.3.2.7 <allow-location-info-when-talking>):
the client includes a location-info <Report> with an implicit floor request when the element is "true" (clauses
10.1.1.2.1.1 step 16 a), 11.1.1.2.1.1 step 13 a), 17.2.2.1.1 step 14a a)); the originating participating function passes
it to the controlling function only when the element is "true" for private and ad hoc calls (clauses 6.3.2.1.3 step
9, 11.1.1.3.1.1 step 21, 17.3.2.1.1 step 17) and as before for an on-demand group call, whose step 7 copies it with no
condition (a conflict of the specification, Known limitations "Location in call requests"). client-a has the element
"true", client-b and client-c "false"; client-c sends its location whatever its profile says (a lab sender for the
participating function's check). mcptt-part-1 serves client-a and client-c, mcptt-part-2 client-b and client-d. The
outcome is read from the participating functions' "talking_location" events and the clients' "talking_location_sent".

Specifications: TS 24.379 V19.8.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
SPEECH = '/artifacts/speech/alpha.wav'
SERVES = {'client-a': 'mcptt-part-1', 'client-c': 'mcptt-part-1', 'client-b': 'mcptt-part-2', 'client-d': 'mcptt-part-2'}


# ------------------------------------------------------------------------------
def main():
    """Run LWF-01 to LWF-06 against the lab of --compose and write integration/location-with-floor-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-location-floor')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    site = json.loads((generated / 'site.json').read_text())
    allowed = {user['mcptt_id'] for user in site['users'] if user.get('location_when_talking')}
    if allowed != {ids['client-a']} or configs['client-c']['mcptt'].get('location_when_talking') != 'always':
        parser.error('the fixture must be prepared with --location-when-talking client-a '
                     '--location-when-talking-always client-c')
    checks = []
    result = dict(scenario='location-with-floor-request', passed=False, checks=checks)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """Every client's and the controlling function's status, for the failure report."""
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
    def wait(label, predicate, timeout=20):
        """Poll the predicate until it holds, then record the label; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:4000])

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
    def hangup_all(label):
        """Hang up every client still in a call and wait until the controlling function holds no session."""
        for role in ROLES:
            if status(role).get('call_state') != 'idle':
                command(role, 'hangup')
        wait(label, idle, 30)

    # ------------------------------------------------------------------------------
    def call(label, role, text, session_type, implicit, outcome, sent):
        """Run the call command of role; the participating function serving it reports the outcome for the call's
        INVITE, and the client sent (sent true) or did not send its location."""
        relay = SERVES[role]
        before = len(events(relay, 'talking_location'))
        before_sent = len(events(role, 'talking_location_sent'))
        command(role, text)
        user = ids[role]

        def done():
            """The participating function's event for this call is in."""
            found = [e for e in events(relay, 'talking_location')[before:] if e.get('user_id') == user]
            return found and found[-1].get('session_type') == session_type and found[-1].get('implicit') == implicit

        wait(f'{label} {relay} handled the call request of {role}', done)
        last = [e for e in events(relay, 'talking_location')[before:] if e.get('user_id') == user][-1]
        if last.get('outcome') != outcome:
            raise AssertionError(f'{label}: outcome {last.get("outcome")!r}, expected {outcome!r}: {last}')
        checks.append(f'{label} location {outcome}')
        print(f'{label} location {outcome}', flush=True)
        count = len(events(role, 'talking_location_sent')) - before_sent
        if (count > 0) != sent:
            raise AssertionError(f'{label}: {role} sent its location {count} times, expected {"some" if sent else 0}')
        checks.append(f'{label} {role} {"sent" if sent else "did not send"} its location')

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(role).get('authorized') and status(role).get('affiliated') for role in ROLES),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for role in ROLES:
            command(role, 'answer-mode auto')

        # LWF-01 element "true": the client's location goes to the controlling function.
        call('LWF-01', 'client-a', f"private {ids['client-b']} auto implicit={SPEECH}", 'private', True, 'passed', True)
        hangup_all('LWF-01 private call released')
        # LWF-02 element "false", the location sent anyway: withheld for a private call.
        call('LWF-02', 'client-c', f"private {ids['client-d']} auto implicit={SPEECH}", 'private', True, 'withheld',
             True)
        hangup_all('LWF-02 private call released')
        # LWF-03 element "false": the client sends none; the function has none to add.
        call('LWF-03', 'client-b', f"private {ids['client-d']} auto implicit={SPEECH}", 'private', True, 'none', False)
        hangup_all('LWF-03 private call released')
        # LWF-04 ad hoc group call: withheld with "false".
        call('LWF-04', 'client-c', f"adhoc {ids['client-a']} {ids['client-b']} implicit={SPEECH}", 'adhoc', True,
             'withheld', True)
        hangup_all('LWF-04 ad hoc call released')
        # LWF-05 on-demand group call: passed as before (clause 10.1.1.3.1.1 step 7, the conflict kept).
        call('LWF-05', 'client-c', f'call implicit={SPEECH}', 'prearranged', True, 'passed', True)
        hangup_all('LWF-05 group call released')
        # LWF-06 no implicit floor request: the client sends no location.
        call('LWF-06', 'client-a', f"private {ids['client-b']} auto", 'private', False, 'none', False)
        hangup_all('LWF-06 private call released')

        if status('mcptt-server')['instance_id'] != instance:
            raise AssertionError('controlling server restarted during the scenario')
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/location-with-floor-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
