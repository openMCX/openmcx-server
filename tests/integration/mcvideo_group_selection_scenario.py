#!/usr/bin/env python3
"""MCVideo remote change of a user's selected group (TS 24.281 clause 9.2.4): a change to a
group the target is not affiliated to (<affiliation-required>, the target affiliates first), a
change to a group it is affiliated to, a call on the newly selected group, the refusals 155, 120
and 167, and the wire format.

Procedures under test: TS 24.281 clause 9.2.4.2.1 (initiation), clause 9.2.4.2.2 (target
client), clause 9.2.4.3.1 step 3a (warning 155), clause 9.2.4.4 steps 2A (warning 167), 3a
(warning 120) and 8a (<affiliation-required>), and the MCVideo Information of TS 24.281 annex F.1.

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): client-a may change the selected group of client-b
and client-d; video-field is a second prearranged group none is affiliated to at the
start, video-closed has client-a as its only member, and video-regroup is
preconfigured-use-only. Check IDs match tests/mcvideo/MCVIDEO_GROUP_SELECTION_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import time

import capture

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
# Run the scenario against the lab and write integration/mcvideo-group-selection-results.json; return 0 when every check
# passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    # Over TLS the captured SIP is encrypted: the SIP wire checks need a --debug-sip lab.
    compose = json.loads(args.compose.read_text())
    sip_on_wire = '--disable-tls' in compose['services']['client-a']['command']
    ids = {role: json.loads((generated / f'{role}.json').read_text())['mcvideo']['user_id'] for role in ROLES}
    checks, observations = [], {}
    result = dict(scenario='mcvideo-group-selection', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-group-selection.pcap'
    capture_name = f'{args.project}-mcvideo-group-selection-capture'

    # ------------------------------------------------------------------------------
    # The status.json a client role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The status.json of mcvideo-server (its affiliations), or {} while it is missing or half written.
    def server_status():
        try:
            return json.loads((args.artifacts / 'mcvideo-server' / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The group selection state of every client and the server's affiliations, for a timed-out check's message.
    def snapshot():
        keys = (
            'mcvideo_call_state',
            'mcvideo_group',
            'mcvideo_selected_group',
            'mcvideo_group_selection',
            'mcvideo_group_selection_result',
            'mcvideo_affiliations',
            'last_error',
        )
        out = {role: {key: status(role).get(key) for key in keys} for role in ROLES}
        out['mcvideo-server'] = server_status().get('affiliations')
        return out

    # ------------------------------------------------------------------------------
    # Poll condition until it holds (record label as passed) or timeout seconds pass (fail with a snapshot).
    def wait(label, condition, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                return
            time.sleep(0.25)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    # Record label as passed if condition holds, else fail with detail.
    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)

    # ------------------------------------------------------------------------------
    # Send one interactive command to the mcx-client of a role.
    def command(role, text):
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
        )

    # ------------------------------------------------------------------------------
    # True when every given role has no MCVideo call.
    def idle(*roles):
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    # Capture the SIP of mcvideo-server (tcpdump in its network namespace) until the capture container is stopped.
    def start_capture():
        server = subprocess.run(
            cli + ['ps', '-q', 'mcvideo-server'], check=True, capture_output=True, text=True
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
    # The SIP messages of the capture as text.
    def sip_text():
        return capture.sip_text(capture_file)

    group = json.loads((generated / 'client-a.json').read_text())['mcvideo']['group_id']
    domain = group.split('@', 1)[1]
    field, closed, preconf = (f'sip:video-{name}@{domain}' for name in ('field', 'closed', 'regroup'))

    # ------------------------------------------------------------------------------
    # The groups mcvideo-server holds a role's MCVideo user affiliated to.
    def affiliations(role):
        return (server_status().get('affiliations') or {}).get(ids[role]) or []

    # ------------------------------------------------------------------------------
    # TS 24.281 clause 9.2.4.2.1: role asks the server to change the selected group of target to the group to, and the
    # answer must be code with warning (empty for none).
    def select(role, target, to, code, warning, label):
        before = json.dumps(status(role).get('mcvideo_group_selection_result'))
        command(role, f'mcvideo-select-remote {ids[target]} {to}')
        wait(
            f'{label} answered',
            lambda: (
                json.dumps(status(role).get('mcvideo_group_selection_result')) != before
                and (status(role).get('mcvideo_group_selection_result') or {}).get('status', 0) >= 200
            ),
        )
        outcome = status(role).get('mcvideo_group_selection_result') or {}
        observations[label] = outcome
        check(label, outcome.get('status') == code and warning in outcome.get('warning', ''), outcome)

    # ------------------------------------------------------------------------------
    # End the MCVideo call of every given role still in one.
    def hang_up(*roles):
        for role in roles:
            if not idle(role):
                command(role, 'mcvideo-hangup')

    try:
        wait(
            'four clients MCVideo authorised and affiliated',
            lambda: all(
                status(role).get('mcvideo_authorized') and status(role).get('mcvideo_affiliated') for role in ROLES
            ),
            90,
        )
        start_capture()
        check(
            'client-b starts on the configured group, not affiliated to video-field',
            status('client-b').get('mcvideo_selected_group') == group and field not in affiliations('client-b'),
            snapshot()['client-b'],
        )

        # MV-SG-01 TS 24.281 clause 9.2.4.2.1, clause 9.2.4.4 steps 3a and 8a and clause 9.2.4.2.2:
        # client-a changes client-b's selected group to video-field; client-b, eligible but not
        # affiliated, is asked to affiliate, does so, selects the group and reports success to client-a.
        select('client-a', 'client-b', field, 200, '', 'MV-SG-01 client-a\'s request for client-b is accepted with 200')
        wait(
            'MV-SG-01 client-b is asked to affiliate and reports success',
            lambda: (status('client-b').get('mcvideo_group_selection') or {}).get('outcome') == 'success',
        )
        check(
            'MV-SG-01 the request carried <affiliation-required>',
            (status('client-b').get('mcvideo_group_selection') or {}).get('affiliation_required') is True,
            status('client-b').get('mcvideo_group_selection'),
        )
        wait(
            'MV-SG-01 mcvideo-server holds client-b\'s affiliation to video-field',
            lambda: field in affiliations('client-b'),
        )
        check(
            'MV-SG-01 client-b\'s selected group is video-field',
            status('client-b').get('mcvideo_selected_group') == field,
            status('client-b').get('mcvideo_selected_group'),
        )
        wait(
            'MV-SG-01 client-a is told of the success',
            lambda: (status('client-a').get('mcvideo_group_selection_result') or {}).get('outcome') == 'success',
        )
        check(
            'MV-SG-01 client-b keeps its affiliation to the group it had selected',
            group in affiliations('client-b'),
            affiliations('client-b'),
        )

        # MV-SG-02: client-b's next call is on its selected group, and reaches the members
        # affiliated to it.
        for role in ('client-a', 'client-c'):
            command(role, f'mcvideo-affiliate {field}')
        wait(
            'MV-SG-02 client-a and client-c affiliate to video-field',
            lambda: all(field in affiliations(role) for role in ('client-a', 'client-c')),
        )
        command('client-b', 'mcvideo-call')
        wait(
            'MV-SG-02 client-b\'s call is on video-field and reaches client-a and client-c',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active' and status(role).get('mcvideo_group') == field
                for role in ('client-a', 'client-b', 'client-c')
            ),
        )
        check('MV-SG-02 client-d, not affiliated to video-field, is not in the call', idle('client-d'))
        hang_up('client-b')
        wait('MV-SG-02 client-b left the call', lambda: idle('client-b'), 30)
        hang_up('client-a', 'client-c')
        wait('MV-SG-02 the call ended', lambda: idle(*ROLES), 30)

        # MV-SG-03: a change back to a group client-b is affiliated to needs no affiliation.
        select(
            'client-a',
            'client-b',
            group,
            200,
            '',
            'MV-SG-03 client-a\'s request to select the first group is accepted with 200',
        )
        wait(
            'MV-SG-03 client-b selects it without being asked to affiliate',
            lambda: (
                status('client-b').get('mcvideo_selected_group') == group
                and (status('client-b').get('mcvideo_group_selection') or {}).get('affiliation_required') is False
                and (status('client-b').get('mcvideo_group_selection') or {}).get('outcome') == 'success'
            ),
        )

        # MV-SG-04 TS 24.281 clause 9.2.4.3.1 step 3a: client-b is not in client-c's <RemoteGroupSelectionURIList>.
        select(
            'client-c',
            'client-b',
            field,
            403,
            '155',
            'MV-SG-04 client-c\'s request is refused with 403 and warning 155',
        )
        # MV-SG-05 TS 24.281 clause 9.2.4.4 step 3a-ii: client-d is not a member of video-closed.
        select(
            'client-a',
            'client-d',
            closed,
            403,
            '120',
            'MV-SG-05 a group client-d may not affiliate to is refused with 403 and warning 120',
        )
        # MV-SG-06 TS 24.281 clause 9.2.4.4 step 2A: video-regroup is preconfigured-use-only.
        select(
            'client-a',
            'client-b',
            preconf,
            403,
            '167',
            'MV-SG-06 a preconfigured-use-only group is refused with 403 and warning 167',
        )
        check(
            'MV-SG-06 client-b\'s selected group is unchanged by the refusals',
            status('client-b').get('mcvideo_selected_group') == group,
        )

        # MV-SG-07 on the wire (TS 24.281 annex F.1).
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            messages = [message for message in capture.split(sip) if message.startswith('MESSAGE sip:')]
            check(
                'MV-SG-07 the request carries group-selection-change-request with the group and the target listed',
                any(
                    '<request-type>group-selection-change-request</request-type>' in message
                    and f'uri="{ids["client-b"]}"' in message
                    and re.search(r'<mcvideo-request-uri[^>]*><mcvideoURI>' + re.escape(field), message)
                    for message in messages
                ),
            )
            check(
                'MV-SG-07 the server\'s request to client-b names the group in <mcvideo-calling-group-id> with <affiliation-required>true',
                any(
                    '<affiliation-required>true</affiliation-required>' in message
                    and re.search(r'<mcvideo-calling-group-id[^>]*><mcvideoURI>' + re.escape(field), message)
                    for message in messages
                ),
            )
            check(
                'MV-SG-07 the response carries group-selection-change-response and <selected-group-change-outcome>success',
                any(
                    '<response-type>group-selection-change-response</response-type>' in message
                    and '<selected-group-change-outcome>success</selected-group-change-outcome>' in message
                    for message in messages
                ),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-group-selection-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
