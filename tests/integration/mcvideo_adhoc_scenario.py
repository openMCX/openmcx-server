#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo ad hoc group calls (TS 24.281 clause 22, on-demand sessions): with a list of MCVideo
users (clause 22.2.2.1.1) and with participant criteria (clause 22.2.2.1.1 step 12, clause 22.4.6.1),
the ad hoc group identity the controlling function assigns (clause 22.4.2), H.264 video checked
picture by picture, a refused originator (warning 185, clause 22.3.2.1.1), and the ad hoc group
emergency alert (clause 12.1A).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): every user but client-d may make ad hoc group calls;
mcvideo-server allows 3 participants besides the originator. Check IDs match
tests/mcvideo/MCVIDEO_ADHOC_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 26.281 V19.0.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

import capture
import refusal_probe

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
def main():
    """Run the scenario against the lab and write its results JSON; exit status 0 when every check passed."""
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
    # On a protected lab (prepare-prearranged-test.py --protected --mcvideo, add_adhoc_security): the preconfigured
    # group whose GMK keys an end-to-end protected ad hoc group call (TS 24.281 clause 22.4.2.2 step 11).
    adhoc_policy = json.loads((generated / 'mcvideo-server.json').read_text())['mcvideo'].get('adhoc_call', {})
    security_group = (adhoc_policy.get('security_groups') or [''])[0]
    checks, observations = [], {}
    result = dict(scenario='mcvideo-adhoc', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-adhoc.pcap'
    capture_name = f'{args.project}-mcvideo-adhoc-capture'

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json as the lab container last wrote it, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The MCVideo state of every client, quoted in a timeout message."""
        keys = (
            'mcvideo_call_state',
            'mcvideo_call_type',
            'mcvideo_video_mode',
            'mcvideo_peer',
            'mcvideo_transmitting',
            'mcvideo_transmitter',
            'mcvideo_frames_received',
            'mcvideo_group',
            'mcvideo_last_call',
            'mcvideo_call_protected',
            'mcvideo_security_group',
            'last_error',
        )
        return {role: {key: status(role).get(key) for key in keys} for role in ROLES}

    # ------------------------------------------------------------------------------
    def wait(label, condition, timeout=30):
        """Poll the condition until it holds (then record the check) or the timeout expires (then fail with a
        snapshot).
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                return
            time.sleep(0.25)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot()))

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=None):
        """Record the check if the condition holds, otherwise fail with the detail."""
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Send a command line to the role's running mcx-client."""
        subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            check=True,
            capture_output=True,
            text=True,
        )

    # ------------------------------------------------------------------------------
    def compare(sent, received):
        """The number of received pictures, of those with a sent picture of the same RTP timestamp, and of
        those equal.
        """
        common = [key for key in received if key in sent]
        return dict(
            received=len(received), compared=len(common), equal=sum(1 for key in common if sent[key] == received[key])
        )

    # ------------------------------------------------------------------------------
    def matching(sender, receiver):
        """compare() of the pictures the sender encoded and the pictures the receiver decoded."""
        return compare(
            status(sender).get('mcvideo_sent_frames') or {}, status(receiver).get('mcvideo_received_frames') or {}
        )

    # ------------------------------------------------------------------------------
    def idle(*roles):
        """Whether every given client has no MCVideo call."""
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    def client_errors(role, reason):
        """The role's client_error log entries with this reason, in log order."""
        run = subprocess.run(
            cli + ['logs', '--no-color', '--no-log-prefix', role], capture_output=True, text=True, timeout=30
        )
        found = []
        for line in run.stdout.splitlines():
            start = line.find('{"')
            try:
                entry = json.loads(line[start:]) if start >= 0 else {}
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and entry.get('event') == 'client_error' and entry.get('reason') == reason:
                found.append(entry)
        return found

    # ------------------------------------------------------------------------------
    def refused(role, text, code, reason, label):
        """Send the command and check that the call it starts is answered with the status code and, when given, the
        warning code.
        """
        before = json.dumps(status(role).get('mcvideo_last_call'))
        command(role, text)
        wait(f'{label} answered', lambda: json.dumps(status(role).get('mcvideo_last_call')) != before and idle(role))
        outcome = status(role).get('mcvideo_last_call') or {}
        observations[label] = outcome
        check(label, outcome.get('status') == code and (not reason or reason in outcome.get('warning', '')), outcome)

    # ------------------------------------------------------------------------------
    def start_capture():
        """Capture the SIP on mcvideo-server's network namespace with tcpdump in a container; return once it listens."""
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
                    'openmcx-dev:0.5',
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

    group = json.loads((generated / 'client-a.json').read_text())['mcvideo']['group_id']

    # ------------------------------------------------------------------------------
    def in_adhoc(roles):
        """Whether all given clients are in one active ad hoc group call (TS 24.281 clause 22) with the same, non-empty
        ad hoc group identity.
        """
        groups = {status(role).get('mcvideo_group') for role in roles}
        return (
            all(
                status(role).get('mcvideo_call_state') == 'active' and status(role).get('mcvideo_call_type') == 'adhoc'
                for role in roles
            )
            and len(groups) == 1
            and None not in groups
            and '' not in groups
        )

    # ------------------------------------------------------------------------------
    def adhoc_sessions():
        """The MCVideo server's ad hoc group call sessions."""
        value = status('mcvideo-server').get('sessions', [])
        calls = value.values() if isinstance(value, dict) else value
        return [call for call in calls if call.get('call_type') == 'adhoc']

    # ------------------------------------------------------------------------------
    def keyed(roles, label):
        """MV-AH-E2E: on a protected lab every given client keys the ad hoc call with the GMK of the preconfigured group
        named in <preconfigured-group-id> (TS 24.281 clauses 22.2.2.1.1 2xx step 3 and 22.2.2.1.2 step 8, TS 33.180
        clause 5.7), as the server's session does; on a clear lab the call is in the clear.
        """
        wait(
            f'{label} the clients key the call with the preconfigured group'
            if security_group
            else f'{label} the call is in the clear',
            lambda: all(
                status(role).get('mcvideo_call_protected') is bool(security_group)
                and (status(role).get('mcvideo_security_group') or '') == security_group
                for role in roles
            ),
        )
        if security_group:
            sessions = adhoc_sessions()
            check(
                f'{label} the server keys the session with the preconfigured group',
                any(call.get('protected') and call.get('security_group') == security_group for call in sessions),
                sessions,
            )

    try:
        wait(
            'four clients MCVideo authorised and affiliated',
            lambda: all(
                status(role).get('mcvideo_authorized') and status(role).get('mcvideo_affiliated') for role in ROLES
            ),
            90,
        )
        start_capture()

        # MV-AH-01 TS 24.281 clause 22.2.2.1.1 and clause 22.4.2: client-a calls client-b and client-c. The server
        # assigns an ad hoc group identity, which all three share; client-d is not invited.
        command('client-a', f"mcvideo-adhoc {ids['client-b']} {ids['client-c']}")
        wait(
            'MV-AH-01 client-a, client-b and client-c in one ad hoc group call',
            lambda: in_adhoc(['client-a', 'client-b', 'client-c']),
        )
        adhoc_group = status('client-a').get('mcvideo_group')
        observations['adhoc_group'] = adhoc_group
        check('MV-AH-01 the ad hoc group identity is not the preconfigured group', adhoc_group != group, adhoc_group)
        check('MV-AH-01 client-d is not in the call', idle('client-d'))
        keyed(['client-a', 'client-b', 'client-c'], 'MV-AH-E2E')
        observations['security_group'] = security_group
        command('client-a', 'mcvideo-transmit')
        wait('MV-AH-01 client-a granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        for role in ('client-b', 'client-c'):
            wait(
                f'MV-AH-01 {role} decodes client-a',
                lambda role=role: status(role).get('mcvideo_frames_received', 0) >= 15,
                30,
            )
            observations[f'{role}_from_a'] = matching('client-a', role)
            got = observations[f'{role}_from_a']
            check(
                f'MV-AH-01 {role} pictures equal client-a\'s',
                got['compared'] >= 10 and got['equal'] == got['compared'],
                got,
            )
        command('client-a', 'mcvideo-end')
        wait('MV-AH-01 client-a released', lambda: status('client-a').get('mcvideo_transmitting') is False)
        command('client-b', 'mcvideo-transmit')
        wait('MV-AH-01 client-b granted in turn', lambda: status('client-b').get('mcvideo_transmitting') is True)
        wait(
            'MV-AH-01 client-c decodes client-b',
            lambda: (
                len(status('client-c').get('mcvideo_received_frames') or {})
                > observations['client-c_from_a']['received'] + 10
            ),
            30,
        )
        observations['c_from_b'] = matching('client-b', 'client-c')
        check(
            'MV-AH-01 client-c pictures of client-b equal client-b\'s',
            observations['c_from_b']['equal'] >= 5
            and observations['c_from_b']['equal'] == observations['c_from_b']['compared'],
            observations['c_from_b'],
        )
        # MV-AH-02 TS 24.281 clause 6.3.8.1: the initiator leaving ends only a pre-arranged group call (item 3), and
        # a group call with one participant left is released (item 2).
        command('client-a', 'mcvideo-hangup')
        wait('MV-AH-02 the originator leaves', lambda: idle('client-a'), 30)
        time.sleep(2)
        check('MV-AH-02 the call goes on for the others without its initiator', in_adhoc(['client-b', 'client-c']))
        command('client-b', 'mcvideo-hangup')
        wait('MV-AH-02 with one participant left, the call is released', lambda: idle(*ROLES), 30)

        # MV-AH-03 TS 24.281 clause 22.2.2.1.1 step 12 and clause 22.4.6.1: participants by criteria. Everyone
        # affiliated to the MCVideo group is invited.
        command('client-a', f'mcvideo-adhoc criteria affiliated:{group}')
        wait('MV-AH-03 the criteria call invites every user affiliated to the group', lambda: in_adhoc(ROLES))
        keyed(ROLES, 'MV-AH-E2E criteria call:')
        for role in ('client-a', 'client-b', 'client-c'):
            command(role, 'mcvideo-hangup')
            wait(f'MV-AH-03 {role} leaves', lambda role=role: idle(role), 30)
        wait('MV-AH-03 the call ended with one participant left', lambda: idle(*ROLES), 30)

        # MV-AH-04 TS 24.281 clause 22.3.2.1.1: client-d may not make ad hoc group calls (warning 185).
        refused(
            'client-d',
            f"mcvideo-adhoc {ids['client-a']}",
            403,
            '185 user is not authorised to initiate the adhoc group call',
            'MV-AH-04 client-d\'s ad hoc group call is refused with 403 and warning 185 (clause 22.3.2.1.1 step 9 text)',
        )

        # MV-AH-06 TS 24.281 clause 12.1A.1.1 and clause 12.1A.1.2: client-a raises an ad hoc group
        # emergency alert to the users affiliated to the group. The server answers with the alert's ad
        # hoc group, confirms receipt to client-a (clause 12.1A.3.1 step 3e) and tells the others; the
        # cancellation ends it. client-b is refused with 403 (clause 12.1A.3.1 step 3a).
        command('client-a', f'mcvideo-adhoc-alert affiliated:{group}')
        wait(
            'MV-AH-06 client-a\'s ad hoc group emergency alert is accepted and confirmed',
            lambda: (
                status('client-a').get('mcvideo_adhoc_alert_state') == 3
                and (status('client-a').get('mcvideo_adhoc_alert_result') or {}).get('status') == 200
                and bool(status('client-a').get('mcvideo_adhoc_alert_group'))
            ),
        )
        alert_group = status('client-a').get('mcvideo_adhoc_alert_group')
        observations['adhoc_alert_group'] = alert_group
        wait(
            'MV-AH-06 the other members receive the alert from client-a with its ad hoc group',
            lambda: all(
                ((status(role).get('mcvideo_received_adhoc_alerts') or {}).get(alert_group) or {}).get('initiator')
                == ids['client-a']
                for role in ('client-b', 'client-c', 'client-d')
            ),
        )
        command('client-a', 'mcvideo-adhoc-alert cancel')
        wait(
            'MV-AH-06 the cancellation clears the alert everywhere',
            lambda: (
                status('client-a').get('mcvideo_adhoc_alert_state') == 1
                and all(
                    alert_group not in (status(role).get('mcvideo_received_adhoc_alerts') or {})
                    for role in ('client-b', 'client-c', 'client-d')
                )
            ),
        )
        # client-b has no <allow-activate-adhoc-group-emergency-alert>: its client does not send the alert (TS 24.281
        # clause 12.1A, as TS 24.379 clause 12.1A.1.1 steps 1 and 2: tell the user, skip the procedure); the server's
        # 403 (clause 12.1A.3.1 step 3a) is checked with the same MESSAGE sent raw as client-b (refusal_probe.py).
        reason = (
            'not authorised by the MCVideo user profile: ad hoc group emergency alert '
            '(allow-activate-adhoc-group-emergency-alert)'
        )
        earlier = len(client_errors('client-b', reason))
        earlier_result = status('client-b').get('mcvideo_adhoc_alert_result')
        command('client-b', f'mcvideo-adhoc-alert affiliated:{group}')
        wait(
            'MV-AH-06 client-b, without <allow-activate-adhoc-group-emergency-alert>, does not send the alert',
            lambda: (
                len(client_errors('client-b', reason)) > earlier
                and status('client-b').get('mcvideo_adhoc_alert_result') == earlier_result
                and status('client-b').get('mcvideo_adhoc_alert_state') == 1
            ),
        )
        answer = refusal_probe.run_in(cli, args.compose, 'client-b', ['--video-adhoc-alert', f'affiliated:{group}'])
        answer = answer['video_adhoc_alert'][0]
        observations['unauthorised_adhoc_alert_probe'] = answer
        check(
            'MV-AH-06 client-b, without <allow-activate-adhoc-group-emergency-alert>, is refused with 403',
            answer['status'] == 403,
            answer,
        )
        check(
            'MV-AH-06 the refused alert reached nobody',
            all(
                not any(
                    alert.get('initiator') == ids['client-b']
                    for alert in (status(role).get('mcvideo_received_adhoc_alerts') or {}).values()
                )
                for role in ('client-a', 'client-c', 'client-d')
            ),
        )

        # MV-AH-05 on the wire: <call-participants-criteria> as in TS 24.281 annex F.1.
        # The capture streams its packets through docker; let the last ones reach the file.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:mcvideo@')]
            adhoc = [message for message in invites if '<session-type>adhoc</session-type>' in message]
            check('MV-AH-05 ad hoc INVITEs to the MCVideo PSI', len(adhoc) >= 2, len(adhoc))
            check(
                'MV-AH-05 the called MCVideo IDs in a resource-lists body',
                any(
                    'application/resource-lists+xml' in message
                    and ids['client-b'] in message
                    and ids['client-c'] in message
                    for message in adhoc
                ),
            )
            check(
                'MV-AH-05 the criteria in <call-participants-criteria> (TS 24.281 F.1, without the MCPTT "s")',
                any(
                    f'<call-participants-criteria>affiliated:{group}</call-participants-criteria>' in message
                    for message in adhoc
                ),
            )
            answers = [
                message
                for message in capture.split(sip)
                if message.startswith('SIP/2.0 200') and '<session-type>adhoc' in message
            ]
            check(
                'MV-AH-05 the 200 (OK) names the ad hoc group in <mcvideo-calling-group-id>',
                any(
                    f'<mcvideo-calling-group-id type="Normal"><mcvideoURI>{adhoc_group}</mcvideoURI>' in message
                    for message in answers
                ),
            )
            # MV-AH-E2E TS 24.281 clauses 22.2.2.1.1 step 10 d) iii) and 22.4.2.2: the protected request asks for
            # end-to-end security and offers RTP/SAVP; the 200 (OK) and the invitations name the preconfigured group.
            if security_group:
                named = f'<preconfigured-group-id>{security_group}</preconfigured-group-id>'
                check(
                    'MV-AH-E2E the ad hoc INVITE carries <end-to-end-security>true with RTP/SAVP',
                    any('<end-to-end-security>true</end-to-end-security>' in m and 'RTP/SAVP' in m for m in adhoc),
                )
                check(
                    'MV-AH-E2E the 200 (OK) names the group in <preconfigured-group-id>',
                    any(named in m for m in answers),
                )
                invitations = [
                    m
                    for m in capture.split(sip)
                    if m.startswith('INVITE sip:') and not m.startswith('INVITE sip:mcvideo@')
                ]
                check(
                    'MV-AH-E2E the invitations name the group in <preconfigured-group-id>',
                    any(named in m and '<session-type>adhoc' in m for m in invitations),
                )
            messages = [message for message in capture.split(sip) if message.startswith('MESSAGE sip:')]
            check(
                'MV-AH-06 the alert carries <adhoc-alert-ind>true, the criteria and an MCVideo location body',
                any(
                    '<adhoc-alert-ind>true</adhoc-alert-ind>' in message
                    and f'affiliated:{group}' in message
                    and 'application/vnd.3gpp.mcvideo-location-info+xml' in message
                    for message in messages
                ),
            )
            check(
                'MV-AH-06 client-a is sent <adhoc-alert-ind-rcvd>true',
                any('<adhoc-alert-ind-rcvd>true</adhoc-alert-ind-rcvd>' in message for message in messages),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-adhoc-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
