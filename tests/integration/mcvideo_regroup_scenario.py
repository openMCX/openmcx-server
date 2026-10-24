#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo regroups using a preconfigured group (TS 24.281 clause 21): a group regroup (TS 24.281
clause 21.2) and a user regroup (TS 24.281 clause 21.3), their notifications, a group call on
each regroup with H.264 video checked picture by picture, a call on a regrouped group, the
removals and the refusals of an unauthorised user.

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): client-a may regroup, client-b may not; the
preconfigured group video-regroup only gives a regroup its configuration. Check IDs
match tests/mcvideo/MCVIDEO_REGROUP_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

import capture

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


# ------------------------------------------------------------------------------
# Run the scenario against the lab and write integration/mcvideo-regroup-results.json; return 0 when every check passed.
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
    result = dict(scenario='mcvideo-regroup', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-regroup.pcap'
    capture_name = f'{args.project}-mcvideo-regroup-capture'

    # ------------------------------------------------------------------------------
    # The status.json a role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The call and regroup state of every client, for a timed-out check's message.
    def snapshot():
        keys = (
            'mcvideo_call_state',
            'mcvideo_call_type',
            'mcvideo_video_mode',
            'mcvideo_peer',
            'mcvideo_transmitting',
            'mcvideo_transmitter',
            'mcvideo_frames_received',
            'mcvideo_group',
            'mcvideo_regroups',
            'mcvideo_regroup_result',
            'mcvideo_last_call',
            'last_error',
        )
        return {role: {key: status(role).get(key) for key in keys} for role in ROLES}

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
    # Compare received frames with sent frames by RTP timestamp: frames received, compared and equal.
    def compare(sent, received):
        common = [key for key in received if key in sent]
        return dict(
            received=len(received), compared=len(common), equal=sum(1 for key in common if sent[key] == received[key])
        )

    # ------------------------------------------------------------------------------
    # Compare the frames receiver decoded with those sender encoded.
    def matching(sender, receiver):
        return compare(
            status(sender).get('mcvideo_sent_frames') or {}, status(receiver).get('mcvideo_received_frames') or {}
        )

    # ------------------------------------------------------------------------------
    # True when every given role has no MCVideo call.
    def idle(*roles):
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

    # ------------------------------------------------------------------------------
    # The status.json of mcvideo-server (its affiliations), or {} while it is missing or half written.
    def server_status():
        try:
            return json.loads((args.artifacts / 'mcvideo-server' / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

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
                    'openmcx-dev:0.2',
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
    closed, preconf = f'sip:video-closed@{domain}', f'sip:video-regroup@{domain}'
    tgi, user_tgi = f'sip:video-rg1@{domain}', f'sip:video-rg2@{domain}'

    # ------------------------------------------------------------------------------
    # The regroups role was notified of (TS 24.281 clause 21.2.1.3), by regroup identity.
    def regroups(role):
        return status(role).get('mcvideo_regroups') or {}

    # ------------------------------------------------------------------------------
    # role sends an mcvideo-regroup request (create or remove, TS 24.281 clauses 21.2.1.1, 21.2.1.2 and 21.3.1.1); the
    # answer must carry status code[0] and warning code[1] (empty for none).
    def regroup(role, text, label, code):
        before = json.dumps(status(role).get('mcvideo_regroup_result'))
        command(role, f'mcvideo-regroup {text}')
        wait(
            f'{label} answered',
            lambda: (
                json.dumps(status(role).get('mcvideo_regroup_result')) != before
                and (status(role).get('mcvideo_regroup_result') or {}).get('status', 0) >= 200
            ),
        )
        outcome = status(role).get('mcvideo_regroup_result') or {}
        observations[label] = outcome
        check(label, outcome.get('status') == code[0] and code[1] in outcome.get('warning', ''), outcome)

    # ------------------------------------------------------------------------------
    # True when every given role is in an active MCVideo call on group target.
    def in_call(roles, target):
        return all(
            status(role).get('mcvideo_call_state') == 'active' and status(role).get('mcvideo_group') == target
            for role in roles
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

        # MV-RG-01 TS 24.281 clauses 21.2.1.1 and 21.2.3.1: client-a regroups the MCVideo group with
        # video-closed using the preconfigured group; every affiliated member is told.
        regroup(
            'client-a',
            f'create {tgi} {preconf} groups {group},{closed}',
            'MV-RG-01 client-a\'s group regroup is accepted with 200',
            (200, ''),
        )
        wait(
            'MV-RG-01 every affiliated member is told of the regroup (21.2.2.4)',
            lambda: all(tgi in regroups(role) for role in ROLES),
        )
        check(
            'MV-RG-01 the notice names the constituent groups and the preconfigured group',
            set(regroups('client-b')[tgi].get('groups', [])) == {group, closed}
            and regroups('client-b')[tgi].get('preconfigured') == preconf,
            regroups('client-b'),
        )

        # MV-RG-02: a group call on the regroup reaches the members of both constituent
        # groups. TS 24.281 clause 21.2.1.3 step 4: each client counts itself affiliated with the regroup; as
        # in the MCPTT regroup scenario, it affiliates to the regroup's identity, which is
        # what the shared core counts.
        for role in ROLES:
            command(role, f'mcvideo-affiliate {tgi}')
        wait(
            'MV-RG-02 mcvideo-server holds every member\'s affiliation to the regroup',
            lambda: all(tgi in ((server_status().get('affiliations') or {}).get(ids[role]) or []) for role in ROLES),
        )
        command('client-a', f'mcvideo-call group={tgi}')
        wait('MV-RG-02 all four in the group call on the regroup', lambda: in_call(ROLES, tgi))
        command('client-a', 'mcvideo-transmit')
        wait('MV-RG-02 client-a granted', lambda: status('client-a').get('mcvideo_transmitting') is True)
        # client-c is in the MCVideo group only, not in video-closed; client-d does not
        # accept a transmission by itself (the lab's reception control case).
        wait(
            'MV-RG-02 client-c decodes client-a', lambda: status('client-c').get('mcvideo_frames_received', 0) >= 15, 30
        )
        observations['c_from_a'] = matching('client-a', 'client-c')
        check(
            'MV-RG-02 client-c pictures equal client-a\'s',
            observations['c_from_a']['compared'] >= 10
            and observations['c_from_a']['equal'] == observations['c_from_a']['compared'],
            observations['c_from_a'],
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-RG-02 client-a left the call', lambda: idle('client-a'), 30)
        for role in ('client-b', 'client-c', 'client-d'):
            if not idle(role):
                command(role, 'mcvideo-hangup')
        wait('MV-RG-02 the call ended for all', lambda: idle(*ROLES), 30)

        # MV-RG-03: a call on a group that is part of the regroup is refused with 148.
        before = json.dumps(status('client-b').get('mcvideo_last_call'))
        command('client-b', 'mcvideo-call')
        wait(
            'MV-RG-03 client-b\'s call on the regrouped MCVideo group answered',
            lambda: json.dumps(status('client-b').get('mcvideo_last_call')) != before and idle('client-b'),
        )
        outcome = status('client-b').get('mcvideo_last_call') or {}
        observations['constituent_call'] = outcome
        check(
            'MV-RG-03 it is refused with 403 and warning 148',
            outcome.get('status') == 403 and '148' in outcome.get('warning', ''),
            outcome,
        )

        # MV-RG-04 TS 24.281 clauses 21.2.2.2 (warning 160) and 21.2.2.3 (warning 161): client-b
        # may neither create nor remove a regroup.
        regroup(
            'client-b',
            f'create {user_tgi} {preconf} users {ids["client-c"]}',
            'MV-RG-04 client-b\'s regroup is refused with 403 and warning 160',
            (403, '160'),
        )
        regroup(
            'client-b',
            f'remove {tgi}',
            'MV-RG-04 client-b\'s removal is refused with 403 and warning 161',
            (403, '161'),
        )

        # MV-RG-05 TS 24.281 clauses 21.2.1.2 and 21.2.2.5: client-a removes the regroup; everyone is told.
        regroup('client-a', f'remove {tgi}', 'MV-RG-05 client-a\'s removal is accepted with 200', (200, ''))
        wait('MV-RG-05 every member is told of the removal', lambda: not any(tgi in regroups(role) for role in ROLES))

        # MV-RG-06 TS 24.281 clause 21.3: a user regroup of client-b and client-c; only they are told, and a
        # call on it reaches them.
        regroup(
            'client-a',
            f'create {user_tgi} {preconf} users {ids["client-b"]},{ids["client-c"]}',
            'MV-RG-06 client-a\'s user regroup is accepted with 200',
            (200, ''),
        )
        wait(
            'MV-RG-06 client-b and client-c are told of the user regroup (21.3.2.4)',
            lambda: all(user_tgi in regroups(role) for role in ('client-b', 'client-c')),
        )
        check('MV-RG-06 client-d is not told', user_tgi not in regroups('client-d'))
        # As for the group regroup, its users affiliate to it (TS 24.281 clause 21.3.1.3); client-b, one of
        # them, calls it and reaches client-c; client-a, who created it but is not one of
        # its users, is not in it.
        for role in ('client-b', 'client-c'):
            command(role, f'mcvideo-affiliate {user_tgi}')
        wait(
            'MV-RG-06 mcvideo-server holds the affiliations of client-b and client-c to the user regroup',
            lambda: all(
                user_tgi in ((server_status().get('affiliations') or {}).get(ids[role]) or [])
                for role in ('client-b', 'client-c')
            ),
        )
        command('client-b', f'mcvideo-call group={user_tgi}')
        wait(
            'MV-RG-06 client-b and client-c in the call on the user regroup',
            lambda: in_call(['client-b', 'client-c'], user_tgi),
        )
        check('MV-RG-06 client-a and client-d are not in it', idle('client-a', 'client-d'))
        command('client-b', 'mcvideo-hangup')
        if not idle('client-c'):
            command('client-c', 'mcvideo-hangup')
        wait('MV-RG-06 the call ended', lambda: idle(*ROLES), 30)
        regroup('client-a', f'remove {user_tgi}', 'MV-RG-06 the user regroup is removed with 200', (200, ''))
        wait(
            'MV-RG-06 its members are told of the removal',
            lambda: not any(user_tgi in regroups(role) for role in ROLES),
        )

        # MV-RG-07 on the wire: the MCVideo regroup body (TS 24.281 annex F.6).
        # The capture streams its packets through docker; let the last ones reach the file.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            messages = [message for message in capture.split(sip) if message.startswith('MESSAGE sip:')]
            check(
                'MV-RG-07 regroup requests and notices carry application/vnd.3gpp.mcvideo-regroup+xml',
                sum('application/vnd.3gpp.mcvideo-regroup+xml' in message for message in messages) >= 6,
            )
            check(
                'MV-RG-07 the body is <mcvideoregroup> with <mcvideo-regroup-uri>, not the MCPTT names',
                any(
                    '<mcvideoregroup xmlns="urn:3gpp:ns:preconfiguredRegroup:1.0">' in message
                    and f'<mcvideo-regroup-uri>{tgi}' in message
                    for message in messages
                )
                and not any('mcpttregroup' in message for message in messages),
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-regroup-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
