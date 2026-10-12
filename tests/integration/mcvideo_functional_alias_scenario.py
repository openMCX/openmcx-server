#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo functional aliases (TS 24.281 clause 20): status determination subscriptions to a
user's aliases and to an alias's users (clause 20.2.1.3), activation (clause 20.2.1.2) answered
200 (clause 20.2.2.2.3 step 8) with the outcome in the status NOTIFY (clause 20.2.2.2.5), the
refusals of a user outside the alias's user list and beyond its activation limit (clause
20.2.2.3.3), the "take-over-possible" offer and the take-over after it (clause 20.2.1.2 step 6
d)), the alias presented in a group call and left out when no longer held (clause 10.2.2.3.1.1
step 17a), the binding of an alias to a group (clause 20.4) with refusals
176 (clause 20.4.2.2.2) and 178 (clause 20.4.2.3.2), a private call to an alias redirected with
300 (clause 10.2.2.2.1), deactivation, and the wire format (clause 20.3.1, annex F.1).

Run against a fixture prepared with --mcvideo (add_mcvideo_policy in
tools/prepare-prearranged-test.py): video-dispatcher for client-a and client-b with one
activation and take-over allowed, of which only client-b has the right; video-medic for
client-b and client-c with two activations; only client-b may bind. Check IDs match
tests/mcvideo/MCVIDEO_FUNCTIONAL_ALIAS_TEST.md.

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
    checks, observations = [], {}
    result = dict(scenario='mcvideo-functional-alias', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-functional-alias.pcap'
    capture_name = f'{args.project}-mcvideo-functional-alias-capture'

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json as the lab container last wrote it, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    def server_status():
        """mcvideo-server's status.json, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / 'mcvideo-server' / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    def snapshot():
        """The MCVideo state of every client, quoted in a timeout message."""
        keys = (
            'mcvideo_call_state',
            'mcvideo_call_type',
            'mcvideo_peer',
            'mcvideo_functional_aliases',
            'mcvideo_functional_alias_in_use',
            'mcvideo_functional_alias_result',
            'mcvideo_functional_alias_redirect',
            'mcvideo_calling_functional_alias',
            'mcvideo_called_functional_alias',
            'mcvideo_participant_aliases',
            'mcvideo_last_call',
            'last_error',
        )
        out = {role: {key: status(role).get(key) for key in keys} for role in ROLES}
        out['mcvideo-server'] = server_status().get('functional_aliases')
        return out

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
    def idle(*roles):
        """Whether every given client has no MCVideo call."""
        return all(status(role).get('mcvideo_call_state') == 'idle' for role in roles)

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

    domain = ids['client-a'].split('@', 1)[1]
    dispatcher, medic = f'sip:video-dispatcher.alias@{domain}', f'sip:video-medic.alias@{domain}'

    # ------------------------------------------------------------------------------
    def holders(alias):
        """The MCVideo IDs mcvideo-server counts as having activated the functional alias."""
        return (server_status().get('functional_aliases') or {}).get(alias) or []

    # ------------------------------------------------------------------------------
    def fa(role, action, alias, code, label, outcome=None):
        """Send an activation, deactivation or take-over of the functional alias (TS 24.281 clause 20.2.1.2) and check
        the status code of the answer and, for a client following its own status, the alias's outcome in the NOTIFY
        with the request's p-id-fa (clause 20.2.2.2.5).
        """
        before = json.dumps(status(role).get('mcvideo_functional_alias_result'))
        command(role, f'mcvideo-fa {action} {alias}')
        wait(
            f'{label} answered',
            lambda: (
                json.dumps(status(role).get('mcvideo_functional_alias_result')) != before
                and (status(role).get('mcvideo_functional_alias_result') or {}).get('status', 0) >= 200
                and (
                    outcome is None
                    or alias in ((status(role).get('mcvideo_functional_alias_result') or {}).get('outcomes') or {})
                )
            ),
        )
        result = status(role).get('mcvideo_functional_alias_result') or {}
        observations[label] = result
        check(
            label,
            result.get('status') == code and (outcome is None or (result.get('outcomes') or {}).get(alias) == outcome),
            result,
        )

    # ------------------------------------------------------------------------------
    def hang_up(*roles):
        """Hang up the given clients that are still in a call."""
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

        # MV-FA-01 TS 24.281 clause 20.2.1.3 and clause 20.2.2.2.4: client-c follows its own aliases
        # before changing them (clause 20.2.1.1); client-b follows the users of video-dispatcher
        # (clause 20.2.1.3 step 2A), which it may activate; client-d, outside its user list, is
        # refused (clause 20.2.2.3.4 step 5).
        command('client-c', 'mcvideo-fa-subscribe')
        wait(
            'MV-FA-01 client-c\'s status subscription gets the per-user status, with no alias active',
            lambda: (
                status('client-c').get('mcvideo_functional_alias_status_known') is True
                and status('client-c').get('mcvideo_functional_aliases') == []
            ),
        )
        command('client-b', f'mcvideo-fa-subscribe {dispatcher}')
        wait(
            'MV-FA-01 client-b\'s subscription to video-dispatcher gets the per-alias status, with no user',
            lambda: (status('client-b').get('mcvideo_alias_users') or {}).get(dispatcher) == [],
        )
        command('client-b', 'mcvideo-fa-subscribe')
        wait(
            'MV-FA-01 client-b follows its own aliases too (clause 20.2.1.1)',
            lambda: status('client-b').get('mcvideo_functional_alias_status_known') is True,
        )
        command('client-d', f'mcvideo-fa-subscribe {dispatcher}')
        wait(
            'MV-FA-01 client-d\'s subscription to video-dispatcher is refused with 403',
            lambda: (
                status('client-d').get('mcvideo_functional_alias_subscription_result')
                == {'alias': dispatcher, 'status': 403}
            ),
        )

        # MV-FA-02 TS 24.281 clause 20.2.1.2 and clause 20.2.2.2.3: client-a activates
        # video-dispatcher, and client-b is notified of its user (clause 20.2.2.3.5).
        fa(
            'client-a',
            'activate',
            dispatcher,
            200,
            'MV-FA-02 client-a\'s activation of video-dispatcher is accepted with 200',
        )
        wait(
            'MV-FA-02 mcvideo-server holds client-a as its only user', lambda: holders(dispatcher) == [ids['client-a']]
        )
        check(
            'MV-FA-02 client-a counts it active',
            dispatcher in (status('client-a').get('mcvideo_functional_aliases') or []),
        )
        wait(
            'MV-FA-02 client-b is notified that client-a holds video-dispatcher',
            lambda: (status('client-b').get('mcvideo_alias_users') or {}).get(dispatcher) == [ids['client-a']],
        )

        # MV-FA-03 TS 24.281 clause 20.2.2.3.3: client-c is not in the alias's <mcvideo-user-list>, and one
        # activation at a time refuses client-b's plain activation; both are answered 200 (clause 20.2.2.2.3
        # step 8, which has no step 4B) and learn the outcome from their status NOTIFY. client-b, which may
        # take the alias over, is offered "take-over-possible".
        fa(
            'client-c',
            'activate',
            dispatcher,
            200,
            'MV-FA-03 client-c, not in the user list: 200, then refused in the NOTIFY',
            'refused',
        )
        fa(
            'client-b',
            'activate',
            dispatcher,
            200,
            'MV-FA-03 client-b\'s activation beyond the limit: 200, then NOTIFY "take-over-possible"',
            'take-over-possible',
        )
        check(
            'MV-FA-03 client-a still holds video-dispatcher',
            holders(dispatcher) == [ids['client-a']],
            holders(dispatcher),
        )

        # MV-FA-04 TS 24.281 clause 20.2.1.2 step 6d: client-b takes it over (<take-over>), which the alias
        # allows and its profile permits; client-a, without the right, cannot take it back.
        fa(
            'client-b',
            'takeover',
            dispatcher,
            200,
            'MV-FA-04 client-b\'s take-over after the offer: 200, then NOTIFY "activated"',
            'activated',
        )
        check(
            'MV-FA-04 client-b\'s take-over carries <take-over>',
            (status('client-b').get('mcvideo_functional_alias_result') or {}).get('take_over') is True,
        )
        wait(
            'MV-FA-04 mcvideo-server holds client-b in place of client-a',
            lambda: holders(dispatcher) == [ids['client-b']],
        )
        wait(
            'MV-FA-04 client-b is notified that it now holds video-dispatcher',
            lambda: (status('client-b').get('mcvideo_alias_users') or {}).get(dispatcher) == [ids['client-b']],
        )
        fa(
            'client-a',
            'takeover',
            dispatcher,
            200,
            'MV-FA-04 client-a, offered no take-over, asks for an activation (200) and does not get the alias',
        )
        check(
            'MV-FA-04 client-a\'s request carries no <take-over> and client-b keeps video-dispatcher',
            (status('client-a').get('mcvideo_functional_alias_result') or {}).get('take_over') is False
            and holders(dispatcher) == [ids['client-b']],
        )

        # MV-FA-05 TS 24.281 clause 10.2.2.3.1.1 step 17a: client-a, which does not follow its status, still
        # presents video-dispatcher; the participating function leaves out an alias it no
        # longer holds.
        command('client-a', f'mcvideo-fa use {dispatcher}')
        command('client-a', f'mcvideo-private {ids["client-b"]}')
        wait(
            'MV-FA-05 client-a and client-b are in a private call',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b')),
        )
        check(
            'MV-FA-05 client-b is shown no functional alias for client-a',
            not status('client-b').get('mcvideo_calling_functional_alias'),
            status('client-b').get('mcvideo_calling_functional_alias'),
        )
        hang_up('client-a')
        wait('MV-FA-05 the private call ended', lambda: idle('client-a', 'client-b'), 30)

        # MV-FA-06 TS 24.281 clause 9.2.1.2.1.1: client-b presents video-dispatcher in a group call; the
        # invited members are told of it, and the conference lists it for client-b.
        command('client-b', f'mcvideo-fa use {dispatcher}')
        command('client-b', 'mcvideo-call')
        wait(
            'MV-FA-06 all four in client-b\'s group call',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        wait(
            'MV-FA-06 client-a and client-c are called by video-dispatcher',
            lambda: all(
                status(role).get('mcvideo_calling_functional_alias') == dispatcher for role in ('client-a', 'client-c')
            ),
        )
        wait(
            'MV-FA-06 the conference event lists client-b with video-dispatcher (6.3.3.4 step 2b-iii)',
            lambda: (status('client-a').get('mcvideo_participant_aliases') or {}).get(ids['client-b']) == dispatcher,
        )
        hang_up('client-b')
        wait('MV-FA-06 client-b left the call', lambda: idle('client-b'), 30)
        hang_up('client-a', 'client-c', 'client-d')
        wait('MV-FA-06 the call ended for all', lambda: idle(*ROLES), 30)

        # MV-FA-07 TS 24.281 clause 20.4.2.1.2 and clause 20.4.2.1.3: client-b binds
        # video-dispatcher to the MCVideo group, and the conference event lists it for client-b
        # in a group call where client-b presents no alias (clause 6.3.3.4 step 2b-iii). A second
        # alias cannot be bound to the same group (178, clause 20.4.2.3.2), and client-c, without
        # <allow-functional-alias-binding-with-group>, may not bind or unbind (176, clause
        # 20.4.2.2.2).
        group = json.loads((generated / 'client-a.json').read_text())['mcvideo']['group_id']

        # ------------------------------------------------------------------------------
        def binding(role, text, code, warning, label):
            """Send a functional alias to group binding or unbinding (TS 24.281 clause 20.4.2.1.2 and clause
            20.4.2.1.3) and check the status code and warning code of the answer.
            """
            before = json.dumps(status(role).get('mcvideo_functional_alias_binding_result'))
            command(role, f'mcvideo-fa-{text}')
            wait(
                f'{label} answered',
                lambda: (
                    json.dumps(status(role).get('mcvideo_functional_alias_binding_result')) != before
                    and (status(role).get('mcvideo_functional_alias_binding_result') or {}).get('status', 0) >= 200
                ),
            )
            outcome = status(role).get('mcvideo_functional_alias_binding_result') or {}
            observations[label] = outcome
            check(label, outcome.get('status') == code and warning in outcome.get('warning', ''), outcome)

        binding(
            'client-b',
            f'bind {dispatcher} {group}',
            200,
            '',
            'MV-FA-07 client-b binds video-dispatcher to the group with 200',
        )
        binding('client-b', f'bind {dispatcher} {group}', 200, '', 'MV-FA-07 binding it again is accepted with 200')
        fa('client-b', 'activate', medic, 200, 'MV-FA-07 client-b activates video-medic with 200')
        binding(
            'client-b',
            f'bind {medic} {group}',
            403,
            '178',
            'MV-FA-07 binding video-medic to the same group is refused with 403 and warning 178',
        )
        fa('client-b', 'deactivate', medic, 200, 'MV-FA-07 client-b deactivates video-medic with 200')
        binding(
            'client-c',
            f'unbind {medic} {group}',
            403,
            '176',
            'MV-FA-07 client-c, without the binding right, is refused with 403 and warning 176',
        )
        command('client-b', 'mcvideo-fa use none')
        command('client-b', 'mcvideo-call')
        wait(
            'MV-FA-07 all four in client-b\'s group call without a presented alias',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        check(
            'MV-FA-07 the invited members are shown no calling alias',
            not status('client-a').get('mcvideo_calling_functional_alias'),
            status('client-a').get('mcvideo_calling_functional_alias'),
        )
        wait(
            'MV-FA-07 the conference event lists client-b with its bound video-dispatcher',
            lambda: (status('client-a').get('mcvideo_participant_aliases') or {}).get(ids['client-b']) == dispatcher,
        )
        hang_up('client-b')
        wait('MV-FA-07 client-b left the call', lambda: idle('client-b'), 30)
        hang_up('client-a', 'client-c', 'client-d')
        wait('MV-FA-07 the call ended for all', lambda: idle(*ROLES), 30)
        binding(
            'client-b', f'unbind {dispatcher} {group}', 200, '', 'MV-FA-07 client-b unbinds video-dispatcher with 200'
        )

        # MV-FA-08 TS 24.281 clause 20.2.1.3: once client-a follows its own status, the NOTIFY shows it no
        # longer holds video-dispatcher, and it stops presenting it.
        command('client-a', 'mcvideo-fa-subscribe')
        wait(
            'MV-FA-08 client-a learns from the per-user status that it lost video-dispatcher',
            lambda: (
                status('client-a').get('mcvideo_functional_alias_status_known') is True
                and dispatcher not in status('client-a').get('mcvideo_functional_aliases', [dispatcher])
            ),
        )

        # MV-FA-09 TS 24.281 clause 10.2.2.2.1: client-c activates video-medic, and its own
        # subscription is notified with the p-id-fa of that PUBLISH (clause 20.2.2.2.5 step 2c);
        # client-a calls the alias (step 11c), the controlling function answers 300 naming
        # client-c, and client-a calls client-c with <called-functional-alias-URI> (steps 1 to 3
        # on receiving the SIP 300 (Multiple Choices) response).
        fa('client-c', 'activate', medic, 200, 'MV-FA-09 client-c\'s activation of video-medic is accepted with 200')
        pid = (status('client-c').get('mcvideo_functional_alias_result') or {}).get('p_id_fa')
        wait(
            'MV-FA-09 client-c\'s status NOTIFY lists video-medic with the p-id-fa of its PUBLISH',
            lambda: (
                status('client-c').get('mcvideo_functional_aliases') == [medic]
                and (status('client-c').get('mcvideo_functional_alias_notified') or {}).get('p_id_fa') == pid
            ),
        )
        command('client-a', f'mcvideo-private-fa {medic}')
        wait(
            'MV-FA-09 client-a\'s call to video-medic is redirected to client-c',
            lambda: (
                (status('client-a').get('mcvideo_functional_alias_redirect') or {}).get('selected') == ids['client-c']
            ),
        )
        wait(
            'MV-FA-09 client-a and client-c are in a private call',
            lambda: all(
                status(role).get('mcvideo_call_state') == 'active'
                and status(role).get('mcvideo_call_type') == 'private'
                for role in ('client-a', 'client-c')
            ),
        )
        check(
            'MV-FA-09 client-c is told it was called by video-medic',
            status('client-c').get('mcvideo_called_functional_alias') == medic,
            status('client-c').get('mcvideo_called_functional_alias'),
        )
        check(
            'MV-FA-09 client-a\'s peer is client-c',
            status('client-a').get('mcvideo_peer') == ids['client-c'],
            status('client-a').get('mcvideo_peer'),
        )
        hang_up('client-a')
        wait('MV-FA-09 the private call ended', lambda: idle('client-a', 'client-c'), 30)

        # MV-FA-10 TS 24.281 clause 20.2.2.3.3 with Expires 0: client-c deactivates video-medic; a
        # call to it then finds no user and is refused with 403 and warning 145 (clause
        # 10.2.2.3.1.1).
        fa(
            'client-c',
            'deactivate',
            medic,
            200,
            'MV-FA-10 client-c\'s deactivation of video-medic is accepted with 200',
        )
        wait('MV-FA-10 mcvideo-server holds no user of video-medic', lambda: holders(medic) == [])
        wait(
            'MV-FA-10 client-c\'s status NOTIFY lists no alias',
            lambda: status('client-c').get('mcvideo_functional_aliases') == [],
        )
        before = json.dumps(status('client-a').get('mcvideo_last_call'))
        command('client-a', f'mcvideo-private-fa {medic}')
        wait(
            'MV-FA-10 client-a\'s call to the inactive alias answered',
            lambda: json.dumps(status('client-a').get('mcvideo_last_call')) != before and idle('client-a'),
        )
        outcome = status('client-a').get('mcvideo_last_call') or {}
        observations['inactive_alias_call'] = outcome
        check(
            'MV-FA-10 it is refused with 403 and warning 145',
            outcome.get('status') == 403 and '145' in outcome.get('warning', ''),
            outcome,
        )

        # MV-FA-11 TS 24.281 clause 20.2.1.3 step 5 and de-subscription: client-b fetches the users of
        # video-dispatcher once (Expires 0), and client-c ends its subscription.
        command('client-b', f'mcvideo-fa-unsubscribe {dispatcher}')
        wait(
            'MV-FA-11 client-b\'s subscription to video-dispatcher ends',
            lambda: dispatcher not in status('client-b').get('mcvideo_functional_alias_subscriptions', [dispatcher]),
        )
        command('client-b', f'mcvideo-fa-fetch {dispatcher}')
        wait(
            'MV-FA-11 client-b\'s fetch returns client-b and leaves no subscription',
            lambda: (
                (status('client-b').get('mcvideo_alias_users') or {}).get(dispatcher) == [ids['client-b']]
                and dispatcher not in status('client-b').get('mcvideo_functional_alias_subscriptions', [dispatcher])
            ),
        )
        observations['server_events'] = server_status().get('functional_aliases')

        # MV-FA-12 on the wire: the MCVideo namespaces and elements of TS 24.281 clause 20.3.1 and
        # annex F.1.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            publishes = [message for message in capture.split(sip) if message.startswith('PUBLISH sip:')]
            alias_publishes = [message for message in publishes if 'urn:3gpp:ns:mcvideoPresInfoFA:1.0' in message]
            check(
                'MV-FA-12 the alias PUBLISHes use urn:3gpp:ns:mcvideoPresInfoFA:1.0 and no MCPTT alias namespace',
                len(alias_publishes) >= 6 and not any('mcpttPresInfoFA' in message for message in publishes),
                len(alias_publishes),
            )
            check(
                'MV-FA-12 an activation has Expires 4294967295 and a deactivation Expires 0',
                any(re.search(r'(?im)^Expires:\s*4294967295', message) for message in alias_publishes)
                and any(re.search(r'(?im)^Expires:\s*0\s*$', message) for message in alias_publishes),
            )
            check(
                'MV-FA-12 the take-over carries <take-over>true</take-over>',
                any('take-over>true<' in message for message in alias_publishes),
            )
            subscribes = [message for message in capture.split(sip) if message.startswith('SUBSCRIBE sip:')]
            check(
                'MV-FA-12 the status SUBSCRIBEs carry both <req-type> values',
                any('<req-type>functional-alias-status-determination</req-type>' in message for message in subscribes)
                and any('<req-type>fa-user-status-determination</req-type>' in message for message in subscribes),
            )
            notifies = [message for message in capture.split(sip) if message.startswith('NOTIFY sip:')]
            check(
                'MV-FA-12 a per-user NOTIFY lists an alias with status="activated"',
                any(
                    re.search(r'functionalAliasID="' + re.escape(medic) + r'" status="activated"', message)
                    for message in notifies
                ),
            )
            check(
                'MV-FA-12 a per-user NOTIFY offers an alias with status="take-over-possible"',
                any(
                    re.search(
                        r'functionalAliasID="' + re.escape(dispatcher) + r'" status="take-over-possible"', message
                    )
                    for message in notifies
                ),
            )
            check(
                'MV-FA-12 a per-alias NOTIFY names the alias as entity and its user in "user"',
                any(
                    f'entity="{dispatcher}"' in message and f'user="{ids["client-b"]}"' in message
                    for message in notifies
                ),
            )
            messages = [message for message in capture.split(sip) if message.startswith('MESSAGE sip:')]
            check(
                'MV-FA-12 the binding MESSAGE carries fa-group-binding-req, <binding-ind> and <binding-fa-uri> with the group listed',
                any(
                    '<request-type>fa-group-binding-req</request-type>' in message
                    and '<binding-ind>true</binding-ind>' in message
                    and f'<binding-fa-uri>{dispatcher}</binding-fa-uri>' in message
                    and f'uri="{group}"' in message
                    for message in messages
                ),
            )
            check(
                'MV-FA-12 the unbinding MESSAGE carries <binding-ind>false and <unbinding-fa-uri>',
                any(
                    '<binding-ind>false</binding-ind>' in message
                    and f'<unbinding-fa-uri>{dispatcher}</unbinding-fa-uri>' in message
                    for message in messages
                ),
            )
            check(
                'MV-FA-12 the conference NOTIFY carries <functional-alias> for client-b',
                any('application/conference-info+xml' in message and dispatcher in message for message in notifies),
            )
            invites = [message for message in capture.split(sip) if message.startswith('INVITE sip:')]
            check(
                'MV-FA-12 the call to the alias carries <call-to-functional-alias-ind>true',
                any(
                    '<call-to-functional-alias-ind>true</call-to-functional-alias-ind>' in message
                    for message in invites
                ),
            )
            check(
                'MV-FA-12 the call after the 300 carries <called-functional-alias-URI> without the indication',
                any(
                    re.search(r'<called-functional-alias-URI[^>]*><mcvideoURI>' + re.escape(medic), message)
                    and 'call-to-functional-alias-ind' not in message
                    for message in invites
                ),
            )
            check(
                'MV-FA-12 the 300 names client-c in <mcvideo-request-uri>',
                re.search(
                    r'SIP/2\.0 300 [^\r\n]*\r\n(?:(?!SIP/2\.0 ).)*<mcvideo-request-uri[^>]*><mcvideoURI>'
                    + re.escape(ids['client-c']),
                    sip,
                    re.S,
                )
                is not None,
            )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-functional-alias-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
