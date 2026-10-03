#!/usr/bin/env python3
"""Exercise on-network, on-demand broadcast group calls.

Run against a separate four-client fixture prepared with --broadcast. Check
labels carry the IDs used in tests/mcptt/BROADCAST_CALL_TEST.md.

A broadcast group call (TS 24.379 clause 4.12) is requested as in TS 24.379 clause 6.2.8.2, has no
conference subscription (clause 10.1.3.4.1: 480 with warning 105), and ends with the initiator's
transmission. Floor control: receivers are denied with cause #5 (Receive only, TS 24.380 clause
8.2.6.2) and see Floor Taken with the B-bit and no permission to request (TS 24.380 clause
6.3.4.4.2, the Floor Indicator of clause 8.2.3.15). Broadcast hierarchies and override follow
TS 23.379 clause 10.6.2.5 (no stage-3 procedure exists for them).

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
# Floor Indicator bits B (broadcast group call), A (normal call), D (emergency call) and E (imminent
# peril call): TS 24.380 table 8.2.3.15-2.
BROADCAST_BIT, NORMAL_BIT, EMERGENCY_BIT, IMMINENT_BIT = 0x4000, 0x8000, 0x1000, 0x0800


# ------------------------------------------------------------------------------
def main():
    """Run the broadcast group call checks BC-01 to BC-19 and write integration/broadcast-call-results.json.

    BC-11 to BC-14 are not checks of this scenario: they are the wire verifier, regression and unit test rows
    of tests/mcptt/BROADCAST_CALL_TEST.md.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-broadcast')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    receivers = ['client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    ids = {client: json.loads((generated / f'{client}.json').read_text())['mcptt']['user_id'] for client in roles}
    checks, observations = [], {}
    result = dict(scenario='on-demand-broadcast-group-call', passed=False, checks=checks, observations=observations)

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
    def idle(wanted=roles):
        """Every wanted client idle and the server holding no session."""
        return all(status(client).get('call_state') == 'idle' for client in wanted) and not sessions()

    # ------------------------------------------------------------------------------
    def call_active(wanted, call_type):
        """Exactly one session, of the call type, started by client-a, whose participants are the wanted
        users, each active in it."""
        current = sessions()
        return (
            len(current) == 1
            and current[0].get('call_type') == call_type
            and current[0].get('initiator') == ids['client-a']
            and set(current[0].get('participants', [])) == {ids[client] for client in wanted}
            and all(
                status(client).get('call_state') == 'active' and status(client).get('call_type') == call_type
                for client in wanted
            )
        )

    # ------------------------------------------------------------------------------
    def rejected(role, code, warning):
        """A predicate: the role is idle and its last call failed with the code and the warning text."""

        # ------------------------------------------------------------------------------
        def check():
            """The role is idle and its last call failure carries the code and the warning."""
            failure = status(role).get('last_call_failure') or {}
            return (
                status(role).get('call_state') == 'idle'
                and failure.get('status') == code
                and warning in failure.get('warning', '')
            )

        return check

    # ------------------------------------------------------------------------------
    def denied(role, before):
        """A predicate: the role got a new Floor Deny with cause #5 (Receive only, TS 24.380 clause 8.2.6.2)
        and is not talking."""
        return lambda: (
            status(role).get('floor_denials', 0) > before
            and status(role).get('last_floor_reject_cause') == 5
            and not status(role).get('talking')
        )

    try:
        wait(
            'four clients authorized and affiliated',
            lambda: all(status(client).get('authorized') and status(client).get('affiliated') for client in roles),
            90,
        )
        wait('fixture initially idle', idle)
        instance = status('mcptt-server')['instance_id']
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name

        # BC-01 setup reaches every affiliated member with the broadcast indication.
        command('client-a', 'call broadcast')
        wait('BC-01 broadcast call reaches all affiliated members', lambda: call_active(roles, 'broadcast'), 20)
        # BC-02 no conference subscription in a broadcast group call.
        assert all(
            status(client).get('conference_subscription', '') == ''
            and status(client).get('conference_wait_reason') == 'broadcast group call'
            for client in roles
        ), 'conference subscription sent'
        checks.append('BC-02 no member subscribes to conference events')

        # BC-03 receivers are receive-only even while the floor is idle.
        before = status('client-b').get('floor_denials', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('BC-03 receiver request on idle floor denied with cause 5 (receive only)', denied('client-b', before))

        # BC-04 initiator speech reaches every receiver; Taken signals the B-bit and no permission to request.
        base = {client: status(client).get('received_packets', 0) for client in receivers}
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'BC-04 initiator granted floor',
            lambda: (
                status('client-a').get('talking') and sessions() and sessions()[0].get('floor_owner') == ids['client-a']
            ),
        )
        wait(
            'BC-04 receivers see Floor Taken with B-bit and permission to request 0',
            lambda: all(
                status(client).get('floor_indicator') == BROADCAST_BIT
                and status(client).get('permission_to_request') is False
                for client in receivers
            ),
        )
        before = status('client-c').get('floor_denials', 0)
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait('BC-04 receiver request during transmission denied with cause 5', denied('client-c', before))
        wait(
            'BC-04 every receiver receives initiator speech',
            lambda: all(status(client).get('received_packets', 0) >= base[client] + 100 for client in receivers),
            20,
        )
        observations['broadcast_speech_packets'] = {
            client: status(client).get('received_packets', 0) - base[client] for client in receivers
        }
        assert status('client-a').get('received_packets', 0) == 0, 'initiator received media in a broadcast'
        checks.append('BC-04 initiator receives no media')

        # BC-05 completing the transmission releases the call without any hangup.
        wait('BC-05 initiator transmission completes', lambda: not status('client-a').get('talking'), 20)
        released = time.monotonic()
        wait('BC-05 transmission end releases the broadcast for everyone', idle, 10)
        observations['release_after_transmission_seconds'] = round(time.monotonic() - released, 2)

        # BC-06 conference SUBSCRIBE rejected (TS 24.379 clause 10.1.3.4.1); initiator leaving ends
        # the broadcast.
        command('client-a', 'call broadcast')
        wait('BC-06 second broadcast active', lambda: call_active(roles, 'broadcast'), 20)
        command('client-b', 'conference-subscribe')
        wait(
            'BC-06 forced conference SUBSCRIBE rejected with 480',
            lambda: status('client-b').get('last_error') == 'conference subscription: 480',
        )
        command('client-a', 'hangup')
        wait('BC-06 initiator hangup before transmitting ends the broadcast', idle)

        # BC-07 initiation restricted by call_policy.broadcast_members.
        command('client-c', 'call broadcast')
        wait(
            'BC-07 unauthorised initiator rejected with 403',
            rejected('client-c', 403, 'broadcast group call not authorised'),
        )
        wait('BC-07 rejected broadcast leaves no session', idle)

        # BC-08 a broadcast cannot take over an ongoing non-broadcast call.
        command('client-a', 'call')
        wait('BC-08 normal group call active', lambda: call_active(roles, 'prearranged'), 20)
        command('client-b', 'hangup')
        wait(
            'BC-08 member leaves normal call',
            lambda: (
                status('client-b').get('call_state') == 'idle'
                and call_active(['client-a', 'client-c', 'client-d'], 'prearranged')
            ),
        )
        command('client-b', 'call broadcast')
        wait(
            'BC-08 broadcast during ongoing group call rejected with 486',
            rejected('client-b', 486, 'group call in progress'),
        )
        assert call_active(['client-a', 'client-c', 'client-d'], 'prearranged'), 'rejected broadcast disturbed the call'
        checks.append('BC-08 ongoing group call unaffected')

        # BC-09 normal call keeps normal floor semantics after broadcasts.
        base_a = status('client-a').get('received_packets', 0)
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait('BC-09 non-initiator granted floor in a normal call', lambda: status('client-c').get('talking'))
        wait(
            'BC-09 normal Floor Taken has A-bit and permission to request 1',
            lambda: all(
                status(client).get('floor_indicator') == NORMAL_BIT
                and status(client).get('permission_to_request') is True
                for client in ['client-a', 'client-d']
            ),
        )
        wait(
            'BC-09 initiator hears the other member',
            lambda: status('client-a').get('received_packets', 0) >= base_a + 100,
            20,
        )
        wait(
            'BC-09 floor released',
            lambda: not status('client-c').get('talking') and not sessions()[0].get('floor_owner'),
            20,
        )
        command('client-a', 'hangup')
        wait('BC-09 normal call released', idle)

        # BC-10 late entry joins an ongoing broadcast as a receiver.
        command('client-d', 'deaffiliate')
        wait('BC-10 client d deaffiliated', lambda: not status('client-d').get('affiliated'))
        command('client-a', 'call broadcast')
        wait(
            'BC-10 broadcast among affiliated members',
            lambda: call_active(['client-a', 'client-b', 'client-c'], 'broadcast'),
            20,
        )
        command('client-d', 'affiliate')
        wait('BC-10 late entry adds client d as a broadcast receiver', lambda: call_active(roles, 'broadcast'), 20)
        base_d = status('client-d').get('received_packets', 0)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'BC-10 late entrant receives broadcast speech',
            lambda: status('client-d').get('received_packets', 0) >= base_d + 100,
            20,
        )
        wait('BC-10 late-entry broadcast released at transmission end', idle, 25)

        # BC-18 emergency broadcast group call (H7, local policy for TS 24.380
        # clause 8.2.3.15): the Floor Indicator carries B and D, receivers stay receive-only.
        first_group = status('client-a').get('group_id')

        # ------------------------------------------------------------------------------
        def group_priority(value):
            """The server holds the first group in the priority state value ('emergency', 'imminent', 'normal')."""
            return (status('mcptt-server').get('group_priority') or {}).get(first_group, {}).get('priority') == value

        # ------------------------------------------------------------------------------
        def broadcast_priority(value):
            """One broadcast call with every member, the session and every member at the priority value."""
            # call_active() reads the sessions itself; read them once more only after it succeeds.
            if not call_active(roles, 'broadcast'):
                return False
            current = sessions()
            return (
                len(current) == 1
                and current[0].get('priority') == value
                and all(status(client).get('priority') == value for client in roles)
            )

        command('client-a', 'call broadcast emergency')
        wait(
            'BC-18 emergency broadcast reaches every member in emergency state',
            lambda: broadcast_priority('emergency'),
            20,
        )
        base = {client: status(client).get('received_packets', 0) for client in receivers}
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'BC-18 receivers see Floor Taken with B and D bits and permission to request 0',
            lambda: all(
                status(client).get('floor_indicator') == BROADCAST_BIT | EMERGENCY_BIT
                and status(client).get('permission_to_request') is False
                for client in receivers
            ),
        )
        before = status('client-b').get('floor_denials', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait('BC-18 a receiver is still denied with cause 5 in an emergency broadcast', denied('client-b', before))
        wait(
            'BC-18 every receiver receives the emergency broadcast speech',
            lambda: all(status(client).get('received_packets', 0) >= base[client] + 100 for client in receivers),
            20,
        )
        wait('BC-18 emergency broadcast released at transmission end', idle, 25)
        assert group_priority('emergency'), 'group emergency state lost at call end'
        checks.append('BC-18 group stays in emergency state after the broadcast ends')
        command('client-a', 'emergency off')
        wait('BC-18 initiator cancels the group emergency state', lambda: group_priority('normal'), 15)

        # BC-19 in-dialog imminent peril upgrade: refused for a receiver, allowed
        # for the initiator; the Floor Indicator then carries B and E.
        command('client-a', 'call broadcast')
        wait('BC-19 normal broadcast active', lambda: broadcast_priority('normal'), 20)
        command('client-b', 'imminent on')
        wait(
            'BC-19 receiver priority upgrade refused with 403',
            lambda: (
                status('client-b').get('last_error') == 'priority update: 403'
                and not status('client-b').get('priority_pending')
            ),
        )
        assert broadcast_priority('normal'), 'refused upgrade changed the call'
        checks.append('BC-19 refused upgrade leaves the broadcast normal')
        command('client-a', 'imminent on')
        wait(
            'BC-19 initiator upgrades the broadcast to imminent peril for every member',
            lambda: broadcast_priority('imminent'),
            15,
        )
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'BC-19 receivers see Floor Taken with B and E bits',
            lambda: all(status(client).get('floor_indicator') == BROADCAST_BIT | IMMINENT_BIT for client in receivers),
        )
        wait('BC-19 imminent-peril broadcast released at transmission end', idle, 25)
        command('client-a', 'call broadcast')
        wait('BC-19 next broadcast inherits the group imminent-peril state', lambda: broadcast_priority('imminent'), 20)
        command('client-a', 'imminent off')
        wait('BC-19 initiator cancels imminent peril in-dialog', lambda: broadcast_priority('normal'), 15)
        command('client-a', 'hangup')
        wait('BC-19 broadcast released', idle)

        # BC-15..BC-17: broadcast hierarchies and override (TS 23.379 clause 10.6.2.5;
        # project profile, TS 24.379 clause 4.12 has no stage-3 procedure for them).
        site = json.loads((args.compose.resolve().parent / 'generated/site.json').read_text())
        groups = {item.get('type', 'prearranged'): item['id'] for item in site['groups']}
        first, second = site['groups'][0]['id'], site['groups'][1]['id']
        everyone, users = groups['group-broadcast'], groups['user-broadcast']

        # ------------------------------------------------------------------------------
        def on(role, group):
            """Move the role to the group (affiliating it) unless it is there already; a predicate for the result."""
            if status(role).get('group_id') != group:
                command(role, 'group ' + group)
            return lambda: status(role).get('affiliated') and status(role).get('group_id') == group

        # ------------------------------------------------------------------------------
        def select_all(assignment):
            """Move each role to its group of the assignment and wait until all are affiliated there."""
            checks_ = [on(client, item) for client, item in assignment.items()]
            wait(
                'affiliations for '
                + ', '.join(f'{client}={item.split("@")[0].split(":")[1]}' for client, item in assignment.items()),
                lambda: all(ready() for ready in checks_),
                30,
            )

        # ------------------------------------------------------------------------------
        def session_of(group):
            """The server's session of the group, or None."""
            return next((call for call in sessions() if call.get('group_id') == group), None)

        # ------------------------------------------------------------------------------
        def hierarchy_active(group, initiator, wanted):
            """A broadcast session on the group, started by the initiator, whose participants are the wanted
            users, each active in a broadcast call (TS 23.379 clause 10.6.2.5.2)."""
            current = session_of(group)
            return (
                current is not None
                and current.get('call_type') == 'broadcast'
                and current.get('initiator') == ids[initiator]
                and set(current.get('participants', [])) == {ids[client] for client in wanted}
                and all(
                    status(client).get('call_state') == 'active' and status(client).get('call_type') == 'broadcast'
                    for client in wanted
                )
            )

        # ------------------------------------------------------------------------------
        def group_call(group, wanted, priority=None):
            """A prearranged group call session on the group with the wanted participants, at the priority if given."""
            current = session_of(group)
            return (
                current is not None
                and current.get('call_type') == 'prearranged'
                and set(current.get('participants', [])) == {ids[client] for client in wanted}
                and (priority is None or current.get('priority') == priority)
            )

        # BC-15 group-broadcast group: an ongoing call on a subordinate group is
        # released and its members, plus the other subordinate group's affiliated
        # members, receive the broadcast through <associated-group-id>.
        select_all({'client-a': everyone, 'client-b': first, 'client-c': second, 'client-d': second})
        command('client-c', 'call')
        wait('BC-15 ongoing call on a subordinate group', lambda: group_call(second, ['client-c', 'client-d']), 20)
        command('client-a', 'call')
        wait(
            'BC-15 non-broadcast call on a group-broadcast group rejected with 403',
            rejected('client-a', 403, 'broadcast group requires broadcast-ind'),
        )
        command('client-a', 'call broadcast')
        wait(
            'BC-15 subordinate call released and all subordinate members join the broadcast',
            lambda: (
                hierarchy_active(everyone, 'client-a', ['client-a', 'client-b', 'client-c', 'client-d'])
                and session_of(second) is None
            ),
            25,
        )
        assert session_of(everyone).get('hierarchy') == 'group-broadcast', 'hierarchy not reported'
        assert all(status(client).get('call_group') == everyone for client in ['client-b', 'client-c', 'client-d']), (
            'receivers lack the broadcast group'
        )
        before = {client: status(client).get('received_packets', 0) for client in ['client-b', 'client-c']}
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'BC-15 receivers in both subordinate groups get the broadcast speech',
            lambda: all(status(client).get('received_packets', 0) >= before[client] + 100 for client in before),
            20,
        )
        wait('BC-15 group-broadcast released at the end of transmission', idle, 25)

        # An emergency call on a subordinate group is neither preempted nor invited.
        command('client-c', 'call emergency')
        wait(
            'BC-15 emergency call on the second subordinate group',
            lambda: group_call(second, ['client-c', 'client-d'], 'emergency'),
            20,
        )
        command('client-a', 'call broadcast')
        wait(
            'BC-15 broadcast skips the subordinate group in an emergency call',
            lambda: (
                hierarchy_active(everyone, 'client-a', ['client-a', 'client-b'])
                and group_call(second, ['client-c', 'client-d'], 'emergency')
            ),
            20,
        )
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait(
            'BC-15 broadcast ends while the emergency call continues',
            lambda: session_of(everyone) is None and group_call(second, ['client-c', 'client-d'], 'emergency'),
            30,
        )
        command('client-c', 'emergency off')
        wait('BC-15 emergency cancelled', lambda: group_call(second, ['client-c', 'client-d'], 'normal'))
        command('client-c', 'hangup')
        wait('BC-15 subordinate call released', idle, 20)

        # BC-16 user-broadcast group: its users' ongoing group call is released
        # and they receive the broadcast through the group they are affiliated to.
        select_all({'client-a': first, 'client-b': users, 'client-c': second, 'client-d': second})
        command('client-c', 'call')
        wait(
            'BC-16 ongoing call involving the user-broadcast users',
            lambda: group_call(second, ['client-c', 'client-d']),
            20,
        )
        command('client-b', 'call broadcast')
        wait(
            'BC-16 users released from their call and joined to the user-broadcast',
            lambda: (
                hierarchy_active(users, 'client-b', ['client-b', 'client-c', 'client-d']) and session_of(second) is None
            ),
            25,
        )
        assert status('client-a').get('call_state') == 'idle', 'non-member invited to the user-broadcast'
        checks.append('BC-16 users outside the user-broadcast group are not invited')
        before_c = status('client-c').get('received_packets', 0)
        command('client-b', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'BC-16 users receive the broadcast speech',
            lambda: status('client-c').get('received_packets', 0) >= before_c + 100,
            20,
        )
        wait('BC-16 user-broadcast released at the end of transmission', idle, 25)

        # BC-17 override: an authorised overrider (client-d) takes over the
        # transmission; an unauthorised receiver is still denied with cause 5.
        select_all({'client-a': first, 'client-b': first, 'client-c': first, 'client-d': first})
        command('client-a', 'call broadcast')
        wait('BC-17 broadcast to all members', lambda: hierarchy_active(first, 'client-a', roles), 20)
        command('client-a', 'ptt /artifacts/speech/alpha.wav')
        wait('BC-17 initiator transmitting', lambda: status('client-a').get('talking'))
        denials = status('client-c').get('floor_denials', 0)
        command('client-c', 'ptt /artifacts/speech/bravo.wav')
        wait('BC-17 unauthorised receiver denied with cause 5', denied('client-c', denials))
        before_c = status('client-c').get('received_packets', 0)
        command('client-d', 'ptt /artifacts/speech/bravo.wav')
        wait(
            'BC-17 authorised overrider takes the floor from the initiator',
            lambda: (
                status('client-d').get('talking')
                and not status('client-a').get('talking')
                and (session_of(first) or {}).get('floor_owner') == ids['client-d']
            ),
            15,
        )
        wait(
            'BC-17 receivers get the overriding speech',
            lambda: status('client-c').get('received_packets', 0) >= before_c + 100,
            20,
        )
        wait('BC-17 broadcast released when the overriding transmission ends', idle, 25)

        assert status('mcptt-server')['instance_id'] == instance, 'server restarted during scenario'
        checks.append('server instance unchanged')
        result['passed'] = True
    except (AssertionError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/broadcast-call-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({field: content for field, content in result.items() if field != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
