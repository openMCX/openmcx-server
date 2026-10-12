#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Exercise MCData IP connectivity: session setup and release (TS 24.282 clauses 20.2.1, 20.2.2,
20.3.1, 20.3.2, 20.4.1 and 20.4.2), the transmission control and one-to-one list checks of
TS 24.282 clause 11.1, the functional alias redirection of TS 24.282 clause 20.4.2 step 5a1,
and the GRE-in-UDP media plane of TS 24.582 clause 13 (clauses 13.1 to 13.4).

Run against a fixture prepared with --mcdata (see add_mcdata_policy in
tools/prepare-prearranged-test.py). Each client is also the IP application of
TS 24.582 clause 13.1.1 at its configured tunnel address (mcdata.ipconn.address): it
answers ICMP echo, and "ipcon-ping" sends echo requests into the tunnel. Check
IDs match tests/mcdata/MCDATA_IPCONN_TEST.md.

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# Run the MCData IP connectivity scenario against the running lab and write integration/mcdata-ipconn-results.json;
# returns 0 when every check passed.
# ------------------------------------------------------------------------------
# Run the MCData IP connectivity scenario against the running lab, write integration/mcdata-ipconn-results.json and
# return 0 when every check passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcdata')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    roles = ['client-a', 'client-b', 'client-c', 'client-d']
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in roles}
    ids = {role: configs[role]['mcdata']['user_id'] for role in roles}
    tunnel = {role: configs[role]['mcdata']['ipconn']['address'] for role in roles}
    domain = ids['client-a'].split('@', 1)[1]
    desk = f'sip:desk.fa@{domain}'
    checks, observations = [], {}
    result = dict(scenario='mcdata-ip-connectivity', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the role last wrote, or {} while it has none.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    # The IP connectivity part of every role's status, attached to a failure and to the results.
    def snapshot():
        return {
            role: {
                key: value
                for key, value in status(role).items()
                if key.startswith('mcdata_ipconn')
                or key == 'ipconn_sessions'
                or key == 'counters'
                or key == 'last_error'
            }
            for role in roles + ['mcdata-server']
        }

    # ------------------------------------------------------------------------------
    # Run one mcx-client console command in the role's container.
    def command(role, text):
        run = subprocess.run(
            cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode:
            raise RuntimeError(f'{role} {text}: {run.stderr.strip() or run.stdout.strip()}')

    # ------------------------------------------------------------------------------
    # Poll the predicate until it holds (recorded as a passed check) or the timeout expires (AssertionError).
    def wait(label, predicate, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    checks.append(label)
                    print(label, flush=True)
                    return
            except (KeyError, IndexError, TypeError):
                pass
            time.sleep(0.05)
        raise AssertionError(label + ' timed out: ' + json.dumps(snapshot())[:6000])

    # ------------------------------------------------------------------------------
    # Record the check as passed if the condition holds, else raise AssertionError with the snapshot.
    def check(label, condition):
        if not condition:
            raise AssertionError(label + ': ' + json.dumps(snapshot())[:6000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    # The client's current IP connectivity session state.
    def ipcon(role):
        return status(role).get('mcdata_ipconn') or {}

    # ------------------------------------------------------------------------------
    # The client's IP application counters (echoes answered, packets received and dropped).
    def counts(role):
        return status(role).get('mcdata_ipconn_counters') or {}

    # ------------------------------------------------------------------------------
    # The ICMP echo replies the client has received.
    def pings(role):
        return status(role).get('mcdata_ipconn_pings') or []

    # ------------------------------------------------------------------------------
    # The MCData server's status.
    def server():
        return status('mcdata-server')

    # ------------------------------------------------------------------------------
    # The GRE-in-UDP tunnels the server relays (TS 24.582 clause 13.4).
    def tunnels():
        return server().get('ipconn_sessions') or []

    # ------------------------------------------------------------------------------
    # The MCData server's counters.
    def counters():
        return server().get('counters') or {}

    # ------------------------------------------------------------------------------
    # Wait until no listed client has an open session and the server holds no tunnel.
    def idle(label, roles_):
        wait(label, lambda: all(ipcon(role).get('state') != 'open' for role in roles_) and not tunnels(), 30)

    # ------------------------------------------------------------------------------
    # The caller opens an IP connectivity session (TS 24.282 clause 20.2.1) and both ends reach 'open'.
    def open_session(caller, callee_role, target=None, label=None):
        command(caller, f'ipcon {target or ids[callee_role]}')
        wait(
            label or f'{caller} opens an IP connectivity session with {callee_role}',
            lambda: ipcon(caller).get('state') == 'open' and ipcon(callee_role).get('state') == 'open',
        )

    # ------------------------------------------------------------------------------
    # The caller's IP connectivity request is rejected with the expected status and Warning code.
    def refused(caller, target, expect, warning, label):
        command(caller, f'ipcon {target}')
        wait(
            label,
            lambda: (
                ipcon(caller).get('status') == expect
                and ipcon(caller).get('state') == 'rejected'
                and (warning is None or f'"{warning} ' in ipcon(caller).get('warning', ''))
            ),
        )

    try:
        wait('four clients MCData-authorised', lambda: all(status(role).get('mcdata_authorized') for role in roles), 90)
        instance = server()['instance_id']

        # IP-01 session setup (TS 24.282 clauses 20.2.1, 20.3.1, 20.4.1 and 20.4.2): the server invites the
        # called client and answers the caller once the called client has accepted.
        open_session('client-a', 'client-b', label='IP-01 the session is open at both clients')
        check(
            'IP-01 the called client learns the caller and the Referred-By identity (20.4.1 step 6)',
            ipcon('client-b').get('from') == ids['client-a'] and 'sip:' in ipcon('client-b').get('referred_by', ''),
        )
        wait(
            'IP-01 the server holds one established tunnel between the two users',
            lambda: (
                len(tunnels()) == 1
                and tunnels()[0]['established']
                and tunnels()[0]['originator'] == ids['client-a']
                and tunnels()[0]['target'] == ids['client-b']
            ),
        )
        session = tunnels()[0]
        check(
            'IP-01 the server faces each client from a port of its own (13.2, 13.3)',
            session['origin_port'] != session['target_port']
            and ipcon('client-a')['peer'].endswith(f":{session['origin_port']}")
            and ipcon('client-b')['peer'].endswith(f":{session['target_port']}"),
        )

        # IP-02 IP traffic in both directions through the GRE-in-UDP tunnel (TS 24.582 clauses 13.1 and 13.4).
        before = counters().get('ipconn_packets', 0)
        command('client-a', f'ipcon-ping {tunnel["client-b"]} 5 64')
        wait(
            'IP-02 five ICMP echo requests from the caller are answered by the called IP application',
            lambda: len([ping for ping in pings('client-a') if ping['from'] == tunnel['client-b']]) >= 5,
        )
        check(
            'IP-02 each reply carries the echo data unchanged and a TTL of 64',
            all(ping['bytes'] == 64 and ping['ttl'] == 64 for ping in pings('client-a')),
        )
        wait('IP-02 the called client answered five echoes', lambda: counts('client-b').get('echo_answered') == 5)
        command('client-b', f'ipcon-ping {tunnel["client-a"]} 3 1200')
        wait(
            'IP-02 the called client pings back through the same tunnel with 1200-byte echoes',
            lambda: (
                len(
                    [ping for ping in pings('client-b') if ping['from'] == tunnel['client-a'] and ping['bytes'] == 1200]
                )
                >= 3
            ),
        )
        wait(
            'IP-02 the server relayed every datagram in both directions',
            lambda: (
                counters().get('ipconn_packets', 0) >= before + 16
                and tunnels()[0]['to_target'] >= 8
                and tunnels()[0]['to_origin'] >= 8
            ),
        )
        observations['relayed'] = tunnels()[0]

        # IP-03 the IP application only takes packets addressed to it.
        dropped = counts('client-b').get('dropped', 0)
        command('client-a', 'ipcon-ping 10.77.0.99 2')
        wait(
            'IP-03 packets for another address are dropped by the called client, and nothing answers',
            lambda: counts('client-b').get('dropped', 0) >= dropped + 2,
        )
        wait('IP-03 the caller has two unanswered echoes', lambda: counts('client-a').get('outstanding') == 2)

        # IP-04 the server relays only datagrams from the address and source port
        # negotiated in SDP: a GRE datagram sent from another container is dropped.
        dropped = tunnels()[0]['dropped']
        dropped_b, received_b = counts('client-b').get('dropped', 0), counts('client-b').get('received', 0)
        port = tunnels()[0]['origin_port']
        subprocess.run(
            cli
            + [
                'exec',
                '-T',
                'client-c',
                'python3',
                '-c',
                'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);'
                f'[s.sendto(bytes.fromhex("00000800450000140000400040010000c0000201c0000202"),'
                f'("mcdata-server",{port})) for _ in range(3)]',
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        wait(
            'IP-04 datagrams from an address outside the session are dropped by the server',
            lambda: tunnels()[0]['dropped'] >= dropped + 3,
        )
        check(
            'IP-04 nothing reached the called client',
            counts('client-b').get('dropped', 0) == dropped_b and counts('client-b').get('received', 0) == received_b,
        )

        # IP-05 either party releases the session with BYE, and the server ends the other leg.
        command('client-a', 'ipcon close')
        wait(
            'IP-05 closing the session releases both clients and the tunnel',
            lambda: (
                ipcon('client-a').get('state') == 'closed'
                and ipcon('client-b').get('state') == 'released'
                and not tunnels()
            ),
        )

        # IP-06 a client with a session open answers a second one 486, which the
        # server passes back to the caller (TS 24.282 clauses 20.3.2 and 20.3.1).
        open_session('client-a', 'client-c', label='IP-06 a session between client-a and client-c is open')
        refused('client-b', ids['client-c'], 486, None, 'IP-06 a second session to a busy client is refused with 486')
        wait(
            'IP-06 the first session is unaffected',
            lambda: ipcon('client-c').get('state') == 'open' and len(tunnels()) == 1,
        )
        command('client-c', 'ipcon close')
        idle('IP-06 the called party may release the session too', ['client-a', 'client-c'])
        wait('IP-06 the caller learns the release', lambda: ipcon('client-a').get('state') == 'released')

        # IP-07 transmission control and one-to-one lists (TS 24.282 clause 20.3.1 step 7 with clause 11.1).
        refused(
            'client-d', ids['client-a'], 403, '200', 'IP-07 a user without <allow-transmit-data> is rejected with 200'
        )
        refused(
            'client-a', ids['client-d'], 403, '229', 'IP-07 a target outside the one-to-one list is rejected with 229'
        )
        refused(
            'client-c',
            ids['client-b'],
            403,
            '230',
            "IP-07 a caller outside the target's incoming list is rejected with 230",
        )
        refused(
            'client-a',
            f'fa=sip:nobody.fa@{domain}',
            403,
            '145',
            'IP-07 a functional alias nobody has activated is rejected with 145',
        )
        wait('IP-07 no tunnel was created by a refused request', lambda: not tunnels())

        # IP-08 a session to a functional alias (TS 24.282 clause 20.4.2 step 5a1 and clause 20.2.1): 300
        # (Multiple Choices) names the user, and the caller invites that user with
        # the alias in <called-functional-alias-URI>.
        command('client-b', f'mcdata-fa activate {desk}')
        wait(
            'IP-08 client-b activates the functional alias',
            lambda: (server().get('functional_aliases') or {}).get(desk) == [ids['client-b']],
        )
        command('client-a', f'ipcon fa={desk}')
        wait(
            'IP-08 the session reaches the user that activated the alias',
            lambda: (
                ipcon('client-a').get('state') == 'open'
                and ipcon('client-a').get('selected') == ids['client-b']
                and ipcon('client-b').get('state') == 'open'
            ),
        )
        check(
            'IP-08 the called client learns the alias it was reached through (20.2.2 step 3B)',
            ipcon('client-b').get('called_alias') == desk and ipcon('client-a').get('called_alias') == desk,
        )
        answered = counts('client-b').get('echo_answered', 0)
        command('client-a', f'ipcon-ping {tunnel["client-b"]} 2')
        wait(
            'IP-08 IP traffic flows on the session',
            lambda: counts('client-b').get('echo_answered', 0) >= answered + 2,
        )
        command('client-b', 'ipcon close')
        idle('IP-08 the session is released', ['client-a', 'client-b'])
        command('client-b', f'mcdata-fa deactivate {desk}')

        observations['server_counters'] = {key: value for key, value in counters().items() if key.startswith('ipconn')}
        observations['client_counters'] = {role: counts(role) for role in roles}
        check('server instance unchanged', server()['instance_id'] == instance)
        result['passed'] = True
    except (AssertionError, KeyError, IndexError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    result['status'] = snapshot()
    output = args.artifacts / 'integration/mcdata-ipconn-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'status'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
