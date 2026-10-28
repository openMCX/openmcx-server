#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A re-INVITE that changes the floor control SSRC is refused and the call goes on unchanged.

The SSRC a client allocates in its SDP ("mc_floor_ssrc") is the one the MCPTT server "shall use in the RTCP header of
the floor control messages it sends in this session" (TS 24.380 clause 4.3.3.1); under the CSK the server refuses an
offer whose SSRC it may not use (McServer::peer_floor_ssrc_refused). A re-INVITE without MC service information that
changes the SSRC is refused with 488 (Not Acceptable Here) before anything is accepted, and the session goes on as it
was (RFC 3261 section 14.2: a UAS rejecting the offer of a re-INVITE keeps the session; section 14.1 for the UAC).
The lab clients send these re-INVITEs on the refresh-reinvite command, from their own SIP stack, in the call's dialog.
With protected floor control (--protected), the scenario checks that
  - RS-01 a group call is set up and floor control works under the CSK (a burst granted, decrypted and decoded);
  - RS-02 an unchanged refresh re-INVITE is answered 200 (OK) and floor control goes on;
  - RS-03 a refresh re-INVITE with a new floor SSRC is answered 488; the call goes on, its negotiated floor SSRCs are
    unchanged at the client and floor control goes on;
  - RS-04 the same with the server's own SSRC offered (a colliding SSRC);
  - RS-05 in a protected private call, a hold and a resume re-INVITE (RFC 5359 section 2.1) are answered 200 and floor
    control goes on;
  - RS-06 a hold re-INVITE with a new floor SSRC is answered 488 and the call goes on unchanged, also floor control.
The wire verifier (verify_reinvite_ssrc.py) checks the ACK of each 488, that no BYE ends the dialog while it is
checked, and that the floor control SRTCP keeps its SSRCs and its index in both directions.

Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261,
RFC 3264, RFC 4028, RFC 5359.
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
    """Run RS-01 to RS-06 against the lab of --compose; print the result and write
    integration/reinvite-ssrc-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-reinvite-ssrc')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcptt']['user_id'] for role in ROLES}
    if not all(configs[role].get('security', {}).get('protect_media') for role in ROLES):
        parser.error('the fixture must be prepared with --protected')
    checks, observations = [], {}
    result = dict(scenario='reinvite-ssrc', passed=False, checks=checks, observations=observations)

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
    def wait(label, predicate, timeout=20):
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
    def check(label, condition):
        """Record label if condition holds, else raise with a snapshot."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(snapshot())[:4000])
        checks.append(label)
        print(label, flush=True)

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
    def in_call(roles):
        """The roles are in an active call."""
        return lambda: all(status(role).get('call_state') == 'active' for role in roles)

    # ------------------------------------------------------------------------------
    def media(role):
        """The call's negotiated parameters at the role: session URI, its floor SSRC and the server's."""
        current = status(role)
        return dict(
            session_uri=current.get('session_uri'),
            floor_ssrc=current.get('floor_ssrc'),
            remote_floor_ssrc=current.get('remote_floor_ssrc'),
        )

    # ------------------------------------------------------------------------------
    def floor_works(sender, receivers, label, wav='alpha.wav'):
        """A burst from sender: the floor is granted (floor control under the CSK) and every receiver decrypts and
        decodes 100 packets of it; the floor is released."""
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
    def refresh(role, options, expected, label):
        """A refresh re-INVITE from role with options, answered with expected: the answer to this request (the
        client numbers its refresh re-INVITEs: last_refresh_offer and last_refresh carry the number)."""
        sequence = (status(role).get('last_refresh_offer') or {}).get('sequence', 0) + 1
        command(role, ('refresh-reinvite ' + options).strip())
        wait(
            f'{label} re-INVITE ({options or "unchanged"}) answered {expected}',
            lambda: (
                (status(role).get('last_refresh_offer') or {}).get('sequence') == sequence
                and (status(role).get('last_refresh') or {}).get('sequence') == sequence
                and status(role)['last_refresh'].get('status') == expected
            ),
        )
        observations.setdefault('offers', []).append(
            dict(label=label, role=role, options=options, offer=status(role).get('last_refresh_offer'), status=expected)
        )

    # ------------------------------------------------------------------------------
    def unchanged(roles, before, label, hold=3):
        """For hold seconds the roles stay in the call with the negotiated parameters of before."""
        deadline = time.monotonic() + hold
        while time.monotonic() < deadline:
            for role in roles:
                if status(role).get('call_state') != 'active':
                    raise AssertionError(f'{label} {role} left the call: ' + json.dumps(snapshot())[:4000])
                if media(role) != before[role]:
                    raise AssertionError(f'{label} {role} parameters changed: {media(role)} != {before[role]}')
            time.sleep(0.2)
        checks.append(f'{label} call goes on with its negotiated floor SSRCs')
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
        wait('fixture initially idle', idle, 30)
        for role in ROLES:
            command(role, 'answer-mode auto')
        for name in ['alpha.wav', 'bravo.wav']:
            assert (args.artifacts / 'speech' / name).is_file(), 'missing speech fixture ' + name

        # RS-01 a protected group call and its floor control.
        command('client-a', 'call')
        wait('RS-01 group call with the four clients', in_call(ROLES))
        wait(
            'RS-01 floor SSRCs negotiated at client-b',
            lambda: media('client-b')['floor_ssrc'] and media('client-b')['remote_floor_ssrc'],
        )
        others = [role for role in ROLES if role != 'client-b']
        floor_works('client-b', others, 'RS-01')
        group = {role: media(role) for role in ROLES}
        observations['group_call'] = group

        # RS-02 unchanged refresh.
        refresh('client-b', '', 200, 'RS-02')
        unchanged(ROLES, group, 'RS-02')
        floor_works('client-b', others, 'RS-02', 'bravo.wav')

        # RS-03 a new floor SSRC.
        refresh('client-b', 'floor-ssrc changed', 488, 'RS-03')
        check(
            'RS-03 the refused offer carried another SSRC',
            status('client-b')['last_refresh_offer']['floor_ssrc'] != group['client-b']['floor_ssrc'],
        )
        unchanged(ROLES, group, 'RS-03')
        floor_works('client-b', others, 'RS-03')

        # RS-04 the server's own SSRC.
        refresh('client-b', 'floor-ssrc colliding', 488, 'RS-04')
        check(
            'RS-04 the refused offer carried the server\'s SSRC',
            status('client-b')['last_refresh_offer']['floor_ssrc'] == group['client-b']['remote_floor_ssrc'],
        )
        unchanged(ROLES, group, 'RS-04')
        floor_works('client-b', others, 'RS-04', 'bravo.wav')
        refresh('client-b', '', 200, 'RS-04 afterwards')
        command('client-a', 'hangup')
        wait('RS-04 group call released', idle, 30)

        # RS-05 a protected private call, held and resumed.
        pair = ['client-a', 'client-b']
        command('client-a', f"private {ids['client-b']} auto")
        wait('RS-05 protected private call', in_call(pair))
        wait(
            'RS-05 floor SSRCs negotiated at client-a',
            lambda: media('client-a')['floor_ssrc'] and media('client-a')['remote_floor_ssrc'],
        )
        floor_works('client-a', ['client-b'], 'RS-05')
        private = {role: media(role) for role in pair}
        observations['private_call'] = private
        refresh('client-a', 'hold', 200, 'RS-05 hold')
        refresh('client-a', 'resume', 200, 'RS-05 resume')
        unchanged(pair, private, 'RS-05')
        floor_works('client-a', ['client-b'], 'RS-05 resumed', 'bravo.wav')

        # RS-06 a hold with a new floor SSRC.
        refresh('client-a', 'hold floor-ssrc changed', 488, 'RS-06')
        unchanged(pair, private, 'RS-06')
        floor_works('client-a', ['client-b'], 'RS-06')
        refresh('client-a', '', 200, 'RS-06 afterwards')
        command('client-a', 'hangup')
        wait('RS-06 private call released', idle, 30)
        result['passed'] = True
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    out = args.artifacts / 'integration' / 'reinvite-ssrc-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
