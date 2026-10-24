#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""MCVideo XML confidentiality and integrity protection (protection of sensitive application
data, TS 24.281 clause 4.8; confidentiality protection, TS 24.281 clause 6.6.2; integrity
protection, TS 24.281 clause 6.6.3; application signalling security, TS 33.180 clause 9.3): the
access token of the MCVideo service authorisation encrypted under the uploaded MCVideo CSK, then
the sensitive mcvideo-info elements and URI attributes encrypted and, with integrity protection,
every XML body signed, between each client and the MCVideo server, through affiliation, a group
call and a private call.

Run against a fixture prepared with --mcvideo --protected --key-parameters-iei N
--xml-protection [--integrity-protection]. Check IDs match
tests/mcvideo/MCVIDEO_XML_PROTECTION_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
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
# Run the scenario against the lab and write integration/mcvideo-xml-results.json; return 0 when every check passed.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo-xml')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    compose = json.loads(args.compose.read_text())
    sip_on_wire = '--disable-tls' in compose['services']['client-a']['command']
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ROLES}
    ids = {role: configs[role]['mcvideo']['user_id'] for role in ROLES}
    integrity = configs['client-a'].get('security', {}).get('integrity_protection', False)
    checks, observations = [], dict(integrity=integrity)
    result = dict(scenario='mcvideo-xml-protection', passed=False, checks=checks, observations=observations)
    capture_file = args.artifacts / 'integration/mcvideo-xml.pcap'
    capture_name = f'{args.project}-mcvideo-xml-capture'

    # ------------------------------------------------------------------------------
    # The status.json a role last wrote, or {} while it is missing or half written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # The XML protection counters of a role (encrypted, decrypted, signed, verified, refused).
    def counters(role):
        return status(role).get('xml_protection') or {}

    # ------------------------------------------------------------------------------
    # The authorisation, call and XML protection state of every client and server, for a timed-out check's message.
    def snapshot():
        out = {
            role: {
                key: status(role).get(key)
                for key in (
                    'mcvideo_authorized',
                    'mcvideo_affiliated',
                    'mcvideo_call_state',
                    'mcvideo_last_call',
                    'last_error',
                )
            }
            | {'xml': counters(role)}
            for role in ROLES
        }
        out['mcvideo-server'] = counters('mcvideo-server')
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
                    'openmcx-dev:0.3',
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

    try:
        # MV-XP-01 TS 24.281 clause 7.2.5 with clause 6.6: the MCVideo authorisation carries the
        # CSK, and the access token in it is encrypted under that CSK; the server opens every one.
        start_capture()
        wait(
            'MV-XP-01 four clients MCVideo authorised and affiliated with XML protection on',
            lambda: all(
                status(role).get('mcvideo_authorized') and status(role).get('mcvideo_affiliated') for role in ROLES
            ),
            120,
        )
        wait(
            'MV-XP-01 mcvideo-server decrypted the protected authorisations and affiliations',
            lambda: counters('mcvideo-server').get('decrypted', 0) >= 2 * len(ROLES),
        )

        # MV-XP-02 and MV-XP-03: a group call and a private call with protected mcvideo-info.
        command('client-a', 'mcvideo-call')
        wait(
            'MV-XP-02 a group call is set up with protected MCVideo signalling',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ROLES),
        )
        command('client-a', 'mcvideo-hangup')
        for role in ROLES:
            if not idle(role):
                command(role, 'mcvideo-hangup')
        wait('MV-XP-02 released', lambda: idle(*ROLES), 30)
        command('client-a', f"mcvideo-private {ids['client-b']} auto")
        wait(
            'MV-XP-03 a private call is set up with the protected called MCVideo ID',
            lambda: all(status(role).get('mcvideo_call_state') == 'active' for role in ('client-a', 'client-b')),
        )
        command('client-a', 'mcvideo-hangup')
        wait('MV-XP-03 released', lambda: idle('client-a', 'client-b'), 30)

        # MV-XP-04 the MCVideo server protected what it sent and opened what it received.
        server = counters('mcvideo-server')
        observations['mcvideo-server'] = server
        check(
            'MV-XP-04 mcvideo-server encrypted and decrypted MCVideo XML',
            server.get('encrypted', 0) > 0 and server.get('decrypted', 0) > 0,
            server,
        )
        if integrity:
            check(
                'MV-XP-06 mcvideo-server signed its XML bodies and verified those it received (6.6.3)',
                server.get('signed', 0) > 0 and server.get('verified', 0) > 0,
                server,
            )
        # The MCPTT signalling of the same clients stays protected under their MCPTT CSKs.
        mcptt = counters('mcptt-server')
        observations['mcptt-server'] = mcptt
        check(
            'MV-XP-04 mcptt-server still decrypts the MCPTT signalling under the MCPTT CSKs',
            mcptt.get('decrypted', 0) >= len(ROLES) and (not integrity or mcptt.get('verified', 0) > 0),
            mcptt,
        )
        refused = {role: counters(role).get('refused', 0) for role in ROLES + ['mcvideo-server', 'mcptt-server']}
        check('MV-XP-05 no protected content was refused', not any(refused.values()), refused)

        # MV-XP-07 on the wire: no sensitive MCVideo data in clear.
        time.sleep(3)
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
        if sip_on_wire:
            sip = sip_text()
            check(
                'MV-XP-07 mcvideo-info elements are sent encrypted (type="Encrypted")',
                'mcvideo-request-uri type="Encrypted"' in sip and 'mcvideo-client-id type="Encrypted"' in sip,
            )
            check(
                'MV-XP-07 no MCVideo ID appears in clear in an mcvideo-info or resource-lists body',
                not any(
                    re.search(r'<mcvideoURI>' + re.escape(mcvideo_id), sip) or f'uri="{mcvideo_id}"' in sip
                    for mcvideo_id in ids.values()
                ),
            )
            check('MV-XP-07 no access token appears in clear', '<mcvideo-access-token type="Normal">' not in sip)
            if integrity:
                check(
                    'MV-XP-07 the MCVideo messages carry signatures in application/vnd.3gpp.mcptt-signed+xml',
                    sip.count('application/vnd.3gpp.mcptt-signed+xml') >= 4,
                )
        else:
            observations['sip_wire_checks'] = 'skipped: SIP over TLS'
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, KeyError) as error:
        result['error'] = str(error)
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', capture_name], capture_output=True)
    output = args.artifacts / 'integration/mcvideo-xml-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
