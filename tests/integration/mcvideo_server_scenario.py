#!/usr/bin/env python3
"""The MCVideo server container runs beside the MCPTT server (MCVideo plan V1a.5).

Run against a fixture prepared with --mcvideo: mcvideo-server is the mcptt-server
executable started with the MCVideo service profile (TS 24.281). The SIP core
routes its PSI to it (V1a.6), but it offers no MCVideo procedure yet, so the
scenario checks that it starts, reports the MCVideo service and its public service
identity, runs without an MCVideo-2 Diameter peer, is reached through the SIP core
at its PSI (a SIP OPTIONS request, RFC 3261 section 11), and leaves the MCPTT server
and the MCPTT call unaffected. Check IDs match tests/mcvideo/MCVIDEO_SHARED_CORE_TEST.md.

Specifications: TS 24.281 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
# Run the scenario: wait for both servers, check SC-05 to SC-08 and write the results file.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-mcvideo')
    args = parser.parse_args()
    generated = args.compose.resolve().parent / 'generated'
    checks, observations = [], {}
    result = dict(scenario='mcvideo-server', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    # The status.json the container of a role writes, or {} while it is missing or partly written.
    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------------------
    # Record a passed check, or fail the scenario with its label and detail.
    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)

    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not (
            status('mcvideo-server').get('ready') and status('mcptt-server').get('ready')
        ):
            time.sleep(1)
        video, ptt = status('mcvideo-server'), status('mcptt-server')
        config = json.loads((generated / 'mcvideo-server.json').read_text())
        observations.update(
            mcvideo_server={key: video.get(key) for key in ('ready', 'service', 'role', 'sip_transport')},
            mcx_server={key: ptt.get(key) for key in ('ready', 'service', 'role')},
        )
        # SC-05 the same executable runs as the MCVideo server and becomes ready.
        check('SC-05 mcvideo-server ready', video.get('ready') is True, video)
        check(
            'SC-05 mcvideo-server reports the MCVideo service', video.get('service') == 'mcvideo', video.get('service')
        )
        check(
            'SC-05 mcvideo-server is a separate instance',
            video.get('instance_id') and video.get('instance_id') != ptt.get('instance_id'),
        )
        # SC-06 its identity is the MCVideo PSI and it has no MCVideo-2 Diameter peer.
        check(
            'SC-06 MCVideo PSI',
            config['sip']['identity'] == config['mcvideo']['service_uri']
            and config['sip']['identity'].startswith('sip:mcvideo@'),
            config['sip']['identity'],
        )
        check('SC-06 no Diameter configuration', 'diameter_config' not in config)
        # SC-07 the MCPTT server keeps the MCPTT profile beside it.
        check(
            'SC-07 mcptt-server ready as MCPTT',
            ptt.get('ready') is True and ptt.get('service') == 'mcptt',
            ptt.get('service'),
        )
        check('SC-07 MCPTT users authorised', ptt.get('authorized_users', 0) >= 2, ptt.get('authorized_users'))
        # SC-08 the SIP core routes the MCVideo PSI to mcvideo-server (V1a.6): an OPTIONS
        # (RFC 3261 section 11) from a client reaches it and is answered, like the MCData PSI; a PSI with no
        # server is not, so the answers come from the servers, not from the core.
        cli = [
            str(ROOT / '.cache/deps/docker-compose-linux-x86_64'),
            '-p',
            args.project,
            '-f',
            str(args.compose.resolve()),
        ]
        domain = config['sip']['identity'].split('@', 1)[1]
        targets = {
            'mcvideo': config['sip']['identity'],
            'mcdata': f'sip:mcdata@{domain}',
            'none': f'sip:no-such-service@{domain}',
        }
        for target in targets.values():
            subprocess.run(
                cli
                + [
                    'exec',
                    '-T',
                    'client-a',
                    'mcx-client',
                    '--config',
                    '/config/client-a.json',
                    '--command',
                    f'options {target}',
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and len(status('client-a').get('options', {})) < len(targets):
            time.sleep(0.5)
        answers = status('client-a').get('options', {})
        observations['options'] = answers
        check('SC-08 MCVideo PSI answered by mcvideo-server', answers.get(targets['mcvideo']) == 200, answers)
        check('SC-08 MCData PSI still answered', answers.get(targets['mcdata']) == 200, answers)
        check(
            'SC-08 a PSI without a server is not answered 200', answers.get(targets['none']) not in (None, 200), answers
        )
        result['passed'] = True
    except AssertionError as error:
        result['error'] = str(error)
    output = args.artifacts / 'integration/mcvideo-server-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
