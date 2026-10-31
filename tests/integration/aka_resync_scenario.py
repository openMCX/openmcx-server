#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA after a restart of the SIP core (AKA-11) in a running aka lab, on client-a.

client-a gets a registration of 60 s (sip.register_expires) and is restarted. Once it is authorised over a set of
security associations, the SIP core is restarted: it keeps the registrations and the sequence numbers of its vectors in
memory only, and supports no S-CSCF restoration. At client-a's next reregistration:
- the SIP core answers the protected REGISTER of a user it has no registration for with 500 (TS 24.229 clause
  5.4.1.2.3A), and the UE then performs the procedures for initial registration (clause 5.1.1.4.1: "On receiving ...
  500 (Server Internal Error) response ... for a reregistration, the UE shall perform the procedures for initial
  registration");
- the new vector carries an SQN the UE's ISIM has already seen: the UE answers with AUTS (TS 33.102 clause 6.3.5,
  TS 24.229 clause 5.1.1.5.3) and the SIP core resynchronises and challenges again (clause 5.4.1.2.3A);
- the UE authenticates, a new set of security associations is taken into use (port_uc changes) and client-a is
  registered and authorised again.
The result is written as integration/aka-resync-results.json.

Specifications: TS 24.229 V19.7.0, TS 33.203 V19.1.0 (Rel-19); TS 33.102; RFC 3310.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def status(artifacts):
    try:
        return json.loads((artifacts / 'client-a' / 'status.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ------------------------------------------------------------------------------
def wait_for(predicate, timeout, what):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise AssertionError(f'timed out: {what}')


# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-resync')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    out = args.artifacts / 'integration' / 'aka-resync-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-resync', passed=False, checks=[])

    def check(name, passed, detail):
        result['checks'].append(dict(name=name, passed=bool(passed), detail=detail))

    def logs(service, since):
        return subprocess.run(cli + ['logs', '--since', since, service], capture_output=True, text=True,
                              timeout=60).stdout

    try:
        config = args.compose.resolve().parent / 'generated' / 'client-a.json'
        cfg = json.loads(config.read_text())
        cfg['sip']['register_expires'] = 60
        config.write_text(json.dumps(cfg, indent=2))
        subprocess.run(cli + ['restart', 'client-a'], check=True, capture_output=True, timeout=120)
        time.sleep(3)
        first = wait_for(lambda: (s := status(args.artifacts)).get('authorized') and (s.get('sip_security') or {})
                         .get('port_uc') and s['sip_security'], 120, 'client-a authorised over IMS AKA')
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        subprocess.run(cli + ['restart', 'sip-core'], check=True, capture_output=True, timeout=120)
        wait_for(lambda: '(healthy)' in subprocess.run(cli + ['ps', 'sip-core'], capture_output=True, text=True)
                 .stdout, 120, 'the SIP core healthy again')
        marker = 'reregistration answered 500; initial registration'
        line = wait_for(lambda: next((text for text in logs('client-a', since).splitlines() if marker in text), None),
                        90, 'the 500 to the reregistration')
        check('AKA-11 500 to the reregistration, then an initial registration (TS 24.229 clause 5.1.1.4.1)', line,
              line.strip()[-140:])
        second = wait_for(lambda: (s := status(args.artifacts)).get('authorized') and (sa := s.get('sip_security')
                          or {}).get('port_uc') and sa['port_uc'] != first['port_uc'] and sa, 120,
                          'a new set after the initial registration')
        resync = next((text for text in logs('sip-core', since).splitlines()
                       if 'IMS AKA resynchronisation from AUTS for' in text), '')
        check('AKA-11 the SIP core resynchronised from the UE\'s AUTS (its SQN was lost with the restart)', resync,
              resync.strip()[-120:] or 'no resynchronisation')
        check('AKA-11 registered and authorised again over a new set', second,
              f"port_uc {first['port_uc']} -> {second.get('port_uc')}")
        failed = [c['name'] + ' (' + c['detail'] + ')' for c in result['checks'] if not c['passed']]
        if failed:
            result['error'] = 'failed: ' + '; '.join(failed)
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
