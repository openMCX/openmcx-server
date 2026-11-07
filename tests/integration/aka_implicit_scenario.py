#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA with an implicit registration set and a card subscription, in a running aka-implicit lab.

client-a registers with an ISIM of the IMSI form (prepare-prearranged-test.py --aka-imsi): the barred registration
identity sip:<IMSI>@<domain> in its REGISTER, client-a's own identity the default public user identity (TS 23.228
clauses 4.3.3.3, 5.2.1 item 7). client-c is a SIP digest client whose identity is shared with a test card's IMS AKA
subscription (--test-card, TS 23.228 clause 4.3.3.4).
- IMP-01: client-a is registered and authorised, and its P-Associated-URI lists its own identity only (TS 24.229
  clause 5.4.1.2.2F b): the barred identity is not listed).
- IMP-02: the SIP core binds client-a's contact to its own identity and none to the barred one (TS 24.229 clause
  5.4.1.2.2 and its NOTE 9).
- IMP-03, IMP-05, IMP-06: aka_implicit.py from client-c's container, before and after tools/load-card-keys.py.
- IMP-04: client-c stays registered with SIP digest, its identity shared with the card's subscription (the scheme is
  the private user identity's, TS 23.228 clause 4.3.3.1).
The calls and SDS of the lab's other scenarios show that the MC servers serve client-a under its own identity, the
To of the third-party REGISTER (TS 24.229 clause 5.4.1.7 c)). Its result is integration/aka-implicit-results.json.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-implicit')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    fixture = args.compose.resolve().parent
    services = json.loads(args.compose.read_text()).get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get('client-c', {}).get('command', []))
    out = args.artifacts / 'integration' / 'aka-implicit-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-implicit', passed=False, checks=[])

    def check(name, passed, detail):
        result['checks'].append(dict(name=name, passed=bool(passed), detail=detail))

    try:
        lab = json.loads((fixture / 'lab.json').read_text())
        domain = lab['domain']
        user_a = next(user for user in lab['users'] if user['role'] == 'client-a')
        user_c = next(user for user in lab['users'] if user['role'] == 'client-c')
        own_a, own_c = f"sip:{user_a['username']}@{domain}", f"sip:{user_c['username']}@{domain}"
        barred = f"sip:{user_a['isim_imsi']}@{domain}"
        card = next(line.split(',') for line in (fixture / 'test-cards.csv').read_text().splitlines()[1:]
                    if line.startswith(user_c['card']))
        card_impi, card_identity = f'{card[1]}@{domain}', f'sip:{card[1]}@{domain}'

        def status(role):
            try:
                return json.loads((args.artifacts / role / 'status.json').read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return {}

        deadline = time.monotonic() + 120
        while not (status('client-a').get('authorized') and status('client-c').get('authorized')):
            if time.monotonic() > deadline:
                raise AssertionError('client-a or client-c not authorised')
            time.sleep(0.5)
        associated = [uri.strip().strip('<>')
                      for uri in status('client-a').get('sip_security', {}).get('associated_uris', [])]
        check('IMP-01 client-a authorised, P-Associated-URI its own identity only', associated == [own_a],
              f'{associated}')

        def lookup(aor):
            run = subprocess.run(cli + ['exec', '-T', 'sip-core', '/opt/kamailio/sbin/kamcmd', '-s',
                                        'unix:/tmp/kamailio_ctl', 'ul.lookup', 'location',
                                        aor.removeprefix('sip:')],  # usrloc keys user@domain
                                 capture_output=True, text=True, timeout=30)
            return run.returncode == 0 and 'Contact' in run.stdout, (run.stdout + run.stderr).strip()[:160]

        own_bound, own_text = lookup(own_a)
        barred_bound, barred_text = lookup(barred)
        check('IMP-02 contact bound to the default identity, none to the barred one', own_bound and not barred_bound,
              f'own: {own_text} | barred: {barred_text}')

        subprocess.run(cli + ['cp', str(HERE / 'aka_implicit.py'), 'client-c:/tmp/aka_implicit.py'],
                       check=True, capture_output=True)

        def probe(phase):
            command = ['python3', '/tmp/aka_implicit.py', '--config', '/config/client-c.json', '--phase', phase,
                       '--barred-identity', barred, '--card-identity', card_identity, '--card-impi', card_impi]
            command += [] if tls else ['--disable-tls']
            run = subprocess.run(cli + ['exec', '-T', 'client-c'] + command, capture_output=True, text=True,
                                 timeout=120)
            result['checks'].extend(json.loads(run.stdout.strip().splitlines()[-1])['checks'])

        probe('before')
        container = subprocess.run(cli + ['ps', '-q', 'sip-db'], capture_output=True, text=True,
                                   check=True).stdout.strip()
        load = subprocess.run(['python3', str(fixture / 'tools/load-card-keys.py'), '--card-keys',
                               str(fixture / 'test-cards.csv'), '--cards', str(fixture / 'generated/cards.json'),
                               '--container', container, '--domain', domain],
                              capture_output=True, text=True, timeout=60)
        check('IMP-05b test card keys loaded into the SIP database', load.returncode == 0,
              (load.stdout + load.stderr).strip())
        probe('after')
        check('IMP-04 client-c still registered with SIP digest, its identity shared with the card',
              status('client-c').get('registered') and status('client-c').get('authorized'), own_c)
        failed = [item['name'] for item in result['checks'] if not item['passed']]
        if failed:
            result['error'] = 'failed: ' + ', '.join(failed)
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    result['passed'] = not result.get('error')
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
