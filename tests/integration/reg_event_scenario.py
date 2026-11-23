#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The SIP core's network-initiated procedures of the reg event package in a running aka lab (TS 24.229 V19.7.0).

REG-01..03, re-authentication of one private user identity (clause 5.4.1.6: "If the S-CSCF is informed that a private
user identity needs to be re-authenticated"; the event "shortened" and the operator's expiry only for "each <contact>
element that was registered by this UE", items e) and f)), on client-a (IMS AKA):
- REG-01 reginfo.shorten for client-a's address-of-record with another private user identity (client-b's): refused
  (no contact of that identity), and client-a is not told "shortened";
- a second contact is added to client-a's address-of-record by the operator (usrloc ul.add: no private user identity
  of its own), standing for another device of the user;
- REG-02 reginfo.shorten with client-a's private user identity: client-a's contact gets the operator's expiry and
  client-a the event "shortened" (reg_shortened), while the other contact keeps its expiry (items c) and d));
- REG-03 client-a registers again before the expiry.
The added contact is removed afterwards.

REG-04..05, network-initiated deregistration of a SIP digest client (clause 5.4.1.5, sipcore-deregister ... deactivated)
and the UE's side (clause 5.1.1.7: "the UE shall delete all security associations or TLS sessions towards the
P-CSCF" and, for "deactivated", "start the initial registration procedure"), on client-c:
- REG-04 client-c is told "deactivated" and registers and is authorised again;
- REG-05 over TLS, the TLS connection client-c registered over is closed and the new registration uses a new one
  (over the debug TCP transport there is no TLS session: recorded, not checked).

Run last in the lab (it re-registers client-a and client-c). The result is written as
integration/reg-event-results.json.

Specifications: TS 24.229 V19.7.0 clauses 5.1.1.7, 5.4.1.5 and 5.4.1.6; RFC 3680.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = 'openmcx-dev:0.5'
SHORTENED = 60  # the operator's expiry of REG-02 ("an operator defined value"), shorter than any lab registration
OTHER_CONTACT = 'sip:other-device@192.0.2.9:5060'  # TEST-NET-1 (RFC 5737): never reached, removed after REG-02


# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-reg-event')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    out = args.artifacts / 'integration' / 'reg-event-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='reg-event', passed=False, checks=[])

    def check(name, passed, detail=''):
        result['checks'].append(dict(name=name, passed=bool(passed), detail=str(detail)))

    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def wait(predicate, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.5)
        return None

    def events(role, name):
        run = subprocess.run(cli + ['logs', '--no-color', role], capture_output=True, text=True, timeout=60)
        found = []
        for line in run.stdout.splitlines():
            text = line.split('|', 1)[-1].strip()
            if f'"event":"{name}"' in text:
                try:
                    found.append(json.loads(text))
                except json.JSONDecodeError:
                    continue
        return found

    def kamcmd(*command):
        run = subprocess.run(cli + ['exec', '-T', 'sip-core', '/opt/kamailio/sbin/kamcmd', '-s',
                                    'unix:/tmp/kamailio_ctl'] + list(command),
                             capture_output=True, text=True, timeout=30)
        return run.returncode, (run.stdout + run.stderr).strip()

    def contact_expiries(aor):
        """{contact URI: seconds left} of the address-of-record (ul.lookup)."""
        _, text = kamcmd('ul.lookup', 'location', aor)
        found, uri = {}, None
        for line in text.splitlines():
            key, _, value = line.strip().partition(':')
            if key.strip() == 'Address':
                uri = line.strip().split(':', 1)[1].strip()
            elif key.strip() == 'Expires' and uri:
                found[uri] = value.strip()
                uri = None
        return found

    def connections(role, port):
        """The established TCP connections of role's network namespace to the remote port (local ports)."""
        cid = subprocess.run(cli + ['ps', '-q', role], capture_output=True, text=True, check=True).stdout.strip()
        text = subprocess.run(['docker', 'run', '--rm', '--network', f'container:{cid}', TOOLS, 'ss', '-tnH',
                               'state', 'established', 'dport', '=', f':{port}'],
                              capture_output=True, text=True, timeout=60).stdout
        return sorted({line.split()[-2].rsplit(':', 1)[1] for line in text.splitlines() if line.strip()})

    added = False
    try:
        cfg_a = json.loads((generated / 'client-a.json').read_text())
        cfg_b = json.loads((generated / 'client-b.json').read_text())
        cfg_c = json.loads((generated / 'client-c.json').read_text())
        aor_a = cfg_a['sip']['identity'].removeprefix('sip:')  # usrloc keys user@domain
        impi_a = cfg_a['sip']['isim']['impi']  # the SIP core stores the Authorization username as sent: the IMPI
        impi_b = cfg_b['sip']['isim']['impi']
        aor_c = cfg_c['sip']['identity'].removeprefix('sip:')
        compose = json.loads(args.compose.read_text())
        tls = '--disable-tls' not in compose['services']['client-c']['command']  # --debug-sip labs: TCP, no TLS
        core_port = int(cfg_c['sip']['core_uri'].split(':')[2].split(';')[0])
        if not wait(lambda: status('client-a').get('authorized') and status('client-c').get('authorized'), 120):
            raise AssertionError('client-a or client-c not authorised')

        # REG-01: another private user identity has no contact of client-a's address-of-record.
        shortened_before = len(events('client-a', 'reg_shortened'))
        _, text = kamcmd('reginfo.shorten', 'location', aor_a, impi_b, str(SHORTENED))  # kamcmd exits 0 on a fault
        time.sleep(3)
        check('REG-01 reginfo.shorten with another private user identity: refused, client-a not told "shortened"',
              text.startswith('error: 404') and 'No contact of the private user identity' in text
              and len(events('client-a', 'reg_shortened')) == shortened_before, text[:160])

        # REG-02: client-a's own identity; the operator's second contact of the AOR keeps its expiry.
        code, text = kamcmd('ul.add', 'location', aor_a, OTHER_CONTACT, '3600', '1.0', 's:0', '0', '0', '0')  # path 's:0' (kamcmd string): unset
        added = code == 0 and not text.startswith('error')  # kamcmd exits 0 on a fault
        if not added:
            raise AssertionError(f'ul.add: {text[:160]}')
        before = contact_expiries(aor_a)
        _, text = kamcmd('reginfo.shorten', 'location', aor_a, impi_a, str(SHORTENED))
        after = contact_expiries(aor_a)
        # client-a registers again at once on "shortened" (its reregistration time is 0 for 60 s), so the SIP core's
        # expiry may already be renewed when read: the shortened expiry is the one client-a was told in the NOTIFY.
        told = wait(lambda: events('client-a', 'reg_shortened')[shortened_before:], 20) or []
        own_shortened = bool(told) and all(0 < int(event.get('expires', 0)) <= SHORTENED for event in told)
        other_kept = (OTHER_CONTACT in after and after[OTHER_CONTACT].isdigit()
                      and int(after[OTHER_CONTACT]) > SHORTENED)
        check('REG-02 reginfo.shorten with client-a\'s private user identity: its contact shortened, the other '
              'contact of the AOR kept, client-a told "shortened"',
              text.startswith('shortened 1') and own_shortened and other_kept,
              f'{text[:40]}; told {told}; before {before}; after {after}')
        kamcmd('ul.rm_contact', 'location', aor_a, OTHER_CONTACT)
        added = False

        # REG-03: client-a registers again (a new expiry above the operator's).
        again = wait(lambda: [v for uri, v in contact_expiries(aor_a).items() if uri != OTHER_CONTACT
                              and v.isdigit() and int(v) > SHORTENED], SHORTENED + 30)
        check('REG-03 client-a registered again before the shortened expiry', again, f'{contact_expiries(aor_a)}')

        # REG-04/05: network-initiated deregistration of client-c (SIP digest), "deactivated".
        old = connections('client-c', core_port)
        deregistered_before = len(events('client-c', 'network_deregistered'))
        run = subprocess.run(cli + ['exec', '-T', 'sip-core', 'sipcore-deregister', aor_c, 'deactivated'],
                             capture_output=True, text=True, timeout=60)
        told = wait(lambda: len(events('client-c', 'network_deregistered')) > deregistered_before, 20)
        back = told and wait(lambda: status('client-c').get('registered') and status('client-c').get('authorized')
                             and contact_expiries(aor_c), 60)
        check('REG-04 client-c told "deactivated", registered and authorised again',
              run.returncode == 0 and told and back, (run.stdout + run.stderr).strip()[:120])
        new = wait(lambda: connections('client-c', core_port), 20) or []
        if tls:
            check('REG-05 the TLS session client-c registered over is closed, the new registration on a new one',
                  old and new and not set(old) & set(new), f'before {old}, after {new}')
        else:
            result['tcp_connections'] = dict(before=old, after=new)
    except Exception as error:  # noqa: BLE001 - the result records any failure
        result['error'] = str(error)
    finally:
        if added:
            kamcmd('ul.rm_contact', 'location', aor_a, OTHER_CONTACT)
    failed = [c['name'] for c in result['checks'] if not c['passed']]
    if failed and not result.get('error'):
        result['error'] = 'failed: ' + '; '.join(failed)
    result['passed'] = not result.get('error') and bool(result['checks'])
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], error=result.get('error', ''))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
