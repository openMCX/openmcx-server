#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""IMS AKA re-registration (TS 33.203 V19.1.0 clauses 7.4.0, 7.4.1a and 7.4.2a) in a running aka lab, on client-a.

client-a gets a registration of 60 s (sip.register_expires) and is restarted, so that it re-registers during the
lab. After its first re-registration over a new set of security associations:
- the P-CSCF's protected server port is unchanged and the UE's protected client port changed ("the protected server
  ports at the UE (port_us) and the PCSCF (port_ps) shall remain unchanged, while the protected client ports ... shall
  change", clause 7.4.0);
- at SM12 the P-CSCF keeps the old set, over which SM1 came, in use for outbound messages, and takes the new set into
  use only on the UE's first message over it (clause 7.4.2a: "the P-CSCF keeps this inbound SA and the corresponding
  three SAs ... and continues to use them ... When ... a further SIP message protected with a new inbound SA is
  successfully received from the UE, the P-CSCF starts to use the new SAs for outbound messages"), in that order in
  the P-CSCF's log;
- once the old set's pending transactions are over, no SA or policy of the old set is left in the UE's or the P-CSCF's
  network namespace (clauses 7.4.1a and 7.4.2a: "deleted as soon as all pending SIP transactions have been completed,
  or have timed out"). The check waits at most as long as a transaction can last: 64*T1 (RFC 3261 Timers F and J),
  plus the P-CSCF's transaction wait timer (Kamailio tm wait_timer, 5 s) and each end's 1 s look-up.
The scenarios after this one (calls and SDS to the AKA UEs) then run over the new set. The result is written as
integration/aka-reregistration-results.json.

Specifications: TS 33.203 V19.1.0 (Rel-19); TS 24.229 V19.7.0 clause 5.1.1.4.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = 'openmcx-dev:0.4'
WAIT_OLD_SET = 64 * 0.5 + 5 + 2  # 64*T1, tm wait_timer, the 1 s look-ups at the UE and the P-CSCF


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
def xfrm(cli, service, port):
    """The SA and policy lines of service's network namespace that name port (ip xfrm state/policy)."""
    cid = subprocess.run(cli + ['ps', '-q', service], capture_output=True, text=True, check=True).stdout.strip()
    out = subprocess.run(
        ['docker', 'run', '--rm', '--cap-add', 'NET_ADMIN', '--network', f'container:{cid}', TOOLS, 'bash', '-c',
         'ip xfrm state; ip xfrm policy'],
        capture_output=True, text=True, timeout=60,
    ).stdout
    return [line.strip() for line in out.splitlines() if f'port {port} ' in line + ' ']


# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-aka-reregistration')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    out = args.artifacts / 'integration' / 'aka-reregistration-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    result = dict(scenario='aka-reregistration', passed=False, checks=[])

    def check(name, passed, detail):
        result['checks'].append(dict(name=name, passed=bool(passed), detail=detail))

    try:
        config = args.compose.resolve().parent / 'generated' / 'client-a.json'
        cfg = json.loads(config.read_text())
        cfg['sip']['register_expires'] = 60
        config.write_text(json.dumps(cfg, indent=2))
        subprocess.run(cli + ['restart', 'client-a'], check=True, capture_output=True, timeout=120)
        time.sleep(3)
        first = wait_for(lambda: (s := status(args.artifacts)).get('authorized') and (s.get('sip_security') or {})
                         .get('port_uc') and s['sip_security'], 120, 'client-a authorised over IMS AKA')
        second = wait_for(lambda: (sa := (status(args.artifacts).get('sip_security') or {})).get('port_uc')
                          and sa['port_uc'] != first['port_uc'] and sa, 120, 'a re-registration over a new set')
        def pcscf_log():
            return subprocess.run(cli + ['logs', 'pcscf'], capture_output=True, text=True, timeout=60).stdout

        keep = (f"keeping the old security associations of port_uc {first['port_uc']} until the UE's first message "
                f"over port_uc {second['port_uc']}")
        switch = f"the UE's first message over port_uc {second['port_uc']}: outbound messages over it"
        try:
            log = wait_for(lambda: next((text for text in [pcscf_log()] if switch in text), None), WAIT_OLD_SET,
                           'the switch')
        except AssertionError:
            log = pcscf_log()
        check('7.4.2a old set kept at SM12', keep in log, keep)
        check('7.4.2a new set used after the UE\'s first message over it',
              keep in log and switch in log and log.index(keep) < log.index(switch), switch)
        check('7.4.0 port_ps unchanged', second.get('port_ps') == first.get('port_ps'),
              f"port_ps {first.get('port_ps')} -> {second.get('port_ps')}")
        check('7.4.0 port_us unchanged, port_uc changed',
              second.get('port_us') == first.get('port_us') and second.get('port_uc') != first.get('port_uc'),
              f"port_us {first.get('port_us')} -> {second.get('port_us')}, port_uc {first.get('port_uc')} -> "
              f"{second.get('port_uc')}")
        # A later re-registration may have replaced the second set too: only the first set's client port is checked.
        deadline = time.monotonic() + WAIT_OLD_SET
        while True:
            ue = xfrm(cli, 'client-a', first['port_uc'])
            pcscf = xfrm(cli, 'pcscf', first['port_uc'])
            if (not ue and not pcscf) or time.monotonic() > deadline:
                break
            time.sleep(1)
        check('7.4.1a old set gone at the UE', not ue, '; '.join(ue[:4]) or 'none left')
        check('7.4.2a old set gone at the P-CSCF', not pcscf, '; '.join(pcscf[:4]) or 'none left')
        check('client-a still registered and authorised', status(args.artifacts).get('authorized'),
              json.dumps(status(args.artifacts).get('sip_security'))[:200])
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
