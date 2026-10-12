#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""N5 AF role: mcptt-server requests MCPTT QoS from a PCF (TS 29.514 Npcf_PolicyAuthorization).

Run against a fixture prepared with --pcf --priority --floor-queue --private-call:
mock-pcf (tests/integration/mock_pcf.go) records every request over HTTP/2 cleartext
and can send notifications to the server. Check IDs N5-01..N5-07 are listed in
docs/architecture/5g-ims-mcx-functional-entities.md (OpenMCX N5 AF).
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']
BASE = '/npcf-policyauthorization/v1/app-sessions'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-pcf')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {r: json.loads((generated / f'{r}.json').read_text()) for r in ROLES}
    server_cfg = json.loads((generated / 'mcptt-server.json').read_text())
    pcf_cfg = server_cfg['pcf']
    ids = {r: configs[r]['mcptt']['user_id'] for r in ROLES}
    group = configs['client-a']['mcptt']['group_id']
    checks, observations = [], {}
    result = dict(scenario='pcf-n5-af', passed=False, checks=checks, observations=observations)

    def status(role):
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (OSError, ValueError):
            return {}

    def pcf_status():
        return status('mcptt-server').get('pcf', {})

    def exec_(service, *command, timeout=15):
        run = subprocess.run(cli + ['exec', '-T', service, *command], capture_output=True, text=True, timeout=timeout)
        if run.returncode:
            raise RuntimeError(f'{service} {command}: {run.stderr.strip() or run.stdout.strip()}')
        return run.stdout

    def command(role, text):
        exec_(role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text)

    def mock(path, body=None):
        command_line = ['curl', '-sf', '--http2-prior-knowledge', f'http://127.0.0.1:8080{path}']
        if body is not None:
            command_line += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
        out = exec_('mock-pcf', *command_line)
        return json.loads(out) if out.strip() else None

    def requests():
        return mock('/mock/requests') or []

    def creates(since=0):
        return [r for r in requests()[since:] if r['method'] == 'POST' and r['path'] == BASE]

    def patches(since=0):
        return [r for r in requests()[since:] if r['method'] == 'PATCH']

    def deletes(since=0):
        return [r for r in requests()[since:] if r['method'] == 'POST' and r['path'].endswith('/delete')]

    def snapshot():
        return dict(pcf=pcf_status(), clients={r: {k: status(r).get(k) for k in ('call_state', 'call_type', 'priority')}
                                               for r in ROLES}, requests=requests()[-6:])

    def wait(label, condition, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(f'{label} timed out: ' + json.dumps(snapshot())[:3000])

    def check(label, condition, detail=None):
        if not condition:
            raise AssertionError(f'{label}: {json.dumps(detail)[:3000] if detail is not None else "failed"}')
        checks.append(label)
        print(label, flush=True)

    def session():
        for value in status('mcptt-server').get('sessions', []):
            if value.get('group_id') == group:
                return value
        return {}

    def idle(*roles):
        return all(status(r).get('call_state') == 'idle' for r in roles)

    try:
        wait('four clients authorised', lambda: all(status(r).get('authorized') for r in ROLES), 90)
        wait('fixture initially idle', lambda: idle(*ROLES))
        check('N5-00 the AF is enabled and holds no app session', pcf_status().get('enabled') and pcf_status().get('active') == 0,
              pcf_status())
        def address(service):
            container = subprocess.run(cli + ['ps', '-q', service], check=True, capture_output=True, text=True).stdout.strip()
            return subprocess.run(['docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}',
                                   container], check=True, capture_output=True, text=True).stdout.split()[0]
        addresses = {r: address(r) for r in ROLES + ['mcptt-server']}
        observations['addresses'] = addresses
        server_ip = addresses['mcptt-server']
        for r in ROLES:
            command(r, 'answer-mode auto')
            if status(r).get('group_id') != group:
                command(r, 'group ' + group)
            elif not status(r).get('affiliated'):
                command(r, 'affiliate')
        wait('clients affiliated', lambda: all(status(r).get('affiliated') and status(r).get('group_id') == group for r in ROLES))
        command('client-d', 'deaffiliate')
        wait('client-d detached', lambda: not status('client-d').get('affiliated'))

        # N5-01 a group call: one app session per confirmed leg, created over HTTP/2.
        mark = len(requests())
        command('client-a', 'call')
        wait('N5-01 three-party group call established', lambda: len(session().get('participants', [])) == 3 and
             all(status(r).get('call_state') == 'active' for r in ROLES[:3]))
        wait('N5-01 one create per leg', lambda: len(creates(mark)) == 3 and pcf_status().get('active') == 3)
        made = creates(mark)
        observations['create_example'] = made[0]['body']
        check('N5-01 over HTTP/2 cleartext (prior knowledge)', all(r['proto'] == 'HTTP/2.0' for r in made), [r['proto'] for r in made])
        check('N5-01 application/json, 201 with a Location', all(r['content_type'] == 'application/json' and r['status'] == 201
                                                                  for r in made))
        data = {r['body']['ascReqData']['mcpttId']: r['body']['ascReqData'] for r in made}
        check('N5-01 one app session per participant (mcpttId)', set(data) == {ids[r] for r in ROLES[:3]}, list(data))
        by_role = {r: data[ids[r]] for r in ROLES[:3]}
        for role, d in by_role.items():
            ue = addresses[role]
            check(f'N5-01 {role}: afAppId, dnn, sliceInfo, suppFeat',
                  d['afAppId'] == pcf_cfg['af_app_id'] and d['dnn'] == pcf_cfg['dnn'] and d['sliceInfo'] == {'sst': 1}
                  and d['suppFeat'] == '0', d)
            check(f'N5-01 {role}: ueIpv4 is the UE', d['ueIpv4'] == ue, d['ueIpv4'])
            check(f'N5-01 {role}: no resPrio at normal priority', 'resPrio' not in d, d.get('resPrio'))
            check(f'N5-01 {role}: notifUri under notif_uri_base, events subscribed',
                  d['notifUri'].startswith(pcf_cfg['notif_uri_base'] + '/') and d['evSubsc']['notifUri'] == d['notifUri'] and
                  [e['event'] for e in d['evSubsc']['events']] == ['FAILED_RESOURCES_ALLOCATION', 'SUCCESSFUL_RESOURCES_ALLOCATION'],
                  d['evSubsc'])
            component = d['medComponents']['1']
            check(f'N5-01 {role}: one AUDIO component of 41 Kbps each way',
                  list(d['medComponents']) == ['1'] and component['medCompN'] == 1 and component['medType'] == 'AUDIO' and
                  component['marBwUl'] == component['marBwDl'] == '41 Kbps', component)
            subs = component['medSubComps']
            check(f'N5-01 {role}: RTP, RTCP and floor control flows', sorted(subs) == ['1', '2', '3'] and
                  all(subs[n]['fNum'] == int(n) and subs[n]['fStatus'] == 'ENABLED' and subs[n]['flowUsage'] == ('RTCP' if n == '2' else 'NO_INFO')
                      for n in subs), subs)
            ports = []
            for n in ('1', '2', '3'):
                down, up = subs[n]['fDescs']
                dfields, ufields = down.split(), up.split()
                ok = (dfields[:4] == ['permit', 'out', '17', 'from'] and dfields[4] == server_ip and dfields[6] == 'to' and
                      dfields[7] == ue and ufields[4] == ue and ufields[7] == server_ip and
                      dfields[5] == ufields[8] and dfields[8] == ufields[5])
                check(f'N5-01 {role}: flow {n} fDescs downlink and uplink', ok, subs[n]['fDescs'])
                ports.append(int(dfields[5]))
            check(f'N5-01 {role}: server RTCP is RTP + 1 and floor is separate', ports[1] == ports[0] + 1 and ports[2] not in ports[:2],
                  ports)
        app_ids = {d['mcpttId']: r['id'] for r, d in ((r, r['body']['ascReqData']) for r in made)}
        observations['app_sessions'] = app_ids

        # N5-02 emergency upgrade: every leg's app session is updated with resPrio.
        mark = len(requests())
        command('client-a', 'emergency on')
        wait('N5-02 the group call is an emergency call', lambda: session().get('priority') == 'emergency')
        wait('N5-02 one PATCH per app session', lambda: len(patches(mark)) == 3)
        upgraded = patches(mark)
        observations['patch_example'] = upgraded[0]
        check('N5-02 merge-patch over HTTP/2 to each app session',
              all(r['content_type'] == 'application/merge-patch+json' and r['proto'] == 'HTTP/2.0' and r['status'] == 200
                  for r in upgraded) and {r['path'] for r in upgraded} == {f'{BASE}/{i}' for i in app_ids.values()}, upgraded)
        check('N5-02 resPrio PRIO_16 and nothing else', all(r['body'] == {'ascReqData': {'resPrio': 'PRIO_16'}} for r in upgraded),
              [r['body'] for r in upgraded])

        # N5-03 emergency cancelled: resPrio removed.
        mark = len(requests())
        command('client-a', 'emergency off')
        wait('N5-03 the group call is back to normal priority', lambda: session().get('priority') == 'normal')
        wait('N5-03 one PATCH per app session', lambda: len(patches(mark)) == 3)
        check('N5-03 resPrio removed (null)', all(r['body'] == {'ascReqData': {'resPrio': None}} for r in patches(mark)),
              [r['body'] for r in patches(mark)])

        # N5-04 the PCF's event notification is accepted.
        answer = mock('/mock/notify', dict(id=app_ids[ids['client-b']], kind='notify', body=dict(
            evSubsUri='x', evNotifs=[dict(event='SUCCESSFUL_RESOURCES_ALLOCATION')])))
        check('N5-04 notification answered 204', answer['status'] == 204, answer)
        wait('N5-04 notification counted', lambda: pcf_status().get('notifications') == 1)

        # N5-05 hang-up: every app session deleted.
        mark = len(requests())
        command('client-a', 'hangup')
        wait('N5-05 the call ended', lambda: not session() and idle(*ROLES))
        wait('N5-05 one delete per app session', lambda: len(deletes(mark)) == 3 and pcf_status().get('active') == 0 and
             not pcf_status().get('sessions'))
        check('N5-05 POST .../{appSessionId}/delete, 204',
              {r['path'] for r in deletes(mark)} == {f'{BASE}/{i}/delete' for i in app_ids.values()} and
              all(r['status'] == 204 for r in deletes(mark)), deletes(mark))

        # N5-06 private call; a PCF-initiated termination is answered with a delete and the
        # call goes on (release_on_terminate is false).
        mark = len(requests())
        command('client-a', f"private {ids['client-b']} auto")
        wait('N5-06 private call active', lambda: all(status(r).get('call_state') == 'active' and
                                                      status(r).get('call_type') == 'private' for r in ('client-a', 'client-b')))
        wait('N5-06 two creates', lambda: len(creates(mark)) == 2 and pcf_status().get('active') == 2)
        private = {r['body']['ascReqData']['mcpttId']: r['id'] for r in creates(mark)}
        check('N5-06 private call legs for both parties', set(private) == {ids['client-a'], ids['client-b']}, private)
        answer = mock('/mock/notify', dict(id=private[ids['client-b']], kind='terminate',
                                           body=dict(termCause='PDU_SESSION_TERMINATION', resUri='x')))
        check('N5-06 termination answered 204', answer['status'] == 204, answer)
        wait('N5-06 the AF deletes the terminated app session',
             lambda: [r['path'] for r in deletes(mark)] == [f'{BASE}/{private[ids["client-b"]]}/delete'] and
             pcf_status().get('active') == 1)
        time.sleep(1)
        check('N5-06 the call goes on', all(status(r).get('call_state') == 'active' for r in ('client-a', 'client-b')))
        command('client-a', 'hangup')
        wait('N5-06 the call ended', lambda: idle('client-a', 'client-b'))
        wait('N5-06 the remaining app session deleted once', lambda: len(deletes(mark)) == 2 and pcf_status().get('active') == 0)
        time.sleep(1)
        check('N5-06 no second delete of the terminated app session', len(deletes(mark)) == 2, deletes(mark))

        # N5-07 the PCF refuses: best effort, the call is set up anyway and nothing is deleted.
        mock('/mock/config', dict(fail_create=True))
        mark = len(requests())
        failed_before = pcf_status().get('failed', 0)
        command('client-a', f"private {ids['client-b']} auto")
        wait('N5-07 private call active despite the refusal', lambda: all(status(r).get('call_state') == 'active'
                                                                         for r in ('client-a', 'client-b')))
        wait('N5-07 both creates refused with 503', lambda: len(creates(mark)) == 2 and
             all(r['status'] == 503 for r in creates(mark)) and pcf_status().get('failed', 0) - failed_before == 2)
        command('client-a', 'hangup')
        wait('N5-07 the call ended', lambda: idle('client-a', 'client-b'))
        time.sleep(1.5)
        check('N5-07 nothing to delete', not deletes(mark) and not pcf_status().get('sessions'), requests()[mark:])
        mock('/mock/config', dict(fail_create=False))

        # Overall: every created app session was deleted exactly once.
        everything = requests()
        created = {r['id'] for r in everything if r['method'] == 'POST' and r['path'] == BASE and r['status'] == 201}
        deleted = [r['id'] for r in everything if r['path'].endswith('/delete')]
        observations['totals'] = dict(created=len(created), deleted=len(deleted), patched=len(patches()))
        check('N5-08 every app session deleted exactly once', sorted(deleted) == sorted(created), observations['totals'])
        result['passed'] = True
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        result['error'] = str(error)
    output = args.artifacts / 'integration/pcf-n5-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks),
                          error=result.get('error', ''))))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
