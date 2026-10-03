#!/usr/bin/env python3
"""MCX Admin manages the accounts of a lab.

ADM-01 the store is seeded from the lab and the user database's file is written.
ADM-02 an administrator suspends bob: IdMS refuses his sign-in, the CMS stops serving
       his user record, he leaves the user database's file, and his client, restarted,
       is not authorised. The standard refusals only (3GPP conformance guard).
ADM-03 restoring bob brings all of that back, and his client authorises again.
ADM-04 the revisions and the audit name the administrator; no secret is stored.
ADM-05 alice creates erin; she sets her password from a one-time IdMS link.
ADM-06 an activation URL (with its QR code) delivers erin's bootstrap package once:
       client-e, with local settings only, activates, gets its SIP credential from
       the Credential Service and is authorised.
ADM-07 suspending erin moves her SIP credential aside (the SIP core refuses her
       REGISTER with the standard 401); restoring her brings it back.
ADM-08 the web console: alice signs in through the IdMS's sign-in form (the console
       sees the code, not the password), gets an HttpOnly session, and reads the live
       status; a write without the console header and a wrong password are refused.
ADM-09 groups through MCX Admin (slice D): alice adds erin to operations; the GMS
       serves the change and the CMS lists the group on erin's profile; erin's
       device, activated again, affiliates and calls the group, and alice's client
       takes part in the call.
ADM-10 alice removes erin: the GMS drops her, and her call to operations fails.
ADM-12 (run before ADM-10) erin's device offering media at another host's address
       is refused by the SIP core with 488 (TS 24.229 clause 5.2.7.2); her calls in ADM-09
       need no device address in the MCPTT server's configuration.
ADM-13 (in a lab with MCData rights, --mcdata) erin, created with an MCData ID,
       is MCData-authorised on her activated device and sends a one-to-one SDS
       that alice receives (TS 24.282 clause 9.2.2).
ADM-14 (in a lab with protected groups, --protected) adding erin to operations
       and removing her each give the members a new group key (GMK, TS 33.180
       clause 5.7.3), and erin's device, a member, receives it and calls.
ADM-15 (slice F2) erin's device activates with no certificate of its own: the Credential
       Service certifies the key it made, naming her client ID and not a server; Revoke
       devices in MCX Admin records it revoked and removes her SIP credential, so her
       device, restarted, is refused at registration.
ADM-16 (SIP over TLS) the Credential Service publishes the revocation list and has the SIP
       core reload it: the revoked certificate is refused at the TLS handshake.
ADM-17 the dashboard's presence: erin's device registered at the SIP core, and alice's
       last sign-in at IdMS.
ADM-11 a user's XCAP write at the GMS (TS 24.481 clause 6.3.7.3) becomes a revision with
       source xcap, and the removed member's group list follows (conformance
       guard, rule 3).
ADM-18 the activated device keeps IdMS's refresh token (TS 33.180 annex B.5), owner-only,
       and no password.

Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
TS 24.229 (cited, not kept locally).
"""

import base64
import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
from urllib.parse import quote
import time

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------
def main():
    """Run the checks ADM-01 to ADM-18 and write integration/admin-results.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', required=True)
    args = parser.parse_args()
    fixture = args.compose.resolve().parent
    generated = fixture / 'generated'
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    compose = json.loads(args.compose.read_text())
    network = compose['networks']['mcx']['name']
    image = compose['services']['mcxadmin']['image']
    site = json.loads((generated / 'site.json').read_text())
    clients = {item: json.loads((generated / f'{item}.json').read_text()) for item in ('client-a', 'client-b')}
    checks, result = [], dict(scenario='admin', passed=False, checks=[])
    result['checks'] = checks

    # ------------------------------------------------------------------------------
    def helper(*words):
        """Run admin_helper.py with the words in a container on the lab network; its JSON result."""
        run = subprocess.run(
            [
                'docker',
                'run',
                '--rm',
                '--network',
                network,
                '-v',
                f'{generated / "tls/ca.crt"}:/ca.crt:ro',
                '-v',
                f'{Path(__file__).resolve().parent / "admin_helper.py"}:/admin_helper.py:ro',
                '--entrypoint',
                'python3',
                image,
                '/admin_helper.py',
                *words,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if run.returncode:
            raise AssertionError(f'helper {words[0]}: {run.stderr.strip()[-500:]}')
        return json.loads(run.stdout.strip().splitlines()[-1])

    # ------------------------------------------------------------------------------
    def login(role):
        """Sign the role's user in at IdMS (admin_helper.py login)."""
        oauth = clients[role]['oauth']
        return helper('login', oauth['username'], oauth['password'], oauth['client_id'], oauth['redirect_uri'])

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json from the artifacts, or {} while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def userdb_logins():
        """The user names in the user database's file (empty when it cannot be read)."""
        out = subprocess.run(
            cli + ['exec', '-T', 'mcx-user-db', 'cat', '/shared/userdb.json'], capture_output=True, text=True
        )
        return {account['username'] for account in json.loads(out.stdout)['users']} if out.returncode == 0 else set()

    # ------------------------------------------------------------------------------
    def cms_record(mcptt_id):
        """The CMS's internal user record of the MCPTT ID (status and body)."""
        return helper(
            'internal',
            site['server_client_id'],
            site['server_secret'],
            f'{site["endpoints"]["cms"]}/internal/user?mcptt_id={quote(mcptt_id)}',
        )

    # ------------------------------------------------------------------------------
    def gms_group(group_id):
        """The GMS's internal record of the group, or {}."""
        out = helper(
            'internal',
            site['server_client_id'],
            site['server_secret'],
            f'https://gms:8443/internal/group?id={quote(group_id)}',
        )
        return out['body'] if out['status'] == 200 and isinstance(out['body'], dict) else {}

    # ------------------------------------------------------------------------------
    def client_command(role, text, config):
        """Run one mcx-client command in the role's container of the activation profile with the given config."""
        return subprocess.run(
            cli + ['--profile', 'activation', 'exec', '-T', role, 'mcx-client', '--config', config, '--command', text],
            capture_output=True,
            text=True,
            timeout=15,
        )

    # ------------------------------------------------------------------------------
    def cms_user(mcptt_id):
        """The status of the CMS's internal user record of the MCPTT ID (the ID not URL-quoted)."""
        return helper(
            'internal',
            site['server_client_id'],
            site['server_secret'],
            f'{site["endpoints"]["cms"]}/internal/user?mcptt_id={mcptt_id}',
        )['status']

    # ------------------------------------------------------------------------------
    def sip_db(query):
        """The output of an SQL query on the SIP core's database."""
        out = subprocess.run(
            cli
            + [
                'exec',
                '-T',
                'sip-db',
                'sh',
                '-c',
                f'MYSQL_PWD=$(cat /run/secrets/mysql-root-password) mysql -h 127.0.0.1 -u root -N -e "{query}"',
            ],
            capture_output=True,
            text=True,
        )
        return out.stdout.strip()

    # ------------------------------------------------------------------------------
    def sip_rows(table, username):
        """The number of the user's rows in a table of the SIP core's database, as text."""
        return sip_db(f"SELECT COUNT(*) FROM mcx.{table} WHERE username = '{username}'")

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=None):
        """Record the label as a passed check if the condition holds; raise with the detail otherwise."""
        if not condition:
            raise AssertionError(f'{label}: {detail if detail is not None else "failed"}')
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Poll the predicate until it holds, then record the label as a passed check; raise on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.5)
        raise AssertionError(f'{label} timed out')

    bob = clients['client-b']['mcptt']['user_id']
    try:
        wait(
            'ADM-01 the clients are authorised in admin mode',
            lambda: all(status(item).get('authorized') for item in clients),
            90,
        )
        admin = login('client-a')
        check('ADM-01 alice, an administrator, signs in at IdMS', admin['status'] == 200 and admin['token'], admin)
        token = admin['token']
        config = helper('api', token, 'GET', '/v1/config')
        check(
            'ADM-01 the store holds the lab\'s users, seeded as revision 1',
            config['status'] == 200 and config['etag'] == '1' and len(config['body']['users']) == 4,
            config['etag'],
        )
        check(
            'ADM-01 the user database\'s file holds every active user',
            {'alice', 'bob'} <= userdb_logins(),
            userdb_logins(),
        )
        check('ADM-01 the CMS serves bob\'s user record from MCX Admin', cms_user(bob) == 200)
        not_admin = helper('api', login('client-b')['token'], 'GET', '/v1/config')
        check('ADM-01 bob, not an administrator, is refused (403)', not_admin['status'] == 403, not_admin['status'])

        suspended = helper('api', token, 'POST', '/v1/users/bob/suspend', '1')
        check(
            'ADM-02 alice suspends bob: revision 2', suspended['status'] == 200 and suspended['etag'] == '2', suspended
        )
        check('ADM-02 IdMS refuses bob\'s sign-in', login('client-b')['status'] == 401)
        check('ADM-02 the CMS no longer serves bob\'s user record', cms_user(bob) == 404)
        wait(
            'ADM-02 bob leaves the user database\'s file (unknown over Diameter)',
            lambda: 'bob' not in userdb_logins(),
            15,
        )
        # The restarted client stops at sign-in, before it rewrites its status: its
        # log since the restart says why.
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        subprocess.run(cli + ['restart', 'client-b'], check=True, capture_output=True)
        wait(
            'ADM-02 bob\'s client, restarted, is refused at IdMS sign-in',
            lambda: (
                'IdMS user authentication failed'
                in subprocess.run(
                    cli + ['logs', '--no-color', '--since', since, 'client-b'], capture_output=True, text=True
                ).stdout
            ),
            30,
        )

        restored = helper('api', token, 'POST', '/v1/users/bob/restore', '2')
        check('ADM-03 alice restores bob: revision 3', restored['status'] == 200 and restored['etag'] == '3', restored)
        check('ADM-03 IdMS signs bob in again', login('client-b')['status'] == 200)
        check('ADM-03 the CMS serves bob\'s record again', cms_user(bob) == 200)
        wait('ADM-03 bob is back in the user database\'s file', lambda: 'bob' in userdb_logins(), 15)
        subprocess.run(cli + ['restart', 'client-b'], check=True, capture_output=True)
        wait('ADM-03 bob\'s client authorises again', lambda: status('client-b').get('authorized'), 60)

        revisions = helper('api', token, 'GET', '/v1/revisions')['body']['revisions']
        check(
            'ADM-04 the revisions: seeded, then suspended and restored by alice',
            [(item['source'], item['actor']) for item in revisions]
            == [('import', 'import'), ('api', 'alice'), ('api', 'alice')],
            revisions,
        )
        audit = json.dumps(helper('api', token, 'GET', '/v1/audit')['body'])
        check('ADM-04 the audit holds no token', token not in audit and 'Bearer' not in audit)
        secret_rows = subprocess.run(
            cli
            + [
                'exec',
                '-T',
                'sip-db',
                'sh',
                '-c',
                'MYSQL_PWD=$(cat /run/secrets/mysql-root-password) mysql -h 127.0.0.1 -u root -N -D mcxadmin '
                '-e "SELECT COUNT(*) FROM revisions WHERE document LIKE \'%password%\'"',
            ],
            capture_output=True,
            text=True,
        )
        check(
            'ADM-04 no password in the MCX Admin store',
            secret_rows.stdout.strip() == '0',
            secret_rows.stdout + secret_rows.stderr,
        )

        # ADM-05: a new user, from the API, with her own password.
        current = helper('api', token, 'GET', '/v1/config')
        domain = current['body']['system']['domain']
        erin = dict(next(account for account in current['body']['users'] if account['login'] == 'bob'))
        erin.update(
            login='erin',
            display_name='Erin',
            status='active',
            mc_id=f'sip:erin.mc@{domain}',
            mcptt_id=f'sip:erin.mcptt@{domain}',
            sip_uri=f'sip:erin@{domain}',
            client_ids=['urn:uuid:5d3c9a1e-6f0b-4c1e-9a55-0000000000e5'],
            groups=[],
        )
        # No group: in M1 the GMS still takes groups from the lab's configuration.
        for key in ('mcdata_id', 'mcvideo_id', 'email'):
            erin.pop(key, None)
        # In a lab with MCData rights (--mcdata), erin gets MCData too (ADM-13).
        mcdata_lab = 'mcdata' in (erin.get('profile') or {})
        if mcdata_lab:
            erin['mcdata_id'] = f"sip:erin.mcdata@{domain}"
        created = helper('api', token, 'PUT', '/v1/users/erin', current['etag'], json.dumps(erin))
        check('ADM-05 alice creates erin', created['status'] == 200, created)
        wait('ADM-05 erin is in the user database\'s file', lambda: 'erin' in userdb_logins(), 15)
        check('ADM-05 the CMS serves erin\'s user record', cms_user(erin['mcptt_id']) == 200)
        check('ADM-05 erin has no SIP credential yet', sip_rows('subscriber', 'erin') == '0')
        link = helper('api', token, 'POST', '/v1/users/erin/password-link')
        check(
            'ADM-05 alice gets erin a one-time set-password link',
            link['status'] == 200 and link['body'].get('url'),
            link,
        )
        password = secrets.token_urlsafe(18)
        check(
            'ADM-05 erin sets her password at IdMS',
            helper('set-password', link['body']['url'], password)['status'] == 200,
        )

        # ADM-06: activation of a client with local settings only.
        issued = helper('api', token, 'POST', '/v1/users/erin/activation')
        url = issued['body'].get('url', '') if isinstance(issued['body'], dict) else ''
        png = base64.b64decode(issued['body'].get('qr_png', '')) if url else b''
        check(
            'ADM-06 alice issues an activation URL with its QR code',
            issued['status'] == 200
            and url.startswith('https://mcxadmin:8443/activate/')
            and png.startswith(b'\x89PNG'),
            issued['status'],
        )
        activate = generated / 'activate-e'
        (activate / 'url').write_text(url + '\n')
        (activate / 'password').write_text(password + '\n')
        up = subprocess.run(cli + ['--profile', 'activation', 'up', '-d', 'client-e'], capture_output=True, text=True)
        check('ADM-06 client-e starts with the activation URL', up.returncode == 0, up.stderr[-500:])
        wait('ADM-06 client-e activates and is authorised as erin', lambda: status('client-e').get('authorized'), 90)
        # The client keeps its activated configuration owner-only; read it as the client.
        saved = json.loads(
            subprocess.run(
                cli + ['--profile', 'activation', 'exec', '-T', 'client-e', 'cat', '/config/activate/client-e.json'],
                capture_output=True,
                text=True,
            ).stdout
        )
        check(
            'ADM-06 the activated configuration is erin\'s and marked activated',
            saved.get('activated') is True
            and saved['sip']['identity'] == erin['sip_uri']
            and saved['mcptt']['user_id'] == erin['mcptt_id']
            and saved['sip']['username'] == 'erin',
            saved.get('sip', {}).get('identity'),
        )
        check('ADM-06 the Credential Service wrote erin\'s SIP credential', sip_rows('subscriber', 'erin') == '1')
        # TS 33.180 annex B.5: the device keeps IdMS's refresh token, owner-only, not erin's password.
        session_file = saved.get('oauth', {}).get('refresh_token_file', '')
        session_mode = subprocess.run(
            cli
            + ['--profile', 'activation', 'exec', '-T', 'client-e', 'stat', '-c', '%a', session_file or '/nonexistent'],
            capture_output=True,
            text=True,
        ).stdout.strip()
        check(
            'ADM-18 the activated device keeps a refresh token (owner-only) and no password',
            'password' not in saved.get('oauth', {}) and password not in json.dumps(saved) and session_mode == '600',
            (sorted(saved.get('oauth', {})), session_mode),
        )
        presence = helper('api', token, 'GET', '/v1/presence')['body']
        check(
            'ADM-17 the presence shows erin\'s device registered and alice\'s last sign-in',
            presence.get('users', {}).get('erin', {}).get('registered') is True
            and presence['users'].get('alice', {}).get('last_sign_in'),
            presence,
        )
        issued = sip_db(
            "SELECT client_id, revoked_at IS NULL FROM mcx.client_certificates WHERE username = 'erin'"
        ).split()
        check(
            'ADM-15 erin\'s device got its certificate from the Credential Service, for her client ID',
            issued == [erin['client_ids'][0], '1']
            and saved['tls'].get('cert_file') == '/config/activate/device.crt'
            and saved['tls'].get('key_file') == '/config/activate/device.key',
            (issued, saved.get('tls')),
        )
        check('ADM-06 the activation URL works once', helper('fetch', url)['status'] == 404)

        # ADM-07: suspension reaches the SIP core.
        etag = helper('api', token, 'GET', '/v1/config')['etag']
        suspended = helper('api', token, 'POST', '/v1/users/erin/suspend', etag)
        check('ADM-07 alice suspends erin', suspended['status'] == 200, suspended)
        wait(
            'ADM-07 erin\'s SIP credential is moved aside (REGISTER refused with 401)',
            lambda: sip_rows('subscriber', 'erin') == '0' and sip_rows('subscriber_suspended', 'erin') == '1',
            30,
        )
        restored = helper('api', token, 'POST', '/v1/users/erin/restore', suspended['etag'])
        check('ADM-07 alice restores erin', restored['status'] == 200, restored)
        wait(
            'ADM-07 erin\'s SIP credential is back',
            lambda: sip_rows('subscriber', 'erin') == '1' and sip_rows('subscriber_suspended', 'erin') == '0',
            30,
        )
        restarted = time.time()
        subprocess.run(cli + ['--profile', 'activation', 'restart', 'client-e'], check=True, capture_output=True)
        status_file = args.artifacts / 'client-e' / 'status.json'
        wait(
            'ADM-07 client-e, restarted, is authorised again from its saved configuration',
            lambda: (
                status_file.exists()
                and status_file.stat().st_mtime > restarted
                and status('client-e').get('authorized')
            ),
            60,
        )
        check(
            'ADM-07 no password in the MCX Admin store',
            sip_db("SELECT COUNT(*) FROM mcxadmin.revisions WHERE document LIKE '%password%'") == '0',
        )
        audit = json.dumps(helper('api', token, 'GET', '/v1/audit')['body'])
        check(
            'ADM-07 the audit records the activation, not its URL',
            'activation-issued' in audit and url.rsplit('/', 1)[1] not in audit,
        )

        # ADM-08: the web console.
        oauth = clients['client-a']['oauth']
        ui = helper('console', oauth['username'], oauth['password'])
        check(
            'ADM-08 the console page is served with the openMCX logo and a strict CSP',
            ui['page'] == 200 and ui['page_logo'] and ui['page_csp'],
            ui,
        )
        signin = ui['signin']
        check(
            'ADM-08 sign-in goes to the IdMS, whose own form takes the password',
            signin['start'] == 302
            and signin['authorize'] == f'{site["endpoints"]["idms"]}/authorize'
            and signin['form'] == 200
            and signin['request_id'],
            signin,
        )
        check(
            'ADM-08 the IdMS sends the code back to the console, which opens an HttpOnly session',
            signin['login'] == 302
            and signin['callback'] == 'https://mcxadmin:8443/ui/callback'
            and signin['landing'] == '/'
            and ui['session']
            and 'httponly' in signin['session_attrs']
            and 'secure' in signin['session_attrs'],
            signin,
        )
        check(
            'ADM-08 the session is alice\'s', isinstance(ui['me'], dict) and ui['me'].get('login') == 'alice', ui['me']
        )
        st = ui['status']
        services = {service['name']: service['up'] for service in st['services']} if isinstance(st, dict) else {}
        check(
            'ADM-08 the dashboard status: every service up, every change delivered',
            services
            and all(services.values())
            and all(
                delivery['applied_revision'] == st['revision'] and not delivery['failed'] for delivery in st['delivery']
            ),
            st
            if not isinstance(st, dict)
            else {field: content for field, content in services.items() if not content} or st['delivery'],
        )
        check('ADM-08 the dashboard counts erin among the active users', st['users']['active'] == 5, st['users'])
        check(
            'ADM-08 a console write without the console header is refused (403)',
            ui['write_without_header'] == 403,
            ui['write_without_header'],
        )
        wrong = ui['wrong_password']
        check(
            'ADM-08 a wrong password goes back to the console as access_denied, with no session',
            wrong['denied'] and wrong['landing'] == '/?signin=failed',
            wrong,
        )

        # ADM-09: erin joins operations through MCX Admin and calls it.
        ops = clients['client-a']['mcptt']['group_id']
        protected_lab = bool(site.get('security'))
        key_before = status('client-a').get('group_key_id')
        erin_id = erin['mcptt_id']
        listed = helper('api', token, 'GET', '/v1/groups')
        group = next(candidate for candidate in listed['body']['groups'] if candidate['id'] == ops)
        group['members'] = [*group['members'], erin_id]
        saved = helper('api', token, 'PUT', '/v1/groups/' + quote(ops, safe=''), listed['etag'], json.dumps(group))
        check('ADM-09 alice adds erin to operations', saved['status'] == 200, saved)
        wait('ADM-09 the GMS serves operations with erin', lambda: erin_id in gms_group(ops).get('members', []), 20)
        if protected_lab:
            wait(
                'ADM-14 adding erin gives alice\'s device a new group key',
                lambda: status('client-a').get('group_key_id') not in (None, key_before),
                90,
            )
        record = cms_record(erin_id)
        check(
            'ADM-09 the CMS lists operations on erin\'s profile',
            ops in (record.get('body') or {}).get('groups', []),
            record,
        )
        subprocess.run(cli + ['--profile', 'activation', 'stop', 'client-e'], check=True, capture_output=True)
        (activate / 'client-e.json').unlink(missing_ok=True)
        shutil.copyfile(activate / 'device.json', activate / 'client-e.json')
        (activate / 'client-e.json').chmod(0o666)
        again = helper('api', token, 'POST', '/v1/users/erin/activation')
        (activate / 'url').write_text(again['body']['url'] + '\n')
        started = time.time()
        subprocess.run(cli + ['--profile', 'activation', 'up', '-d', 'client-e'], check=True, capture_output=True)
        status_file = args.artifacts / 'client-e' / 'status.json'
        wait(
            'ADM-09 erin\'s device, activated again, is authorised and affiliated to operations',
            lambda: (
                status_file.stat().st_mtime > started
                and status('client-e').get('authorized')
                and status('client-e').get('affiliated')
            ),
            90,
        )
        erin_config = '/config/activate/client-e.json'
        if protected_lab:
            wait(
                'ADM-14 erin\'s device holds the group key',
                lambda: (
                    status('client-e').get('protected_ready')
                    and status('client-e').get('group_key_id') == status('client-a').get('group_key_id')
                ),
                90,
            )
        client_command('client-e', 'call', erin_config)
        wait(
            'ADM-09 erin\'s group call reaches alice',
            lambda: (
                status('client-e').get('call_state') == 'active' and status('client-a').get('call_state') == 'active'
            ),
            30,
        )
        client_command('client-e', 'hangup', erin_config)
        wait(
            'ADM-09 the call ends',
            lambda: status('client-e').get('call_state') == 'idle' and status('client-a').get('call_state') == 'idle',
            30,
        )

        # ------------------------------------------------------------------------------
        def reactivate(label, advertise=None):
            """Restart client-e from its device configuration (optionally offering media at another host's
            address), activate it again with a new activation URL and wait until it is authorised and affiliated."""
            subprocess.run(cli + ['--profile', 'activation', 'stop', 'client-e'], check=True, capture_output=True)
            device = json.loads((activate / 'device.json').read_text())
            if advertise:
                device['media']['advertise'] = advertise
            (activate / 'client-e.json').unlink(missing_ok=True)
            (activate / 'client-e.json').write_text(json.dumps(device, indent=2) + '\n')
            (activate / 'client-e.json').chmod(0o666)
            link = helper('api', token, 'POST', '/v1/users/erin/activation')
            (activate / 'url').write_text(link['body']['url'] + '\n')
            begun = time.time()
            subprocess.run(cli + ['--profile', 'activation', 'up', '-d', 'client-e'], check=True, capture_output=True)
            wait(
                label,
                lambda: (
                    status_file.stat().st_mtime > begun
                    and status('client-e').get('authorized')
                    and status('client-e').get('affiliated')
                ),
                90,
            )

        # ADM-13: MCData for a user created in MCX Admin.
        if mcdata_lab:
            wait('ADM-13 erin\'s device is MCData-authorised', lambda: status('client-e').get('mcdata_authorized'), 60)
            alice_data = clients['client-a']['mcdata']['user_id']
            text = f'hello-from-erin-{secrets.token_hex(4)}'
            client_command('client-e', f'sds {alice_data} {text}', erin_config)
            wait(
                'ADM-13 erin\'s SDS is accepted (202)',
                lambda: (status('client-e').get('mcdata_last_result') or {}).get('status') == 202,
                20,
            )
            wait(
                'ADM-13 alice receives it from erin',
                lambda: any(
                    element.get('from') == erin['mcdata_id']
                    and any(payload.get('text') == text for payload in element.get('payloads', []))
                    for element in status('client-a').get('mcdata_inbox') or []
                ),
                20,
            )

        # ADM-12: media offered at another host's address.
        reactivate(
            'ADM-12 erin\'s device, set to offer media at client-a\'s address, is authorised', advertise='client-a'
        )
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        client_command('client-e', 'call', erin_config)
        wait(
            'ADM-12 the SIP core refuses her offer with 488',
            lambda: (
                (status('client-e').get('last_call_failure') or {}).get('status') == 488
                and 'is not the sender'
                in subprocess.run(
                    cli + ['logs', '--no-color', '--since', since, 'sip-core'], capture_output=True, text=True
                ).stdout
            ),
            20,
        )
        check('ADM-12 alice is not called', status('client-a').get('call_state') == 'idle')
        reactivate('ADM-12 erin\'s device, set back, is authorised again')

        # ADM-10: erin leaves operations.
        listed = helper('api', token, 'GET', '/v1/groups')
        group = next(candidate for candidate in listed['body']['groups'] if candidate['id'] == ops)
        group['members'] = [element for element in group['members'] if element != erin_id]
        saved = helper('api', token, 'PUT', '/v1/groups/' + quote(ops, safe=''), listed['etag'], json.dumps(group))
        check('ADM-10 alice removes erin from operations', saved['status'] == 200, saved)
        key_with_erin = status('client-a').get('group_key_id')
        wait(
            'ADM-10 the GMS no longer lists erin',
            lambda: gms_group(ops) and erin_id not in gms_group(ops).get('members', []),
            20,
        )
        if protected_lab:
            wait(
                'ADM-14 removing erin gives alice\'s device a new group key',
                lambda: status('client-a').get('group_key_id') not in (None, key_with_erin),
                90,
            )
        client_command('client-e', 'call', erin_config)
        check(
            'ADM-10 erin\'s call to operations fails; alice is not called',
            holds(
                lambda: (
                    status('client-e').get('call_state') != 'active' and status('client-a').get('call_state') == 'idle'
                ),
                5,
            ),
            {
                item: {
                    field: status(item).get(field)
                    for field in ('call_state', 'last_call_failure', 'last_error', 'affiliated')
                }
                for item in ('client-e', 'client-a')
            },
        )

        # ADM-11: a user's XCAP write comes back as a revision.
        alice_user = helper('api', token, 'GET', '/v1/users/alice')
        user = alice_user['body']['user']
        user['profile'] = {**(user.get('profile') or {}), 'group_management': {'manage': ['*']}}
        granted = helper('api', token, 'PUT', '/v1/users/alice', alice_user['etag'], json.dumps(user))
        check('ADM-11 alice is given group management in MCX Admin', granted['status'] == 200, granted)
        d_id = json.loads((generated / 'client-d.json').read_text())['mcptt']['user_id']
        entry = quote(f'group/list-service/list/entry[@uri="{d_id}"]', safe='')
        removed = helper(
            'xcap',
            token,
            'DELETE',
            f'https://gms:8443/xcap-root/org.openmobilealliance.groups/global/byGroupID/{quote(ops, safe="")}/~~/{entry}',
        )
        check(
            'ADM-11 alice removes client-d from operations with an XCAP DELETE at the GMS',
            removed['status'] == 200,
            removed,
        )

        # ------------------------------------------------------------------------------
        def imported():
            """MCX Admin's latest revision comes from XCAP and client-d's user no longer lists operations."""
            revs = helper('api', token, 'GET', '/v1/revisions')['body']['revisions']
            d_user = next(
                account
                for account in helper('api', token, 'GET', '/v1/config')['body']['users']
                if account['mcptt_id'] == d_id
            )
            return revs[-1]['source'] == 'xcap' and ops not in d_user['groups']

        wait(
            'ADM-11 MCX Admin records the change as a revision from xcap; client-d\'s group list follows', imported, 20
        )

        # ADM-15: Revoke devices. erin is a member of operations again first, so that her
        # restarted device, whose configuration names it, gets as far as registering.
        listed = helper('api', token, 'GET', '/v1/groups')
        group = next(candidate for candidate in listed['body']['groups'] if candidate['id'] == ops)
        group['members'] = [*group['members'], erin_id]
        check(
            'ADM-15 erin is a member of operations again',
            helper('api', token, 'PUT', '/v1/groups/' + quote(ops, safe=''), listed['etag'], json.dumps(group))[
                'status'
            ]
            == 200,
        )
        wait(
            'ADM-15 the GMS serves operations with erin again', lambda: erin_id in gms_group(ops).get('members', []), 20
        )
        revoked = helper('api', token, 'POST', '/v1/users/erin/revoke-devices')
        check('ADM-15 alice revokes erin\'s devices', revoked['status'] == 200, revoked)
        check(
            'ADM-15 her certificates are recorded revoked and her SIP credential is gone',
            sip_db("SELECT COUNT(*) FROM mcx.client_certificates WHERE username = 'erin' AND revoked_at IS NULL") == '0'
            and sip_rows('subscriber', 'erin') == '0'
            and sip_rows('subscriber_suspended', 'erin') == '0',
        )
        tls_lab = not any(
            '--disable-tls' in argument for argument in compose['services']['client-a'].get('command', [])
        )
        if tls_lab:
            wait(
                'ADM-16 the revocation list names her certificate',
                lambda: (
                    'crl_published'
                    in subprocess.run(
                        cli + ['logs', '--no-color', 'credentials'], capture_output=True, text=True
                    ).stdout
                ),
                20,
            )
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        restarted = time.time()
        subprocess.run(cli + ['--profile', 'activation', 'restart', 'client-e'], check=True, capture_output=True)
        # IdMS revoked her refresh tokens with the devices: the device, which keeps no password,
        # is refused its sign-in before it registers (TS 33.180 annex B.5.3).
        wait(
            'ADM-15 her device, restarted, is refused at IdMS: its refresh token is revoked',
            lambda: (
                'IdMS refused the refresh token'
                in subprocess.run(
                    cli + ['--profile', 'activation', 'logs', '--no-color', '--since', since, 'client-e'],
                    capture_output=True,
                    text=True,
                ).stdout
            ),
            60,
        )
        # The SIP core's own checks, for a device that still gets past IdMS (it is given
        # erin's password, which Revoke devices leaves as it is).
        subprocess.run(cli + ['--profile', 'activation', 'stop', 'client-e'], check=True, capture_output=True)
        subprocess.run(
            cli
            + [
                '--profile',
                'activation',
                'run',
                '--rm',
                '-T',
                '--no-deps',
                '--entrypoint',
                'python3',
                'client-e',
                '-c',
                'import json,sys; p="/config/activate/client-e.json"; c=json.load(open(p)); '
                'c["oauth"]["password"]=sys.argv[1]; json.dump(c,open(p,"w"))',
                password,
            ],
            check=True,
            capture_output=True,
        )
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        restarted = time.time()
        subprocess.run(cli + ['--profile', 'activation', 'up', '-d', 'client-e'], check=True, capture_output=True)
        wait(
            'ADM-15 with the password it gets past IdMS and is refused at registration',
            lambda: (
                status_file.stat().st_mtime > restarted
                and 'SIP registration: ' in (status('client-e').get('last_error') or '')
            ),
            60,
        )
        if tls_lab:
            # OpenSSL names a certificate on the revocation list a verification failure.
            wait(
                'ADM-16 the SIP core refuses her revoked certificate at the TLS handshake',
                lambda: (
                    'certificate verify failed'
                    in subprocess.run(
                        cli + ['logs', '--no-color', '--since', since, 'sip-core'], capture_output=True, text=True
                    ).stdout
                ),
                30,
            )
        result['passed'] = True
    except (AssertionError, subprocess.SubprocessError, OSError, KeyError, ValueError, StopIteration) as error:
        result['error'] = str(error)
        logs = subprocess.run(
            cli + ['--profile', 'activation', 'logs', '--no-color', 'client-e'], capture_output=True, text=True
        )
        (args.artifacts / 'integration').mkdir(parents=True, exist_ok=True)
        (args.artifacts / 'integration/client-e.log').write_text(logs.stdout + logs.stderr)
    subprocess.run(cli + ['--profile', 'activation', 'rm', '-sf', 'client-e'], capture_output=True)
    out = args.artifacts / 'integration/admin-results.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
