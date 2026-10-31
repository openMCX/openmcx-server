#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Write the configuration of tutorial 8's MCX system, with Keycloak as its IdMS, into ./config.

It runs the lab's own generator (tools/prepare-prearranged-test.py --keycloak: a new CA and certificates, the users,
the MCPTT and MCData servers, the common services, and Keycloak's realm with the users, the MC scopes and the claim
mappers), keeps only its configuration files, and sets them up for phones and a dispatcher that reach every
service through HOST_IP:

- Keycloak answers at https://HOST_IP:8443 (the issuer https://HOST_IP:8443/realms/openmcx, for the servers too), with
  a certificate of the system's CA that names HOST_IP, and an administrator for its console;
- the MCPTT server puts HOST_IP in its SDP and accepts the addresses the SIP core checked;
- each phone gets a provisioning file (config/phones/<user>.mcxprov) without a password: it signs in on Keycloak's
  page;
- the dispatcher (config/dispatcher.json) signs its operator in on Keycloak's page, in the browser of this
  computer.

Run by `docker compose -f docker-compose-keycloak.yaml run --rm setup`. It refuses to overwrite an existing
configuration (a new one makes a new CA, which no phone trusts): remove ./config to start again.
"""

import ipaddress
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile

GENERATOR = pathlib.Path('/opt/mcxserver/tools/prepare-prearranged-test.py')
LAB = pathlib.Path(__file__).resolve().parent / 'lab.json'
# The tutorial folder is mounted at /work; the configuration goes into its config/ and belongs to its owner.
WORK = pathlib.Path('/work')
OUT = WORK / 'config'

# The host ports docker-compose-keycloak.yaml publishes (host port -> container port 8443 for the HTTPS services).
SIP_PORT, IDMS_PORT, PROXY_PORT = 5061, 8443, 8444
# The dispatcher's web page, on this computer: Keycloak sends the browser back to its callback.
DISPATCHER_PAGE = 'http://127.0.0.1:8080'
# The phones' and the dispatcher's users (the generator's client-a, client-b and client-c).
PHONES = {'client-a': 'alice', 'client-b': 'bob'}


# ------------------------------------------------------------------------------
def edit(path, change):
    """Apply change to the JSON file at path."""
    cfg = json.loads(path.read_text())
    change(cfg)
    path.write_text(json.dumps(cfg, indent=2) + '\n')


# ------------------------------------------------------------------------------
def openssl(*args):
    """Run openssl."""
    subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)


# ------------------------------------------------------------------------------
def phone_bundle(ref, site, role, host):
    """The Android app's provisioning (as android/lab/androidlab.py writes it) from the generated client
    configuration: no IdMS username or password, so the app signs in on Keycloak's page; the services reached through
    HOST_IP."""
    sip, mcptt, mcdata, oauth = ref['sip'], ref['mcptt'], ref['mcdata'], ref['oauth']
    return {
        'name': PHONES[role],
        'domain': site['domain'],
        'client_id': mcptt['client_id'],
        'sip': {'public_user_id': sip['identity'], 'private_user_id': sip['username'], 'password': sip['password'],
                'proxy': 'sip-core', 'proxy_port': SIP_PORT, 'transport': 'TLS', 'register_expires': 3600},
        'tls': {'ca': 'ca.crt', 'cert': 'client.crt', 'key': 'client.key'},
        'idms': {'issuer': oauth['issuer'], 'client_id': oauth['client_id'], 'redirect_uri': oauth['redirect_uri']},
        'cms': ref['endpoints']['cms'],
        'gms': ref['endpoints']['gms'],
        'mcptt': {'user_id': mcptt['user_id'], 'psi': mcptt['service_uri'], 'groups': [mcptt['group_id']],
                  'answer_mode': 'automatic', 'session_expires': 1800, 'manual_answer_timeout': 20},
        'mcdata': {'user_id': mcdata['user_id'], 'psi': mcdata['service_uri'], 'groups': [mcdata['group_id']],
                   'max_payload_size_sds_cplane_bytes': 1000, 'tdu1_seconds': 10},
        'media': {'port_range': [20000, 20400], 'amr_wb_mode': 2},
        'endpoints': {f'sip-core:{SIP_PORT}': f'{host}:{SIP_PORT}', 'http-proxy:8443': f'{host}:{PROXY_PORT}'},
    }


# ------------------------------------------------------------------------------
def dispatcher(ref, host):
    """The dispatcher's configuration (lab mode, dispatcher/README.md): client-c's identity, on this
    computer's network as the phones are (SIP on 5071, speech on 4400 and 5400), its operator signing in on Keycloak's
    page (oauth.login "browser") and sent back to the dispatcher's callback."""
    cfg = json.loads(json.dumps(ref))
    cfg['sip'].update(listen='0.0.0.0', advertise=host, port=5071, register_expires=120, outbound=True)
    cfg['tls'] = {'ca_file': '/config/tls/ca.crt', 'cert_file': '/config/tls/client-c.crt',
                  'key_file': '/config/tls/client-c.key'}
    cfg['media'] = {'bind': host, 'advertise': host, 'rtp_port': 4400, 'floor_port': 5400, 'mode': 0,
                    'server_source': 'port',
                    'live': {'listen': '127.0.0.1', 'port': 7700, 'send_host': '127.0.0.1', 'send_port': 7701}}
    for key in ('username', 'password', 'refresh_token_file'):
        cfg['oauth'].pop(key, None)
    cfg['oauth'].update(login='browser', redirect_uri=DISPATCHER_PAGE + '/api/login/callback')
    # The servers' names, as the configuration names them, at this computer's published ports (TLS still checks the
    # names); sip-core itself resolves to HOST_IP in the container (docker-compose-keycloak.yaml).
    cfg['address_map'] = {'http-proxy:8443': f'{host}:{PROXY_PORT}'}
    cfg['server_address'] = host
    cfg['control_fifo'] = '/run/mcx/control'
    cfg['status_file'] = '/run/mcx/status.json'
    cfg.pop('received_wav', None)
    cfg.pop('mcvideo', None)
    return cfg


# ------------------------------------------------------------------------------
def main():
    """Generate, then set up for HOST_IP."""
    host = os.environ.get('HOST_IP', '').strip()
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        sys.exit("HOST_IP is not set to this computer's IPv4 address on the Wi-Fi (see .env.example)")
    if OUT.exists() and any(OUT.iterdir()):
        sys.exit('./config already holds a configuration: remove it to make a new system')
    OUT.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        lab = pathlib.Path(tmp) / 'lab'
        # The image names only matter for the generator's own compose file, which is not used here.
        subprocess.run(
            [sys.executable, str(GENERATOR), '--directory', str(lab), '--input', str(LAB), '--project',
             'openmcx-keycloak', '--mcdata', '--images', 'tutorial', '--keycloak', 'keycloak'],
            check=True,
        )
        generated = lab / 'generated'
        for item in generated.iterdir():
            if item.name in ('refresh', 'client-d.json', 'mcvideo-server.json'):
                continue
            target = OUT / item.name
            if item.is_dir():
                shutil.copytree(item, target, symlinks=False)
            else:
                shutil.copy2(item, target)
        # The servers' status files (their health checks read them).
        shutil.copytree(lab / 'artifacts', OUT / 'artifacts')

    # Keycloak at HOST_IP: the issuer of the tokens, for the phones, the browser and the servers alike.
    issuer = f'https://{host}:{IDMS_PORT}/realms/openmcx'
    for path in OUT.glob('*.json'):
        cfg = json.loads(path.read_text())
        if not isinstance(cfg, dict):
            continue
        if path.name == 'site.json':
            cfg['issuer'] = issuer
        elif 'common' in cfg:
            cfg['common']['issuer'] = issuer
        elif 'oauth' in cfg:
            cfg['oauth']['issuer'] = issuer
            # Another IdMS: its endpoints come from its discovery document (no configured <idms-auth-endpoint>,
            # <idms-token-endpoint> or JWKS URI of the lab IdMS).
            for key in ('idms_auth_endpoint', 'idms_token_endpoint', 'jwks_uri'):
                cfg['oauth'].pop(key, None)
        else:
            continue
        path.write_text(json.dumps(cfg, indent=2) + '\n')
    # Keycloak's certificate names HOST_IP too (the phones and the browser reach it there).
    tls = OUT / 'tls'
    (tls / 'idms-host.ext').write_text(
        f'subjectAltName=DNS:idms,IP:{host}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n'
        'keyUsage=digitalSignature,keyEncipherment\n'
    )
    openssl('req', '-new', '-key', tls / 'idms.key', '-subj', '/CN=idms', '-out', tls / 'idms-host.csr')
    openssl('x509', '-req', '-in', tls / 'idms-host.csr', '-CA', tls / 'ca.crt', '-CAkey', tls / 'ca.key',
            '-CAcreateserial', '-days', '30', '-extfile', tls / 'idms-host.ext', '-out', tls / 'idms.crt')
    for name in ('idms-host.ext', 'idms-host.csr'):
        (tls / name).unlink()
    # The dispatcher's callback is a redirect URI of the OAuth client too.
    callback = DISPATCHER_PAGE + '/api/login/callback'
    edit(OUT / 'site.json', lambda cfg: cfg['oauth_redirect_uris'].append(callback))
    realm_file = OUT / 'keycloak' / 'openmcx.json'
    realm = json.loads(realm_file.read_text())
    realm['clients'][0]['redirectUris'].append(callback)
    realm_file.write_text(json.dumps(realm, indent=2) + '\n')
    # Keycloak's administrator, created at its first start (its admin console).
    admin_password = secrets.token_hex(12)
    (OUT / 'keycloak' / 'admin.env').write_text(
        f'KC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}\n'
    )

    # The MCPTT server: HOST_IP in its SDP, on the ports docker-compose-keycloak.yaml publishes; it accepts the SDP
    # address the SIP core checked against the sender (the phones' own addresses, which no configuration names).
    def mcptt(cfg):
        cfg['media']['advertise'] = host
        cfg['sip']['core_checks_media_address'] = True

    edit(OUT / 'mcptt-server.json', mcptt)

    site = json.loads((OUT / 'site.json').read_text())
    phones = OUT / 'phones'
    phones.mkdir()
    for role, name in PHONES.items():
        ref = json.loads((OUT / f'{role}.json').read_text())
        prov = {'format': 'mcx-provisioning/1', 'bundle': phone_bundle(ref, site, role, host),
                'ca': (tls / 'ca.crt').read_text(), 'cert': (tls / f'{role}.crt').read_text(),
                'key': (tls / f'{role}.key').read_text()}
        (phones / f'{name}.mcxprov').write_text(json.dumps(prov, indent=2) + '\n')
    console = dispatcher(json.loads((OUT / 'client-c.json').read_text()), host)
    (OUT / 'dispatcher.json').write_text(json.dumps(console, indent=2) + '\n')
    # The generator's clients: the phones and the dispatcher have their own files now.
    for role in ('client-a', 'client-b', 'client-c'):
        (OUT / f'{role}.json').unlink()

    # Every container reads these files under its own user; the database password files are the MySQL image's.
    for path in OUT.rglob('*'):
        path.chmod(0o777 if path.is_dir() else 0o644)
    for path in [OUT / 'artifacts', *(OUT / 'artifacts').rglob('*')]:
        path.chmod(0o777 if path.is_dir() else 0o666)
    for path in [phones, *phones.iterdir(), OUT / 'keycloak' / 'admin.env']:
        path.chmod(0o700 if path.is_dir() else 0o600)
    # Keycloak's own user reads its administrator's password.
    (OUT / 'keycloak' / 'admin.env').chmod(0o644)
    owner = WORK.stat()
    for path in [OUT, *OUT.rglob('*')]:
        os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)

    users = {user['username']: user['password'] for user in site['users']}
    note = (
        f"Keycloak: https://{host}:{IDMS_PORT}/admin/ (administrator admin, password {admin_password})\n"
        f"Users (they sign in on Keycloak's page): alice {users['alice']}, bob {users['bob']}, "
        f"client-c (the dispatcher) {users['client-c']}\n"
        "Phones: import config/phones/alice.mcxprov and config/phones/bob.mcxprov; "
        f"the dispatcher: {DISPATCHER_PAGE}/\n"
        f"The certificates are the system's own CA's (./config/tls/ca.crt) and expire after 30 days.\n"
    )
    (OUT / 'ADMIN.txt').write_text(note)
    os.chown(OUT / 'ADMIN.txt', owner.st_uid, owner.st_gid)
    os.chmod(OUT / 'ADMIN.txt', 0o600)
    print('\nConfiguration written to ./config.\n' + note
          + 'Next: docker compose -f docker-compose-keycloak.yaml up -d')


if __name__ == '__main__':
    main()
