#!/usr/bin/env python3
"""Write the configuration of the tutorial's MCX system into ./config.

It runs the lab's own generator (tools/prepare-prearranged-test.py: a new CA and certificates, the users, the
MCPTT, MCData and MCVideo servers, the common services and MCX Admin), keeps only its configuration files, and sets
them up for phones on the same network as this computer, which reach every service through HOST_IP:

- the MCPTT and MCVideo servers put HOST_IP in their SDP, on the ports docker-compose-basic-mcx.yaml publishes,
  and accept the phones' own addresses as the SIP core checks them;
- MCX Admin's activation codes give the phones HOST_IP and the published ports for each service, and MCVideo;
- the MCX Admin console and the password links of IdMS are at HOST_IP, for a browser on this computer.

Run by `docker compose -f docker-compose-basic-mcx.yaml run --rm setup`. It refuses to overwrite an existing
configuration (a new one makes a new CA, which no activated phone trusts): remove ./config to start again.
"""

import ipaddress
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

GENERATOR = pathlib.Path('/opt/mcxserver/tools/prepare-prearranged-test.py')
LAB = pathlib.Path(__file__).resolve().parent / 'lab.json'
# The tutorial folder is mounted at /work; the configuration goes into its config/ and belongs to its owner.
WORK = pathlib.Path('/work')
OUT = WORK / 'config'

# The host ports docker-compose-basic-mcx.yaml publishes (host port -> container port 8443 for the HTTPS services).
SIP_PORT, IDMS_PORT, PROXY_PORT, KMS_PORT, ADMIN_PORT, CREDENTIALS_PORT = 5061, 8443, 8444, 8445, 8446, 8447
# The MCVideo server's audio, transmission control and video ports, off the MCPTT server's (4000 and 5000 up).
MCVIDEO_BASES = {'rtp_port': 7000, 'floor_port': 7200, 'video_port': 7400}


# The rights of the 'phone-user' template (TS 24.484 profile sections, as MCX Admin's templates hold them): private
# and ad hoc calls to and from any user, one-to-one MCData from any user, MCVideo calls to any user.
# The rights of emergency and imminent peril group calls and emergency alerts, and their cancellation (TS 24.484 user
# profile, read by TS 24.379 clause 6.3.3.1.13 and TS 24.281 clause 6.3.3.1.12), for the group the user has selected.
GROUP_CALL_RIGHTS = {
    'emergency': True,
    'emergency_cancel': True,
    'imminent': True,
    'imminent_cancel': True,
    'alert': True,
    'alert_cancel': True,
}
# Emergency private calls to any user, and their cancellation.
PRIVATE_EMERGENCY = {'emergency': True, 'emergency_any': True, 'emergency_cancel': True}

# The rights of the 'phone-user' template (TS 24.484 profile sections, as MCX Admin's templates hold them): private
# and ad hoc calls to and from any user, emergency and imminent peril calls and emergency alerts, one-to-one MCData
# from any user, MCVideo calls to any user with the same emergency rights.
PHONE_USER = {
    'private_call': {
        'allow': True,
        'automatic_commencement': True,
        'manual_commencement': True,
        'callable': True,
        'incoming_any': True,
        **PRIVATE_EMERGENCY,
    },
    'group_call': dict(GROUP_CALL_RIGHTS),
    'adhoc_call': {'allow': True, 'participation': True},
    'mcdata': {'transmit_data': True, 'incoming_any': True, 'adhoc': True, 'adhoc_participation': True,
               'emergency_alert': True, 'alert_cancel': True},
    'mcvideo': {
        'private_call': {'allow': True, 'automatic_commencement': True, 'manual_commencement': True, 'any_target': True,
                         **PRIVATE_EMERGENCY},
        'group_call': dict(GROUP_CALL_RIGHTS),
        'adhoc_call': {'allow': True, 'participation': True},
        'allow_video_pull_from_server': True,
    },
}
# The dispatcher's template: the same rights (tutorials 2 and 3 create the user 'dispatcher' from it).
DISPATCHER = PHONE_USER


def clean_groups(cfg):
    """The tutorial's system has one group, operations, for real users: the lab generator's other groups and their
    test restrictions go. Every member may raise and cancel emergency and imminent peril calls and emergency alerts
    (TS 24.481 rules for every member, MCPTT and MCVideo) and transmit data in the group (MCData)."""
    keep = next(group for group in cfg['groups'] if group['id'].startswith('sip:operations@'))
    keep['allow_emergency_call'] = keep['allow_imminent_peril'] = keep['allow_emergency_alert'] = True
    policy = keep.get('priority_policy', {})
    keep['priority_policy'] = {key: policy[key] for key in ('emergency_timeout_ms',) if key in policy}
    if 'mcvideo' in keep:
        video = keep['mcvideo']
        video['allow_emergency_call'] = video['allow_imminent_peril'] = video['allow_emergency_alert'] = True
        video_policy = video.get('priority_policy', {})
        video['priority_policy'] = {key: video_policy[key] for key in ('emergency_timeout_ms',)
                                    if key in video_policy}
    if 'mcdata' in keep:
        keep['mcdata'].pop('transmit_members', None)
        keep['mcdata']['transmit_all'] = True
    removed = {group['id'] for group in cfg['groups'] if group is not keep}
    cfg['groups'] = [keep]

    def drop(node):
        """Remove the references to the removed groups: list entries, values naming one and entries keyed by one."""
        if isinstance(node, dict):
            for key in [key for key, value in node.items() if key in removed or (isinstance(value, str) and value in removed)]:
                del node[key]
            for value in node.values():
                drop(value)
        elif isinstance(node, list):
            node[:] = [item for item in node if not (isinstance(item, str) and item in removed)]
            for item in node:
                drop(item)

    for key, value in cfg.items():
        if key != 'groups':
            drop(value)


def edit(path, change):
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data, indent=2) + '\n')


def main():
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
            [
                sys.executable,
                str(GENERATOR),
                '--directory',
                str(lab),
                '--input',
                str(LAB),
                '--project',
                'openmcx-basic',
                '--mcdata',
                '--mcvideo',
                '--adhoc',
                '--admin',
                '--admin-image',
                'openmcx-admin',
                '--images',
                'tutorial',
            ],
            check=True,
        )
        generated = lab / 'generated'
        for item in generated.iterdir():
            target = OUT / item.name
            if item.is_dir():
                shutil.copytree(item, target, symlinks=False)
            else:
                shutil.copy2(item, target)
        # The servers' status files (their health checks read them).
        shutil.copytree(lab / 'artifacts', OUT / 'artifacts')

    def https(port):
        """The HTTPS URL of a service published on the host's port."""
        return f'https://{host}:{port}'

    def mcptt(cfg):
        cfg['media']['advertise'] = host

    def mcvideo(cfg):
        cfg['media'].update(advertise=host, **MCVIDEO_BASES)
        # As the generator does for the MCPTT server in admin mode: the SIP core checks each client's SDP address,
        # so the server accepts it for users MCX Admin creates (their phones' addresses are not configured).
        cfg['sip']['core_checks_media_address'] = True
        # A person answers a ringing video call: 30 s, as for MCPTT.
        cfg.setdefault('mcvideo', {}).setdefault('private_call', {})['setup_timeout_ms'] = 30000

    video_service = json.loads((OUT / 'client-a.json').read_text())['mcvideo']['service_uri']

    def admin(cfg):
        activation = cfg['activation']
        # Activation codes carry MCVideo too, so that the phones also make video calls.
        activation['services']['mcvideo'] = video_service
        activation['base_url'] = https(ADMIN_PORT)
        activation['address_map'] = {
            f'sip-core:{SIP_PORT}': f'{host}:{SIP_PORT}',
            'idms:8443': f'{host}:{IDMS_PORT}',
            'http-proxy:8443': f'{host}:{PROXY_PORT}',
            'kms:8443': f'{host}:{KMS_PORT}',
            'credentials:8443': f'{host}:{CREDENTIALS_PORT}',
            'mcxadmin:8443': f'{host}:{ADMIN_PORT}',
        }
        cfg['console']['authorize_url'] = https(IDMS_PORT) + '/authorize'
        cfg['console']['redirect_uri'] = https(ADMIN_PORT) + '/ui/callback'

    def site(cfg):
        cfg['oauth_redirect_uris'].append(https(ADMIN_PORT) + '/ui/callback')
        cfg['admin_accounts']['link_base_url'] = https(IDMS_PORT)
        # MCX Admin's template for the phones' users: users made from it in the console call, message and video
        # call any user of the system (without a template a new user has no rights; the test users' rights name
        # each other only). MCX Admin imports it on its first start; the servers do not read it.
        cfg['templates'] = {'phone-user': PHONE_USER, 'dispatcher': DISPATCHER}
        clean_groups(cfg)

    edit(OUT / 'mcptt-server.json', mcptt)
    edit(OUT / 'mcvideo-server.json', mcvideo)
    edit(OUT / 'mcxadmin.json', admin)
    edit(OUT / 'site.json', site)

    # Every container reads these files under its own user; the database password files are the MySQL image's.
    for path in OUT.rglob('*'):
        path.chmod(0o777 if path.is_dir() else 0o644)
    (OUT / 'artifacts').chmod(0o777)
    for path in (OUT / 'artifacts').rglob('*'):
        path.chmod(0o777 if path.is_dir() else 0o666)
    (OUT / 'idms-data').chmod(0o777)
    for path in (OUT / 'idms-data').iterdir():
        path.chmod(0o666)
    (OUT / 'crl').chmod(0o777)
    for path in (OUT / 'crl').iterdir():
        path.chmod(0o666)

    owner = WORK.stat()
    for path in [OUT, *OUT.rglob('*')]:
        os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)

    administrator = json.loads((OUT / 'site.json').read_text())['users'][0]
    note = (
        f"MCX Admin console: {https(ADMIN_PORT)}/\n"
        f"Administrator: {administrator['username']}, password {administrator['password']}\n"
        f"The certificates are the system's own CA's (./config/tls/ca.crt) and expire after 30 days.\n"
    )
    (OUT / 'ADMIN.txt').write_text(note)
    os.chown(OUT / 'ADMIN.txt', owner.st_uid, owner.st_gid)
    os.chmod(OUT / 'ADMIN.txt', 0o600)
    print(
        '\nConfiguration written to ./config.\n' + note + 'Next: docker compose -f ' + os.environ.get('TUTORIAL_COMPOSE', 'docker-compose-basic-mcx.yaml') + ' up -d'
    )


if __name__ == '__main__':
    main()
