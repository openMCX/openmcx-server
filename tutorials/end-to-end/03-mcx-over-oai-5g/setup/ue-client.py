#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Tutorial 3's addition to tutorial 1's configuration (tutorials 4 and 5 use it too): the MC client in the UE, which
registers with IMS AKA.

The setup provisions the test user client-d for IMS AKA (IMS_AKA_ROLES, TS 33.180 clause 6.2.1: 3GPP access): a
software ISIM with its own K and OPc, the private user identity client-d@mcx.test, its ims_subscription row in the
SIP database and the P-CSCF pcscf (config/pcscf.cfg). This script turns the lab configuration of client-d into the
one of the Linux client that runs in the UE's network namespace (ue-client: in the nr-UE of docker-compose-5g-mcx.yaml,
srsUE in tutorial 4, the LTE UE in tutorial 5), next to the dispatcher:

- SIP: through the P-CSCF at 192.168.72.140 on the N6 network, reached over the UE's PDU session (TS 24.229 clause
  5.1.1.2.2; the P-CSCF's address is preconfigured, not discovered, TS 24.229 clause 9.2.1); the client's address in
  its Via, Contact and security associations is the UE's (UE_IP, filled in when the client starts);
- HTTP: the IdMS, HTTP proxy and KMS at HOST_IP, the addresses MCX Admin gives the phones and the dispatcher;
- media: the UE's address, on ports of its own (the dispatcher's are 4400, 5400, 4600, 5600 and 6600).

It is preconfigured (TS 37.579-1 table 5.3.2.3.1-1 step 1a: the initial UE configuration data of table 5.5.8.1-1),
username and password included (NOTE 1 of that table: stored on the UE).
"""
import json
import os
from pathlib import Path

CONFIG = Path('/work/config')
ROLE = 'client-d'

cfg = json.loads((CONFIG / f'{ROLE}.json').read_text())
if cfg['sip'].get('auth') != 'aka':
    raise SystemExit(f'{ROLE} is not provisioned for IMS AKA: run the setup with IMS_AKA_ROLES={ROLE}')
admin = json.loads((CONFIG / 'mcxadmin.json').read_text())
groups = [group['id'] for group in json.loads((CONFIG / 'site.json').read_text())['groups']]

cfg['sip'].update(advertise='UE_IP', pcscf={'address': 'pcscf', 'port': 5060})
cfg['media'].update(bind='UE_IP', advertise='UE_IP', rtp_port=4500, floor_port=5500, server_source='port')
cfg['mcvideo']['media'] = {'audio_port': 4700, 'control_port': 5700, 'video_port': 6700}
# The MCPTT and MCVideo servers' media come from HOST_IP (host-network.sh).
cfg['server_address'] = os.environ['HOST_IP']
# Tutorial 1's setup keeps one group, operations.
cfg['mcptt']['allowed_groups'] = [group for group in cfg['mcptt'].get('allowed_groups', []) if group in groups]
# TS 37.579-1 tables 5.3.2.6.1-1 and 5.3.2.7.1-1: the documents are read on the subscriptions' NOTIFYs.
cfg['mcptt']['documents_on_notify'] = True
# TS 37.579-1 table 5.3.2.3.1-1 steps 11-14: KMS initialisation and key provisioning at sign-in, the group calls
# staying unprotected (no protect_media or protect_floor; TS 33.180 clause 5.3.3).
site = json.loads((CONFIG / 'site.json').read_text())
cfg.setdefault('security', {}).update(
    kms_uri=site.get('endpoints', {}).get('kms', 'https://kms:8443'),
    key_parameter_profile=dict(message_type=10, algorithm=1, key_parameters_iei=0x79, encrypted_payload_iei=0x78))
# The services' names, as the configuration has them, at HOST_IP (as in MCX Admin's activation packages).
cfg['address_map'] = {name: address for name, address in admin['activation']['address_map'].items()
                      if not name.startswith('sip-core:')}
out = CONFIG / 'ue-client.json'
out.write_text(json.dumps(cfg, indent=2) + '\n')
out.chmod(0o644)
owner = CONFIG.stat()
os.chown(out, owner.st_uid, owner.st_gid)
print(f'IMS AKA: {ROLE} ({cfg["sip"]["identity"]}) is the MC client in the UE, through the P-CSCF')
