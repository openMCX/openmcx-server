"""Tutorial 3's addition to tutorial 1's configuration: the MCPTT server's "pcf" block (N5, TS 29.514).

The MCPTT server then acts as an AF: for each call leg of a UE in the 5G pool (12.1.1.0/24) it asks the OAI PCF for
the QoS of the leg's media; legs of the phones on the Wi-Fi are outside the pool and left alone.
"""
import json
from pathlib import Path

path = Path('/work/config/mcptt-server.json')
cfg = json.loads(path.read_text())
cfg['pcf'] = {
    'enabled': True,
    'pcf_uri': 'http://192.168.71.139:8080',  # oai-pcf on the core network (SBI, HTTP/2 cleartext)
    'http2': True,
    'dnn': 'mcptt',
    'snssai': {'sst': 1},
    'af_app_id': 'mcptt',
    'notif_bind': '0.0.0.0:8099',
    'notif_uri_base': 'http://192.168.71.141:8099/npcf-af',  # the MCPTT server on the core network
    'ue_subnets': ['12.1.1.0/24'],
    'audio_bw_kbps': 41,
    'required': False,
    'prio_map': {'normal': '', 'imminent': 'PRIO_12', 'emergency': 'PRIO_16'},
}
path.write_text(json.dumps(cfg, indent=2) + '\n')
print('N5: mcptt-server asks oai-pcf for the QoS of the 5G UEs (12.1.1.0/24)')
