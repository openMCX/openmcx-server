"""Tutorial 5's addition to tutorial 1's configuration: the MCPTT server's "rx" block (Rx, TS 29.214, MCPTT-5) and the
EPC's Diameter certificates.

The MCPTT server then acts as an AF towards the PCRF: for each call leg of a UE in the LTE pool (10.45.0.0/16) it opens
an Rx session for the QoS of the leg's media; legs of the phones on the Wi-Fi are outside the pool and left alone. The
PCRF is one more peer of the server's freeDiameter core, which also serves MCPTT-2 (the user database): over TCP
without TLS, as the PCRF is configured; the user database keeps its own peer settings (SCTP with TLS).
"""
import json
import re
import subprocess
from pathlib import Path

CONFIG = Path('/work/config')
PCRF = 'pcrf.epc.mcx.test'

path = CONFIG / 'mcptt-server.json'
cfg = json.loads(path.read_text())
cfg['rx'] = {
    'enabled': True,
    'destination_realm': 'epc.mcx.test',
    'destination_host': PCRF,
    'ue_subnets': ['10.45.0.0/16'],
    'audio_bw_kbps': 41,
    'required': False,
}
path.write_text(json.dumps(cfg, indent=2) + '\n')

# The server's freeDiameter core: TCP allowed (the PCRF peer), and the PCRF as a peer on the EPC network.
conf = CONFIG / 'diameter-server.conf'
text = re.sub(r'^No_TCP;\n', '', conf.read_text(), flags=re.M)
if PCRF not in text:
    text += (
        '# Rx to the PCRF of the EPC (TS 29.214), over TCP without TLS.\n'
        f'ConnectPeer = "{PCRF}" {{ ConnectTo = "192.168.73.136"; Port = 3868; TcTimer = 5; No_SCTP; No_TLS; '
        'Realm = "epc.mcx.test"; };\n'
    )
conf.write_text(text)

# freeDiameter needs a certificate even when its peers do not use TLS: a CA and one certificate per EPC function.
tls = CONFIG / 'epc-tls'
tls.mkdir(exist_ok=True)


def openssl(*args):
    subprocess.run(['openssl', *args], check=True, capture_output=True)


if not (tls / 'ca.crt').exists():
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=openMCX EPC CA',
            '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt'))
    for name in ('mme', 'hss', 'smf', 'pcrf'):
        key, csr, crt = (str(tls / f'{name}.{suffix}') for suffix in ('key', 'csr', 'crt'))
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={name}.epc.mcx.test', '-keyout', key, '-out', csr)
        openssl('x509', '-req', '-in', csr, '-CA', str(tls / 'ca.crt'), '-CAkey', str(tls / 'ca.key'),
                '-CAcreateserial', '-days', '30', '-out', crt)
        (tls / f'{name}.csr').unlink()
    for item in tls.iterdir():
        item.chmod(0o644)  # read by the EPC containers' user
print('Rx: mcptt-server asks the PCRF for the QoS of the LTE UEs (10.45.0.0/16)')
