#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Tutorial 3a: a best-effort PDU session on the MC UEs, DNN "internet", 5QI 9, pool 12.1.2.0/24,
for the subscribers of UE 1 and UE 2 (IMSI ...1100 and ...1101), next to their MCX PDU session (DNN mcptt, 5QI 69).
The load UEs 3 and 4 (...1102, ...1103) get only that DNN: their load is best effort (5QI 9), not on the MCX DNN's
default flow (5QI 69, MC signalling), which a QoS scheduler rightly puts first.

Writes copies of tutorial 3's files to generated/ (docker-compose-qos.yaml mounts them; qos.sh runs this script
once), leaving tutorial 3's untouched:
  oai_db.sql            the two subscribers' SessionManagementSubscriptionData with an "internet" DNN configuration
  mcx_core_config.yaml  the DNN in the SMF's and UPF's DNN lists and in the DNNs (pool 12.1.2.0/24)
  nrue.uicc.internet.yaml  a second PDU session (DNN internet) for the nr-UE: its TUN is oaitun_ue1p2
  nrue.uicc.load.yaml   the load UEs' only PDU session, DNN internet (oaitun_ue1)
The PCF needs no change: its default policy decision (policies/policy_decisions) is the 5QI 9 PCC rule.

  python3 setup/internet.py [tutorial 3 directory]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
TUT = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / '03-mcx-over-oai-5g'
OUT = HERE / 'generated'
OUT.mkdir(exist_ok=True)
MC_UES = ('208990100001100', '208990100001101')
LOAD_UES = ('208990100001102', '208990100001103')
INTERNET = (r'\"internet\":{\"pduSessionTypes\":{\"defaultSessionType\": \"IPV4\"},\"sscModes\": {\"defaultSscMode\": '
            r'\"SSC_MODE_1\"},\"5gQosProfile\": {\"5qi\": 9,\"arp\":{\"priorityLevel\": 15,\"preemptCap\": '
            r'\"NOT_PREEMPT\",\"preemptVuln\":\"PREEMPTABLE\"},\"priorityLevel\":90},\"sessionAmbr\":{\"uplink\":'
            r'\"200Mbps\", \"downlink\":\"200Mbps\"}}')


def replace_once(text, old, new, what):
    if text.count(old) != 1:
        raise SystemExit(f'{what}: expected one {old!r} in tutorial 3, found {text.count(old)}')
    return text.replace(old, new)


# Subscription data: the SessionManagementSubscriptionData rows of the two MC UEs end with the mcptt DNN's
# configuration, `...\"downlink\":\"100Mbps\"}}}')`: insert the internet DNN before the outer closing brace.
db = (TUT / 'oai/oai_db.sql').read_text()
lines = db.split('\n')
done = 0
for i, line in enumerate(lines):
    if line.startswith('(') and any(f"'{ue}', '20899'" in line for ue in MC_UES + LOAD_UES) and 'dnnConfigurations' not in line:
        if r'\"mcptt\":' in line and line.rstrip(',;').endswith("}}}')"):
            end = line.rstrip(',;')
            tail = line[len(end):]
            lines[i] = end[:-len("}')")] + ',' + INTERNET + "}')" + tail
            done += 1
if done != len(MC_UES + LOAD_UES):
    raise SystemExit(f'oai_db.sql: changed {done} SessionManagementSubscriptionData rows, expected {len(MC_UES + LOAD_UES)}')
(OUT / 'oai_db.sql').write_text('\n'.join(lines))

# Core configuration: the SMF's and UPF's DNN lists and the DNNs
cfg = (TUT / 'oai/mcx_core_config.yaml').read_text()
cfg = replace_once(cfg, '        dnnSmfInfoList:\n          - dnn: "mcptt"\n',
                   '        dnnSmfInfoList:\n          - dnn: "mcptt"\n          - dnn: "internet"\n', 'SMF')
cfg = replace_once(cfg, '        dnnUpfInfoList:\n          - dnn: "mcptt"\n',
                   '        dnnUpfInfoList:\n          - dnn: "mcptt"\n          - dnn: "internet"\n', 'UPF')
cfg = replace_once(cfg, '  - dnn: "mcptt"\n    pdu_session_type: "IPV4"\n    ipv4_subnet: "12.1.1.0/24"\n',
                   '  - dnn: "mcptt"\n    pdu_session_type: "IPV4"\n    ipv4_subnet: "12.1.1.0/24"\n'
                   '  - dnn: "internet"   # tutorial 3a: best effort on the MC UEs (setup/internet.py)\n'
                   '    pdu_session_type: "IPV4"\n    ipv4_subnet: "12.1.2.0/24"\n', 'DNNs')
(OUT / 'mcx_core_config.yaml').write_text(cfg)

# The nr-UE: a second PDU session
ue = (TUT / 'oai/nrue.uicc.mcptt.yaml').read_text()
ue = replace_once(ue, '    - dnn: mcptt\n      nssai_sst: 1\n',
                  '    - dnn: mcptt\n      nssai_sst: 1\n    - dnn: internet   # tutorial 3a: oaitun_ue1p2 (setup/internet.py)\n'
                  '      nssai_sst: 1\n', 'nr-UE')
(OUT / 'nrue.uicc.internet.yaml').write_text(ue)
load = (TUT / 'oai/nrue.uicc.mcptt.yaml').read_text()
load = replace_once(load, '    - dnn: mcptt\n', '    - dnn: internet   # tutorial 3a: the load UEs, best effort (setup/internet.py)\n', 'load UE')
(OUT / 'nrue.uicc.load.yaml').write_text(load)
print(f'internet DNN (5QI 9, 12.1.2.0/24) for {", ".join(MC_UES)} and, alone, {", ".join(LOAD_UES)}: {OUT}')
