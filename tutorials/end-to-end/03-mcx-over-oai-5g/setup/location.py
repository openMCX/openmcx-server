#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Tutorial 3's addition to tutorial 1's configuration: the location reporting configuration of the MCPTT, MCVideo
and MCData servers.

Upon successful service authorisation each server sends the client a SIP MESSAGE with a location reporting
configuration (TS 24.379 clause 13.2.2, TS 24.281 clause 18.2.2, TS 24.282 clause 17.2.2), as TS 37.579-1 table
5.3.2.2.1-1 steps 6-7 expect at start-up. The configuration is the one of TS 37.579-1 tables 5.5.3.4.2-1 (MCPTT),
5.5.3.4.2-2 (MCVideo) and 5.5.3.4.2-3 (MCData): ConfigScope "Full", the serving and neighbouring ECGIs, the MBMS SA,
the MBSFN area and the geographical coordinate for non-emergency (minimumIntervalLength 10 s) and emergency
(minimumIntervalLength 5 s) reports, and no triggering criteria, so the client sends no report on its own.
"""
import json
from pathlib import Path

REQUESTED = {'serving_ecgi': True, 'neighbouring_ecgi': True, 'mbms_sa': True, 'mbsfn': True, 'coordinate': True}
CONFIGURATION = {
    'scope': 'full',
    'non_emergency': dict(REQUESTED, minimum_interval=10),
    'emergency': dict(REQUESTED, minimum_interval=5),
    'triggers': [],
    'emergency_triggers': [],
}

for name, service in (('mcptt-server.json', 'mcptt'), ('mcvideo-server.json', 'mcvideo'),
                      ('mcdata-server.json', 'mcdata')):
    path = Path('/work/config') / name
    cfg = json.loads(path.read_text())
    cfg.setdefault(service, {}).setdefault('location', {})['configuration'] = CONFIGURATION
    path.write_text(json.dumps(cfg, indent=2) + '\n')
print('Location: the MCPTT, MCVideo and MCData servers configure location reporting at service authorisation')
