#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The MC client of the second emulated UE (oai-nr-ue2): tutorial 3's setup/ue-client.py for client-b instead of
client-d, written to config/ue2-client.json. client-b must be in IMS_AKA_ROLES (docker-compose-qos.yaml)."""
from pathlib import Path

script = Path('/tutorial3/ue-client.py').read_text()
for old, new in (("ROLE = 'client-d'", "ROLE = 'client-b'"), ("CONFIG / 'ue-client.json'", "CONFIG / 'ue2-client.json'")):
    if old not in script:
        raise SystemExit(f'tutorial 3 ue-client.py changed: {old!r} not found')
    script = script.replace(old, new)
exec(compile(script, '/tutorial3/ue-client.py (client-b)', 'exec'))
