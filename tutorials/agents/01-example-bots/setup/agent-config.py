#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Tutorial tooling: the agent's part of ./config for Agent Tutorial 1. It implements no 3GPP procedure.
"""Write the agent's configuration next to what the lab generator wrote in ./config.

  agent.json         mcx-agent on client-a's identity (alice): MCData, voice (MCPTT) and video (MCVideo), MCP over HTTP
  agent-token        the bearer token the bots and the daemon share
  client-b-ui.json   bob's configuration for the browser client page: live audio and received video for the browser

  python3 setup/agent-config.py ./config
"""

import json
import secrets
import sys
from pathlib import Path

config = Path(sys.argv[1])

# The daemon: client-a's engine configuration as it is, with the lab's argument (SIP in clear).
agent = {
    'engine': {'config': '/config/client-a.json', 'args': ['--disable-tls']},
    'socket': '/run/mcx/agent.sock',
    'data_dir': '/var/lib/mcx-agent',
    # Nobody on a list: the agent answers only users who wrote to it within allow_senders_hours.
    'recipients': [],
    'allow_senders_hours': 24,
    'rate_per_recipient_per_minute': 10,
    'rate_per_minute': 60,
    'max_text_bytes': 1000,
    'voice': {'enabled': True, 'max_speech_s': 60},
    'video': {'enabled': True, 'width': 320, 'height': 240, 'frame_rate': 15},
    'mcp_http': {'listen': '0.0.0.0:8765', 'token_file': '/config/agent-token'},
}
(config / 'agent.json').write_text(json.dumps(agent, indent=2) + '\n')
(config / 'agent-token').write_text(secrets.token_hex(32) + '\n')

# The client page: the engine sends the call's audio to the page's bridge and takes the microphone from it
# (media.live), and forwards each received H.264 picture for the browser to decode (mcvideo.live_receive).
ui = json.loads((config / 'client-b.json').read_text())
ui['media']['live'] = {'listen': '127.0.0.1', 'port': 7100, 'send_host': '127.0.0.1', 'send_port': 7101}
ui['mcvideo']['live_receive'] = {'send_host': '127.0.0.1', 'send_port': 7102}
(config / 'client-b-ui.json').write_text(json.dumps(ui, indent=2) + '\n')
print('wrote the agent configuration, its token and the client page configuration')
