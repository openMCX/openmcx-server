#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Tutorial 3a: MCVideo over 5G with N5. The MCVideo server asks the PCF for the QoS of its 5G legs, as tutorial 3's
setup/pcf.py makes the MCPTT server do. The PCF patch turns the VIDEO media component into 5QI 67 with GFBR = MFBR =
video_bw_kbps. The UE clients send video at that rate: the test-pattern encoder's options come from mcvideo.live, so
the clients get a live FIFO (media/video-feeder.py writes noise pictures into it during qos.sh vcall), and the
listener receives without asking (auto_receive).

Idempotent: run by the setup, or again on an existing configuration (qos.sh video-config). VIDEO_KBPS (default
2048) sets the video rate (the GFBR/MFBR asked for is 10 % above), VIDEO_ENCODER_KBPS another encoder target, VIDEO_SIZE (default
640x480) the picture, VIDEO_KEY_INTERVAL (default 30) the IDR period."""
import json
import os
from pathlib import Path

CONFIG = Path('/work/config')
kbps = int(os.environ.get('VIDEO_KBPS', '2048'))
# The encoder holds its target (measured: 512 kbit/s asked, 512-514 on the wire, 1050-octet packets); the GFBR/MFBR
# asked for is 10 % above it, for the RTP/UDP/IP headers (about 4 %) and the rate control's swings.
encoder_kbps = int(os.environ.get('VIDEO_ENCODER_KBPS') or kbps)
gfbr_kbps = (kbps * 11 + 9) // 10
width, height = (int(v) for v in os.environ.get('VIDEO_SIZE', '640x480').split('x'))


def update(name, change):
    path = CONFIG / name
    cfg = json.loads(path.read_text())
    change(cfg)
    path.write_text(json.dumps(cfg, indent=2) + '\n')


def server(cfg):
    pcf = dict(json.loads((CONFIG / 'mcptt-server.json').read_text())['pcf'])  # tutorial 3's block
    pcf.update(af_app_id='mcvideo',
               # the MCVideo server on the core network (docker-compose-qos.yaml)
               notif_uri_base='http://192.168.71.142:8099/npcf-af',
               video_bw_kbps=gfbr_kbps)
    cfg['pcf'] = pcf


def client(cfg):
    cfg['mcvideo']['auto_receive'] = True
    cfg['mcvideo']['live'] = {'fifo': '/run/mcx/video.fifo', 'width': width, 'height': height, 'frame_rate': 15,
                              'bitrate': encoder_kbps * 1000, 'key_frame_interval': int(os.environ.get('VIDEO_KEY_INTERVAL', '30'))}


update('mcvideo-server.json', server)
for name in ('ue-client.json', 'ue2-client.json'):
    update(name, client)
print(f'MCVideo: N5 for the MCVideo server (5QI 67, GFBR {gfbr_kbps} kbit/s), the UE clients send {width}x{height}, encoder target {encoder_kbps} kbit/s')
