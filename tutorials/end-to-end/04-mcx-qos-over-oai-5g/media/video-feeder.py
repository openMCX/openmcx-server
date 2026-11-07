#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Write noise pictures (raw I420) into an MC client's live FIFO (mcvideo.live) at its frame rate, so that its H.264
encoder runs at the configured bitrate. The noise is of low amplitude (AMPLITUDE, default 16 levels around grey): a
still or black picture would compress to almost nothing, full-range noise saturates the rate control at its highest
quantiser (measured: about 17 Mbit/s at 1280x720 for a 4 Mbit/s target); low-amplitude noise lets it hold the target.
Run in the client's container: python3 video-feeder.py <fifo> <width> <height> <frame rate> [seconds]."""
import os
import sys
import time

fifo, width, height, rate = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
seconds = float(sys.argv[5]) if len(sys.argv) > 5 else 3600
amplitude = int(os.environ.get('AMPLITUDE', '16'))
luma = width * height
chroma = bytes([128]) * (luma // 2)  # flat chroma: the noise in luma only (as measured offline)
# Random bytes to levels 128 - amplitude/2 .. 128 + amplitude/2 - 1, in C (bytes.translate)
table = bytes(128 - amplitude // 2 + (b % amplitude) for b in range(256))
fd = os.open(fifo, os.O_WRONLY)
end = time.monotonic() + seconds
next_frame = time.monotonic()
while time.monotonic() < end:
    os.write(fd, os.urandom(luma).translate(table) + chroma)
    next_frame += 1 / rate
    time.sleep(max(0, next_frame - time.monotonic()))
