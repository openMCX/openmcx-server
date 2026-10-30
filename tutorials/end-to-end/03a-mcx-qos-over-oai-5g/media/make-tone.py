#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Write a 16 kHz mono PCM16 WAV (what mcx-client's ptt reads): 30 s of a 440 Hz tone with a slow amplitude swing."""
import math
import struct
import sys
import wave

RATE, SECONDS = 16000, 30
with wave.open(sys.argv[1], 'wb') as out:
    out.setnchannels(1)
    out.setsampwidth(2)
    out.setframerate(RATE)
    out.writeframes(b''.join(
        struct.pack('<h', int(8000 * (0.6 + 0.4 * math.sin(2 * math.pi * 0.5 * n / RATE)) * math.sin(2 * math.pi * 440 * n / RATE)))
        for n in range(RATE * SECONDS)))
