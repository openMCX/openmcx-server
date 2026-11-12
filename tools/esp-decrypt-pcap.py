#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Write a copy of a capture in which the ESP packets are replaced by the packets they carry, in the clear.

The keys come from a file in Wireshark's ESP SA table format (one quoted CSV line per security association:
protocol, source, destination, SPI, encryption algorithm, encryption key, authentication algorithm, authentication
key), as the tutorials write them. The copy opens in any Wireshark without its ESP preferences.

Each replaced packet carries a packet comment "ESP SPI 0x..., decrypted", so the Wireshark filter
'frame.comment contains "ESP"' shows what travelled inside IPsec.

Supported: IPv4, transport mode, "AES-GCM with 16 octet ICV [RFC4106]" (key = 16 key octets + 4 salt octets, RFC 4106
section 8.1), without extended sequence numbers. An ESP packet whose SA is not in the file, or that fails to decrypt,
is kept as it was and reported. Every other packet is copied unchanged, with its timestamp and frame number.

Usage: esp-decrypt-pcap.py capture.pcap[ng] keys.esp_sa output.pcapng

The input is read with editcap (Wireshark) into a classic pcap first; the output is pcapng (for the comments).
"""

import csv
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GCM = 'AES-GCM with 16 octet ICV [RFC4106]'


# ------------------------------------------------------------------------------
def load_sas(path):
    """The SAs by (source, destination, SPI): (encryption algorithm, key octets)."""
    sas = {}
    with open(path, newline='') as handle:
        for row in csv.reader(handle):
            if len(row) < 6 or row[0] != 'IPv4':
                continue
            key = bytes.fromhex(row[5][2:]) if row[5].startswith('0x') else b''
            sas[(row[1], row[2], int(row[3], 16))] = (row[4], key)
    return sas


# ------------------------------------------------------------------------------
def checksum(header):
    """The IPv4 header checksum (RFC 791) of a header whose checksum field is zero."""
    total = sum(struct.unpack(f'!{len(header) // 2}H', header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# ------------------------------------------------------------------------------
def decrypt(ip, sas):
    """(The IPv4 packet with its ESP payload decrypted, the SPI), or (None, the reason)."""
    ihl = (ip[0] & 0x0F) * 4
    esp = ip[ihl : struct.unpack('!H', ip[2:4])[0]]
    src = '.'.join(str(octet) for octet in ip[12:16])
    dst = '.'.join(str(octet) for octet in ip[16:20])
    spi = struct.unpack('!I', esp[0:4])[0]
    sa = sas.get((src, dst, spi))
    if sa is None:
        return None, f'no SA for {src} -> {dst} SPI 0x{spi:08x}'
    algorithm, key = sa
    if algorithm != GCM:
        return None, f'unsupported algorithm {algorithm!r} for SPI 0x{spi:08x}'
    # RFC 4106: nonce = salt (4) || IV (8); AAD = SPI || sequence number (no ESN); ICV of 16 octets.
    try:
        plain = AESGCM(key[:-4]).decrypt(key[-4:] + esp[8:16], esp[16:], esp[0:8])
    except InvalidTag:
        return None, f'ICV check failed for SPI 0x{spi:08x}'
    # RFC 4303 section 2: payload || padding || pad length || next header.
    pad_length, next_header = plain[-2], plain[-1]
    payload = plain[: len(plain) - 2 - pad_length]
    header = bytearray(ip[:ihl])
    header[2:4] = struct.pack('!H', ihl + len(payload))
    header[9] = next_header
    header[10:12] = b'\0\0'
    header[10:12] = struct.pack('!H', checksum(bytes(header)))
    return bytes(header) + payload, spi


# ------------------------------------------------------------------------------
def option(code, value):
    """A pcapng option, padded to 32 bits."""
    return struct.pack('<HH', code, len(value)) + value + b'\0' * (-len(value) % 4)


# ------------------------------------------------------------------------------
def block(kind, body):
    """A pcapng block with its two total lengths."""
    length = 12 + len(body)
    return struct.pack('<II', kind, length) + body + struct.pack('<I', length)


# ------------------------------------------------------------------------------
def main():
    """Decrypt the capture; exit status 1 when an ESP packet was left encrypted."""
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    capture, keys, output = (Path(arg) for arg in sys.argv[1:])
    sas = load_sas(keys)
    with tempfile.TemporaryDirectory() as tmp:
        classic = Path(tmp) / 'in.pcap'
        subprocess.run(['editcap', '-F', 'pcap', str(capture), str(classic)], check=True)
        data = classic.read_bytes()
    magic = data[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nanoseconds = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    snaplen, linktype = struct.unpack(endian + 'II', data[16:24])
    if linktype != 1:
        sys.exit(f'link type {linktype} not supported (Ethernet only)')
    # Section header (pcapng byte-order magic, version 1.0, length unknown) and one Ethernet interface whose
    # timestamp resolution (if_tsresol, option 9) matches the input.
    out = [block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1) + option(0, b''))]
    resolution = option(9, bytes([9 if nanoseconds else 6])) + option(0, b'')
    out.append(block(0x00000001, struct.pack('<HHI', linktype, 0, snaplen) + resolution))
    units = 10**9 if nanoseconds else 10**6
    offset, decrypted, kept = 24, 0, []
    while offset < len(data):
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + 'IIII', data[offset : offset + 16])
        frame = data[offset + 16 : offset + 16 + incl]
        offset += 16 + incl
        options = b''
        if len(frame) > 34 and frame[12:14] == b'\x08\x00' and frame[14 + 9] == 50 and incl == orig:
            ip, result = decrypt(frame[14:], sas)
            if ip is None:
                kept.append(result)
            else:
                frame = frame[:14] + ip
                incl = orig = len(frame)
                decrypted += 1
                options = option(1, f'ESP SPI 0x{result:08x}, decrypted'.encode()) + option(0, b'')
        stamp = ts_sec * units + ts_frac
        body = struct.pack('<IIIII', 0, stamp >> 32, stamp & 0xFFFFFFFF, incl, orig)
        out.append(block(0x00000006, body + frame + b'\0' * (-incl % 4) + options))
    output.write_bytes(b''.join(out))
    print(f'{decrypted} ESP packets decrypted, {len(kept)} kept encrypted')
    for reason in sorted(set(kept)):
        print(f'  kept: {reason} ({kept.count(reason)})')
    return 1 if kept else 0


if __name__ == '__main__':
    sys.exit(main())
