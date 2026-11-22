#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Lab tooling, no 3GPP behaviour (prototype/resiprocate/PLAN.md phase 4): the server's relay delay of RTP packets in a
# capture taken in its network namespace (tests/integration/wire_check.py: integration/<scenario>-wire.pcap).
"""The delay from an RTP packet reaching the server to the server sending its payload on, per relayed packet.

  prototype/resiprocate/relay_delay.py PCAP [PCAP...] [--server ADDRESS]

Each RTP packet (version 2, dynamic payload type, over UDP) that leaves the server is matched to the earliest packet
with the same RTP payload that reached it at most 100 ms before and is not matched yet; payloads of fewer than 8
bytes (silence descriptors, comfort noise) and payloads that occur twice within 100 ms are left out, as they cannot
be matched unambiguously. The server's address is the one that both receives and sends RTP, unless given. Prints the
count, median, 90th and 99th percentiles and the maximum in milliseconds, as JSON.
"""

import argparse
import collections
import json
import pathlib
import socket
import statistics
import struct

WINDOW = 0.1
MINIMUM_PAYLOAD = 8


# ------------------------------------------------------------------------------
def rtp_packets(path):
    """The RTP packets of a classic Ethernet PCAP file: (time, source, destination, payload)."""
    raw = pathlib.Path(path).read_bytes()
    magic = raw[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nanoseconds = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    assert struct.unpack_from(endian + 'I', raw, 20)[0] == 1, 'Ethernet capture required'
    offset = 24
    out = []
    while offset + 16 <= len(raw):
        seconds, fraction, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        if len(packet) < 34 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17 or struct.unpack_from('!H', ip, 6)[0] & 0x3FFF:
            continue
        length = struct.unpack_from('!H', ip, ihl + 4)[0]
        udp = ip[ihl + 8 : ihl + length]
        if len(udp) < 12 or udp[0] >> 6 != 2 or not 96 <= udp[1] & 127 <= 127:
            continue
        start = 12 + (udp[0] & 15) * 4
        if udp[0] & 16:
            if len(udp) < start + 4:
                continue
            start += 4 + struct.unpack_from('!H', udp, start + 2)[0] * 4
        time = seconds + fraction / (1e9 if nanoseconds else 1e6)
        out.append((time, socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20]), bytes(udp[start:])))
    return out


# ------------------------------------------------------------------------------
def delays(packets, server=None):
    """The relay delays in seconds of one capture's packets."""
    if server is None:
        senders = {source for _, source, _, _ in packets}
        receivers = {destination for _, _, destination, _ in packets}
        both = senders & receivers
        assert len(both) == 1, f'cannot tell the server among {sorted(both)}: pass --server'
        server = both.pop()
    inbound = collections.defaultdict(collections.deque)
    result = []
    for time, source, destination, payload in sorted(packets):
        if len(payload) < MINIMUM_PAYLOAD:
            continue
        waiting = inbound[payload]
        while waiting and waiting[0][0] < time - WINDOW:
            waiting.popleft()
        if destination == server:
            # A payload seen twice within the window cannot be matched: both copies go.
            if waiting and not waiting[-1][1]:
                waiting[-1][1] = True
                continue
            waiting.append([time, False])
        elif source == server:
            if len(waiting) == 1 and not waiting[0][1]:
                result.append(time - waiting.popleft()[0])
    return result


# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('pcaps', nargs='+')
    parser.add_argument('--server')
    arguments = parser.parse_args()
    measured = []
    for path in arguments.pcaps:
        measured += delays(rtp_packets(path), arguments.server)
    measured.sort()
    if not measured:
        print(json.dumps({'packets': 0}))
        return 1
    at = lambda share: measured[min(len(measured) - 1, int(share * len(measured)))] * 1000
    print(json.dumps({'packets': len(measured), 'median_ms': round(statistics.median(measured) * 1000, 3),
                      'p90_ms': round(at(0.9), 3), 'p99_ms': round(at(0.99), 3),
                      'max_ms': round(measured[-1] * 1000, 3)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
