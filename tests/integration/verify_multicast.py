#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify the IP multicast delivery of group call speech (an OpenMCX profile) from a capture at the MCPTT server.

Reads the capture of multicast_scenario.py and its results (the containers' addresses and the server's counters).
The server sends the speech RTP (RFC 3550 section 5.1, payload type 96) to the IPv4 host group with time-to-live 1
(RFC 1112 section 6.1), from its own address; it sends no speech by unicast to the opted-in clients, and one copy by
unicast to client-d for each packet sent to the host group.

Usage: verify_multicast.py capture.pcap results.json --output result.json

Specifications: RFC 1112, RFC 3550; no 3GPP procedure.
"""

import argparse
import collections
import json
from pathlib import Path
import struct
import sys

SPEECH_PAYLOAD_TYPE = 96
OPTED_IN = ['client-a', 'client-b', 'client-c']


# ------------------------------------------------------------------------------
def datagrams(path):
    """Yield (source, destination, destination port, ttl, payload) of each UDP/IPv4 datagram of a classic pcap."""
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        frame = raw[offset : offset + captured]
        offset += captured
        if len(frame) < 42 or frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        header = (ip[0] & 0x0F) * 4
        if ip[9] != 17:
            continue
        udp = ip[header:]
        source, destination = '.'.join(map(str, ip[12:16])), '.'.join(map(str, ip[16:20]))
        yield source, destination, int.from_bytes(udp[2:4], 'big'), ip[8], udp[8:]


# ------------------------------------------------------------------------------
def is_speech(payload):
    """RFC 3550 section 5.1: an RTP packet (version 2) of the speech payload type; floor control is RTCP."""
    return len(payload) >= 12 and payload[0] >> 6 == 2 and payload[1] & 0x7F == SPEECH_PAYLOAD_TYPE


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('results', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    results = json.loads(args.results.read_text())
    addresses = results['addresses']
    group, port = results['host_group'].rsplit(':', 1)
    server = addresses['mcptt-server']
    sent = sum(burst['mcptt-server']['multicast'] for burst in results['bursts'].values())

    multicast, unicast, ttls, sources = 0, collections.Counter(), set(), set()
    for source, destination, destination_port, ttl, payload in datagrams(args.capture):
        if not is_speech(payload):
            continue
        if destination == group and destination_port == int(port):
            multicast += 1
            ttls.add(ttl)
            sources.add(source)
        elif source == server:
            unicast[destination] += 1

    checks, errors = [], []

    # ------------------------------------------------------------------------------
    def check(condition, label):
        """Record a passed check or an error."""
        (checks if condition else errors).append(label)

    check(multicast == sent and multicast > 0, f'{multicast} speech packets to {group}:{port}, server counted {sent}')
    check(ttls == {1}, f'host group packets sent with time-to-live {sorted(ttls)}')
    check(sources == {server}, f'host group packets sent from {sorted(sources)}')
    for role in OPTED_IN:
        check(unicast[addresses[role]] == 0, f'{unicast[addresses[role]]} unicast speech packets to {role}')
    check(unicast[addresses['client-d']] == multicast, f'{unicast[addresses["client-d"]]} unicast packets to client-d')
    result = dict(capture=str(args.capture), passed=not errors, checks=checks, errors=errors)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
