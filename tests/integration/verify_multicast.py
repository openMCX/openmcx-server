#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify the MBMS delivery of group call speech (TS 24.380 clause 10) from a capture at the MCPTT server.

Reads the capture of multicast_scenario.py and its results (the containers' addresses, the counters of each talk
burst and the final status). The server sends the speech RTP (RFC 3550 section 5.1, payload type 96) over the MBMS
subchannel (an IPv4 host group on the emulated bearer) with time-to-live 1 (RFC 1112 section 6.1), from its own
address, as many packets as it counted; by unicast to each client exactly as many packets as arrived at that client
by unicast (kept, or dropped as a copy): none to a client while it listens to the subchannel, all of them to
client-d, outside the bearer's service area. The Map Group To Bearer messages go to the general purpose subchannel
and the Unmap Group To Bearer messages to the subchannel ("MCMC", TS 24.380 clause 8.4), as many as the server
counted.

Usage: verify_multicast.py capture.pcap results.json --output result.json

Specifications: TS 24.380 V19.2.0 (Rel-19), RFC 1112, RFC 3550.
"""

import argparse
import collections
import json
from pathlib import Path
import struct
import sys

SPEECH_PAYLOAD_TYPE = 96
ROLES = ['client-a', 'client-b', 'client-c', 'client-d']


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
def subchannel_control(payload):
    """TS 24.380 clause 8.4: the subtype of an MBMS subchannel control message ("MCMC", RTCP APP), or None."""
    if len(payload) < 12 or payload[0] >> 6 != 2 or payload[1] != 204:
        return None
    if payload[8:12] == b'MCMC':
        return payload[0] & 0x1F
    return 3 if payload[4:8] == b'MCMC' else None


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
    bursts = results['bursts'].values()
    sent = sum(burst['mcptt-server']['multicast'] for burst in bursts)
    # A client receives by unicast what it kept that way and the copies it dropped that came that way.
    by_unicast = {
        role: sum(
            burst[role]['received'] - burst[role]['multicast'] + burst[role]['unicast_copies'] for burst in bursts
        )
        for role in ROLES
    }

    final = results['status']['mcptt-server']
    general_purpose = tuple(results['general_purpose'].rsplit(':', 1))
    maps = unmaps = 0
    multicast, unicast, ttls, sources = 0, collections.Counter(), set(), set()
    for source, destination, destination_port, ttl, payload in datagrams(args.capture):
        subtype = subchannel_control(payload)
        if subtype == 0 and (destination, str(destination_port)) == general_purpose:
            maps += 1
        elif subtype == 1 and destination == group and destination_port == int(port):
            unmaps += 1
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
    for role in ROLES:
        found = unicast[addresses[role]]
        check(found == by_unicast[role], f'{found} unicast speech packets to {role}, it received {by_unicast[role]}')
    received_d = sum(burst['client-d']['received'] for burst in bursts)
    check(by_unicast['client-d'] == received_d, f'{by_unicast["client-d"]} of {received_d} packets to client-d by unicast')
    check(maps == final.get('mbms_map_sent') and maps > 0, f'{maps} Map Group To Bearer to the general purpose subchannel')
    check(unmaps == final.get('mbms_unmap_sent') and unmaps > 0, f'{unmaps} Unmap Group To Bearer to the subchannel')
    result = dict(capture=str(args.capture), passed=not errors, checks=checks, errors=errors)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
