#!/usr/bin/env python3
# Reads a classic PCAP file of an Ethernet capture and, without relying on the server's own
# code, checks the clear (unprotected) floor control and media of a lab call: every floor
# control message (RTCP APP with name "MCPT", TS 24.380 clause 8.2) with its fields in bounds
# and padded (TS 24.380 clause 8.2.3.1), the Audio SSRC of Granted Participant field (TS 24.380
# clause 8.2.3.16), the floor message subtypes the floor profile requires (TS 24.380
# table 8.2.2.1-1), and the AMR-WB frame types of the RTP streams (RFC 4867 section 4.3).
# When tshark is available it also lets Wireshark dissect the floor packets and fails on any
# diagnostic. Usage: inspect-pcap.py PCAP [OUTPUT] [--floor-profile contention|group|queue];
# prints the result as JSON (and writes it to OUTPUT).
#
# Specifications: TS 24.380 V19.2.0 (Rel-19); RFC 3550, RFC 4867.
"""Independent, bounded classic-PCAP decoder for this lab's clear MCPTT wire evidence."""

import argparse
import collections
import json
import os
import shutil
import subprocess
import pathlib
import socket
import struct


# ------------------------------------------------------------------------------
def inspect(path, required_types=(0, 1, 2, 3, 4, 5)):
    """Decode the capture at path and check its floor control messages and RTP streams; the
    floor message subtypes in required_types (TS 24.380 table 8.2.2.1-1, the low four bits)
    must each occur at least once. Returns the counts as a dict; fails with AssertionError."""
    raw = pathlib.Path(path).read_bytes()
    assert len(raw) >= 24, 'truncated PCAP'
    magic = raw[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    assert magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'), (
        'PCAP format required'
    )
    link = struct.unpack_from(endian + 'I', raw, 20)[0]
    assert link == 1, 'Ethernet capture required'
    offset = 24
    floor = collections.Counter()
    streams = collections.Counter()
    amr = collections.Counter()
    packets = 0
    floor_ports = set()
    audio_ssrc_fields = 0
    grant_ssrcs = collections.defaultdict(set)
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        assert captured <= 65536 and offset + captured <= len(raw), 'truncated or oversized record'
        packet = raw[offset : offset + captured]
        offset += captured
        packets += 1
        if len(packet) < 34 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
            continue
        if struct.unpack_from('!H', ip, 6)[0] & 0x3FFF:
            continue
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        sport, dport, length, _ = struct.unpack_from('!HHHH', ip, ihl)
        payload = ip[ihl + 8 : ihl + length]
        if len(payload) >= 12 and payload[0] >> 6 == 2 and payload[1] == 204 and payload[8:12] == b'MCPT':
            assert (struct.unpack_from('!H', payload, 2)[0] + 1) * 4 == len(payload), 'RTCP length mismatch'
            # Independently validate TLV bounds and the six-octet SSRC field,
            # including its two spare octets (TS 24.380 clause 8.2.3.16).
            field_offset = 12
            while field_offset < len(payload):
                assert field_offset + 2 <= len(payload), 'truncated floor field header'
                field_id = payload[field_offset]
                header = 2 if field_id < 192 else 3
                assert field_offset + header <= len(payload), 'truncated floor field length'
                size = (
                    payload[field_offset + 1] if header == 2 else struct.unpack_from('!H', payload, field_offset + 1)[0]
                )
                end = field_offset + header + size
                aligned = (end + 3) & ~3
                assert aligned <= len(payload), 'floor field exceeds packet'
                assert not any(payload[end:aligned]), 'nonzero floor field padding'
                if field_id == 14:
                    assert size == 6, 'Audio SSRC field length must be 6, including spare octets'
                    assert payload[end - 2 : end] == b'\0\0', 'nonzero Audio SSRC spare octets'
                    audio_ssrc_fields += 1
                    if payload[0] & 15 == 1:
                        grant_ssrcs[str(struct.unpack_from('!I', payload, 4)[0])].add(
                            struct.unpack_from('!I', payload, field_offset + header)[0]
                        )
                field_offset = aligned
            floor_ports.update((sport, dport))
            floor[str(payload[0] & 15)] += 1
        elif len(payload) >= 14 and payload[0] >> 6 == 2 and payload[1] & 127 >= 96:
            cc = payload[0] & 15
            start = 12 + cc * 4
            if payload[0] & 16:
                if len(payload) < start + 4:
                    continue
                start += 4 + struct.unpack_from('!H', payload, start + 2)[0] * 4
            if len(payload) < start + 2:
                continue
            frame = payload[start:]
            ft = ((frame[0] & 7) << 1) | (frame[1] >> 7)
            assert ft <= 9 or ft in (14, 15), 'invalid RFC4867 AMR-WB frame type'
            amr[str(ft)] += 1
            ssrc = struct.unpack_from('!I', payload, 8)[0]
            streams[f'{src}:{sport}->{dst}:{dport};pt={payload[1] & 127};ssrc={ssrc}'] += 1
    assert offset == len(raw), 'trailing incomplete record'
    assert all(floor[str(subtype)] for subtype in required_types), f'missing floor message types: {floor}'
    assert len(streams) >= 4, 'expected two send and two relay RTP streams'
    result = {
        'passed': True,
        'packets': packets,
        'floor_subtypes': dict(floor),
        'rtp_streams': dict(streams),
        'amr_wb_frame_types': dict(amr),
        'validated_audio_ssrc_fields': audio_ssrc_fields,
    }
    assert audio_ssrc_fields >= 4, 'missing Granted/Taken Audio SSRC fields'
    result['grant_audio_ssrcs'] = {key: sorted(values) for key, values in grant_ssrcs.items()}
    if 8 in required_types:
        assert any(len(values) >= 2 for values in grant_ssrcs.values()), (
            'repeated floor acquisitions must allocate fresh audio SSRCs'
        )
    tshark = os.environ.get('MCX_TSHARK') or shutil.which('tshark')
    if tshark:
        command = [tshark, '-r', str(path)]
        for port in sorted(floor_ports):
            command += ['-d', f'udp.port=={port},rtcp']
        command += ['-Y', 'rtcp', '-T', 'fields', '-e', 'frame.number', '-e', '_ws.expert.message']
        decoded = subprocess.run(command, check=True, capture_output=True, text=True).stdout.splitlines()
        assert len(decoded) == sum(floor.values()), 'dissector did not decode all floor packets'
        diagnostics = [row for row in decoded if row.partition('\t')[2].strip()]
        assert not diagnostics, 'Wireshark RTCP diagnostics: ' + repr(diagnostics)
        result['wireshark'] = {
            'checked': True,
            'version': subprocess.run(
                [tshark, '--version'], check=True, capture_output=True, text=True
            ).stdout.splitlines()[0],
            'rtcp_frames': len(decoded),
            'expert_diagnostics': 0,
        }
    else:
        result['wireshark'] = {
            'checked': False,
            'reason': 'set MCX_TSHARK or install tshark to enable external dissection',
        }
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap')
    parser.add_argument('output', nargs='?')
    parser.add_argument('--floor-profile', choices=('contention', 'group', 'queue'), default='contention')
    args = parser.parse_args()
    profiles = {'contention': (0, 1, 2, 3, 4, 5), 'group': (0, 1, 2, 4, 5, 10), 'queue': (0, 1, 2, 4, 5, 8, 9, 10)}
    result = inspect(args.pcap, profiles[args.floor_profile])
    result['floor_profile'] = args.floor_profile
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        pathlib.Path(args.output).write_text(text)
    print(text, end='')
