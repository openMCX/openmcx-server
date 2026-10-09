#!/usr/bin/env python3
"""Independently inspect protected-call PCAP wire structure without session keys.

Keying: each client's CSK in an accepted SIP PUBLISH (TS 33.180 clause 9.2.1, MIKEY-SAKKE purpose tag 2) and the GMK in
an accepted xcap-diff NOTIFY of the group's GKTP (TS 33.180 clause 5.7). Media: every leg negotiates RTP/SAVP and
UDP/MCPTT floor control; SRTP carries the GMK-ID || GUK-ID MKI and the ROC (TS 33.180 annex E.2.2) and is relayed
byte-identically within its group; floor control is GCM SRTCP (RFC 7714) with the E bit, index and the CSK-ID as MKI (TS
33.180 clause 9.4), never reusing a nonce tuple with different bytes.

Usage: verify_protected.py capture.pcap --output report.json
Requires tshark/MCX_TSHARK and visible SIP (plaintext debug or TLS keylog).

Specifications: TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import base64
from email import policy
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from verify_prearranged import raw_sip_values, sip_message, media_legs


# ------------------------------------------------------------------------------
def require(condition, message):
    """Raise ValueError with message unless condition holds."""
    if not condition:
        raise ValueError(message)


# ------------------------------------------------------------------------------
def parse_srtp(packet):
    """The header fields, MKI and ROC of a protected SRTP packet (GMK default profile); ValueError if it is not one."""
    # TS 33.180 annex E.2.2 default: header | ciphertext | GCM tag16 | GMK-ID/GUK-ID8 | ROC4.
    require(len(packet) >= 41 and packet[0] >> 6 == 2, 'truncated SRTP or wrong RTP version')
    header = 12 + 4 * (packet[0] & 15)
    if packet[0] & 16:
        require(header + 4 <= len(packet) - 28, 'truncated RTP extension')
        header += 4 + 4 * int.from_bytes(packet[header + 2 : header + 4], 'big')
    require(header < len(packet) - 28, 'no encrypted RTP payload')
    mki = packet[-12:-4]
    require(mki[0] >> 4 == 0 and mki[4] >> 4 == 0, 'GMK/GUK purpose tags must be zero')
    return dict(
        ssrc=int.from_bytes(packet[8:12], 'big'),
        seq=int.from_bytes(packet[2:4], 'big'),
        timestamp=int.from_bytes(packet[4:8], 'big'),
        pt=packet[1] & 127,
        mki=mki.hex(),
        gmk_id=int.from_bytes(mki[:4], 'big'),
        roc=int.from_bytes(packet[-4:], 'big'),
        ciphertext_octets=len(packet) - header - 28,
    )


# ------------------------------------------------------------------------------
def parse_srtcp(packet):
    """The SSRC, SRTCP index and CSK-ID MKI of a protected floor control RTCP APP packet; ValueError if not one."""
    # RFC 7714 GCM SRTCP: first RTCP header8 | encrypted body | GCMtag16 | E/index4 | MKI4.
    require(
        len(packet) >= 36 and packet[0] >> 6 == 2 and packet[1] == 204,
        'floor packet is not a protected RTCP APP packet',
    )
    plain_length = (int.from_bytes(packet[2:4], 'big') + 1) * 4
    require(
        plain_length >= 12 and len(packet) == plain_length + 24,
        'floor wire length lacks exact GCM tag/index/MKI overhead',
    )
    e_index = int.from_bytes(packet[-8:-4], 'big')
    require(e_index & 0x80000000, 'SRTCP encryption E bit is not set')
    mki = packet[-4:]
    require(mki[0] >> 4 == 2, 'SRTCP MKI lacks CSK purpose tag')
    return dict(
        ssrc=int.from_bytes(packet[4:8], 'big'),
        index=e_index & 0x7FFFFFFF,
        csk_id=int.from_bytes(mki, 'big'),
        mki=mki.hex(),
        ciphertext_octets=plain_length - 8,
    )


# ------------------------------------------------------------------------------
def self_test():
    """Check the SRTP/SRTCP parsers and the relay matching offline (--self-test)."""
    plain_header = bytes.fromhex('806000010000014012345678')
    wire = plain_header + b'ciphertext' + bytes(16) + bytes.fromhex('0011223301234567') + bytes(4)
    assert parse_srtp(wire).get('mki') == '0011223301234567', 'SRTP eight-byte MKI before ROC'
    rtcp = bytes.fromhex('80cc000412345678') + bytes(12) + bytes(16) + bytes.fromhex('8000000120000001')
    assert parse_srtcp(rtcp).get('index') == 1, 'SRTCP E/index precedes four-byte MKI'
    for invalid, decoder in [
        (plain_header + b'clear', parse_srtp),
        (rtcp[:-24], parse_srtcp),
        (rtcp[:-8] + bytes.fromhex('0000000120000001'), parse_srtcp),
    ]:
        rejected = False
        try:
            decoder(invalid)
        except ValueError:
            rejected = True
        assert rejected, 'clear or unencrypted wire structure must fail'

    # ------------------------------------------------------------------------------
    def leg(dialog, client_port, server_port):
        """A synthetic negotiated leg for the self-test."""
        return dict(
            dialog=dialog,
            group='group',
            start=0,
            end=10,
            client=dict(address='client', port=client_port, payloads={96}),
            server=dict(address='server', port=server_port, payloads={96}),
            client_floor=dict(address='client', port=client_port + 10, ssrc=1),
            server_floor=dict(address='server', port=server_port + 10, ssrc=2),
        )

    legs = [leg('sender', 101, 201), leg('receiver', 102, 202)]
    packets = [
        dict(frame=1, src='client', dst='server', sport=101, dport=201, payload=wire),
        dict(frame=2, src='server', dst='client', sport=202, dport=102, payload=wire),
    ]
    evidence = inspect_packets(legs, packets, set())
    assert evidence['counts']['matched_relays'] == 1, 'byte-identical relay must match'
    packets[1]['payload'] = wire[:13] + bytes([wire[13] ^ 1]) + wire[14:]
    evidence = inspect_packets(legs, packets, set())
    assert evidence['counts']['matched_relays'] == 0 and any(
        'byte-identical' in error for error in evidence['errors']
    ), 'modified relay must fail'
    print('protected verifier self-tests passed')


# ------------------------------------------------------------------------------
def mime_parts(message):
    """Yield (content type, payload) of every non-multipart MIME part of a SIP message."""
    content_type = message['headers'].get('content-type', message['headers'].get('c', ''))
    parsed = Parser(policy=policy.default).parsestr(
        'Content-Type: ' + content_type + '\nMIME-Version: 1.0\n\n' + message['body']
    )
    for part in parsed.walk():
        if not part.is_multipart():
            payload = part.get_payload(decode=True)
            yield part.get_content_type(), payload if payload is not None else b''


# ------------------------------------------------------------------------------
def mikey_header(raw, purpose):
    """The key identifier of a MIKEY-SAKKE message, checking its common header and purpose tag."""
    require(
        len(raw) >= 10 and raw[:4] == bytes([1, 26, 5, 1]), 'MIKEY-SAKKE header must use version1/type26/T/SHA256PRF'
    )
    require(raw[8:10] == bytes([0, 1]), 'MIKEY default crypto-session map missing')
    identifier = int.from_bytes(raw[4:8], 'big')
    require(identifier >> 28 == purpose, 'MIKEY key identifier purpose tag mismatch')
    return identifier


# ------------------------------------------------------------------------------
def protected_sdp(message):
    """The audio and floor control media of an SDP, which must be RTP/SAVP audio and UDP/MCPTT floor with an SSRC."""
    connection = None
    media = {}
    current = None
    for line in re.split(r'\r?\n', message['body']):
        if line.startswith('m='):
            fields = line[2:].split()
            require(len(fields) >= 4, 'invalid SDP m-line')
            current = fields[0]
            if current in ('audio', 'application'):
                require(current not in media, 'multiple audio/floor SDP streams unsupported')
                media[current] = dict(address=connection, port=int(fields[1]), protocol=fields[2], formats=fields[3:])
        elif line.startswith('c=IN IP4 '):
            address = line.split()[2]
            if current in media:
                media[current]['address'] = address
            elif current is None:
                connection = address
        elif current == 'application' and 'mc_floor_ssrc=' in line:
            value = re.search(r'mc_floor_ssrc=([0-9]+)', line)
            if value:
                media[current]['ssrc'] = int(value.group(1))
    require('audio' in media and media['audio']['protocol'] == 'RTP/SAVP', 'confirmed leg must negotiate RTP/SAVP')
    require(
        'application' in media
        and media['application']['protocol'].lower() == 'udp'
        and media['application']['formats'] == ['MCPTT']
        and media['application'].get('ssrc'),
        'confirmed leg lacks UDP/MCPTT floor SDP/SSRC',
    )
    return media


# ------------------------------------------------------------------------------
def confirmed_legs(messages):
    """The confirmed prearranged legs with their protected audio and floor endpoints (distinct floor SSRCs)."""
    legs = media_legs(messages)
    for leg in legs:
        requests = [
            message
            for message in messages
            if message['method'] == 'INVITE'
            and not message['status']
            and message['headers']['call-id'] == leg['dialog']
        ]
        invite = requests[0]
        answer = next(
            message
            for message in messages
            if message['status'] == 200
            and message['method'] == 'INVITE'
            and message['headers']['call-id'] == leg['dialog']
            and message['headers']['cseq'] == invite['headers']['cseq']
        )
        offer, accepted = protected_sdp(invite), protected_sdp(answer)
        fanout = bool(invite['fields'].get('mcptt-calling-group-id'))
        client, server = (accepted, offer) if fanout else (offer, accepted)
        leg['client_floor'] = client['application']
        leg['server_floor'] = server['application']
        require(
            client['application']['ssrc'] != server['application']['ssrc'],
            'equal bidirectional floor SSRCs can reuse GCM nonces',
        )
    return legs


# ------------------------------------------------------------------------------
def accepted(message, messages):
    """The request message was answered 200."""
    return any(
        reply['status'] == 200
        and reply['method'] == message['method']
        and reply['headers']['call-id'] == message['headers']['call-id']
        and reply['headers']['cseq'] == message['headers']['cseq']
        for reply in messages
    )


# ------------------------------------------------------------------------------
def keying_evidence(messages):
    """The accepted CSK PUBLISHes and GKTP NOTIFYs; ValueError if either is missing."""
    csks = []
    gktps = []
    for message in messages:
        if message['status'] or not accepted(message, messages):
            continue
        event = message['headers'].get('event', '').split(';')[0].lower()
        for kind, body in mime_parts(message):
            if message['method'] == 'PUBLISH' and event == 'poc-settings' and kind == 'application/mikey':
                raw = base64.b64decode(body.strip(), validate=True)
                csks.append(dict(frame=message['frame'], csk_id=mikey_header(raw, 2), octets=len(raw)))
            if (
                message['method'] == 'NOTIFY'
                and event == 'xcap-diff'
                and kind == 'application/xcap-diff+xml'
                and body.strip()
            ):
                require(b'<!DOCTYPE' not in body.upper(), 'DTD in key notification')
                root = ET.fromstring(body)
                require(
                    root.tag == '{urn:ietf:params:xml:ns:xcap-diff}xcap-diff' and root.get('xcap-root'),
                    'missing RFC5874 xcap-diff namespace/root',
                )
                # The same xcap-diff subscription also notifies document changes (<document> entries, TS 24.481
                # clause 6.3.13 and TS 24.484 clause 6.3.13): only a notification selecting a GKTP is a key
                # notification (TS 24.481 clause 7.7).
                elements = root.findall('{urn:ietf:params:xml:ns:xcap-diff}element')
                if not any('MCPTT-GKTP' in element.get('sel', '') for element in elements):
                    continue
                require(len(elements) == 1, 'key notification must contain one selected element')
                element = elements[0]
                selector = element.get('sel', '')
                require(
                    selector.startswith('org.3gpp.MCPTT-GKTP/global/byGroupID/')
                    and '/~~/group/list-service/' in selector
                    and 'GKTPs' in selector,
                    'nonstandard GKTP element selector',
                )
                nodes = element.findall(
                    './{urn:3gpp:ns:mcpttGKTP:1.0}GKTPs/{urn:3gpp:ns:mcpttGKTP:1.0}GMK-GKTPs/{urn:3gpp:ns:mcpttGKTP:1.0}GKTP'
                )
                require(len(nodes) == 1 and nodes[0].get('id'), 'expected one GMK GKTP with identifier')
                raw = bytes.fromhex(''.join((nodes[0].text or '').split()))
                gktps.append(
                    dict(
                        frame=message['frame'],
                        recipient_guk_id=mikey_header(raw, 0),
                        octets=len(raw),
                        selector=selector,
                    )
                )
    require(csks, 'no accepted application/mikey CSK PUBLISH decoded')
    require(gktps, 'no accepted XCAP-diff GKTP NOTIFY decoded')
    return csks, gktps


# ------------------------------------------------------------------------------
def packet_leg(legs, packet, floor=False):
    """The legs (and direction) whose audio, or floor with floor true, endpoints the packet travels between."""

    # ------------------------------------------------------------------------------
    def endpoint_matches(endpoint, address, port):
        """The endpoint has this address and port."""
        return endpoint['address'] == address and endpoint['port'] == port

    matches = []
    for leg in legs:
        if not leg['start'] <= packet['frame'] < leg['end']:
            continue
        client = leg['client_floor' if floor else 'client']
        server = leg['server_floor' if floor else 'server']
        if endpoint_matches(client, packet['src'], packet['sport']) and endpoint_matches(
            server, packet['dst'], packet['dport']
        ):
            matches.append((leg, 'incoming'))
        if endpoint_matches(server, packet['src'], packet['sport']) and endpoint_matches(
            client, packet['dst'], packet['dport']
        ):
            matches.append((leg, 'outgoing'))
    return matches


# ------------------------------------------------------------------------------
def inspect_packets(legs, packets, csk_ids):
    """Classify and check every captured UDP packet of the legs; the counts, errors, MKIs and relay samples."""
    errors = []
    ingress = {}
    nonce_records = {}
    counts = dict(
        inbound_srtp=0,
        relayed_srtp=0,
        matched_relays=0,
        inbound_srtcp=0,
        outbound_srtcp=0,
        duplicate_srtcp_observations=0,
        unclassified_media_udp=0,
    )
    media_mkis = set()
    floor_mkis = set()
    samples = []
    for packet in packets:
        try:
            audio = packet_leg(legs, packet)
            floor = packet_leg(legs, packet, True)
            if not audio and not floor:
                counts['unclassified_media_udp'] += 1
                continue
            require(len(audio) + len(floor) == 1, 'no unique negotiated packet direction')
            if audio:
                leg, direction = audio[0]
                decoded = parse_srtp(packet['payload'])
                require(
                    decoded['pt'] in leg['client']['payloads'] and decoded['pt'] in leg['server']['payloads'],
                    'RTP payload type differs from negotiated SDP',
                )
                media_mkis.add(decoded['mki'])
                identifier = (leg['group'], decoded['ssrc'], decoded['roc'], decoded['seq'], decoded['timestamp'])
                if direction == 'incoming':
                    counts['inbound_srtp'] += 1
                    ingress.setdefault(identifier, []).append((packet['frame'], leg['dialog'], packet['payload']))
                else:
                    counts['relayed_srtp'] += 1
                    sources = [
                        source
                        for source in ingress.get(identifier, [])
                        if source[0] < packet['frame'] and source[1] != leg['dialog'] and source[2] == packet['payload']
                    ]
                    require(sources, 'relay lacks earlier byte-identical same-group ingress on another leg')
                    counts['matched_relays'] += 1
                    if len(samples) < 8:
                        samples.append(
                            dict(
                                ingress_frame=sources[0][0],
                                relay_frame=packet['frame'],
                                ssrc=decoded['ssrc'],
                                sequence=decoded['seq'],
                                roc=decoded['roc'],
                                sha256=hashlib.sha256(packet['payload']).hexdigest(),
                            )
                        )
            else:
                leg, direction = floor[0]
                decoded = parse_srtcp(packet['payload'])
                destination = leg['server_floor'] if direction == 'incoming' else leg['client_floor']
                require(decoded['ssrc'] == destination['ssrc'], 'floor SSRC differs from negotiated receiver SSRC')
                require(decoded['csk_id'] in csk_ids, 'SRTCP MKI has no captured accepted CSK distribution')
                counts['inbound_srtcp' if direction == 'incoming' else 'outbound_srtcp'] += 1
                floor_mkis.add(decoded['mki'])
                nonce = (decoded['csk_id'], decoded['ssrc'], decoded['index'])
                old = nonce_records.setdefault(nonce, packet['payload'])
                require(old == packet['payload'], 'SRTCP nonce tuple reused with differing packet bytes')
                if old is not packet['payload']:
                    counts['duplicate_srtcp_observations'] += 1
        except ValueError as error:
            errors.append(f"frame {packet['frame']}: {error}")
    for field in ('inbound_srtp', 'relayed_srtp', 'matched_relays', 'inbound_srtcp', 'outbound_srtcp'):
        if not counts[field]:
            errors.append('no observed ' + field)
    return dict(
        counts=counts,
        errors=errors,
        media_mkis=sorted(media_mkis),
        floor_mkis=sorted(floor_mkis),
        exact_relay_samples=samples,
    )


# ------------------------------------------------------------------------------
def tshark_command(args):
    """The tshark command line for the capture with the extra preferences."""
    result = [args.tshark, '-r', str(args.capture)]
    for preference in args.tshark_option:
        result += ['-o', preference]
    return result


# ------------------------------------------------------------------------------
def read_sip(args):
    """The SIP messages of the capture, dissected by tshark."""
    command = tshark_command(args) + [
        '-o',
        'tcp.desegment_tcp_streams:TRUE',
        '-o',
        'sip.desegment_headers:TRUE',
        '-o',
        'sip.desegment_body:TRUE',
        '-Y',
        'sip',
        '-T',
        'json',
        '-x',
        '-J',
        'frame sip',
    ]
    packets = json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)
    messages = []
    for index, packet in enumerate(packets, 1):
        for raw in raw_sip_values(packet):
            message = sip_message(raw, index)
            if message:
                message['frame'] = int(packet['_source']['layers']['frame']['frame.number'])
                messages.append(message)
    return messages


# ------------------------------------------------------------------------------
def read_udp(args, legs):
    """The UDP packets on the negotiated ports of the legs, dissected by tshark."""
    ports = sorted(
        {
            endpoint['port']
            for leg in legs
            for endpoint in [leg['client'], leg['server'], leg['client_floor'], leg['server_floor']]
        }
    )
    require(ports, 'no negotiated UDP ports')
    fields = ['frame.number', 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'udp.payload']
    command = tshark_command(args) + [
        '-Y',
        'udp && (' + ' || '.join(f'udp.port=={port}' for port in ports) + ')',
        '-T',
        'fields',
        '-E',
        'occurrence=f',
    ]
    for field in fields:
        command += ['-e', field]
    output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    result = []
    for line in output.splitlines():
        values = line.split('\t')
        require(len(values) == len(fields), 'incomplete UDP dissection')
        frame, src, dst, sport, dport, payload = values
        result.append(
            dict(
                frame=int(frame),
                src=src,
                dst=dst,
                sport=int(sport),
                dport=int(dport),
                payload=bytes.fromhex(payload.replace(':', '')),
            )
        )
    return result


# ------------------------------------------------------------------------------
def main():
    """Inspect the capture (or --self-test) and write the report; exit status 1 on any error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path, nargs='?')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--tshark', default=os.environ.get('MCX_TSHARK') or shutil.which('tshark'))
    parser.add_argument('--tshark-option', action='append', default=[])
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.capture is None or args.output is None:
        parser.error('capture and --output are required unless --self-test is used')
    result = dict(
        passed=False,
        capture=str(args.capture),
        counts={},
        errors=[],
        limitations=[
            'Structural wire evidence and byte-identical relay only: without session keys this does not verify AES-GCM tags, MIKEY signatures, SAKKE decapsulation, or confidentiality.',
            'SIP must be visible via debug plaintext or externally configured TLS decryption. No secret keys or access tokens are exported.',
            'Encrypted floor bodies are not decoded; APP header, clear SRTCP E/index and MKI are checked directly from UDP bytes.',
            'Only the exercised AES-GCM128/16-byte-tag MCPTT profile, single RTCP APP packets and IPv4 unicast are checked; not full 3GPP conformance.',
            'TS33.180 E.6 numeric interoperability-profile assignments are not independently established by this capture.',
        ],
    )
    try:
        require(bool(args.tshark), 'tshark unavailable; install it or set MCX_TSHARK')
        messages = read_sip(args)
        csks, gktps = keying_evidence(messages)
        legs = confirmed_legs(messages)
        require(len(legs) >= 2, 'need at least two confirmed RTP/SAVP legs for opaque relay evidence')
        packet_result = inspect_packets(legs, read_udp(args, legs), {key['csk_id'] for key in csks})
        result.update(packet_result)
        result['counts'].update(
            decoded_sip_messages=len(messages),
            confirmed_savp_legs=len(legs),
            accepted_csk_publishes=len(csks),
            accepted_gktp_notifications=len(gktps),
        )
        result['keying'] = dict(csk_publishes=csks, gktp_notifications=gktps)
        result['passed'] = not result['errors']
    except (
        ValueError,
        KeyError,
        TypeError,
        StopIteration,
        ET.ParseError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        result['errors'].append(error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['passed', 'counts', 'errors']}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
