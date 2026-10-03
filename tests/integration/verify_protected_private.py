#!/usr/bin/env python3
"""Verify end-to-end protected private calls from a clear-SIP server-side capture.

Decodes, independently of the implementation, the MIKEY-SAKKE I_MESSAGE that TS 24.379 clause 11.1.1.2.1.1 step 11 puts
in the SDP (IETF RFC 4567 a=key-mgmt), profiled by TS 33.180 annexes E.1 and E.3, and the SRTP of TS 33.180 clause 7.4.1
and annex E.3.2, and checks that the server relays both unchanged (TS 24.379 clause 6.3.2.2.3). A first-to-answer
request carries no key; the answering invitee's 200 does (TS 33.180 clause 7.2.4.2). Floor control is SRTCP under each
user's CSK. It cannot decrypt: the PCK is encapsulated to the callee's SAKKE key. Requires debug (clear) SIP; reuses the
TCP reassembly of verify_private_call.py.

Usage: verify_protected_private.py capture.pcap --output result.json

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import base64
import collections
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402

# W-05: the share of a call's distinct SRTP packets that must be seen on both legs of the server.
RELAYED_SHARE = 0.9


# ------------------------------------------------------------------------------
def require(condition, message):
    """Raise AssertionError with message unless condition holds."""
    if not condition:
        raise AssertionError(message)


# ------------------------------------------------------------------------------
def mikey(data):
    """RFC 3830/6509 as profiled by TS 33.180 annexes E.1 and E.3 (default crypto session map): the decoded fields."""
    out, at = {}, 0

    # ------------------------------------------------------------------------------
    def take(count):
        """The next count octets of the I_MESSAGE; raise if it is truncated."""
        nonlocal at
        require(at + count <= len(data), 'truncated I_MESSAGE')
        at += count
        return data[at - count : at]

    version, data_type, following, flags = take(4)
    require(version == 1 and data_type == 26, 'HDR is not MIKEY-SAKKE (version 1, data type 26)')
    require(flags >> 7 == 0, 'HDR V bit must be 0 (E.1.2)')
    out['prf'] = flags & 0x7F
    out['csb_id'] = int.from_bytes(take(4), 'big')
    cs_count, map_type = take(2)
    require(cs_count == 0 and map_type == 1, 'E.3.2 default profile: CS# 0 with an empty CS ID map')
    payloads = []
    while following:
        kind = following
        if kind == 5:  # TS
            following, ts_type = take(2)
            require(ts_type == 0, 'TS type must be NTP-UTC (E.1.2)')
            out['ntp'] = int.from_bytes(take(8), 'big') >> 32
        elif kind == 11:  # RAND
            following, length = take(2)
            out['rand_octets'] = len(take(length))
        elif kind == 14:  # IDR (RFC 6043 section 6.6)
            following, role, id_type = take(3)
            length = int.from_bytes(take(2), 'big')
            require(id_type == 1, 'IDR ID type must be a URI')
            out.setdefault('idr', {})[role] = take(length).decode()
        elif kind == 26:  # SAKKE (RFC 6509)
            following, params, scheme = take(3)
            length = int.from_bytes(take(2), 'big')
            require(params == 1 and scheme == 2, 'SAKKE parameter set 1 and ID scheme 2 (3GPP MCX hashed UID)')
            out['sakke_octets'] = len(take(length))
        elif kind == 21:  # general extension (TS 33.180 annex E.5 SAKKE-to-self, annex E.6 key parameters)
            following, extension_type = take(2)
            length = int.from_bytes(take(2), 'big')
            take(length)
            out.setdefault('extensions', []).append(extension_type)
        elif kind == 4:  # SIGN
            raise AssertionError('SIGN is the last payload and has no next payload field')
        else:
            raise AssertionError(f'unexpected MIKEY payload {kind}')
        payloads.append(kind)
        if following == 4:
            break
    sign_type_length = int.from_bytes(take(2), 'big')
    out['sign_type'] = sign_type_length >> 12
    out['sign_octets'] = len(data) - at
    require(out['sign_type'] == 2, 'SIGN type must be ECCSI (2)')
    require(out['sign_octets'] == (sign_type_length & 0xFFF), 'SIGN length field disagrees with the signature')
    out['payloads'] = payloads
    return out


# ------------------------------------------------------------------------------
def key_mgmt(body):
    """The base64 MIKEY message of an SDP a=key-mgmt:mikey attribute, or None."""
    match = re.search(r'(?m)^a=key-mgmt:mikey ([A-Za-z0-9+/=]+)\r?$', body)
    return match.group(1) if match else None


# ------------------------------------------------------------------------------
def udp_packets(path):
    """Yield ((source, sport, destination, dport), payload) of every UDP/IPv4 packet in the classic PCAP at path."""
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        if len(packet) < 42 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 17:
            continue
        total = struct.unpack_from('!H', ip, 2)[0]
        udp = ip[ihl:total]
        sport, dport = struct.unpack_from('!HH', udp, 0)
        yield (bytes(ip[12:16]), sport, bytes(ip[16:20]), dport), bytes(udp[8:])


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks W-00 to W-06 (raising at the first failure) and write the result file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages = []
    for _, stream in tcp_streams(args.capture):
        messages.extend(parse(head, body) for head, body in sip_messages(stream))
    checks, calls = [], []
    result = dict(capture=str(args.capture), passed=False, checks=checks, calls=calls)

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=''):
        """Record label if condition holds, else raise with label and detail."""
        require(condition, label + (': ' + detail if detail else ''))
        checks.append(label)

    try:
        by_call = collections.defaultdict(list)
        for message in messages:
            by_call[message['call_id']].append(message)
        invites = [
            message
            for message in messages
            if message['request']
            and message['method'] == 'INVITE'
            and message['info'].get('session-type') in ('private', 'first-to-answer', 'ambient-listening')
            and 'RTP/SAVP' in message['body']
            and not header(message, 'to').count('tag=')
        ]
        check('W-00 protected private INVITEs captured', invites, 'no RTP/SAVP private INVITE in the capture')
        offers = {}
        for invite in invites:
            value = key_mgmt(invite['body'])
            fta = invite['info'].get('session-type') == 'first-to-answer'
            if fta:
                check('W-03 a first-to-answer request carries no key material (TS 33.180 7.2.4.2)', value is None)
                continue
            check('W-01 a protected private offer carries a=key-mgmt:mikey (RFC 4567)', value is not None)
            offers.setdefault(value, []).append(invite)
        pck_ids = {}
        for value, carriers in offers.items():
            decoded = mikey(base64.b64decode(value, validate=True))
            caller = carriers[0]['info'].get('mcptt-calling-user-id', '')
            check('W-01 CSB-ID is a PCK-ID with purpose tag 0001 (TS 24.379 step 11c)', decoded['csb_id'] >> 28 == 1)
            check('W-01 IDRi, IDRr, IDRkmsi and IDRkmsr are present (E.1.2)', set(decoded['idr']) >= {1, 2, 6, 7})
            check(
                'W-01 IDRi is the calling user (E.3.1)',
                not caller or decoded['idr'][1] == caller,
                f"{decoded['idr'][1]} != {caller}",
            )
            check('W-01 no key parameters extension in a PCK I_MESSAGE (E.3)', 7 not in decoded.get('extensions', []))
            check(
                'W-01 SAKKE payload and ECCSI signature present',
                decoded['sakke_octets'] > 0 and decoded['sign_octets'] > 0,
            )
            check('W-01 RAND of 16 octets', decoded['rand_octets'] == 16)
            # The originating client's INVITE and the server's INVITE to the callee carry the same value.
            relayed = [carrier for carrier in carriers if carrier['target'] != carriers[0]['target']]
            status = [
                message
                for carrier in carriers
                for message in by_call[carrier['call_id']]
                if not message['request'] and message['method'] == 'INVITE' and message['status'] >= 200
            ]
            final = {message['status'] for message in status}
            if 488 in final:
                warning = [header(message, 'warning') for message in status if message['status'] == 488]
                check(
                    'W-04 an I_MESSAGE failing authentication is answered 488 with warning 136',
                    any('136 authentication of the MIKEY-SAKKE I_MESSAGE failed' in text for text in warning),
                )
            else:
                check(
                    'W-02 the server passes the I_MESSAGE to the callee unchanged (TS 24.379 6.3.2.2.3)',
                    len(carriers) >= 2 and relayed,
                    f'{len(carriers)} carriers of one I_MESSAGE',
                )
            pck_ids[decoded['csb_id']] = dict(
                caller=decoded['idr'][1], callee=decoded['idr'][2], session_type=carriers[0]['info'].get('session-type')
            )
        # First-to-answer: the answering invitee's 200 carries its PCK, relayed to the caller unchanged.
        answers = [
            message
            for message in messages
            if not message['request']
            and message['method'] == 'INVITE'
            and message['status'] == 200
            and key_mgmt(message['body'])
        ]
        answer_values = collections.Counter(key_mgmt(message['body']) for message in answers)
        for value, count in answer_values.items():
            decoded = mikey(base64.b64decode(value, validate=True))
            check('W-03 the answer I_MESSAGE carries a PCK-ID', decoded['csb_id'] >> 28 == 1)
            check('W-03 the answer reaches the caller unchanged (invitee 200 and server 200)', count >= 2)
            pck_ids[decoded['csb_id']] = dict(
                caller=decoded['idr'][2], callee=decoded['idr'][1], session_type='first-to-answer'
            )
        check('W-03 first-to-answer answers were captured', answer_values)

        # SRTP: header | ciphertext | GCM tag16 | MKI4 = PCK-ID, with no ROC (TS 33.180 annex E.3.2).
        seen = collections.defaultdict(lambda: collections.Counter())
        floor_mkis = collections.Counter()
        for flow, payload in udp_packets(args.capture):
            if len(payload) < 12 or payload[0] >> 6 != 2:
                continue
            if payload[1] == 204 and len(payload) >= 36:
                floor_mkis[payload[-4] >> 4] += 1
                continue
            tail = int.from_bytes(payload[-4:], 'big')
            if tail in pck_ids and len(payload) > 12 + 16 + 4:
                seen[tail][payload] += 1
        for pck_id, info in pck_ids.items():
            packets = seen.get(pck_id, collections.Counter())
            if info['session_type'] is None:
                continue
            calls.append(
                dict(
                    pck_id=hex(pck_id),
                    **info,
                    srtp_packets=sum(packets.values()),
                    distinct_packets=len(packets),
                    relayed_identically=sum(1 for count in packets.values() if count >= 2),
                )
            )
        protected_calls = [call for call in calls if call['srtp_packets']]
        check('W-05 SRTP packets end in the PCK-ID as their MKI, without a ROC', protected_calls)
        # A packet relayed unchanged is seen twice, on the leg into the server and on the leg out of it. All but a few
        # (the first and last of a call, which may fall outside the capture) must be.
        for call in protected_calls:
            check(
                f"W-05 SRTP of {call['pck_id']} relayed byte-identically by the server",
                call['relayed_identically'] >= RELAYED_SHARE * call['distinct_packets'],
                json.dumps(call),
            )
        check(
            'W-06 floor control is SRTCP under each user\'s CSK (MKI purpose tag 2)',
            floor_mkis.get(2, 0) > 0 and set(floor_mkis) == {2},
            json.dumps(floor_mkis),
        )
        result['passed'] = True
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], checks=len(checks), calls=len(calls)), indent=2))


if __name__ == '__main__':
    main()
