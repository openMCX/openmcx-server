#!/usr/bin/env python3
"""Verify end-to-end protected MCData SDS from a clear-SIP capture at the MCData server.

Decodes independently the application/mikey I_MESSAGE (TS 24.282 clause 9.2.2.2.1 step 2 c), TS 33.180 annex E.3) and
the MCData Protected Payload message (TS 33.180 clause 8.5.4.1, table 8.5.4.1-1; message type bits of TS 24.282 clause
6.6.3.1), with the optional payload authentication of TS 33.180 clause 8.5.5, of each SIP MESSAGE; checks that the
MCData server relays both unchanged, that every signalling body is protected under a CSK (TS 33.180 clause 9.5), that no
MCData ID or access token crosses in clear in an XML body (TS 24.282 clauses 4.6 and 6.5.2), that the media plane offers
and MSRP bodies are protected likewise, and that no text the scenario sent appears anywhere in the capture. It cannot
decrypt.

Usage: verify_mcdata_protected.py capture.pcap --results mcdata-protected-results.json --output result.json

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import base64
import collections
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_sds import header, parse, sip_messages  # noqa: E402
from verify_private_call import tcp_streams  # noqa: E402
from verify_protected_private import mikey  # noqa: E402

PAYLOAD = 'application/vnd.3gpp.mcdata-payload'
# A JWS or JWE compact serialisation (RFC 7515 section 7.1, RFC 7516 section 7.1): a JSON header in base64url, a dot
# and the next segment.
JWT = re.compile(rb'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.')


# ------------------------------------------------------------------------------
def require(condition, message):
    """Raise AssertionError with message unless condition holds."""
    if not condition:
        raise AssertionError(message)


# ------------------------------------------------------------------------------
def protected_payload(data):
    """TS 33.180 table 8.5.4.1-1 with the ciphertext in a TLV-E: the header fields and the ciphertext length."""
    require(len(data) >= 1 + 5 + 4 + 1 + 1 + 16 + 4 + 3 + 16, 'truncated Protected Payload message')
    fields = dict(
        message_type=data[0],
        date=int.from_bytes(data[1:6], 'big'),
        payload_id=int.from_bytes(data[6:10], 'big'),
        sequence=data[10],
        algorithm=data[11],
        dppk_id=int.from_bytes(data[28:32], 'big'),
        iei=data[32],
    )
    length = int.from_bytes(data[33:35], 'big')
    require(35 + length == len(data) and length >= 16, 'Protected Payload length does not match the message')
    fields['ciphertext_octets'] = length - 16
    return fields


# ------------------------------------------------------------------------------
def unsigned(body):
    """TS 33.180 clause 8.5.5 with the local coding: 0x80 | type, Original Payload (0x71, TLV-E), algorithm 1 (ECCSI),
    Signing Data (0x72), Signature (0x75, 129 octets). Returns the inner payload and whether it was signed.
    """
    if not body or not body[0] & 0x80:
        return body, False
    require(body[1] == 0x71, 'Authenticated Payload without an Original Payload')
    length = int.from_bytes(body[2:4], 'big')
    inner = body[4 : 4 + length]
    rest = body[4 + length :]
    require(rest[0] == 1 and rest[1] == 0x72, 'Authenticated Payload without ECCSI Signing Data')
    signing = int.from_bytes(rest[2:4], 'big')
    sig = rest[4 + signing :]
    require(
        sig[0] == 0x75 and int.from_bytes(sig[1:3], 'big') == 129 and len(sig) == 3 + 129,
        'Authenticated Payload signature element',
    )
    require(inner and (inner[0] | 0x80) == body[0], 'signed payload type')
    return inner, True


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks W-00 to W-15 (raising at the first failure) and write the result file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.capture.read_bytes()
    texts = json.loads(args.results.read_text())['texts']
    messages = []
    for _, stream in tcp_streams(args.capture):
        messages.extend(parse(head, body) for head, body in sip_messages(stream))
    checks = []
    result = dict(capture=str(args.capture), passed=False, checks=checks, keys={})

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=''):
        """Record label if condition holds, else raise with label and detail."""
        require(condition, label + (': ' + detail if detail else ''))
        checks.append(label)

    try:
        sds = [
            message
            for message in messages
            if message['request'] and message['method'] == 'MESSAGE' and PAYLOAD in message['parts']
        ]
        check('W-00 SIP MESSAGE requests with MCData payloads captured', sds)
        payloads = collections.Counter()
        keys = collections.defaultdict(set)
        signed_expected = json.loads(args.results.read_text())['observations'].get('signed', False)
        signed_count = 0
        for message in sds:
            body, signed = unsigned(message['parts'][PAYLOAD])
            signed_count += signed
            if signed_expected:
                check('W-15 every DATA PAYLOAD is an Authenticated Payload (bit 8) with an ECCSI signature', signed)
            check(
                'W-01 every DATA PAYLOAD is protected: message type 0x43 (TS 24.282 6.6.3.1, bit 7)',
                body[0] == 0x43,
                hex(body[0]),
            )
            fields = protected_payload(body)
            check(
                'W-01 Payload ID 0 and sequence 0 for a payload in one message',
                fields['payload_id'] == 0 and fields['sequence'] == 0,
            )
            request_type = message['info'].get('request-type', '')
            if request_type == 'one-to-one-sds':
                check('W-02 a one-to-one payload is protected with a PCK-ID', fields['dppk_id'] >> 28 == 1)
            elif request_type == 'group-sds':
                check('W-03 a group payload is protected with a GMK-ID', fields['dppk_id'] >> 28 == 0)
            payloads[body] += 1
            keys[fields['dppk_id']].add(request_type)
            if 'application/mikey' in message['parts']:
                value = message['parts']['application/mikey'].decode().strip()
                decoded = mikey(base64.b64decode(value, validate=True))
                check(
                    'W-04 the I_MESSAGE is only sent with a one-to-one SDS or FD request',
                    request_type in ('one-to-one-sds', 'one-to-one-fd'),
                )
                check(
                    'W-04 the I_MESSAGE carries the PCK-ID the payload uses',
                    decoded['csb_id'] == fields['dppk_id'] and decoded['csb_id'] >> 28 == 1,
                )
                check(
                    'W-04 IDRi and IDRr are MCData IDs (TS 24.282 9.2.2.2.1 step 2c-iv, vi)',
                    '.mcdata@' in decoded['idr'][1] and '.mcdata@' in decoded['idr'][2],
                    json.dumps(decoded['idr']),
                )
                check('W-04 no key parameters extension in the PCK I_MESSAGE', 7 not in decoded.get('extensions', []))
        check(
            'W-05 the MCData server relays each protected payload unchanged',
            all(count >= 2 for count in payloads.values()),
            json.dumps(list(payloads.values())),
        )
        rejected = [
            message
            for message in messages
            if not message['request'] and message['method'] == 'MESSAGE' and message['status'] == 606
        ]
        check(
            'W-06 the altered I_MESSAGE is answered 606 with warning 136',
            any(
                '136 authentication of the MIKEY-SAKKE I_MESSAGE failed' in header(message, 'warning')
                for message in rejected
            ),
        )
        # TS 33.180 clause 9.5: every signalling body in SIP is a Protected Payload message under
        # the CSK of the client it travels to or from, sealed again by the server per hop.
        signalling_keys = collections.Counter()
        for message in messages:
            body = message['parts'].get('application/vnd.3gpp.mcdata-signalling')
            if body is None:
                continue
            fields = protected_payload(body)
            check(
                'W-11 every SIP signalling body is protected (bit 7) under a CSK-ID (purpose 2)',
                fields['message_type'] & 0x40 and fields['dppk_id'] >> 28 == 2,
                hex(body[0]),
            )
            signalling_keys[fields['dppk_id']] += 1
        check(
            'W-11 signalling bodies used one CSK per client',
            len(signalling_keys) >= 3,
            json.dumps(len(signalling_keys)),
        )
        result['signalling_bodies'] = sum(signalling_keys.values())
        # TS 24.282 clauses 4.6 and 6.5.2: no MCData ID or access token in clear in any XML body.
        xml_types = ('application/vnd.3gpp.mcdata-info+xml', 'application/resource-lists+xml', 'application/pidf+xml')
        xml_bodies = [
            (content_type, message['parts'][content_type])
            for message in messages
            for content_type in xml_types
            if content_type in message['parts']
        ]
        clear = [content_type for content_type, body in xml_bodies if b'.mcdata@' in body or b'type="Normal"' in body]
        check(
            'W-12 no MCData ID or clear sensitive element in any mcdata-info, resource-lists or PIDF body',
            xml_bodies and not clear,
            json.dumps(collections.Counter(clear)),
        )
        check(
            'W-12 sensitive elements carry EncryptedData (xmlenc 1.1 AES-128-GCM) or encrypted URIs',
            any(b'xmlenc11#aes128-gcm' in body for _, body in xml_bodies)
            and any(b'@mc1-encryption.3gppnetwork.org' in body for _, body in xml_bodies),
        )
        # No clear access token anywhere in the capture: a JWT (RFC 7519) is base64url segments joined by dots, of which
        # the first is a JSON header and so starts with "eyJ", the base64 of '{"', whatever its first member.
        check('W-13 no access token (a JWT) anywhere in the capture', not JWT.search(raw))
        result['xml_bodies'] = len(xml_bodies)
        # The media plane: the PCK of a one-to-one offer in a=key-mgmt, passed on by the
        # MCData server in its own offer (TS 24.282 clause 9.2.3.3), and the payloads inside MSRP SEND.
        offers = collections.Counter()
        for message in messages:
            sdp = message['parts'].get('application/sdp', b'').decode('utf-8', 'replace')
            if message['request'] and message['method'] == 'INVITE' and 'm=message' in sdp:
                value = next(
                    (line.split()[1] for line in sdp.splitlines() if line.startswith('a=key-mgmt:mikey ')), None
                )
                if value:
                    decoded = mikey(base64.b64decode(value, validate=True))
                    check(
                        'W-08 a media plane offer carries a PCK from one MCData ID to another',
                        decoded['csb_id'] >> 28 == 1
                        and '.mcdata@' in decoded['idr'][1]
                        and '.mcdata@' in decoded['idr'][2],
                    )
                    offers[value] += 1
        check(
            'W-08 the MCData server offers the recipient the same I_MESSAGE',
            offers and all(count >= 2 for count in offers.values()),
            json.dumps(list(offers.values())),
        )
        msrp = b''.join(stream for _, stream in tcp_streams(args.capture, port=None))
        payload_marker = b'Content-Type: application/vnd.3gpp.mcdata-payload\r\n\r\n'
        file_marker = b'Content-Type: application/vnd.3gpp.mcdata-file\r\n\r\n'
        media_payloads = [
            msrp[index + len(payload_marker)] for index in range(len(msrp)) if msrp.startswith(payload_marker, index)
        ]
        if signed_expected:
            check(
                'W-15 every DATA PAYLOAD in MSRP is signed (0xc3)',
                media_payloads and set(media_payloads) == {0xC3},
                json.dumps(media_payloads),
            )
            media_payloads = [octet & 0x7F for octet in media_payloads]
        result['signed_payloads'] = signed_count
        media_files = [
            msrp[index + len(file_marker)] for index in range(len(msrp)) if msrp.startswith(file_marker, index)
        ]
        result['media_payloads'], result['media_files'] = len(media_payloads), len(media_files)
        signalling_marker = b'Content-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\n'
        media_signalling = [
            msrp[index + len(signalling_marker)]
            for index in range(len(msrp))
            if msrp.startswith(signalling_marker, index)
        ]
        result['media_signalling'] = len(media_signalling)
        check(
            'W-14 every signalling body in an MSRP SEND is protected under the CSK (bit 7)',
            media_signalling and all(octet & 0x40 for octet in media_signalling),
            json.dumps(media_signalling),
        )
        check(
            'W-09 every DATA PAYLOAD in an MSRP SEND is protected (0x43)',
            media_payloads and set(media_payloads) == {0x43},
            json.dumps(media_payloads),
        )
        check(
            'W-10 the file in MSRP is a series of Protected Payload messages (0x42)',
            media_files and set(media_files) == {0x42},
            json.dumps(media_files),
        )
        check(
            'W-07 no text the scenario sent appears in clear anywhere in the capture',
            texts and not [content_type for content_type in texts if content_type.encode() in raw],
            json.dumps([content_type for content_type in texts if content_type.encode() in raw]),
        )
        result['keys'] = {hex(key): sorted(value) for key, value in keys.items()}
        result['protected_payloads'] = len(payloads)
        result['passed'] = True
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(
        json.dumps(
            dict(passed=result['passed'], checks=len(checks), payloads=result.get('protected_payloads')), indent=2
        )
    )


if __name__ == '__main__':
    main()
