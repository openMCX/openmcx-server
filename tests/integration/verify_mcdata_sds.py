#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify MCData standalone SDS signalling from a clear-SIP capture of the MCData server.

The procedures under test, all of TS 24.282: service authorisation (clause 7.2.2), affiliation and its notification
(clauses 8.2.2 and 8.3.2.5), standalone SDS over the signalling control plane, one-to-one, group and ad hoc (clause
9.2.2), disposition notifications, individual and aggregated (clauses 6.2.3.1 and 12.2), re-delivery of undelivered
messages, functional aliases (clause 22), emergency alerts (clause 16.2) and the rejections with the warning texts of
clause 4.9.2.

Usage: verify_mcdata_sds.py capture.pcap --service sip:mcdata@DOMAIN --output result.json

Self-contained and independent of the C++ codecs: SIP messages are split from the reassembled TCP streams as bytes,
multipart bodies are split by boundary, and the TS 24.282 clause 15 messages are decoded here from the tables.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import tcp_streams  # noqa: E402

INFO_NS = '{urn:3gpp:ns:mcdataInfo:1.0}'
LISTS_NS = '{urn:ietf:params:xml:ns:resource-lists}'
SDS_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcdata.sds'


# ------------------------------------------------------------------------------
def sip_messages(stream):
    """Yield (head, body) of every SIP message in a TCP stream, the body cut by Content-Length."""
    offset = 0
    while True:
        start = re.search(rb'(?:SIP/2\.0 \d{3}[^\r\n]*|[A-Z]+ \S+ SIP/2\.0)\r\n', stream[offset:])
        if not start:
            return
        begin = offset + start.start()
        end_head = stream.find(b'\r\n\r\n', begin)
        if end_head < 0:
            return
        head = stream[begin:end_head].decode('utf-8', 'replace')
        length = re.search(r'(?im)^(?:content-length|l)\s*:\s*(\d+)', head)
        body_end = end_head + 4 + (int(length.group(1)) if length else 0)
        yield head, stream[end_head + 4 : body_end]
        offset = body_end


# ------------------------------------------------------------------------------
def parse(head, body):
    """A SIP message as a dict: request or response, line, headers (compact forms expanded), multipart parts, the
    mcdata-info elements, the resource-lists targets and the signalling bodies.
    """
    lines = head.split('\r\n')
    headers = collections.defaultdict(list)
    for line in lines[1:]:
        if ':' in line:
            name, value = line.split(':', 1)
            name = {
                'i': 'call-id',
                'f': 'from',
                't': 'to',
                'l': 'content-length',
                'c': 'content-type',
                'a': 'accept-contact',
            }.get(name.strip().lower(), name.strip().lower())
            headers[name].append(value.strip())
    request = not lines[0].startswith('SIP/2.0')
    parts, signalling_bodies = {}, []
    ctype = headers['content-type'][0] if headers['content-type'] else ''
    boundary = re.search(r'boundary="?([^";]+)"?', ctype)
    if boundary:
        marker = b'--' + boundary.group(1).encode()
        for chunk in body.split(marker)[1:]:
            if chunk.startswith(b'--'):
                break
            head_end = chunk.find(b'\r\n\r\n')
            part_type = re.search(rb'(?i)content-type:\s*([^\r\n;]+)', chunk[:head_end]).group(1).decode().strip()
            parts[part_type] = chunk[head_end + 4 : -2]  # strip the CRLF before the next delimiter
            if part_type == 'application/vnd.3gpp.mcdata-signalling':
                signalling_bodies.append(parts[part_type])
    elif ctype:
        parts[ctype.split(';')[0].strip()] = body
    info = {}
    if 'application/vnd.3gpp.mcdata-info+xml' in parts:
        for element in ET.fromstring(parts['application/vnd.3gpp.mcdata-info+xml']).iter():
            name = element.tag.replace(INFO_NS, '')
            if name not in ('mcdatainfo', 'mcdata-Params', 'anyExt', 'mcdataURI', 'mcdataString', 'mcdataBoolean'):
                info[name] = ''.join(element.itertext()).strip()
    targets = None
    if 'application/resource-lists+xml' in parts:
        targets = [
            entry.get('uri')
            for entry in ET.fromstring(parts['application/resource-lists+xml']).iter(LISTS_NS + 'entry')
        ]
    return dict(
        request=request,
        line=lines[0],
        headers=headers,
        parts=parts,
        info=info,
        targets=targets,
        signalling_bodies=signalling_bodies,
        method=lines[0].split()[0] if request else headers['cseq'][0].split()[-1],
        status=0 if request else int(lines[0].split()[1]),
        target=lines[0].split()[1] if request else '',
        call_id=headers['call-id'][0] if headers['call-id'] else '',
    )


# ------------------------------------------------------------------------------
def header(message, name):
    """The first value of the header field name of message, or an empty string."""
    values = message['headers'].get(name, [])
    return values[0] if values else ''


# ------------------------------------------------------------------------------
def decode_signalling(data):
    """TS 24.282 tables 15.1.2.1-1 (SDS SIGNALLING PAYLOAD) and 15.1.5.1-1 (SDS NOTIFICATION): returns a dict or raises
    ValueError.
    """
    kind = data[0]
    if kind & 0xC0:
        raise ValueError('protected')
    if kind == 0x01:
        out = dict(
            type='SDS SIGNALLING PAYLOAD',
            time=int.from_bytes(data[1:6], 'big'),
            conversation=data[6:22].hex(),
            message=data[22:38].hex(),
        )
        at = 38
        while at < len(data):
            iei = data[at]
            if iei >> 4 == 0x8:
                out['disposition'] = iei & 0x0F
                if out['disposition'] not in (1, 2, 3):
                    raise ValueError('reserved disposition')
                at += 1
            elif iei == 0x21:
                out['in_reply_to'] = data[at + 1 : at + 17].hex()
                at += 17
            elif iei == 0x22:
                out['application_id'] = data[at + 1]
                at += 2
            elif iei in (0x7D, 0x7E, 0x51, 0x53):
                length = int.from_bytes(data[at + 1 : at + 3], 'big')
                at += 3 + length
            else:
                raise ValueError(f'unknown IEI {iei:#x}')
        if at != len(data):
            raise ValueError('trailing octets')
        return out
    if kind == 0x05:
        if len(data) < 39 or data[1] not in range(1, 6):
            raise ValueError('bad notification')
        out = dict(
            type='SDS NOTIFICATION', notification=data[1], conversation=data[7:23].hex(), message=data[23:39].hex()
        )
        at = 39
        while at < len(data):
            iei = data[at]
            if iei == 0x22:
                out['application_id'] = data[at + 1]
                at += 2
            elif iei in (0x7D, 0x51):
                length = int.from_bytes(data[at + 1 : at + 3], 'big')
                if iei == 0x51:
                    out['sender'] = data[at + 3 : at + 3 + length].decode()
                at += 3 + length
            else:
                raise ValueError(f'unknown IEI {iei:#x}')
        if at != len(data):
            raise ValueError('trailing octets')
        return out
    raise ValueError(f'unexpected message type {kind:#x}')


# ------------------------------------------------------------------------------
def decode_payload(data):
    """TS 24.282 table 15.1.4.1-1: DATA PAYLOAD with clear Payload IEs, as (content type, content) pairs."""
    if data[0] != 0x03 or data[1] == 0:
        raise ValueError('not a DATA PAYLOAD')
    payloads, at = [], 2
    while at < len(data):
        if data[at] != 0x78:
            raise ValueError('unexpected payload IEI')
        length = int.from_bytes(data[at + 1 : at + 3], 'big')
        value = data[at + 3 : at + 3 + length]
        if len(value) != length or not value or value[0] not in range(1, 11):
            raise ValueError('bad Payload IE')
        payloads.append((value[0], value[1:]))
        at += 3 + length
    if len(payloads) != data[1]:
        raise ValueError('payload count mismatch')
    return payloads


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen = [], set()
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:
                seen.add(key)
                messages.append(message)
    checks, failures, decode_errors = [], [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    responses = collections.defaultdict(list)
    for message in messages:
        if not message['request']:
            responses[(message['call_id'], header(message, 'cseq'))].append(message)

    # ------------------------------------------------------------------------------
    def answers(message):
        """The responses to the request message (same Call-ID and CSeq)."""
        return responses[(message['call_id'], header(message, 'cseq'))]

    requests = [message for message in messages if message['request']]
    auth = [
        message
        for message in requests
        if message['method'] == 'PUBLISH'
        and header(message, 'event') == 'poc-settings'
        and message['target'] == args.service
    ]
    check(
        'service authorisation PUBLISH carries poc-settings and mcdata-info with an access token and client ID (7.2.2)',
        bool(auth)
        and all(
            'application/poc-settings+xml' in message['parts']
            and message['info'].get('mcdata-access-token')
            and message['info'].get('mcdata-client-id')
            and SDS_ICSI.rsplit('.', 1)[0] in header(message, 'p-preferred-service')
            for message in auth
        )
        and all(any(response['status'] == 200 for response in answers(message)) for message in auth),
    )
    presence = [
        message
        for message in requests
        if message['method'] == 'PUBLISH'
        and header(message, 'event') == 'presence'
        and message['target'] == args.service
    ]
    affiliation = [
        message for message in presence if b'mcdataPresInfoFA' not in message['parts'].get('application/pidf+xml', b'')
    ]
    joins = [message for message in affiliation if header(message, 'expires') != '0']
    leaves = [message for message in affiliation if header(message, 'expires') == '0']
    check(
        'affiliation PUBLISH carries an MCData PIDF and mcdata-request-uri (8.2.2 step 5)',
        bool(joins)
        and all(
            b'urn:3gpp:ns:mcdataPresInfo:1.0' in message['parts'].get('application/pidf+xml', b'')
            and message['info'].get('mcdata-request-uri')
            and header(message, 'expires') == '4294967295'
            for message in joins
        ),
    )
    check(
        'de-affiliation is Expires 0 with mcdata-info and no PIDF, accepted with 200 (8.2.2 step 4, NOTE 1)',
        bool(leaves)
        and all(
            'application/pidf+xml' not in message['parts']
            and message['info'].get('mcdata-request-uri')
            and any(response['status'] == 200 for response in answers(message))
            for message in leaves
        ),
    )
    subscribes = [
        message
        for message in requests
        if message['method'] == 'SUBSCRIBE'
        and header(message, 'event') == 'presence'
        and message['target'] == args.service
    ]
    lasting = [message for message in subscribes if header(message, 'expires') == '4294967295']
    check(
        'affiliation status SUBSCRIBE names the user in mcdata-request-uri with the MCData ICSI and Accept PIDF, answered 200 (8.2.3)',
        bool(lasting)
        and all(
            message['info'].get('mcdata-request-uri')
            and header(message, 'p-preferred-service') == SDS_ICSI.rsplit('.', 1)[0]
            and 'application/pidf+xml' in header(message, 'accept')
            and any(response['status'] == 200 for response in answers(message))
            for message in lasting
        ),
    )
    fetches = [
        message
        for message in subscribes
        if header(message, 'expires') == '0' and message['info'].get('mcdata-request-uri')
    ]
    check(
        'a fetch (Expires 0) is answered 200, and one for another user 403 (8.3.2.4 step 4)',
        any(response['status'] == 200 for message in fetches for response in answers(message))
        and any(response['status'] == 403 for message in fetches for response in answers(message)),
    )
    presence_notifies = [
        message
        for message in requests
        if message['method'] == 'NOTIFY'
        and header(message, 'event') == 'presence'
        and args.service in header(message, 'from')
    ]
    # The functional alias status NOTIFYs (22.2.2.2.5) share the presence event with the affiliation ones (8.3.2.5).
    alias_notifies = [
        message
        for message in presence_notifies
        if b'urn:3gpp:ns:mcdataPresInfoFA:1.0' in message['parts'].get('application/pidf+xml', b'')
    ]
    notifies = [message for message in presence_notifies if message not in alias_notifies]
    notified = []
    for message in notifies:
        body = message['parts'].get('application/pidf+xml', b'')
        notified.append(
            (message, body, re.findall(rb'group="([^"]+)"', body), re.search(rb'<[^>]*p-id>([^<]+)<', body))
        )
    published = set()
    for message in requests:
        if message['method'] == 'PUBLISH' and header(message, 'event') == 'presence':
            found = re.search(rb'<[^>]*p-id>([^<]+)<', message['parts'].get('application/pidf+xml', b''))
            if found:
                published.add(found.group(1))
    check(
        'affiliation NOTIFY carries the MCData PIDF with per-client affiliated groups (8.3.2.5, 8.4.1)',
        bool(notified)
        and all(
            b'urn:3gpp:ns:mcdataPresInfo:1.0' in body
            and b'<tuple id=' in body
            and all(state == b'affiliated' for state in re.findall(rb'status="([^"]+)"', body))
            for _, body, _, _ in notified
        ),
    )
    check(
        'a NOTIFY caused by a PUBLISH echoes its p-id (8.3.2.5 step 3d)',
        any(pid and pid.group(1) in published for _, _, _, pid in notified),
    )
    check(
        'NOTIFY reports affiliation to several groups (implicit affiliation, 8.3.2.15, 16.2.3.1)',
        any(len(groups) > 1 for _, _, groups, _ in notified),
    )
    check(
        'de-subscription and fetches end with a terminated NOTIFY',
        any(header(message, 'subscription-state').startswith('terminated') for message in notifies),
    )
    uplink = [message for message in requests if message['method'] == 'MESSAGE' and message['target'] == args.service]
    downlink = [
        message
        for message in requests
        if message['method'] == 'MESSAGE'
        and message['target'] != args.service
        and args.service in header(message, 'from')
    ]
    decoded = {}
    for message in uplink + downlink:
        if message['info'].get('alert-ind'):
            continue  # emergency alerts (TS 24.282 clause 16.2) carry no signalling body
        try:
            message['signalling'] = decode_signalling(message['parts']['application/vnd.3gpp.mcdata-signalling'])
            message['notices'] = [
                decode_signalling(signalling_body) for signalling_body in message['signalling_bodies']
            ]
            if message['signalling']['type'] == 'SDS SIGNALLING PAYLOAD':
                message['payload'] = decode_payload(message['parts']['application/vnd.3gpp.mcdata-payload'])
            decoded[id(message)] = True
        except (KeyError, ValueError, IndexError) as error:
            decode_errors.append(f"{message['line']}: {error}")
    sds_up = [message for message in uplink if message.get('signalling', {}).get('type') == 'SDS SIGNALLING PAYLOAD']
    notes_up = [message for message in uplink if message.get('signalling', {}).get('type') == 'SDS NOTIFICATION']
    check('every MCData signalling and payload body decodes by the clause 15 tables', not decode_errors)
    check(
        'uplink SDS carries the SDS Accept-Contact tags and P-Preferred-Service (6.2.4.1)',
        bool(sds_up)
        and all(
            any('g.3gpp.mcdata.sds' in contact for contact in message['headers']['accept-contact'])
            and any(
                'icsi-ref' in contact and 'mcdata.sds' in contact for contact in message['headers']['accept-contact']
            )
            and header(message, 'p-preferred-service') == SDS_ICSI
            for message in sds_up + notes_up
        ),
    )
    one = [message for message in sds_up if message['info'].get('request-type') == 'one-to-one-sds']
    group = [message for message in sds_up if message['info'].get('request-type') == 'group-sds']
    check(
        'one-to-one SDS names exactly one target in resource-lists (9.2.2.2.1 step 2)',
        bool(one) and all(message['targets'] and len(message['targets']) == 1 for message in one),
    )
    check(
        'group SDS names the group in mcdata-request-uri with the client ID and no resource-lists (step 3)',
        bool(group)
        and all(
            message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-client-id')
            and message['targets'] is None
            for message in group
        ),
    )
    accepted = [response for message in sds_up for response in answers(message) if response['status'] == 202]
    check('accepted SDS gets 202 Accepted (9.2.2.4.2 step 7)', len(accepted) >= 10)
    sds_down = [
        message for message in downlink if message.get('signalling', {}).get('type') == 'SDS SIGNALLING PAYLOAD'
    ]
    check(
        'downlink SDS carries P-Asserted-Service, the recipient in mcdata-request-uri and the sender (9.2.2.4.1.1)',
        bool(sds_down)
        and all(
            header(message, 'p-asserted-service') == SDS_ICSI
            and message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-calling-user-id')
            for message in sds_down
        ),
    )
    check(
        'downlink group SDS carries mcdata-calling-group-id (step 5b)',
        any(
            message['info'].get('request-type') == 'group-sds' and message['info'].get('mcdata-calling-group-id')
            for message in sds_down
        ),
    )
    relayed = {
        (
            message['signalling']['message'],
            message['parts']['application/vnd.3gpp.mcdata-signalling'],
            message['parts']['application/vnd.3gpp.mcdata-payload'],
        )
        for message in sds_up
    }
    check(
        'signalling and payload bodies are relayed unchanged (step 4)',
        all(
            (
                message['signalling']['message'],
                message['parts']['application/vnd.3gpp.mcdata-signalling'],
                message['parts']['application/vnd.3gpp.mcdata-payload'],
            )
            in relayed
            for message in sds_down
        ),
    )
    check(
        'SDS carries each disposition request type',
        {message['signalling'].get('disposition') for message in sds_up} >= {1, 2, 3},
    )
    check(
        'a reply carries InReplyTo in the same conversation (6.2.2.1 step 5)',
        any(
            'in_reply_to' in message['signalling']
            and any(
                original['signalling']['message'] == message['signalling']['in_reply_to']
                and original['signalling']['conversation'] == message['signalling']['conversation']
                for original in sds_up
            )
            for message in sds_up
        ),
    )
    prioritised = {
        message['signalling']['message']: message['info']['user-requested-priority']
        for message in sds_up
        if 'user-requested-priority' in message['info']
    }
    check(
        'requested priority is delivered as <used-priority> without <user-requested-priority> (9.2.2.4.1.1 step 5c)',
        bool(prioritised)
        and all('user-requested-priority' not in message['info'] for message in sds_down)
        and all(
            message['info'].get('used-priority') == prioritised[message['signalling']['message']]
            for message in sds_down
            if message['signalling']['message'] in prioritised
        )
        and all(
            'used-priority' not in message['info']
            for message in sds_down
            if message['signalling']['message'] not in prioritised
        ),
    )
    kinds = {message['signalling']['notification'] for message in notes_up}
    check('SDS NOTIFICATION messages carry DELIVERED, READ and DELIVERED AND READ (6.2.3.1)', kinds >= {2, 3, 4})
    check(
        'uplink notifications name the original sender in resource-lists (12.2.1.1 step 3)',
        bool(notes_up) and all(message['targets'] and len(message['targets']) == 1 for message in notes_up),
    )
    notes_down = [message for message in downlink if message.get('signalling', {}).get('type') == 'SDS NOTIFICATION']
    single_down = [message for message in notes_down if message['info'].get('mcdata-calling-user-id')]
    aggregated_down = [message for message in notes_down if not message['info'].get('mcdata-calling-user-id')]
    check(
        'individually relayed notifications reach the sender with the notifier as calling user (12.2.3)',
        bool(single_down)
        and all(
            len(message['notices']) == 1 and header(message, 'p-asserted-service') == SDS_ICSI
            for message in single_down
        ),
    )
    check(
        'group notifications carry the Sender MCData user ID IE (15.1.5)',
        all(
            notice.get('sender')
            for message in notes_up
            if message['info'].get('mcdata-calling-group-id')
            for notice in message['notices']
        ),
    )
    check(
        'aggregated notifications: one MESSAGE per originator with one signalling body per notification, the calling group '
        'and each notifier in its Sender IE (12.2.3 step 15c)',
        any(len(message['notices']) > 1 for message in aggregated_down)
        and all(
            message['info'].get('mcdata-calling-group-id')
            and header(message, 'p-asserted-service') == SDS_ICSI
            and all(notice['type'] == 'SDS NOTIFICATION' and notice.get('sender') for notice in message['notices'])
            for message in aggregated_down
        ),
    )
    accepted_up = collections.Counter(
        (notice['message'], notice['sender'], notice['notification'])
        for message in notes_up
        if message['info'].get('mcdata-calling-group-id')
        and any(response['status'] == 202 for response in answers(message))
        for notice in message['notices']
        if notice['notification'] != 1
    )
    relayed_down = collections.Counter(
        (notice['message'], notice.get('sender') or message['info']['mcdata-calling-user-id'], notice['notification'])
        for message in notes_down
        if message['info'].get('mcdata-calling-group-id')
        for notice in message['notices']
    )
    check(
        'every accepted group notification reaches the originator exactly once, aggregated or individually',
        bool(accepted_up) and accepted_up == relayed_down,
    )
    adhoc_up = [message for message in sds_up if message['info'].get('request-type') == 'ad-hoc-group-sds']
    check(
        'ad hoc group SDS carries the client ID and one of a participant list, criteria or the ad hoc group (9.2.2.2.1 step 3A)',
        bool(adhoc_up)
        and all(
            message['info'].get('mcdata-client-id')
            and sum(
                bool(named)
                for named in (
                    message['targets'],
                    message['info'].get('comn-participants-criteria'),
                    message['info'].get('mcdata-request-uri'),
                )
            )
            == 1
            for message in adhoc_up
        )
        and any(message['targets'] for message in adhoc_up)
        and any(message['info'].get('comn-participants-criteria') for message in adhoc_up)
        and any(message['info'].get('mcdata-request-uri') for message in adhoc_up),
    )
    adhoc_accepted = [response for message in adhoc_up for response in answers(message) if response['status'] == 202]
    check(
        'accepted ad hoc group SDS gets 202 naming the ad hoc group identity',
        bool(adhoc_accepted)
        and all(
            response['info'].get('mcdata-calling-group-id', '').startswith('sip:adhoc-') for response in adhoc_accepted
        ),
    )
    adhoc_down = [message for message in sds_down if message['info'].get('request-type') == 'ad-hoc-group-sds']
    check(
        'delivered ad hoc group SDS names the ad hoc group in mcdata-calling-group-id without criteria (9.2.2.4.1.1 step 5b)',
        bool(adhoc_down)
        and all(
            message['info'].get('mcdata-calling-group-id', '').startswith('sip:adhoc-')
            and 'comn-participants-criteria' not in message['info']
            and message['targets'] is None
            for message in adhoc_down
        ),
    )
    fa_publish = [
        message
        for message in presence
        if b'urn:3gpp:ns:mcdataPresInfoFA:1.0' in message['parts'].get('application/pidf+xml', b'')
    ]
    check(
        'functional alias status change is a presence PUBLISH with the MCData FA PIDF, p-id-fa and mcdata-request-uri (22.2.1.2)',
        bool(fa_publish)
        and all(
            b'p-id-fa' in message['parts']['application/pidf+xml'] and message['info'].get('mcdata-request-uri')
            for message in fa_publish
        )
        and any(b'take-over' in message['parts']['application/pidf+xml'] for message in fa_publish)
        and any(header(message, 'expires') == '0' for message in fa_publish),
    )
    check(
        'a functional alias status change past the participating checks is answered 200, never with the owning '
        'outcome (22.2.2.2.3 step 8)',
        bool(fa_publish) and {response['status'] for message in fa_publish for response in answers(message)} == {200},
    )
    fa_pids = set()
    for message in fa_publish:
        found = re.search(rb'<[^>]*p-id-fa>([^<]+)<', message['parts']['application/pidf+xml'])
        if found:
            fa_pids.add(found.group(1))
    alias_bodies = [message['parts'].get('application/pidf+xml', b'') for message in alias_notifies]
    check(
        'the functional alias status NOTIFY carries the per-user MCData FA PIDF and echoes the p-id-fa of the change '
        '(22.2.2.2.5, 22.3.1.2)',
        bool(alias_bodies)
        and any(
            (found := re.search(rb'<[^>]*p-id-fa>([^<]+)<', body)) and found.group(1) in fa_pids
            for body in alias_bodies
        ),
    )
    check(
        'the status NOTIFY offers an alias at its limit as take-over-possible and lists activated ones (22.3.1.2, 3.1)',
        any(b'status="take-over-possible"' in body for body in alias_bodies)
        and any(b'status="activated"' in body for body in alias_bodies),
    )
    to_alias = [message for message in sds_up if message['info'].get('call-to-functional-alias-ind') == 'true']
    redirects = [response for message in to_alias for response in answers(message) if response['status'] == 300]
    check(
        'SDS to an alias carries <call-to-functional-alias-ind> and gets 300 naming the selected MCData ID (9.2.2.4.2 step 5b-ii)',
        bool(redirects) and all(response['info'].get('mcdata-request-uri') for response in redirects),
    )
    followups = [
        message
        for message in sds_up
        if message['info'].get('called-functional-alias-URI')
        and message['info'].get('request-type') == 'one-to-one-sds'
    ]
    check(
        'the follow-up names the selected user, carries <called-functional-alias-URI> and no indicator',
        bool(followups)
        and all(
            'call-to-functional-alias-ind' not in message['info']
            and message['targets'] == [response['info']['mcdata-request-uri']]
            for message in followups
            for response in redirects[:1]
        ),
    )
    check(
        'delivered SDS carries <functional-alias-URI> and <called-functional-alias-URI> where applicable',
        any(message['info'].get('functional-alias-URI') for message in sds_down)
        and any(message['info'].get('called-functional-alias-URI') for message in sds_down),
    )
    undelivered_up = [message for message in notes_up if message['signalling']['notification'] == 1]
    check(
        'UNDELIVERED notifications (type 1) are sent to the MCData server naming the sender (12.2.1.1)',
        bool(undelivered_up) and all(message['targets'] and len(message['targets']) == 1 for message in undelivered_up),
    )
    check(
        'UNDELIVERED is never relayed to an originator (12.2.2.1 step 5)',
        not any(
            message.get('signalling', {}).get('type') == 'SDS NOTIFICATION'
            and message['signalling']['notification'] == 1
            for message in downlink
        ),
    )
    copies = collections.defaultdict(list)
    for message in downlink:
        if message.get('signalling', {}).get('type') == 'SDS SIGNALLING PAYLOAD':
            copies[(message['info'].get('mcdata-request-uri'), message['signalling']['message'])].append(message)
    undelivered_ids = {message['signalling']['message'] for message in undelivered_up}
    redelivered = {key: copies_of for key, copies_of in copies.items() if len(copies_of) > 1}
    check(
        'each re-delivery repeats the stored message with identical signalling and payload bodies (Table F.2.1-1)',
        bool(redelivered)
        and all(
            len(
                {
                    (
                        copy['parts']['application/vnd.3gpp.mcdata-signalling'],
                        copy['parts']['application/vnd.3gpp.mcdata-payload'],
                    )
                    for copy in entries
                }
            )
            == 1
            for entries in redelivered.values()
        ),
    )
    check(
        're-delivery happens only for messages reported UNDELIVERED',
        all(key[1] in undelivered_ids for key in redelivered),
    )
    alerts_up = [
        message
        for message in requests
        if message['method'] == 'MESSAGE' and message['target'] == args.service and message['info'].get('alert-ind')
    ]
    raised = [message for message in alerts_up if message['info']['alert-ind'] == 'true']
    check(
        'an emergency alert names the group, alert-ind true and the client ID with an Emergency location report (16.2.1.1)',
        bool(raised)
        and all(
            message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-client-id')
            and b'ReportType="Emergency"' in message['parts'].get('application/vnd.3gpp.mcdata-location-info+xml', b'')
            and 'urn:urn-7:3gpp-service.ims.icsi.mcdata' == header(message, 'p-preferred-service')
            for message in raised
        ),
    )
    check(
        'cancellation of another user\'s alert carries <originated-by> (16.2.1.2 step 5)',
        any(message['info']['alert-ind'] == 'false' and message['info'].get('originated-by') for message in alerts_up),
    )
    alerts_down = [
        message
        for message in requests
        if message['method'] == 'MESSAGE'
        and args.service in header(message, 'from')
        and message['info'].get('alert-ind')
    ]
    notices = [message for message in alerts_down if 'alert-ind-rcvd' not in message['info']]
    receipts = [message for message in alerts_down if message['info'].get('alert-ind-rcvd') == 'true']
    check(
        'alert notifications carry the group, originator, mc-org and the copied location (16.2.3.1, 6.3.7.1.3)',
        any(
            message['info'].get('alert-ind') == 'true'
            and message['info'].get('mcdata-calling-group-id')
            and message['info'].get('mcdata-calling-user-id')
            and message['info'].get('mc-org')
            and 'application/vnd.3gpp.mcdata-location-info+xml' in message['parts']
            for message in notices
        )
        and all(
            header(message, 'p-asserted-service') == 'urn:urn-7:3gpp-service.ims.icsi.mcdata' for message in alerts_down
        ),
    )
    check(
        'receipts carry <alert-ind-rcvd> and the sender\'s client ID for alerts and cancellations (6.3.7.1.5)',
        {message['info'].get('alert-ind') for message in receipts} == {'true', 'false'}
        and all(message['info'].get('mcdata-client-id') for message in receipts),
    )
    alert_rejections = [
        (response['status'], response['info'].get('alert-ind'), header(response, 'warning'))
        for message in alerts_up
        for response in answers(message)
        if response['status'] >= 300
    ]
    check(
        'unauthorised alerts get 403 with alert-ind false and unauthorised cancellations 403 with alert-ind true (16.2.3.1-2)',
        any(status_code == 403 and alert == 'false' for status_code, alert, _ in alert_rejections)
        and any(status_code == 403 and alert == 'true' for status_code, alert, _ in alert_rejections),
    )
    check(
        'alert rejections 168 (preconfigured use only) and 120 (not a member)',
        any('"168 ' in warning for _, _, warning in alert_rejections)
        and any('"120 ' in warning for _, _, warning in alert_rejections),
    )
    rejected = [
        (response['status'], header(response, 'warning'))
        for message in sds_up
        for response in answers(message)
        if response['status'] > 300
    ]
    expected = {
        '200': 403,
        '202': 403,
        '229': 403,
        '203': 403,
        '218': 403,
        '230': 403,
        '204': 403,
        '116': 403,
        '206': 403,
        '207': 488,
        '163': 404,
        '145': 403,
        '238': 403,
        '240': 403,
        '241': 403,
        '242': 403,
        '201': 403,
        '208': 403,
        '217': 403,
        '120': 403,
        '198': 403,
    }
    for code, status in expected.items():
        check(
            f'rejection {status}/{code}',
            any(status_code == status and f'"{code} ' in warning for status_code, warning in rejected),
        )
    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        decode_errors=decode_errors,
        counts=dict(
            sip_messages=len(messages),
            sds_uplink=len(sds_up),
            sds_downlink=len(sds_down),
            notifications_uplink=len(notes_up),
            notifications_downlink=len(notes_down),
            rejections=collections.Counter(f'{status_code} {warning}' for status_code, warning in rejected),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'counts'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
