#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify private-call SIP signaling from a clear-SIP server-side capture.

The private call of TS 24.379 clause 11.1.1: originating INVITEs naming one called party (clause 11.1.1.2.1.1), the
controlling function's INVITE to the callee with the calling user and a focus Contact (clause 11.1.1.4.1), answer modes
forwarded, the final responses and warnings of table 4.4.2-2, release by BYE; the first-to-answer call (clause
11.1.1.2.1.1 steps 10 and 15, clause 11.1.1.4.1 step 3, clause 11.1.1.4.2); the emergency private call (clauses
6.2.8.3.2, 6.2.8.3.3 and 11.1.1.4.3 to 11.1.1.4.6); and optionally a session refresh (RFC 4028).

Usage: verify_private_call.py capture.pcap --service sip:mcptt@DOMAIN --output result.json

Self-contained: reassembles TCP/5060 streams from a classic PCAP without tshark. Requires debug (clear) SIP; TLS
captures cannot be inspected.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import struct
import sys
import xml.etree.ElementTree as ET

INFO_NS = '{urn:3gpp:ns:mcpttInfo:1.0}'
LISTS_NS = '{urn:ietf:params:xml:ns:resource-lists}'


# ------------------------------------------------------------------------------
def tcp_streams(path, port=5060):
    """Reassembles the TCP streams of a capture; port=None keeps every port."""
    raw = Path(path).read_bytes()
    assert len(raw) >= 24, 'truncated PCAP'
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    assert struct.unpack_from(endian + 'I', raw, 20)[0] == 1, 'Ethernet capture required'
    segments = collections.defaultdict(dict)
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        if len(packet) < 34 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        total = struct.unpack_from('!H', ip, 2)[0]
        tcp = ip[ihl:total]
        sport, dport, seq = struct.unpack_from('!HHI', tcp, 0)
        payload = tcp[(tcp[12] >> 4) * 4 :]
        if payload and (port is None or port in (sport, dport)):
            flow = (ip[12:16], sport, ip[16:20], dport)
            segments[flow].setdefault(seq, payload)  # drop retransmitted segments
    for flow, parts in segments.items():
        yield flow, b''.join(parts[sequence_number] for sequence_number in sorted(parts))


# ------------------------------------------------------------------------------
def timed_messages(path, port=5060, parser=None):
    """The SIP messages of a capture, parsed (by parser, parse by default), each with the capture time of the
    segment it starts in ('time'), in time order: the order across TCP connections that the order checks need."""
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = raw[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    segments = collections.defaultdict(dict)
    offset = 24
    while offset + 16 <= len(raw):
        seconds, fraction, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        if len(packet) < 34 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        tcp = ip[ihl : struct.unpack_from('!H', ip, 2)[0]]
        sport, dport, seq = struct.unpack_from('!HHI', tcp, 0)
        payload = tcp[(tcp[12] >> 4) * 4 :]
        if payload and (port is None or port in (sport, dport)):
            stamp = seconds + fraction / (1e9 if nano else 1e6)
            segments[(ip[12:16], sport, ip[16:20], dport)].setdefault(seq, (payload, stamp))
    messages = []
    for parts in segments.values():
        stream, starts = b'', []
        for sequence_number in sorted(parts):
            payload, stamp = parts[sequence_number]
            starts.append((len(stream), stamp))
            stream += payload
        at = 0
        for head, body in sip_messages(stream):
            # The search goes on after the message found: messages that begin alike (responses with the same Via)
            # would otherwise all be found at the first of them, and take its time.
            begin = stream.find(head.encode('utf-8', 'replace')[:40], at)
            begin = at if begin < 0 else begin
            at = begin + 1
            stamp = max((time for start, time in starts if start <= begin), default=0.0)
            message = (parser or parse)(head, body)
            message['time'] = stamp
            messages.append(message)
    return sorted(messages, key=lambda message: message['time'])


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
        yield head, stream[end_head + 4 : body_end].decode('utf-8', 'replace')
        offset = body_end


# ------------------------------------------------------------------------------
def parse(head, body):
    """A SIP message as a dict: request or response, line, headers (compact forms expanded), the mcptt-info elements,
    the resource-lists targets and the body.
    """
    lines = head.split('\r\n')
    headers = collections.defaultdict(list)
    for line in lines[1:]:
        if ':' in line:
            name, value = line.split(':', 1)
            headers[
                {'i': 'call-id', 'm': 'contact', 'f': 'from', 't': 'to', 'l': 'content-length'}.get(
                    name.strip().lower(), name.strip().lower()
                )
            ].append(value.strip())
    request = not lines[0].startswith('SIP/2.0')
    info, targets = {}, None
    match = re.search(r'<(?:[\w.-]+:)?mcpttinfo\b.*?</(?:[\w.-]+:)?mcpttinfo\s*>', body, re.S)
    if match:
        for element in ET.fromstring(match.group()).iter():
            name = element.tag.replace(INFO_NS, '')
            if name not in ('mcpttinfo', 'mcptt-Params'):
                info[name] = ''.join(element.itertext()).strip()
    match = re.search(r'<resource-lists\b.*?</resource-lists\s*>', body, re.S)
    if match:
        targets = [entry.get('uri') for entry in ET.fromstring(match.group()).iter(LISTS_NS + 'entry')]
    return dict(
        request=request,
        line=lines[0],
        headers=headers,
        info=info,
        targets=targets,
        body=body,
        method=lines[0].split()[0] if request else headers['cseq'][0].split()[-1],
        status=0 if request else int(lines[0].split()[1]),
        target=lines[0].split()[1] if request else '',
        call_id=headers['call-id'][0] if headers['call-id'] else '',
    )


# ------------------------------------------------------------------------------
def header(message, name):
    """The first value of the header field name of message, or an empty string."""
    values = message['headers'].get(name.lower(), [])
    return values[0] if values else ''


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True, help='MCPTT service URI, e.g. sip:mcptt@mcx.test')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument(
        '--require-refresh',
        action='store_true',
        help='Require an accepted in-dialog session refresh on a private call (S2 fixture)',
    )
    args = parser.parse_args()
    messages = []
    seen = set()
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:  # a message appears on both server and core flows only once here
                seen.add(key)
                messages.append(message)
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    # Initial INVITEs only; in-dialog re-INVITEs (To tag present) are checked separately.
    invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['info'].get('session-type') == 'private'
        and not re.search(r';\s*tag=', header(message, 'to'), re.I)
    ]
    originating = [message for message in invites if message['target'] == args.service]
    terminating = [message for message in invites if message['target'] != args.service]
    finals = collections.defaultdict(list)
    provisionals = collections.defaultdict(list)
    for sip_message in messages:
        if not sip_message['request'] and sip_message['method'] == 'INVITE' and sip_message['status'] >= 200:
            finals[sip_message['call_id']].append(sip_message)
        elif not sip_message['request'] and sip_message['method'] == 'INVITE' and sip_message['status'] > 100:
            provisionals[sip_message['call_id']].append(sip_message)
    check('originating private INVITEs captured', len(originating) > 0)
    check(
        'every originating INVITE names exactly one called party in resource-lists',
        all(message['targets'] is not None and len(message['targets']) == 1 for message in originating),
    )
    # TS 24.379 clause 11.1.1.2.1.1 step 14 c): the client's mcptt-info names the session type (and its anyExt
    # elements) only; the participating function adds the calling user (clause 11.1.1.3.1.1).
    check(
        'originating INVITEs carry no calling user or group identity',
        all(
            'mcptt-calling-user-id' not in message['info'] and 'mcptt-calling-group-id' not in message['info']
            for message in originating
        ),
    )
    check(
        'originating INVITEs carry MCPTT feature tags and ICSI',
        all(
            '+g.3gpp.mcptt' in ' '.join(message['headers']['accept-contact'])
            and 'urn:urn-7:3gpp-service.ims.icsi.mcptt' in header(message, 'p-preferred-service')
            for message in originating
        ),
    )
    check('terminating private INVITEs captured', len(terminating) > 0)
    check(
        'terminating INVITEs address the callee in mcptt-request-uri with calling user',
        all(
            message['info'].get('mcptt-request-uri')
            and message['info'].get('mcptt-calling-user-id')
            and message['info']['mcptt-request-uri'] != message['info']['mcptt-calling-user-id']
            and 'mcptt-calling-group-id' not in message['info']
            for message in terminating
        ),
    )
    check(
        'terminating INVITEs carry no resource-lists body', all(message['targets'] is None for message in terminating)
    )
    check(
        'terminating INVITEs present a focus Contact with the private session URI',
        all(
            'isfocus' in header(message, 'contact') and ';mcptt-session=' in header(message, 'contact')
            for message in terminating
        ),
    )
    check(
        'private SDP offers are clear RTP/AVP without MIKEY key management',
        all('RTP/SAVP' not in message['body'] and 'a=key-mgmt' not in message['body'] for message in invites),
    )

    # ------------------------------------------------------------------------------
    def modes(group, name):
        """How often each value of the header field name occurs in the messages of group."""
        return collections.Counter(header(message, name) for message in group if header(message, name))

    for name in ('Answer-Mode', 'Priv-Answer-Mode'):
        orig, term = modes(originating, name), modes(terminating, name)
        check(
            f'{name} values requested by callers are forwarded to callees',
            bool(orig) and all(term[value] > 0 for value in orig),
        )
    check(
        'Answer-Mode Auto, Answer-Mode Manual and Priv-Answer-Mode Auto all exercised',
        {'Auto', 'Manual'} <= set(modes(originating, 'Answer-Mode'))
        and modes(originating, 'Priv-Answer-Mode')['Auto'] > 0,
    )

    outcomes = []
    for sip_message in originating:
        for response in finals.get(sip_message['call_id'], []):
            outcomes.append((response['status'], header(response, 'warning')))
    check(
        'originating INVITEs receive 200 OK with isfocus session Contact',
        any(status_code == 200 for status_code, _ in outcomes)
        and all(
            'isfocus' in header(response, 'contact')
            for message in originating
            for response in finals.get(message['call_id'], [])
            if response['status'] == 200
        ),
    )
    for code, warning in [
        (480, '110 user declined the call invitation'),
        (403, '107 '),
        (403, '126 '),
        (403, '143 '),
        (403, '144 '),
        (403, '127 '),
        (403, '159 '),
        (408, None),
        (486, None),
        (480, None),
    ]:
        label = f'caller receives {code}' + (f' with warning {warning.strip()}' if warning else '')
        check(
            label,
            any(
                status_code == code and (warning is None or warning in warning_text)
                for status_code, warning_text in outcomes
            ),
        )
    # TS 24.379 clause 11.1.1.4.2: a caller gets 180 (Ringing) only when its callee rings.
    # The caller is named on the terminating leg only (step 14 c) above), so a call is matched by its callee.
    rang = {
        message['info'].get('mcptt-request-uri')
        for message in terminating
        if any(response['status'] == 180 for response in provisionals.get(message['call_id'], []))
    }
    caller_ringing = [
        (message['targets'] or [''])[0]
        for message in originating
        if any(response['status'] == 180 for response in provisionals.get(message['call_id'], []))
    ]
    check('callers get 180 (Ringing) only for a callee that rang', all(callee in rang for callee in caller_ringing))
    # TS 24.379 clauses 6.3.2.1.5 and 6.3.3.2.3: the service's identity in the provisional responses other than
    # 100 (Trying) and the 200 (OK), whose Supported also has tdialog, norefersub, explicitsub and nosub.
    initial_cseq = {message['call_id']: header(message, 'cseq') for message in originating}
    to_callers = [
        response
        for message in originating
        for response in provisionals.get(message['call_id'], []) + finals.get(message['call_id'], [])
        if response['status'] < 300
    ]
    check(
        'provisional and 200 responses to callers assert the service identity',
        bool(to_callers)
        and all(
            args.service.replace('sips:', 'sip:') in header(response, 'p-asserted-identity').replace('sips:', 'sip:')
            for response in to_callers
        ),
    )
    check(
        '200 responses to callers support tdialog, norefersub, explicitsub and nosub',
        all(
            {'tdialog', 'norefersub', 'explicitsub', 'nosub'}
            <= {tag.strip().lower() for value in response['headers']['supported'] for tag in value.split(',')}
            for response in to_callers
            # TS 24.379 clause 6.3.3.2.3.2: the 200 (OK) to the initial INVITE; a re-INVITE's is by TS 24.229 alone.
            if response['status'] == 200
            and response['call_id'] in initial_cseq
            and header(response, 'cseq') == initial_cseq[response['call_id']]
        ),
    )
    # RFC 3261 section 20.4 with TS 24.229: Alert-Info belongs in an INVITE or a 180 (Ringing), never in a final
    # answer (the ambient listening 200 once copied the INVITE's).
    check(
        'no 2xx answer to an INVITE carries Alert-Info',
        not any(
            not message['request']
            and message['method'] == 'INVITE'
            and 200 <= message['status'] < 300
            and header(message, 'alert-info')
            for message in messages
        ),
    )
    callee_declines = [
        response
        for message in terminating
        for response in finals.get(message['call_id'], [])
        if response['status'] == 480 and '110 user declined' in header(response, 'warning')
    ]
    check('callee decline (480 + warning 110) is observed on the terminating leg', bool(callee_declines))

    private_uris = {
        re.search(r'<([^>]+)>', header(response, 'contact')).group(1)
        for message in originating
        for response in finals.get(message['call_id'], [])
        if response['status'] == 200
    }
    subscribes = [
        message
        for message in messages
        if message['request'] and message['method'] == 'SUBSCRIBE' and 'conference' in header(message, 'event')
    ]
    check(
        'no conference-event SUBSCRIBE targets a private session URI',
        bool(private_uris) and not any(message['target'] in private_uris for message in subscribes),
    )
    private_calls = {message['call_id'] for message in invites}
    byes = [
        message
        for message in messages
        if message['request'] and message['method'] == 'BYE' and message['call_id'] in private_calls
    ]
    bye_ok = {
        message['call_id']
        for message in messages
        if not message['request'] and message['method'] == 'BYE' and message['status'] == 200
    }
    check(
        'private dialogs are released with BYE answered 200 OK',
        bool(byes) and all(message['call_id'] in bye_ok for message in byes),
    )

    # First-to-answer call (TS 24.379 clause 11.1.1.2.1.1 steps 10 and 15, clause 11.1.1.4.1
    # step 3, clause 11.1.1.4.2): list of two or more invitees, forced manual
    # commencement, 183 on first ringing, called party identified in the 200 OK
    # and every unselected invitee cancelled or released.
    fta = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['info'].get('session-type') == 'first-to-answer'
    ]
    fta_orig = [message for message in fta if message['target'] == args.service]
    fta_term = [message for message in fta if message['target'] != args.service]
    if fta:
        check(
            'first-to-answer INVITEs name two or more invitees in resource-lists',
            bool(fta_orig) and all(message['targets'] and len(message['targets']) >= 2 for message in fta_orig),
        )
        check(
            'first-to-answer invitees receive Priv-Answer-Mode Manual and no resource-lists',
            bool(fta_term)
            and all(
                header(message, 'priv-answer-mode') == 'Manual'
                and message['targets'] is None
                and message['info'].get('mcptt-calling-user-id')
                for message in fta_term
            ),
        )
        check('first-to-answer offers are clear RTP/AVP', all('RTP/SAVP' not in message['body'] for message in fta))
        progress = {
            message['call_id']
            for message in messages
            if not message['request'] and message['method'] == 'INVITE' and message['status'] == 183
        }
        answered = [
            (offer, response)
            for offer in fta_orig
            for response in finals.get(offer['call_id'], [])
            if response['status'] == 200
        ]
        check(
            'first-to-answer caller receives 183 Session Progress before answer',
            bool(answered) and all(offer['call_id'] in progress for offer, _ in answered),
        )
        check(
            'first-to-answer callers get no 180 (Ringing)',
            not any(
                response['status'] == 180 for offer in fta_orig for response in provisionals.get(offer['call_id'], [])
            ),
        )
        check(
            'first-to-answer 200 OK identifies an invitee in mcptt-called-party-id',
            bool(answered)
            and all(
                response['info'].get('mcptt-called-party-id') in (offer['targets'] or [])
                for offer, response in answered
            ),
        )
        term_ids = {message['call_id'] for message in fta_term}
        cancels = {
            message['call_id']
            for message in messages
            if message['request'] and message['method'] == 'CANCEL' and message['call_id'] in term_ids
        }
        loser_byes = [
            message
            for message in messages
            if message['request']
            and message['method'] == 'BYE'
            and message['call_id'] in term_ids
            and message['info'].get('release-reason')
        ]
        check('unselected first-to-answer invitees are cancelled', bool(cancels))
        check(
            'any release of an unselected answered invitee carries "not selected for call"',
            all(message['info']['release-reason'] == 'not selected for call' for message in loser_byes),
        )
        fta_outcomes = [
            (response['status'], header(response, 'warning'))
            for offer in fta_orig
            for response in finals.get(offer['call_id'], [])
        ]
        for code, warning in [(480, None), (403, '153 '), (403, '156 ')]:
            check(
                f'first-to-answer caller receives {code}' + (f' with warning {warning.strip()}' if warning else ''),
                any(
                    status_code == code and (warning is None or warning in warning_text)
                    for status_code, warning_text in fta_outcomes
                ),
            )
        private_calls |= {message['call_id'] for message in fta}

    # Emergency private call (TS 24.379 clauses 6.2.8.3.2, 6.2.8.3.3 and 11.1.1.4.3 to 11.1.1.4.6): emergency-ind
    # and emergency Resource-Priority on setup, explicit downgrade in-dialog,
    # SIP INFO alert correction and 403 carrying the unchanged state.
    emergency = [message for message in invites if message['info'].get('emergency-ind') == 'true']
    if emergency:
        rp = {header(message, 'resource-priority') for message in emergency}
        check('emergency private INVITEs carry a single emergency Resource-Priority', len(rp) == 1 and '' not in rp)
        emergency_rp = next(iter(rp))
        check(
            'emergency private INVITEs reach the callee with emergency-ind and alert-ind',
            any(message in terminating for message in emergency)
            and all('alert-ind' in message['info'] for message in emergency if message in originating),
        )
        in_dialog = [
            message
            for message in messages
            if message['request']
            and message['method'] == 'INVITE'
            and re.search(r';\s*tag=', header(message, 'to'), re.I)
            and message['info'].get('session-type') == 'private'
        ]
        downgrades = [message for message in in_dialog if message['info'].get('emergency-ind') == 'false']
        upgrades = [message for message in in_dialog if message['info'].get('emergency-ind') == 'true']
        check(
            'in-dialog emergency cancellation signals emergency-ind false with non-emergency Resource-Priority',
            bool(downgrades) and all(header(message, 'resource-priority') != emergency_rp for message in downgrades),
        )
        check(
            'in-dialog emergency upgrade signals emergency-ind true with emergency Resource-Priority',
            bool(upgrades) and all(header(message, 'resource-priority') == emergency_rp for message in upgrades),
        )
        rejected_changes = [
            response
            for message in in_dialog
            for response in messages
            if not response['request']
            and response['method'] == 'INVITE'
            and response['call_id'] == message['call_id']
            and header(response, 'cseq') == header(message, 'cseq')
            and response['status'] == 403
        ]
        check(
            'rejected emergency cancellation reports the unchanged emergency state',
            any(response['info'].get('emergency-ind') == 'true' for response in rejected_changes),
        )
        infos = [
            message
            for message in messages
            if message['request'] and message['method'] == 'INFO' and message['call_id'] in private_calls
        ]
        check(
            'pending alert withdrawn by SIP INFO with the mcptt-info package and alert-ind false',
            any(
                header(message, 'info-package') == 'g.3gpp.mcptt-info' and message['info'].get('alert-ind') == 'false'
                for message in infos
            ),
        )
        check(
            'unauthorised emergency private call rejected with 403',
            any(
                status_code == 403 and 'emergency private call not authorized' in warning_text
                for status_code, warning_text in outcomes
            ),
        )
        check(
            '149 SIP INFO request pending accompanies the correction',
            any(
                '149 SIP INFO request pending' in header(response, 'warning')
                for response in messages
                if not response['request'] and response['status'] == 200
            ),
        )

    # RFC 4028 refresh: an in-dialog UPDATE or re-INVITE on a private dialog,
    # answered 200 with Session-Expires, after the dialog was established.
    established = {
        message['call_id']
        for message in messages
        if not message['request']
        and message['method'] == 'INVITE'
        and message['status'] == 200
        and message['call_id'] in private_calls
    }
    refreshes = []
    for sip_message in messages:
        if not (
            sip_message['request']
            and sip_message['method'] in ('UPDATE', 'INVITE')
            and sip_message['call_id'] in established
            and re.search(r';\s*tag=', header(sip_message, 'to'), re.I)
        ):
            continue
        if any(
            not response['request']
            and response['call_id'] == sip_message['call_id']
            and header(response, 'cseq') == header(sip_message, 'cseq')
            and response['status'] == 200
            and re.match(r'[1-9][0-9]*(?:\s*;|\s*$)', header(response, 'session-expires'))
            for response in messages
        ):
            refreshes.append(sip_message)
    if args.require_refresh:
        check('private dialog refreshed in-dialog and answered 200 with Session-Expires', bool(refreshes))

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            sip_messages=len(messages),
            originating_invites=len(originating),
            terminating_invites=len(terminating),
            private_byes=len(byes),
            accepted_refreshes=len(refreshes),
            first_to_answer_invites=len(fta),
            caller_final_responses=dict(
                collections.Counter(f'{status_code} {warning_text}'.strip() for status_code, warning_text in outcomes)
            ),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
