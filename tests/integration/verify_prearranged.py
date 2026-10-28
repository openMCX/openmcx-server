#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify normal prearranged SIP call evidence from a server-side capture.

The prearranged group call of TS 24.379 clause 10.1.1: originating INVITEs with mcptt-info, the controlling function's
fan-out INVITEs to each member with the calling group, the calling user and an isfocus Contact (clauses 10.1.1.4.1.1 and
6.3.3.1.2) and Answer-Mode Auto from the terminating participating function (clause 10.1.1.3.2), the originator's 200
with the allocated session URI after a member accepted (or warning 123 for an existing session, table 4.4.2-2), one BYE
per dialog direction, optionally session refreshes and conference event notifications (clause 10.1.3.4.2), and with
--require-isolated-media that the controlling function forwards RTP only within the group it came from.

Usage: verify_prearranged.py capture.pcap --output validation.json
Needs tshark (or MCX_TSHARK), plaintext SIP or configured TLS decryption.
Retransmissions are deduplicated by dialog/CSeq/method/status and tags.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


# ------------------------------------------------------------------------------
def sip_message(raw, packet):
    """Parse one SIP message from tshark's hex bytes: start line, headers (compact forms expanded), the mcptt-info
    fields and the body; None if it is not a complete SIP message.
    """
    text = bytes.fromhex(raw).decode('utf-8', errors='replace')
    if not re.match(r'(?:SIP/2\.0 |[A-Z]+ \S+ SIP/2\.0)', text):
        return None
    head, separator, body = text.partition('\r\n\r\n')
    if not separator:
        head, separator, body = text.partition('\n\n')
    lines = re.split(r'\r?\n', head)
    headers, last = {}, None
    for line in lines[1:]:
        if line[:1] in (' ', '\t') and headers:
            headers[last] += ' ' + line.strip()
        elif ':' in line:
            name, value = line.split(':', 1)
            last = name.lower()
            headers[last] = headers.get(last, '') + value.strip()
    for short, long in [('i', 'call-id'), ('m', 'contact'), ('f', 'from'), ('t', 'to')]:
        if short in headers:
            headers.setdefault(long, headers[short])
    if not headers.get('call-id') or not headers.get('cseq'):
        return None
    fields = {}
    # Locate the XML document inside either single-part or MIME multipart SIP.
    match = re.search(r'<(?:[\w.-]+:)?mcpttinfo\b.*?</(?:[\w.-]+:)?mcpttinfo\s*>', body, re.S)
    if match:
        root = ET.fromstring(match.group())
        for element in root.iter():
            name = element.tag.rsplit('}', 1)[-1]
            value = ''.join(element.itertext()).strip()
            if name not in ('mcpttinfo', 'mcptt-Params'):
                fields[name] = value
    request = not lines[0].startswith('SIP/2.0')
    return dict(
        packet=packet,
        line=lines[0],
        headers=headers,
        fields=fields,
        body=body,
        method=lines[0].split()[0] if request else headers['cseq'].split()[-1],
        status=0 if request else int(lines[0].split()[1]),
        target=lines[0].split()[1] if request else '',
    )


# ------------------------------------------------------------------------------
def option_tags(value):
    """The option tags of a Supported header field value, lower case."""
    return {tag.strip().lower() for tag in value.split(',') if tag.strip()}


# ------------------------------------------------------------------------------
def raw_sip_values(node):
    """Yield the raw hex of every SIP message in tshark's JSON output for one packet."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == 'sip_raw':
                if value and isinstance(value[0], str):
                    yield value[0]
                elif isinstance(value, list):
                    for entry in value:
                        if entry and isinstance(entry[0], str):
                            yield entry[0]
            else:
                yield from raw_sip_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from raw_sip_values(value)


# ------------------------------------------------------------------------------
def uri(value):
    """The first SIP or HTTP URI in a header field value, preferring a bracketed one."""
    bracketed = re.search(r'<((?:sips?|https?):[^>]+)>', value)
    if bracketed:
        return bracketed.group(1)
    match = re.search(r'(?:sips?|https?):[^\s<>]+', value)
    return match.group() if match else ''


# ------------------------------------------------------------------------------
def identity_uri(value):
    """The URI of a From or To value, without the tag of a bare addr-spec."""
    # SIP From/To permit bare addr-spec; its tag is a header parameter,
    # unlike a session-identifying URI parameter inside Contact brackets.
    return uri(value) if '<' in value else re.split(r';\s*tag=', uri(value), flags=re.I)[0]


# ------------------------------------------------------------------------------
def audio_sdp(message):
    """Extract the single negotiated IPv4 audio stream from multipart SDP."""
    connection = None
    audio = None
    current = ''
    for line in re.split(r'\r?\n', message.get('body', '')):
        if line.startswith('m='):
            parts = line[2:].split()
            current = parts[0]
            if current == 'audio':
                if audio is not None:
                    raise ValueError('media isolation verifier requires one audio m-line per leg')
                audio = dict(
                    address=connection,
                    port=int(parts[1]),
                    payloads={int(payload_type) for payload_type in parts[3:]},
                    octet_aligned=False,
                )
        elif line.startswith('c=IN IP4 '):
            value = line.split()[2]
            if not current:
                connection = value
            elif current == 'audio' and audio:
                audio['address'] = value
        elif current == 'audio' and audio and line.startswith('a=fmtp:'):
            if re.search(r'(?:\s|;)octet-align=1(?:;|\s|$)', line):
                audio['octet_aligned'] = True
    if audio and (not audio['address'] or not audio['port']):
        raise ValueError('media isolation verifier needs an enabled IPv4 audio endpoint')
    return audio


# ------------------------------------------------------------------------------
def media_legs(messages):
    """The confirmed prearranged legs (INVITE and its 200) with the client and server audio endpoints, the group and the
    frames between the 200 and the BYE.
    """
    legs = []
    seen = set()
    for invite in messages:
        headers, fields = invite['headers'], invite['fields']
        if invite['method'] != 'INVITE' or invite['status'] or fields.get('session-type') != 'prearranged':
            continue
        if re.search(r';\s*tag=', headers.get('to', ''), re.I) or headers['call-id'] in seen:
            continue
        seen.add(headers['call-id'])
        answers = [
            message
            for message in messages
            if message['status'] == 200
            and message['method'] == 'INVITE'
            and message['headers']['call-id'] == headers['call-id']
            and message['headers']['cseq'] == headers['cseq']
        ]
        if not answers:
            continue
        answer = answers[0]
        offered, accepted = audio_sdp(invite), audio_sdp(answer)
        if not offered or not accepted:
            raise ValueError('confirmed call lacks captured SDP offer/answer for isolation verification')
        fanout = bool(fields.get('mcptt-calling-group-id'))
        client, server = (accepted, offered) if fanout else (offered, accepted)
        # Closing request is authoritative for accepting fresh media; a
        # subsequent packet on that terminated endpoint is reported explicitly.
        endings = [
            message['frame']
            for message in messages
            if message['method'] == 'BYE'
            and not message['status']
            and message['headers']['call-id'] == headers['call-id']
        ]
        # The legs of one call share the session identity of the controlling function's isfocus Contact (TS 24.379
        # clause 6.3.3.2.3.2), in the INVITE to a member or the 200 (OK) to the originator. Under XML protection
        # (TS 24.379 clause 6.6.2) the group identity is encrypted for each leg's recipient and cannot match.
        focus = re.search(r';mcptt-session=([^;>]+)', (invite if fanout else answer)['headers'].get('contact', ''))
        legs.append(
            dict(
                group=focus.group(1)
                if focus
                else (fields.get('mcptt-calling-group-id') if fanout else fields.get('mcptt-request-uri')),
                client=client,
                server=server,
                start=answer['frame'],
                end=min(endings) if endings else float('inf'),
                dialog=headers['call-id'],
            )
        )
    return legs


# ------------------------------------------------------------------------------
def verify_media_packets(legs, packets):
    """Check forwarding against independently captured originating RTP bytes."""
    errors = []
    inbound = {}
    ssrc_groups = {}
    delivery = {}
    incoming_count = outgoing_count = 0
    all_server_addresses = {leg['server']['address'] for leg in legs}
    for packet in packets:
        frame = packet['frame']
        active = [leg for leg in legs if leg['start'] <= frame < leg['end']]

        # ------------------------------------------------------------------------------
        def matches(endpoint, address, port):
            """The endpoint has this address and port."""
            return endpoint['address'] == address and endpoint['port'] == port

        incoming = [
            leg
            for leg in active
            if matches(leg['client'], packet['src'], packet['sport'])
            and matches(leg['server'], packet['dst'], packet['dport'])
        ]
        outgoing = [
            leg
            for leg in active
            if matches(leg['server'], packet['src'], packet['sport'])
            and matches(leg['client'], packet['dst'], packet['dport'])
        ]
        prefix = f'RTP frame {frame}: '
        if len(incoming) + len(outgoing) != 1:
            if packet['src'] in all_server_addresses or packet['dst'] in all_server_addresses:
                errors.append(prefix + 'no unique active negotiated leg')
            continue
        leg = (incoming or outgoing)[0]
        group = leg['group']
        if packet['pt'] not in leg['client']['payloads'] or packet['pt'] not in leg['server']['payloads']:
            errors.append(prefix + 'payload type outside negotiated leg')
        key = (packet['ssrc'], packet['seq'], packet['timestamp'])
        if incoming:
            incoming_count += 1
            previous = ssrc_groups.setdefault(packet['ssrc'], group)
            if previous != group:
                errors.append(prefix + 'same audio SSRC used across groups')
            inbound.setdefault(key, []).append(
                (group, packet['payload'], leg['client']['octet_aligned'], frame, leg['dialog'])
            )
        else:
            outgoing_count += 1
            sources = [source for source in inbound.get(key, []) if source[3] < frame]
            matching = [
                source
                for source in sources
                if source[0] == group
                and source[1] == packet['payload']
                and source[2] == leg['client']['octet_aligned']
                and source[4] != leg['dialog']
            ]
            if not matching:
                errors.append(prefix + 'forwarded SSRC/sequence/timestamp/payload has no same-group source')
            else:
                record = delivery.setdefault(group, dict(packets=0, first_frame=frame, last_frame=frame, ssrcs=set()))
                record['packets'] += 1
                record['last_frame'] = frame
                record['ssrcs'].add(packet['ssrc'])
    if len(delivery) < 2:
        errors.append('Media isolation requires successfully matched forwarding in at least two groups')
    groups = list(delivery.values())
    overlapping = any(
        max(first['first_frame'], second['first_frame']) < min(first['last_frame'], second['last_frame'])
        for index, first in enumerate(groups)
        for second in groups[index + 1 :]
    )
    if not overlapping:
        errors.append('No overlapping forwarded-media intervals from distinct groups')
    return dict(
        passed=not errors,
        errors=errors,
        negotiated_legs=len(legs),
        inbound_rtp=incoming_count,
        forwarded_rtp=outgoing_count,
        groups={group: {**value, 'ssrcs': sorted(value['ssrcs'])} for group, value in delivery.items()},
        limitation='Exact payload comparison requires equal negotiated AMR packing across sender and receiver.',
    )


# ------------------------------------------------------------------------------
def verify_isolated_media(messages, args):
    """Dissect the RTP of the negotiated legs with tshark and check its forwarding per group."""
    legs = media_legs(messages)
    ports = sorted({endpoint['port'] for leg in legs for endpoint in [leg['client'], leg['server']]})
    command = [args.tshark, '-r', str(args.capture)]
    for preference in args.tshark_option:
        command += ['-o', preference]
    for port in ports:
        command += ['-d', f'udp.port=={port},rtp']
    fields = [
        'frame.number',
        'ip.src',
        'ip.dst',
        'udp.srcport',
        'udp.dstport',
        'rtp.ssrc',
        'rtp.seq',
        'rtp.timestamp',
        'rtp.p_type',
        'rtp.payload',
    ]
    command += ['-Y', 'rtp && udp', '-T', 'fields', '-E', 'occurrence=f']
    for field in fields:
        command += ['-e', field]
    output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    packets = []
    for line in output.splitlines():
        values = line.split('\t')
        if len(values) != len(fields):
            raise ValueError('incomplete RTP dissection in isolation capture')
        frame, src, dst, sport, dport, ssrc, seq, timestamp, pt, payload = values
        packets.append(
            dict(
                frame=int(frame),
                src=src,
                dst=dst,
                sport=int(sport),
                dport=int(dport),
                ssrc=int(ssrc, 0),
                seq=int(seq),
                timestamp=int(timestamp),
                pt=int(pt),
                payload=bytes.fromhex(payload.replace(':', '')),
            )
        )
    return verify_media_packets(legs, packets)


# ------------------------------------------------------------------------------
def verify(messages, require_refresh=False, require_conference=False):
    """Run the signalling checks on the decoded messages and return the result with counts and limitations."""
    errors = []
    checks = []

    # ------------------------------------------------------------------------------
    def check(condition, description):
        """Record description as a passed check or an error."""
        (checks if condition else errors).append(description)

    unique = []
    seen = set()
    retransmissions = 0
    for message in messages:
        headers = message['headers']
        key = (headers['call-id'], headers['cseq'], message['status'], headers.get('from'), headers.get('to'))
        if key in seen:
            retransmissions += 1
            continue
        seen.add(key)
        unique.append(message)
    requests = [
        message
        for message in unique
        if message['method'] == 'INVITE'
        and not message['status']
        and message['fields'].get('session-type') == 'prearranged'
        and not re.search(r';\s*tag=', message['headers'].get('to', ''), re.I)
    ]
    fanouts = [message for message in requests if message['fields'].get('mcptt-calling-group-id')]
    origins = [
        message
        for message in requests
        if message['fields'].get('mcptt-client-id') and not message['fields'].get('mcptt-calling-group-id')
    ]
    check(bool(origins), 'At least one originating prearranged INVITE decoded')
    check(bool(fanouts), 'At least one fanout with separate calling-group decoded')
    success = [message for message in unique if message['method'] == 'INVITE' and message['status'] == 200]
    groups = {message['fields'].get('mcptt-request-uri') for message in origins}
    focus_uris = set()
    for message in fanouts:
        fields, headers = message['fields'], message['headers']
        prefix = f"packet {message['packet']} fanout"
        target = fields.get('mcptt-request-uri', '')
        check(
            bool(target) and target != fields.get('mcptt-calling-group-id'),
            prefix + ': destination user differs from calling group',
        )
        check(fields['mcptt-calling-group-id'] in groups, prefix + ': calling group matches captured originating group')
        check(bool(fields.get('mcptt-calling-user-id')), prefix + ': calling user present')
        check(headers.get('answer-mode', '').split(';')[0].strip().lower() == 'auto', prefix + ': Answer-Mode Auto')
        check('isfocus' in headers.get('contact', '').lower(), prefix + ': Contact has isfocus')
        focus_uris.add(uri(headers.get('contact', '')))
    completed = 0
    for origin in origins:
        # TS 24.379 clause 10.1.1.4.2: the controlling function answers the originator with the 200 (OK) only; it
        # sends no 180 (Ringing).
        check(
            not any(
                message['method'] == 'INVITE'
                and message['status'] == 180
                and message['headers']['call-id'] == origin['headers']['call-id']
                for message in unique
            ),
            f"packet {origin['packet']} originating INVITE: no 180 (Ringing) from the controlling function",
        )
        replies = [message for message in success if message['headers']['call-id'] == origin['headers']['call-id']]
        if not replies:
            continue  # A deliberately cancelled/rejected attempt need not receive 200.
        completed += 1
        reply = replies[0]
        contact = reply['headers'].get('contact', '')
        session = uri(contact)
        prefix = f"packet {reply['packet']} originator final 200"
        prior_session = any(
            uri(message['headers'].get('contact', '')) == session and message['packet'] < origin['packet']
            for message in fanouts
        )
        rejoin = prior_session and session == uri(origin['target'])
        check(
            bool(session) and (session != uri(origin['target']) or rejoin),
            prefix + ': allocated session URI (or retained rejoin URI)',
        )
        check('isfocus' in contact.lower(), prefix + ': Contact has isfocus')
        # TS 24.379 clauses 6.3.2.1.5.2 and 6.3.3.2.3.2: the service's identity and the option tags of the 200 (OK).
        check(bool(reply['headers'].get('p-asserted-identity')), prefix + ': P-Asserted-Identity present')
        check(
            {'tdialog', 'norefersub', 'explicitsub', 'nosub'} <= option_tags(reply['headers'].get('supported', '')),
            prefix + ': Supported has tdialog, norefersub, explicitsub and nosub',
        )
        check(session in focus_uris, prefix + ': session URI matches fanout')
        matching_fanouts = [message for message in fanouts if uri(message['headers'].get('contact', '')) == session]
        fanout_ids = {message['headers']['call-id'] for message in matching_fanouts}
        accepted = [
            message
            for message in success
            if message['headers']['call-id'] in fanout_ids and origin['packet'] < message['packet'] < reply['packet']
        ]
        # An ordinary join of an existing session need not trigger new fanout.
        ongoing = '123 ' in reply['headers'].get('warning', '')
        if ongoing:
            # TS 24.379 table 4.4.2-2 and clause 10.1.1.4.2 step j): the text of the join's warning 123.
            check(
                '"123 MCPTT session already exists"' in reply['headers'].get('warning', ''),
                prefix + ': the join\'s warning 123 reads "MCPTT session already exists"',
            )
        check(
            ongoing or rejoin or bool(accepted),
            prefix + ': follows target acceptance (or existing-session join/rejoin)',
        )
    check(completed > 0, 'At least one originating call completed')
    byes = {}
    for message in unique:
        if message['method'] == 'BYE' and not message['status']:
            headers = message['headers']
            direction = (headers['call-id'], headers.get('from', ''), headers.get('to', ''))
            byes.setdefault(direction, set()).add(headers['cseq'])
    check(
        all(len(cseqs) == 1 for cseqs in byes.values()),
        'No repeated BYE with different CSeq on the same dialog direction',
    )
    refreshes = []
    for request in unique:
        headers = request['headers']
        if request['status'] or request['method'] not in ('UPDATE', 'INVITE'):
            continue
        if not re.search(r';\s*tag=', headers.get('to', ''), re.I):
            continue
        prior = [
            message
            for message in success
            if message['headers']['call-id'] == headers['call-id']
            and message['headers']['cseq'] != headers['cseq']
            and message['packet'] < request['packet']
        ]
        responses = [
            message
            for message in unique
            if message['status'] == 200
            and message['headers']['call-id'] == headers['call-id']
            and message['headers']['cseq'] == headers['cseq']
            and message['packet'] > request['packet']
            and re.match(r'[1-9][0-9]*(?:\s*;|\s*$)', message['headers'].get('session-expires', ''))
        ]
        if prior and responses:
            refreshes.append(request)
    if require_refresh:
        check(bool(refreshes), 'Established-dialog UPDATE/re-INVITE accepted with Session-Expires')
    conferences = [
        message
        for message in unique
        if not message['status']
        and message['method'] == 'NOTIFY'
        and message['headers'].get('event', '').split(';')[0].strip().lower() == 'conference'
    ]
    # RFC 6665 section 4.1.3: a subscriber answers a NOTIFY of its subscription 200, also after the call (until the
    # subscription is terminated), and one of no subscription 481; never 403 or another failure.
    for notify in conferences:
        refused = [
            message['status']
            for message in unique
            if message['status'] >= 300
            and message['method'] == 'NOTIFY'
            and message['headers']['call-id'] == notify['headers']['call-id']
            and message['headers']['cseq'] == notify['headers']['cseq']
        ]
        check(
            all(status == 481 for status in refused),
            f"packet {notify['packet']} conference NOTIFY: answered 200 or 481 only",
        )
    # TS 24.229 and RFC 3261 section 20.4: Alert-Info belongs in an INVITE or a 180 (Ringing), never in a final answer.
    check(
        not any(
            message['method'] == 'INVITE' and 200 <= message['status'] < 300 and message['headers'].get('alert-info')
            for message in unique
        ),
        'No Alert-Info in a 2xx answer to an INVITE',
    )
    if require_conference:
        check(bool(conferences), 'At least one conference NOTIFY decoded')
        identity_map = {
            identity_uri(message['headers'].get('to', '')): message['fields'].get('mcptt-request-uri')
            for message in fanouts
        }
        for origin in origins:
            for response in success:
                if response['headers']['call-id'] == origin['headers']['call-id'] and response['fields'].get(
                    'mcptt-calling-user-id'
                ):
                    identity_map.setdefault(
                        identity_uri(origin['headers'].get('from', '')), response['fields']['mcptt-calling-user-id']
                    )
        namespace = 'urn:ietf:params:xml:ns:conference-info'
        for notify in conferences:
            prefix = f"packet {notify['packet']} conference NOTIFY"
            body = notify.get('body', '')
            check(
                notify['headers'].get('content-type', '').lower().startswith('multipart/')
                and 'application/conference-info+xml' in body.lower()
                and 'application/vnd.3gpp.mcptt-info+xml' in body.lower(),
                prefix + ': both required MIME bodies',
            )
            match = re.search(
                r'<(?:[\w.-]+:)?conference-info\b[^>]*(?:/>|>.*?</(?:[\w.-]+:)?conference-info\s*>)', body, re.S
            )
            check(bool(match), prefix + ': conference XML body present')
            if not match:
                continue
            root = ET.fromstring(match.group())
            group = notify['fields'].get('mcptt-calling-group-id')
            check(root.tag == '{' + namespace + '}conference-info', prefix + ': RFC conference namespace')
            check(root.get('entity') == group and group in groups, prefix + ': entity is calling group')
            target = notify['fields'].get('mcptt-request-uri')
            expected_target = identity_map.get(identity_uri(notify['headers'].get('to', '')))
            check(
                bool(target) and target != group and expected_target == target,
                prefix + ': target MCPTT ID matches notified SIP participant',
            )
    return dict(
        passed=not errors,
        counts=dict(
            decoded_messages=len(messages),
            unique_messages=len(unique),
            retransmissions=retransmissions,
            origin_invites=len(origins),
            fanout_invites=len(fanouts),
            completed_origin_calls=completed,
            bye_directions=len(byes),
            accepted_refreshes=len(refreshes),
            conference_notifications=len(conferences),
        ),
        checks=checks,
        errors=errors,
        limitations=[
            'Normal automatic-answer profile only; not full TS 24.379 conformance.',
            'No BYE observed is allowed for captures stopped before teardown.',
            'Destination MCPTT IDs are checked structurally; SIP identities may differ.',
        ],
    )


# ------------------------------------------------------------------------------
def main():
    """Decode the capture with tshark, verify it and write the validation file; exit status 1 on any error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tshark', default=os.environ.get('MCX_TSHARK') or shutil.which('tshark'))
    parser.add_argument('--require-refresh', action='store_true')
    parser.add_argument('--require-conference', action='store_true')
    parser.add_argument('--require-isolated-media', action='store_true')
    parser.add_argument(
        '--tshark-option',
        action='append',
        default=[],
        help='Additional tshark preference name:value, e.g. tls.keylog_file:path',
    )
    args = parser.parse_args()
    try:
        if not args.tshark:
            raise RuntimeError('tshark unavailable; install it or set MCX_TSHARK')
        command = [
            args.tshark,
            '-r',
            str(args.capture),
            '-o',
            'tcp.desegment_tcp_streams:TRUE',
            '-o',
            'sip.desegment_headers:TRUE',
            '-o',
            'sip.desegment_body:TRUE',
        ]
        for preference in args.tshark_option:
            command += ['-o', preference]
        command += ['-Y', 'sip', '-T', 'json', '-x', '-J', 'frame sip']
        run = subprocess.run(command, check=True, capture_output=True, text=True)
        packets = json.loads(run.stdout)
        messages = []
        for index, packet in enumerate(packets, 1):
            for raw in raw_sip_values(packet):
                message = sip_message(raw, index)
                if message:
                    message['frame'] = int(packet['_source']['layers']['frame']['frame.number'])
                    messages.append(message)
        result = verify(messages, args.require_refresh, args.require_conference)
        result['capture'] = str(args.capture)
        if args.require_isolated_media:
            result['media_isolation'] = verify_isolated_media(messages, args)
            result['errors'] += result['media_isolation']['errors']
            result['passed'] = result['passed'] and result['media_isolation']['passed']
    except (RuntimeError, OSError, ValueError, ET.ParseError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        result = dict(passed=False, errors=[detail], counts={})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], counts=result['counts'], errors=result['errors'])))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
