#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Check a capture of the MCData media plane against TS 24.282 and TS 24.582.

Signalling (TS 24.282): SDS over the media plane (clause 9.2.3: the client offer of clauses 9.2.3.2.1 and 9.2.3.2.3, the
server answer of clause 9.2.3.3.2, the legs of the controlling function of clauses 9.2.3.4.3 and 9.2.3.4.4), emergency
one-to-one and emergency or imminent peril group communications (clauses 6.2.8.1, 6.2.8.3, 6.2.8.4 and 6.3.7.1), file
distribution over the media plane (clause 10.2.5), ad hoc group communications (clause 24) and the warning texts of
clause 4.9.2. Media (TS 24.582 and IETF RFC 4975): the MSRP frames, the MCData bodies in one SEND (TS 24.582 clauses
6.1.1.2.4 and 6.4.1), in-band disposition notifications (clause 6.1.2.5) and the file in a SEND of its own (clause
7.1.2.1).

Decodes the MSRP frames (IETF RFC 4975) and the clause 15 MCData bodies they carry, independently of the C++
implementation. The SIP parsing and the clause 15 decoders are shared with verify_mcdata_sds.py.

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_sds import decode_payload, decode_signalling, header, parse, sip_messages, tcp_streams  # noqa: E402
from verify_private_call import timed_messages  # noqa: E402

SDS_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcdata.sds'
FD_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcdata.fd'
FD_TYPES = ('one-to-one-fd', 'group-fd', 'adhoc-group-fd-session')
ADHOC_TYPES = ('adhoc-group-sds-session', 'adhoc-group-fd-session')


# ------------------------------------------------------------------------------
def msrp_frames(stream):
    """Yields the MSRP requests and responses of one TCP stream (RFC 4975 section 5)."""
    at = 0
    while True:
        start = stream.find(b'MSRP ', at)
        if start < 0:
            return
        head = stream.find(b'\r\n', start)
        if head < 0:
            return
        first = stream[start:head].decode('utf-8', 'replace').split()
        if len(first) < 3:
            at = start + 5
            continue
        transaction = first[1]
        end = stream.find(b'\r\n-------' + transaction.encode(), head)
        if end < 0:
            return
        flag = end + 9 + len(transaction)
        if flag >= len(stream):
            return
        # Offsets inside the frame, which does not start at the head of the stream.
        frame = stream[start : flag + 1]
        first_line, last_line = head - start, end - start
        blank = frame.find(b'\r\n\r\n', first_line)
        headers, body = {}, b''
        header_text = (
            frame[first_line + 2 : last_line] if blank < 0 or blank > last_line else frame[first_line + 2 : blank + 2]
        )
        if 0 <= blank < last_line:
            body = frame[blank + 4 : last_line]
        for line in header_text.decode('utf-8', 'replace').split('\r\n'):
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.strip().lower()] = value.strip()
        yield dict(transaction=transaction, kind=first[2], headers=headers, body=body, continuation=chr(stream[flag]))
        at = flag + 1


# ------------------------------------------------------------------------------
def reverse(connection):
    """The other direction of a TCP connection (source address and port, destination address and port)."""
    source, source_port, destination, destination_port = connection
    return destination, destination_port, source, source_port


# ------------------------------------------------------------------------------
def bodies_of(frame):
    """The MIME bodies of an MSRP SEND by content type (TS 24.582 clause 6.4.1)."""
    content_type = frame['headers'].get('content-type', '')
    if not content_type.startswith('multipart/'):
        return {content_type: frame['body']} if content_type else {}
    boundary = re.search(r'boundary="?([^";]+)"?', content_type)
    if not boundary:
        return {}
    out, marker = {}, b'--' + boundary.group(1).encode()
    for chunk in frame['body'].split(marker)[1:]:
        if chunk.startswith(b'--'):
            break
        head = chunk.find(b'\r\n\r\n')
        if head < 0:
            continue
        found = re.search(rb'(?i)content-type:\s*([^\r\n;]+)', chunk[:head])
        if found:
            out[found.group(1).decode().strip()] = chunk[head + 4 : -2]
    return out


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the report; exit status 1 on any failure or decode error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen, frames = [], set(), []
    # The MSRP connections use ephemeral ports, so every stream is read.
    for connection, stream in tcp_streams(args.capture, port=None):
        if stream.startswith(b'MSRP ') or b'\r\nMSRP ' in stream[:4096]:
            frames.extend(dict(frame, connection=connection) for frame in msrp_frames(stream))
            continue
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

    # ------------------------------------------------------------------------------
    def sdp_of(message):
        """The SDP body of message as text."""
        return message['parts'].get('application/sdp', b'').decode('utf-8', 'replace')

    requests = [message for message in messages if message['request']]
    invites = [message for message in requests if message['method'] == 'INVITE' and 'm=message' in sdp_of(message)]
    # File distribution over the media plane (TS 24.282 clause 10.2.5) shares the MSRP stream with SDS.
    files = [message for message in invites if message['info'].get('request-type') in FD_TYPES]
    invites = [message for message in invites if message['info'].get('request-type') not in FD_TYPES]
    offers = [message for message in invites if message['target'] == args.service]
    # The initial INVITEs to recipients (clauses 9.2.3.4.3 and 10.2.5.4.3); the controlling function's re-INVITEs
    # (clause 6.3.7.1.13) are generated by TS 24.229 alone and are checked below.
    deliveries = [
        message
        for message in invites
        if message['target'] != args.service
        and args.service in header(message, 'from')
        and not re.search(r';\s*tag=', header(message, 'to'), re.I)
    ]
    file_offers = [message for message in files if message['target'] == args.service]
    file_deliveries = [
        message
        for message in files
        if message['target'] != args.service
        and args.service in header(message, 'from')
        and not re.search(r';\s*tag=', header(message, 'to'), re.I)
    ]
    one = [message for message in offers if message['info'].get('request-type') == 'one-to-one-sds']
    group = [message for message in offers if message['info'].get('request-type') == 'group-sds']
    check(
        'the media plane offer is an INVITE to the MCData PSI with the SDS feature tag and ICSI (9.2.3.2.3)',
        bool(offers)
        and all(
            any('g.3gpp.mcdata.sds' in contact for contact in message['headers']['accept-contact'])
            and header(message, 'p-preferred-service') == SDS_ICSI
            and 'application/vnd.3gpp.mcdata-info+xml' in message['parts']
            for message in offers
        ),
    )
    check(
        'a one-to-one offer names its target in resource-lists (9.2.3.2.3 step 7)',
        bool(one) and all('application/resource-lists+xml' in message['parts'] for message in one),
    )
    check(
        'a group offer names the group and the client ID without resource-lists (9.2.3.2.3 step 8)',
        bool(group)
        and all(
            message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-client-id')
            and 'application/resource-lists+xml' not in message['parts']
            for message in group
        ),
    )
    check(
        'a group request is delivered to each affiliated member with the calling group (9.2.3.4.4)',
        len([message for message in deliveries if message['info'].get('mcdata-calling-group-id')]) >= 3,
    )
    check(
        'the offer describes an MSRP stream with a path, actpass setup and the MCData types (9.2.3.2.1)',
        bool(offers)
        and all(
            re.search(r'm=message \d+ TCP/MSRP \*', sdp_of(message))
            and re.search(r'a=path:msrp://\S+;tcp', sdp_of(message))
            and 'a=setup:actpass' in sdp_of(message)
            and 'a=accept-types:application/vnd.3gpp.mcdata-signalling application/vnd.3gpp.mcdata-payload'
            in sdp_of(message)
            for message in offers
        ),
    )
    accepted = [response for message in offers for response in answers(message) if response['status'] == 200]
    check(
        'the server answers 200 with a passive MSRP stream of its own (9.2.3.3.2)',
        bool(accepted)
        and all(
            'a=setup:passive' in sdp_of(response) and re.search(r'a=path:msrp://\S+;tcp', sdp_of(response))
            for response in accepted
        ),
    )
    check(
        'the server offers a second media plane leg to the recipient with the SDS ICSI (9.2.3.4.3)',
        bool(deliveries)
        and all(
            header(message, 'p-asserted-service') == SDS_ICSI
            and 'a=setup:passive' in sdp_of(message)
            and message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-calling-user-id')
            for message in deliveries
        ),
    )

    # TS 24.282 clause 6.3.7.1.23 steps 5 and 6 (the 200 (OK) to the originator) and clauses 9.2.3.4.3, 9.2.4.4.3
    # and 10.2.5.4.3 step 7 (the INVITE to a recipient): the Contact is a SIP URI for the MCData session identity at
    # the controlling function, with the subservice's media feature tag, its ICSI and isfocus.
    def focus_contact(message, subservice):
        contact = header(message, 'contact')
        return bool(
            re.match(r'<sips?:[^@>]+@[^:;>]+;[^>]*>', contact)
            and f'+g.3gpp.mcdata.{subservice}' in contact
            and f'+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.{subservice}"' in contact
            and re.search(r';isfocus(;|$)', contact)
            and 'g.3gpp.mcptt' not in contact
        )

    file_accepted = [response for message in file_offers for response in answers(message) if response['status'] == 200]
    if offers:
        check(
            "the server's 200 to an SDS offer has the session identity Contact with the SDS tags and isfocus (6.3.7.1.23)",
            bool(accepted) and all(focus_contact(response, 'sds') for response in accepted),
        )
        check(
            "the server's INVITE to an SDS recipient has the session identity Contact with isfocus (9.2.3.4.3 step 7)",
            bool(deliveries) and all(focus_contact(message, 'sds') for message in deliveries),
        )
    # TS 24.282 clause 10.2.5.4.4: the inviting client of a one-to-one file is answered 200 (OK) only upon the
    # invited client's 200 (OK). The two legs share the session identity of the server's Contact.
    times = {
        (message['call_id'], header(message, 'cseq'), message['line']): message['time']
        for message in timed_messages(args.capture)
    }

    def when(message):
        return times.get((message['call_id'], header(message, 'cseq'), message['line']))

    def session_of(message):
        found = re.search(r';mcdata-session=([^;>]+)', header(message, 'contact'))
        return found.group(1) if found else None

    one_to_one_files = [
        (offer, response)
        for offer in file_offers
        if offer['info'].get('request-type') == 'one-to-one-fd'
        for response in answers(offer)
        if response['status'] == 200
    ]
    early = []
    for offer, response in one_to_one_files:
        recipient_answers = [
            answer
            for delivery in file_deliveries
            if session_of(delivery) == session_of(response)
            for answer in answers(delivery)
            if answer['status'] == 200
        ]
        if not recipient_answers or min(when(answer) or 0 for answer in recipient_answers) > (when(response) or 0):
            early.append(offer['call_id'])
    if one_to_one_files:
        check(
            'a one-to-one file offer is answered 200 only after the invited client answered 200 (10.2.5.4.4)',
            not early,
        )
    if file_offers:
        check(
            "the server's 200 to a file offer has the session identity Contact with the FD tags and isfocus (6.3.7.1.23)",
            bool(file_accepted) and all(focus_contact(response, 'fd') for response in file_accepted),
        )
        check(
            "the server's INVITE to a file recipient has the session identity Contact with isfocus (10.2.5.4.3 step 7)",
            bool(file_deliveries) and all(focus_contact(message, 'fd') for message in file_deliveries),
        )
    rejected = [
        (response['status'], header(response, 'warning'))
        for message in offers
        for response in answers(message)
        if response['status'] >= 300
    ]
    # 207 is answered with 488 Not Acceptable; the other warnings with 403 (TS 24.282 clause 4.9.2).
    for code, expected in (('200', 403), ('229', 403), ('230', 403), ('201', 403), ('206', 403), ('207', 488)):
        check(
            f'rejection {expected}/{code}',
            any(status == expected and f'"{code} ' in warning for status, warning in rejected),
        )
    check('the sessions are released with BYE', any(message['method'] == 'BYE' for message in requests))
    # An emergency one-to-one communication (TS 24.282 clauses 6.2.8.3, 6.2.8.4.3 and 6.2.8.4.4).
    reinvites = [
        message for message in requests if message['method'] == 'INVITE' and message['info'].get('emergency-ind')
    ]
    upgrades = [message for message in reinvites if message['info']['emergency-ind'] == 'true']
    cancels = [message for message in reinvites if message['info']['emergency-ind'] == 'false']
    check(
        'an emergency upgrade is a re-INVITE with <emergency-ind> true and the emergency Resource-Priority (6.2.8.3.3, 6.2.8.4.4)',
        bool(upgrades)
        and all(
            header(message, 'resource-priority') == 'mcpttp.15' and 'm=message' in sdp_of(message)
            for message in upgrades
        ),
    )
    check(
        'the server passes the emergency condition to the other party and answers 200 (6.2.8.4.2)',
        any(args.service in header(message, 'from') for message in upgrades)
        and any(
            response['status'] == 200 and response['info'].get('emergency-ind') == 'true'
            for message in upgrades
            for response in answers(message)
        ),
    )
    check(
        'the cancellation is a re-INVITE with <emergency-ind> false, answered 200 (6.2.8.4.3)',
        bool(cancels) and any(response['status'] == 200 for message in cancels for response in answers(message)),
    )
    check(
        'an unauthorised emergency upgrade is rejected with 403/112 (6.2.8.3.1.1)',
        any(
            response['status'] == 403 and '"112 ' in header(response, 'warning')
            for message in upgrades
            for response in answers(message)
        ),
    )

    # Priority group communications (TS 24.282 clauses 6.2.8.1 and 6.3.7.1) on a group SDS session.
    sessions = [
        message
        for message in requests
        if message['method'] == 'INVITE' and message['info'].get('request-type') == 'group-sds-session'
    ]
    originating = [message for message in sessions if message['target'] == args.service]
    group_emergency = [message for message in originating if message['info'].get('emergency-ind') == 'true']
    group_imminent = [message for message in originating if message['info'].get('imminentperil-ind') == 'true']
    # A re-INVITE is addressed to the dialog's remote target, not to the PSI.
    from_clients = [message for message in sessions if args.service not in header(message, 'from')]
    group_cancel = [message for message in from_clients if message['info'].get('emergency-ind') == 'false']
    check(
        'an emergency group communication carries <emergency-ind> and the emergency '
        'Resource-Priority (6.2.8.1.1, 6.2.8.1.2)',
        bool(group_emergency)
        and all(
            header(message, 'resource-priority') == 'mcpttp.15' and message['info'].get('mcdata-request-uri')
            for message in group_emergency
        ),
    )
    check(
        'an imminent peril group communication carries <imminentperil-ind> and its own '
        'Resource-Priority (6.2.8.1.9, 6.2.8.1.12)',
        bool(group_imminent)
        and all(
            header(message, 'resource-priority') == 'mcpttp.10' and 'emergency-ind' not in message['info']
            for message in group_imminent
        ),
    )
    check(
        'a cancellation carries <emergency-ind> false with the normal Resource-Priority (6.2.8.1.3)',
        bool(group_cancel)
        and any(header(message, 'resource-priority') == 'mcpttp.0' for message in group_cancel)
        and any(response['status'] == 200 for message in group_cancel for response in answers(message)),
    )
    served = [
        message for message in sessions if message['target'] != args.service and args.service in header(message, 'from')
    ]
    check(
        'the members are invited at the level of the in-progress state of the group (6.3.7.1.11)',
        any(
            message['info'].get('emergency-ind') == 'true'
            and header(message, 'resource-priority') == 'mcpttp.15'
            and message['info'].get('mcdata-calling-group-id')
            for message in served
        )
        and any(
            message['info'].get('imminentperil-ind') == 'true' and header(message, 'resource-priority') == 'mcpttp.10'
            for message in served
        ),
    )
    check(
        'the members are told when the in-progress emergency state is cancelled (6.3.7.1.14)',
        any(
            message['info'].get('emergency-ind') == 'false' and header(message, 'resource-priority') == 'mcpttp.0'
            for message in served
        ),
    )
    group_rejections = [
        (response['status'], header(response, 'warning'), response)
        for message in originating
        for response in answers(message)
        if response['status'] >= 300
    ]
    for code in ('233', '236'):
        check(
            f'an unauthorised priority group communication is rejected with 403/{code} (6.3.7.2.4, 6.3.7.2.6)',
            any(status == 403 and f'"{code} ' in warning for status, warning, _ in group_rejections),
        )
    check(
        'the rejection carries the refused indication set to false (6.3.7.2.7, 9.2.4.4.4 step 3C)',
        any(
            response['info'].get('emergency-ind') == 'false'
            for status, warning, response in group_rejections
            if '"233 ' in warning
        )
        and any(
            response['info'].get('imminentperil-ind') == 'false'
            for status, warning, response in group_rejections
            if '"236 ' in warning
        ),
    )
    alerts = [message for message in originating if message['info'].get('alert-ind') == 'true']
    check(
        'an emergency alert may be sent inside the session request with its location (6.2.8.1.1 step 3)',
        bool(alerts)
        and all(
            message['info'].get('emergency-ind') == 'true'
            and 'application/vnd.3gpp.mcdata-location-info+xml' in message['parts']
            for message in alerts
        ),
    )
    check(
        'the members are invited with the alert and the location of the originator (6.3.7.1.3)',
        any(
            message['info'].get('alert-ind') == 'true'
            and 'application/vnd.3gpp.mcdata-location-info+xml' in message['parts']
            for message in served
        ),
    )
    notifications = [
        message
        for message in requests
        if message['method'] == 'MESSAGE'
        and message['info'].get('mcdata-calling-group-id')
        and (message['info'].get('emergency-ind') or message['info'].get('imminentperil-ind'))
    ]
    check(
        'an affiliated member that is not participating is told of the in-progress state (6.3.7.1.2)',
        bool(notifications)
        and all(
            message['info'].get('mcdata-request-uri') and message['info'].get('mcdata-calling-user-id')
            for message in notifications
        )
        and all(response['status'] == 200 for message in notifications for response in answers(message)),
    )
    pending = [
        response
        for message in requests
        if message['method'] == 'INVITE'
        for response in answers(message)
        if response['status'] == 200 and '"149 ' in header(response, 'warning')
    ]
    infos = [
        message
        for message in requests
        if message['method'] == 'INFO' and header(message, 'info-package') == 'g.3gpp.mcdata-info'
    ]
    check(
        'an imminent peril request on a group in an emergency state is answered 200 with warning 149 '
        '(9.2.4.4.4 step 3)',
        bool(pending),
    )
    check(
        'the SIP INFO request corrects it to the emergency level (6.3.7.1.10)',
        bool(infos)
        and any(
            message['info'].get('imminentperil-ind') == 'false' and message['info'].get('emergency-ind') == 'true'
            for message in infos
        )
        and all(response['status'] == 200 for message in infos for response in answers(message)),
    )

    # File distribution over the media plane (TS 24.282 clauses 10.2.5.2.1, 10.2.5.2.3 and 10.2.5.4.4).
    check(
        'an FD offer is an INVITE to the MCData PSI with the FD feature tag and ICSI (10.2.5.2.3)',
        bool(file_offers)
        and all(
            any('g.3gpp.mcdata.fd' in contact for contact in message['headers']['accept-contact'])
            and header(message, 'p-preferred-service') == FD_ICSI
            and 'application/vnd.3gpp.mcdata-signalling' in message['parts']
            for message in file_offers
        ),
    )
    check(
        'the FD offer describes the file with the RFC 5547 attributes (10.2.5.2.1 step 1g-i)',
        bool(file_offers)
        and all(
            re.search(r'a=file-selector:name:"[^"]+" type:\S+ size:\d+ hash:sha-256:', sdp_of(message))
            and 'a=file-date:' in sdp_of(message)
            and 'a=file-description:' in sdp_of(message)
            and 'a=accept-types:application/vnd.3gpp.mcdata-signalling\r\n' in sdp_of(message)
            and 'a=setup:actpass' in sdp_of(message)
            for message in file_offers
        ),
    )
    check(
        'the FD request carries an FD SIGNALLING PAYLOAD with no file URL (6.2.2.3, 15.1.3.1)',
        bool(file_offers)
        and all(
            message['parts']['application/vnd.3gpp.mcdata-signalling'][:1] == b'\x02'
            and b'http' not in message['parts']['application/vnd.3gpp.mcdata-signalling']
            for message in file_offers
        ),
    )
    file_accepted = [response for message in file_offers for response in answers(message) if response['status'] == 200]
    check(
        'the server answers an FD offer with a passive stream that repeats the file selector (10.2.5.3.2)',
        bool(file_accepted)
        and all(
            'a=setup:passive' in sdp_of(response) and 'a=file-selector:' in sdp_of(response)
            for response in file_accepted
        ),
    )
    check(
        'the recipient is offered the same file with the FD ICSI (10.2.5.4.4)',
        bool(file_deliveries)
        and all(
            header(message, 'p-asserted-service') == FD_ICSI
            and 'a=file-selector:' in sdp_of(message)
            and 'application/vnd.3gpp.mcdata-signalling' in message['parts']
            and message['info'].get('mcdata-request-uri')
            for message in file_deliveries
        ),
    )
    check(
        'a group file distribution names the calling group to each member (10.2.5.4.4)',
        len([message for message in file_deliveries if message['info'].get('mcdata-calling-group-id')]) >= 3,
    )
    declined = [
        (response['status'], header(response, 'warning'))
        for message in file_deliveries
        for response in answers(message)
        if response['status'] >= 300
    ]
    check(
        'a recipient that does not accept the file answers 480 with warning 110 (10.2.5.2.4 step 7b)',
        any(status == 480 and '"110 ' in warning for status, warning in declined),
    )
    file_rejections = [
        (response['status'], header(response, 'warning'))
        for message in file_offers
        for response in answers(message)
        if response['status'] >= 300
    ]
    for code, expected in (('202', 403), ('208', 403), ('213', 403), ('214', 488), ('200', 403)):
        check(
            f'FD rejection {expected}/{code}',
            any(status == expected and f'"{code} ' in warning for status, warning in file_rejections),
        )
    check(
        'an emergency group file distribution carries the emergency Resource-Priority (6.3.7.1.11)',
        any(
            message['info'].get('emergency-ind') == 'true' and header(message, 'resource-priority') == 'mcpttp.15'
            for message in file_deliveries
        ),
    )

    # ------------------------------------------------------------------------------
    # Ad hoc group communications over the media plane (TS 24.282 clause 24).
    def direction(message):
        """The first direction attribute of the SDP of message, or an empty string."""
        found = re.search(r'a=(sendonly|recvonly|sendrecv)', sdp_of(message))
        return found.group(1) if found else ''

    adhoc_all = [
        message
        for message in requests
        if message['method'] == 'INVITE' and message['info'].get('request-type') in ADHOC_TYPES
    ]
    adhoc_offers = [message for message in adhoc_all if message['target'] == args.service]
    adhoc_deliveries = [
        message
        for message in adhoc_all
        if message['target'] != args.service and args.service in header(message, 'from')
    ]
    adhoc_sds = [message for message in adhoc_offers if message['info']['request-type'] == 'adhoc-group-sds-session']
    check(
        'an ad hoc group request is an INVITE to the MCData PSI with "adhoc-group-sds-session" or '
        '"adhoc-group-fd-session" and the client ID (24.2.2.1.1 steps 5e and 6f)',
        bool(adhoc_sds)
        and any(message['info']['request-type'] == 'adhoc-group-fd-session' for message in adhoc_offers)
        and all(
            message['info'].get('mcdata-client-id') and 'mcdata-calling-user-id' not in message['info']
            for message in adhoc_offers
        ),
    )
    check(
        'the ad hoc group is named by a participant list, criteria or its identity (24.2.2.1.1 steps 5e-ii, 7, 8)',
        any('application/resource-lists+xml' in message['parts'] for message in adhoc_offers)
        and any(message['info'].get('comn-participants-criteria') for message in adhoc_offers)
        and any(message['info'].get('mcdata-request-uri', '').startswith('sip:adhoc-') for message in adhoc_offers),
    )
    check(
        'a standalone SDS is offered "a=sendonly" and an SDS session "a=sendrecv" (9.2.3.2.1, 9.2.4.2.1)',
        any(direction(message) == 'sendonly' for message in adhoc_sds)
        and any(direction(message) == 'sendrecv' for message in adhoc_sds),
    )
    adhoc_accepted = [
        response for message in adhoc_offers for response in answers(message) if response['status'] == 200
    ]
    check(
        'the 200 names the ad hoc group in <mcdata-calling-group-id> (24.4.2.2)',
        bool(adhoc_accepted)
        and all(
            response['info'].get('mcdata-calling-group-id', '').startswith('sip:adhoc-') for response in adhoc_accepted
        ),
    )
    check(
        'each participant is invited with the ad hoc request type, the ad hoc group, the calling user and '
        'Referred-By (24.4.2.1.1 steps 6 and 7)',
        len(adhoc_deliveries) >= 7
        and all(
            message['info'].get('mcdata-calling-group-id', '').startswith('sip:adhoc-')
            and message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-calling-user-id')
            and header(message, 'referred-by')
            for message in adhoc_deliveries
        ),
    )
    check(
        'the participants of an ad hoc SDS session are offered "a=sendrecv" and answer it (9.2.4.4.1, 9.2.4.2.2)',
        any(
            direction(message) == 'sendrecv'
            and any(response['status'] == 200 and direction(response) == 'sendrecv' for response in answers(message))
            for message in adhoc_deliveries
        ),
    )
    adhoc_rejected = [
        (response['status'], header(response, 'warning'))
        for message in adhoc_offers
        for response in answers(message)
        if response['status'] >= 300
    ]
    for code in ('238', '240', '241', '242'):
        check(
            f'ad hoc rejection 403/{code} (24.3.2.1.1, 24.4.2.2)',
            any(status == 403 and f'"{code} ' in warning for status, warning in adhoc_rejected),
        )

    sends = [frame for frame in frames if frame['kind'] == 'SEND']
    empty = [frame for frame in sends if not frame['body']]
    # TS 24.582 clause 7.1.2.1: the file is the body of a SEND of its own.
    file_sends = [
        frame for frame in sends if frame['headers'].get('content-type') == 'application/vnd.3gpp.mcdata-file'
    ]
    carrying = [frame for frame in sends if frame['body'] and frame not in file_sends]
    # In a session the same connection also carries in-band disposition
    # notifications, which have a signalling body and no payload (TS 24.582 clause 6.1.2.5).
    inband_notifications = [
        frame
        for frame in carrying
        if bodies_of(frame).get('application/vnd.3gpp.mcdata-signalling', b'\x00')[:1] == b'\x05'
    ]
    carrying = [frame for frame in carrying if frame not in inband_notifications]
    check(
        'every MSRP frame carries To-Path and From-Path (RFC 4975 section 7)',
        bool(frames) and all(frame['headers'].get('to-path') and frame['headers'].get('from-path') for frame in frames),
    )
    check('the active endpoint binds the connection with an empty SEND (RFC 6135)', bool(empty))
    check(
        'the MCData bodies travel in one SEND as signalling and payload (TS 24.582 6.1.1.2.4)',
        bool(carrying)
        and all(
            {'application/vnd.3gpp.mcdata-signalling', 'application/vnd.3gpp.mcdata-payload'} <= set(bodies_of(frame))
            for frame in carrying
        ),
    )
    decoded = []
    for frame in carrying:
        bodies = bodies_of(frame)
        try:
            signalling = decode_signalling(bodies['application/vnd.3gpp.mcdata-signalling'])
            payload = decode_payload(bodies['application/vnd.3gpp.mcdata-payload'])
            decoded.append((signalling, payload))
        except (KeyError, ValueError, IndexError) as error:
            decode_errors.append(f"{frame['transaction']}: {error}")
    check(
        'the clause 15 bodies of a media plane SDS decode by their tables',
        bool(decoded)
        and not decode_errors
        and all(signalling['type'] == 'SDS SIGNALLING PAYLOAD' and payload for signalling, payload in decoded),
    )
    # A message seen on more than one leg (sender to server, server to each recipient) carries the same payload on
    # every leg.
    legs = collections.Counter(signalling['message'] for signalling, _ in decoded)
    payloads = collections.defaultdict(set)
    for signalling, payload in decoded:
        payloads[signalling['message']].add(bytes(payload[0][1]))
    relayed = [message for message, count in legs.items() if count >= 2]
    check(
        'the same message is relayed to the recipient unchanged',
        bool(relayed) and all(len(payloads[message]) == 1 for message in relayed),
    )
    check(
        'an SDS session carries in-band disposition notifications on the same connection (TS 24.582 6.1.2.5)',
        bool(inband_notifications) and all(len(bodies_of(frame)) == 1 for frame in inband_notifications),
    )
    check(
        'the file travels as application/vnd.3gpp.mcdata-file in MSRP SEND requests (TS 24.582 7.1.2.1)',
        bool(file_sends) and all(frame['headers'].get('message-id') and frame['body'] for frame in file_sends),
    )
    check(
        'the same file is relayed to the recipients unchanged',
        len({frame['body'] for frame in file_sends}) < len(file_sends),
    )
    # RFC 4975 section 7.1.2: a SEND with Failure-Report "no" (the empty SEND that binds the connection) or
    # "partial" is not answered when it succeeds. A connection whose far end sent nothing in the capture is not
    # judged (the capture may end, or the far end close, before it answers).
    answered = {frame['transaction'] for frame in frames if frame['kind'] == '200'}
    speaking = {frame['connection'] for frame in frames}
    expecting = [
        frame
        for frame in sends
        if frame['headers'].get('failure-report', 'yes') not in ('no', 'partial')
        and reverse(frame['connection']) in speaking
    ]
    unanswered = [frame['transaction'] for frame in expecting if frame['transaction'] not in answered]
    check(
        'every SEND is answered with an MSRP 200 (RFC 4975 section 7.1.2)',
        bool(expecting) and not unanswered and all(frame['continuation'] in '$+' for frame in frames),
    )
    report = dict(
        capture=str(args.capture),
        passed=not failures and not decode_errors,
        checks=checks,
        failures=failures,
        decode_errors=decode_errors,
        observations=dict(
            offers=len(offers),
            deliveries=len(deliveries),
            msrp_frames=len(frames),
            sends=len(sends),
            rejections=len(rejected),
            group_sessions=len(sessions),
            priority_infos=len(infos),
            state_notifications=len(notifications),
            inband_notifications=len(inband_notifications),
            unanswered_sends=unanswered[:20],
            file_offers=len(file_offers),
            file_deliveries=len(file_deliveries),
            file_sends=len(file_sends),
            adhoc_offers=len(adhoc_offers),
            adhoc_deliveries=len(adhoc_deliveries),
            one_to_one_file_answers=len(one_to_one_files),
            early_file_answers=early,
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
