#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify the MCVideo server's SIP signalling from a clear-SIP capture at the server.

The checks read what the server itself sends, independently of the C++ implementation:

- its initial INVITE toward a client (TS 24.281 clause 6.3.3.1.2 with clauses 6.3.2.2.3, 6.3.2.2.5.2 and 6.3.2.2.6.2):
  the focus Contact, the two Accept-Contact header fields, the ICSI, the option tags, its own identity, the answer
  mode, the mcvideo-info body and an SDP offer of the server's media and transmission control addresses (clause
  6.3.3.1.1); in an emergency group call the Resource-Priority and <emergency-ind> of clause 6.3.3.1.6;
- its answers to a client's INVITE (clauses 6.3.2.1.4 and 6.3.3.2.3, SDP answer of clause 6.3.3.2.1);
- the Resource-Priority namespace (clause 6.2.8.1.16);
- its conference event NOTIFYs (clause 6.3.3.4, with the MCVideo extension namespace of clause 9.2.3.6.1.2);
- the affiliation status NOTIFYs (clause 8.3.2.5 with the PIDF of clause 8.4.1) and the clients' affiliation
  SUBSCRIBE (clause 8.2.1.3 step 2);
- no repeated BYE on a dialog direction, and no MCPTT body or ICSI in what the server sends.

Usage: verify_mcvideo.py capture.pcap --service sip:mcvideo@DOMAIN --output result.json [--expect KIND ...]

--expect names what the scenario must have produced: group (a group call), private (a private call), emergency (an
emergency group call), affiliation (affiliation status) or conference (conference event notifications).

Self-contained: reassembles TCP/5060 streams from a classic PCAP without tshark. Requires debug (clear) SIP; TLS
captures cannot be inspected.

Specifications: TS 24.281 V19.6.0 (Rel-19), RFC 3841, RFC 4028, RFC 4412, RFC 4575, RFC 8101.
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402

ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcvideo'
ICSI_ENCODED = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mcvideo'
INFO_NS = '{urn:3gpp:ns:mcvideoInfo:1.0}'
PRES_NS = 'urn:3gpp:ns:mcvideoPresInfo:1.0'
PIDF_NS = '{urn:ietf:params:xml:ns:pidf}'
CONFERENCE_NS = '{urn:ietf:params:xml:ns:conference-info}'
CONFERENCE_EXTENSION_NS = 'urn:3gpp:ns:mcvideoConfInfo:1.0'
INFO_TYPE = 'application/vnd.3gpp.mcvideo-info+xml'


# ------------------------------------------------------------------------------
def body_parts(message):
    """The MIME parts of a message as {content type: body}; a single body under its Content-Type."""
    content_type = header(message, 'content-type')
    boundary = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not boundary:
        return {content_type.split(';')[0].strip().lower(): message['body']} if message['body'] else {}
    parts = {}
    for chunk in message['body'].split('--' + boundary.group(1))[1:]:
        if chunk.startswith('--'):
            break
        head, _, body = chunk.lstrip('\r\n').partition('\r\n\r\n')
        kind = re.search(r'(?im)^content-type\s*:\s*([^;\r\n]+)', head)
        if kind:
            parts[kind.group(1).strip().lower()] = body.rstrip('\r\n')
    return parts


# ------------------------------------------------------------------------------
def video_info(message):
    """The <mcvideo-Params> elements of the mcvideo-info body as {name: text}, or None without the body."""
    xml = message['parts'].get(INFO_TYPE)
    if xml is None:
        return None
    root = ET.fromstring(xml)
    if root.tag != INFO_NS + 'mcvideoinfo':
        return {'(root)': root.tag}
    info = {}
    for element in root.iter():
        name = element.tag.replace(INFO_NS, '')
        if name not in ('mcvideoinfo', 'mcvideo-Params'):
            info.setdefault(name, ''.join(element.itertext()).strip())
    return info


# ------------------------------------------------------------------------------
def sdp_sections(text):
    """The SDP of text as (session connection address, [(media line, connection address, [attribute lines])])."""
    session_address, media = '', []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('m='):
            media.append([line[2:], '', []])
        elif line.startswith('c='):
            address = line.split()[-1]
            if media:
                media[-1][1] = address
            else:
                session_address = address
        elif line.startswith('a=') and media:
            media[-1][2].append(line[2:])
    return session_address, [(line, address or session_address, attributes) for line, address, attributes in media]


# ------------------------------------------------------------------------------
def addresses(message):
    """The connection addresses of the SDP of a message."""
    sdp = message['parts'].get('application/sdp')
    if not sdp:
        return set()
    return {address for _, address, _ in sdp_sections(sdp)[1]}


# ------------------------------------------------------------------------------
def media_problems(message, client_addresses, offer=None):
    """What is wrong with the server's SDP of a message (clauses 6.3.3.1.1 and 6.3.3.2.1); empty when nothing is.

    offer: for an answer, the client's offer it answers."""
    sdp = message['parts'].get('application/sdp')
    if not sdp:
        return ['no SDP']
    problems = []
    sections = sdp_sections(sdp)[1]
    videos = [section for section in sections if section[0].startswith('video ')]
    controls = [section for section in sections if re.match(r'application \d+ udp MCVideo\b', section[0])]
    if not videos or videos[0][0].startswith('video 0 '):
        problems.append('no accepted video media')
    for line, address, _ in sections:
        if not line.split()[1] == '0' and address in client_addresses:
            problems.append(f'{line.split()[0]} at a client address {address}')
    offered_control = offer is None or any(
        re.match(r'application \d+ udp MCVideo\b', section[0])
        for section in sdp_sections(offer['parts'].get('application/sdp', ''))[1]
    )
    if offered_control:
        if not controls:
            problems.append('no transmission control entity')
        elif not any(re.match(r'fmtp:MCVideo .*\bmc_transmission_ssrc=\d+', attribute) for attribute in controls[0][2]):
            problems.append('no mc_transmission_ssrc fmtp of TS 24.581 clause 14')
    return problems


# ------------------------------------------------------------------------------
def option_tags(message):
    """The option tags of every Supported header field of a message, lower case."""
    tags = set()
    for value in message['headers'].get('supported', []):
        tags.update(tag.strip().lower() for tag in value.split(',') if tag.strip())
    return tags


# ------------------------------------------------------------------------------
def focus_contact(message):
    """Whether the Contact names an MCVideo session identity with the MCVideo feature tag, ICSI and isfocus."""
    contact = header(message, 'contact')
    parameters = contact.split('>', 1)[-1]
    return (
        bool(re.match(r'\s*<sips?:[^>]+>', contact))
        and re.search(r';\s*\+g\.3gpp\.mcvideo\b', parameters) is not None
        and ICSI_ENCODED in parameters
        and re.search(r';\s*isfocus\b', parameters) is not None
    )


# ------------------------------------------------------------------------------
def accept_contacts(message):
    """Whether the Accept-Contact header fields are one with g.3gpp.mcvideo and one with the MCVideo ICSI, each with
    "require" and "explicit" (clause 6.3.3.1.2 steps 2 and 4)."""
    values = message['headers'].get('accept-contact', [])

    def has(value, tag):
        return tag in value and re.search(r';\s*require\b', value) and re.search(r';\s*explicit\b', value)

    feature = [value for value in values if has(value, '+g.3gpp.mcvideo') and 'icsi-ref' not in value]
    service = [value for value in values if has(value, '+g.3gpp.icsi-ref') and ICSI_ENCODED in value]
    return len(feature) == 1 and len(service) == 1


# ------------------------------------------------------------------------------
def uri_of(value):
    """The URI of a name-addr or addr-spec header field value, without its parameters after the angle bracket."""
    match = re.search(r'<([^>]+)>', value)
    return (match.group(1) if match else value.split(';')[0]).strip()


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True, help='MCVideo service URI, e.g. sip:mcvideo@mcx.test')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument(
        '--expect',
        action='append',
        default=[],
        choices=['group', 'private', 'emergency', 'affiliation', 'conference'],
        help='What the scenario must have produced (repeatable)',
    )
    args = parser.parse_args()
    messages, seen = [], set()
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key in seen:  # a message appears on both server and core flows only once here
                continue
            seen.add(key)
            message['parts'] = body_parts(message)
            messages.append(message)
    checks, failures, examples = [], [], {}
    service = args.service

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    # ------------------------------------------------------------------------------
    def each(label, items, test):
        """Check that test holds for every message of items (vacuously true without any); a failure keeps the first
        offending messages' start lines and Call-IDs."""
        bad = [item for item in items if not test(item)]
        check(label, not bad)
        if bad:
            examples[label] = [f"{item['line']} ({item['call_id']})" for item in bad[:3]]

    # What the server sends: its requests (From is the service) and its answers to requests sent to the service or to
    # one of its session identities (To is the service, with or without URI parameters).
    from_server = [
        message
        for message in messages
        if (message['request'] and uri_of(header(message, 'from')) == service)
        or (not message['request'] and uri_of(header(message, 'to')).split(';')[0] == service)
    ]
    initial = [
        message
        for message in messages
        if message['request'] and message['method'] == 'INVITE' and not re.search(r';\s*tag=', header(message, 'to'))
    ]
    originating = [message for message in initial if uri_of(message['target']).split(';')[0] == service]
    terminating = [message for message in initial if uri_of(header(message, 'from')) == service]
    for message in originating + terminating:
        message['video'] = video_info(message)
    originating_ids = {message['call_id'] for message in originating}
    # The answers to an initial INVITE share its Call-ID and CSeq; later ones in the dialog answer re-INVITEs.
    initial_keys = {(message['call_id'], header(message, 'cseq')) for message in initial}
    client_addresses = set()
    for message in originating:
        client_addresses |= addresses(message)
    for message in messages:
        if (
            not message['request']
            and message['method'] == 'INVITE'
            and message['status'] == 200
            and (message['call_id'], header(message, 'cseq')) in initial_keys
            and message['call_id'] not in originating_ids
        ):
            client_addresses |= addresses(message)

    # ------------------------------------------------------------------------------
    # The server's initial INVITE toward a client.
    group_types = ('prearranged', 'chat')
    group_fanout = [message for message in terminating if (message['video'] or {}).get('session-type') in group_types]
    private_fanout = [message for message in terminating if (message['video'] or {}).get('session-type') == 'private']
    check(
        'at least one INVITE or affiliation request decoded',
        bool(initial) or any(message['method'] in ('SUBSCRIBE', 'PUBLISH') for message in messages),
    )
    each(
        '6.3.3.1.2 step 1: the Contact is a session identity with g.3gpp.mcvideo, the ICSI and isfocus',
        terminating,
        focus_contact,
    )
    each(
        '6.3.3.1.2 steps 2 and 4: one Accept-Contact with g.3gpp.mcvideo and one with the ICSI, require;explicit',
        terminating,
        accept_contacts,
    )
    each(
        '6.3.3.1.2 step 3: P-Asserted-Service is the MCVideo ICSI',
        terminating,
        lambda message: header(message, 'p-asserted-service') == ICSI,
    )
    each(
        '6.3.3.1.2 step 7 and 6.3.2.2.3 steps 3, 5 and 6: Supported has timer, tdialog and norefersub',
        terminating,
        lambda message: {'timer', 'tdialog', 'norefersub'} <= option_tags(message),
    )
    each(
        '6.3.2.2.3 step 2: Session-Expires without refresher, or refresher=uac',
        terminating,
        lambda message: not re.search(r'refresher\s*=\s*(?!uac\b)', header(message, 'session-expires'), re.I),
    )
    each(
        '6.3.2.2.5.2 step 6 and 6.3.2.2.6.2 step 7: P-Asserted-Identity is the server\'s identity',
        terminating,
        lambda message: uri_of(header(message, 'p-asserted-identity')) == service,
    )
    each(
        '6.3.2.2.5.2 steps 7 and 8, 6.3.2.2.6.2 steps 4 to 6: Answer-Mode and Priv-Answer-Mode are Auto or Manual',
        terminating,
        lambda message: all(
            value.split(';')[0].strip() in ('Auto', 'Manual')
            for name in ('answer-mode', 'priv-answer-mode')
            for value in message['headers'].get(name, [])
        ),
    )
    each(
        '6.3.2.2.3 step 8: an mcvideo-info body naming the invited user in <mcvideo-request-uri>',
        terminating,
        lambda message: bool((message['video'] or {}).get('mcvideo-request-uri')),
    )
    each(
        '6.3.3.1.6 step 3 (9.2.1): a group call INVITE names the calling user and the calling group',
        group_fanout,
        lambda message: (
            bool(message['video'].get('mcvideo-calling-user-id'))
            and bool(message['video'].get('mcvideo-calling-group-id'))
        ),
    )
    each(
        '10.2.2: a private call INVITE names the calling user and no calling group',
        private_fanout,
        lambda message: (
            bool(message['video'].get('mcvideo-calling-user-id')) and 'mcvideo-calling-group-id' not in message['video']
        ),
    )
    # The originating offer of each session, by the session identity in the server's answers to it: the server's
    # offer has a transmission control entity when that offer had one (clause 6.3.3.1.1 step 1 b)).
    session_offers = {}
    for message in messages:
        if not message['request'] and message['method'] == 'INVITE' and message['call_id'] in originating_ids:
            session = uri_of(header(message, 'contact'))
            original = next(item for item in originating if item['call_id'] == message['call_id'])
            if session and (message['call_id'], header(message, 'cseq')) in initial_keys:
                session_offers.setdefault(session, original)
    offer_problems = {
        message['call_id']: media_problems(
            message, client_addresses, session_offers.get(uri_of(header(message, 'contact')), message)
        )
        for message in terminating
    }
    each(
        '6.3.3.1.1: the SDP offer has video and transmission control (mc_transmission_ssrc) at the server',
        terminating,
        lambda message: not offer_problems[message['call_id']],
    )
    if any(offer_problems.values()):
        examples['SDP offer problems'] = sorted({problem for found in offer_problems.values() for problem in found})

    # ------------------------------------------------------------------------------
    # Emergency group calls (clause 6.3.3.1.6 step 6): an emergency originating INVITE makes the fan-out emergency.
    emergency_groups = {
        message['video'].get('mcvideo-request-uri')
        for message in originating
        if (message['video'] or {}).get('emergency-ind') == 'true'
        and (message['video'] or {}).get('session-type') in group_types
    }
    emergency_fanout = [
        message
        for message in group_fanout
        if message['video'].get('mcvideo-calling-group-id') in emergency_groups
        and message['video'].get('emergency-ind') == 'true'
    ]
    each(
        '6.3.3.1.6 step 6: an emergency group call INVITE carries a Resource-Priority',
        emergency_fanout,
        lambda message: bool(header(message, 'resource-priority')),
    )
    each(
        '6.2.8.1.16: every Resource-Priority the server sends is in the mcpttp namespace of RFC 8101',
        from_server,
        lambda message: all(
            re.fullmatch(r'mcpttp\.(\d|1[0-5])', value.strip())
            for field in message['headers'].get('resource-priority', [])
            for value in field.split(',')
        ),
    )

    # ------------------------------------------------------------------------------
    # The server's answers to a client's INVITE.
    answers = [
        message
        for message in messages
        if not message['request']
        and message['method'] == 'INVITE'
        and message['call_id'] in originating_ids
        and (message['call_id'], header(message, 'cseq')) in initial_keys
    ]
    offers = {message['call_id']: message for message in originating}
    successes = [message for message in answers if message['status'] == 200]
    provisionals = [message for message in answers if 100 < message['status'] < 200]
    each(
        '6.3.2.1.4.2 step 1: the 200 (OK) has "timer" in Require',
        successes,
        lambda message: any('timer' in value for value in message['headers'].get('require', [])),
    )
    each(
        '6.3.2.1.4.2 step 2: the 200 (OK) has Session-Expires, refresher=uac when the request named none',
        successes,
        lambda message: (
            bool(header(message, 'session-expires'))
            and (
                'refresher=' in header(offers[message['call_id']], 'session-expires')
                or re.search(r'refresher\s*=\s*uac\b', header(message, 'session-expires'))
            )
        ),
    )
    each(
        '6.3.3.2.3.2 step 4: the 200 (OK) asserts the server\'s identity',
        successes,
        lambda message: uri_of(header(message, 'p-asserted-identity')) == service,
    )
    each(
        '6.3.3.2.3.2 steps 5 and 6: the 200 (OK) Contact is a session identity with the tags and isfocus',
        successes,
        focus_contact,
    )
    each(
        '6.3.3.2.3.2 steps 8 to 10: the 200 (OK) supports tdialog, norefersub, explicitsub and nosub',
        successes,
        lambda message: {'tdialog', 'norefersub', 'explicitsub', 'nosub'} <= option_tags(message),
    )
    answer_problems = {
        message['call_id']: media_problems(message, client_addresses, offers[message['call_id']])
        for message in successes
    }
    each(
        '6.3.3.2.1: the SDP answer has video and transmission control (mc_transmission_ssrc) at the server',
        successes,
        lambda message: not answer_problems[message['call_id']],
    )
    if any(answer_problems.values()):
        examples['SDP answer problems'] = sorted({problem for found in answer_problems.values() for problem in found})
    each(
        '6.3.2.1.4.1 and 6.3.3.2.3.1: a provisional answer asserts the identity, has the focus Contact and norefersub',
        provisionals,
        lambda message: (
            uri_of(header(message, 'p-asserted-identity')) == service
            and focus_contact(message)
            and 'norefersub' in option_tags(message)
        ),
    )

    # ------------------------------------------------------------------------------
    # Conference event NOTIFYs (clause 6.3.3.4).
    conference = [
        message
        for message in from_server
        if message['request'] and message['method'] == 'NOTIFY' and header(message, 'event').startswith('conference')
    ]
    for message in conference:
        message['video'] = video_info(message)
    each(
        '6.3.3.4 step 1: a conference NOTIFY asserts the server\'s identity',
        conference,
        lambda message: uri_of(header(message, 'p-asserted-identity')) == service,
    )
    each(
        '6.3.3.4 step 3: a conference NOTIFY has an Expires header field',
        conference,
        lambda message: header(message, 'expires').isdigit(),
    )
    each(
        '6.3.3.4 step 4: a conference NOTIFY has the MCVideo ICSI in P-Preferred-Service',
        conference,
        lambda message: header(message, 'p-preferred-service') == ICSI,
    )
    each(
        '6.3.3.4 step 5: a conference NOTIFY has an mcvideo-info body with the calling group and request URI',
        conference,
        lambda message: (
            bool((message['video'] or {}).get('mcvideo-calling-group-id'))
            and bool((message['video'] or {}).get('mcvideo-request-uri'))
        ),
    )

    # ------------------------------------------------------------------------------
    def conference_ok(message):
        """RFC 4575 and clause 6.3.3.4: the group in "entity"; extensions only in the MCVideo namespace."""
        xml = message['parts'].get('application/conference-info+xml')
        if xml is None:
            return False
        root = ET.fromstring(xml)
        if root.tag != CONFERENCE_NS + 'conference-info':
            return False
        # With XML protection (TS 33.180 clause 9.3) the calling group in the mcvideo-info body is encrypted, so only a
        # clear value (a SIP URI) can be compared with the entity.
        calling_group = (message['video'] or {}).get('mcvideo-calling-group-id', '')
        if calling_group.startswith(('sip:', 'sips:')) and root.get('entity') != calling_group:
            return False
        foreign = [
            element.tag
            for element in root.iter()
            if element.tag.startswith('{')
            and not element.tag.startswith(CONFERENCE_NS)
            and not element.tag.startswith('{' + CONFERENCE_EXTENSION_NS + '}')
        ]
        return not foreign and 'mcpttConfInfo' not in xml

    each(
        '6.3.3.4 and 9.2.3.6.1.2: the conference-info names the group; its extensions use mcvideoConfInfo',
        conference,
        conference_ok,
    )

    # ------------------------------------------------------------------------------
    # Affiliation (clause 8): the clients' SUBSCRIBE and the server's NOTIFY of the affiliation status.
    subscribes = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'SUBSCRIBE'
        and header(message, 'event').startswith('presence')
        and uri_of(message['target']) == service
        and not re.search(r';\s*tag=', header(message, 'to'))
    ]
    for message in subscribes:
        message['video'] = video_info(message)
    each(
        '8.2.1.3 step 2: an affiliation SUBSCRIBE has an mcvideo-info body with <mcvideo-request-uri>',
        subscribes,
        lambda message: bool((message['video'] or {}).get('mcvideo-request-uri')),
    )
    presence = [
        message
        for message in from_server
        if message['request'] and message['method'] == 'NOTIFY' and header(message, 'event').startswith('presence')
    ]

    def presence_ok(message):
        """Clause 8.3.2.5 with 8.4.1: a PIDF of the MCVideo ID with affiliation elements in the MCVideo namespace."""
        if not header(message, 'subscription-state'):
            return False
        xml = message['parts'].get('application/pidf+xml')
        if xml is None:
            return 'terminated' in header(message, 'subscription-state')
        root = ET.fromstring(xml)
        if root.tag != PIDF_NS + 'presence' or not root.get('entity'):
            return False
        statuses = [element for element in root.iter() if element.tag == '{' + PRES_NS + '}affiliation']
        if any(element.tag.startswith('{urn:3gpp:ns:mcptt') for element in root.iter()):
            return False
        return all(
            element.get('group') and element.get('status') in ('affiliating', 'affiliated', 'deaffiliating')
            for element in statuses
        )

    each(
        '8.3.2.5 and 8.4.1: an affiliation NOTIFY has Subscription-State and a PIDF in the MCVideo namespace',
        presence,
        presence_ok,
    )

    # ------------------------------------------------------------------------------
    # Release and service separation.
    byes = {}
    for message in from_server:
        if message['request'] and message['method'] == 'BYE':
            direction = (message['call_id'], header(message, 'from'), header(message, 'to'))
            byes.setdefault(direction, set()).add(header(message, 'cseq'))
    check(
        '6.3.3.1.4: no repeated BYE with a different CSeq on a dialog direction',
        all(len(cseqs) == 1 for cseqs in byes.values()),
    )
    each(
        'the server sends no MCPTT ICSI, feature tag or mcptt-info body',
        from_server,
        lambda message: (
            'icsi.mcptt' not in message['line'] + json.dumps(message['headers'])
            and '+g.3gpp.mcptt' not in json.dumps(message['headers'])
            and 'application/vnd.3gpp.mcptt-info+xml' not in message['parts']
        ),
    )

    # ------------------------------------------------------------------------------
    expected = {
        'group': bool(group_fanout) and any(message['call_id'] in originating_ids for message in successes),
        'private': bool(private_fanout),
        'emergency': bool(emergency_fanout),
        'affiliation': bool(subscribes) and bool(presence),
        'conference': bool(conference),
    }
    for kind in args.expect:
        check(f'the capture has the expected {kind} signalling', expected[kind])
    report = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        examples=examples,
        counts=dict(
            originating=len(originating),
            terminating=len(terminating),
            group_fanout=len(group_fanout),
            private_fanout=len(private_fanout),
            emergency_fanout=len(emergency_fanout),
            successes=len(successes),
            provisionals=len(provisionals),
            conference_notifies=len(conference),
            affiliation_subscribes=len(subscribes),
            affiliation_notifies=len(presence),
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=report['passed'], failures=failures, examples=examples, counts=report['counts'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
