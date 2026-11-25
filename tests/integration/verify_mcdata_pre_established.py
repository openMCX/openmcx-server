#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Check a capture of MCData pre-established sessions against TS 24.282 clauses 18.3 and 9.2.5 and TS 24.582 clause 12.

Signalling at the MCData server: the client's INVITE with <pre-established-session-ind> "true" and its 200 (OK)
(clause 18.3.2.2 step 9: the URI identifying the session in Contact, Supported "norefersub", the SDP answer of clause
18.3.1.2 with "a=setup:passive"); the client's REFERs to that URI (clauses 9.2.5.2.1.1 and 9.2.5.3.1.1: a cid Refer-To
naming the resource list, Refer-Sub "false", Target-Dialog; 9.2.5.4.1.1: the Refer-To with "method=BYE") and their
200 (OK) (clauses 9.2.5.2.2.1 steps 8 to 10 and 9.2.5.4.2.1 step 4: Refer-Sub "false", Supported "norefersub"); the
server's re-INVITEs in the session's dialog by <mcdata-communication-state> (clauses 9.2.5.1.2 and 9.2.5.1.3:
"establish-success" and "establish-request" with the MCData session identity, isfocus and the SDS tags in Contact,
"establish-request" with the two Accept-Contact header fields and the communication's MCData-Info; "terminated" and
"terminate-request" with the session's URI in Contact again), each answered 2xx; and the BYE that ends a session.
Media (TS 24.582 clause 12, RFC 4975): the clients connect to each session's MSRP URI anew for each communication, and
the SDS bodies go over those connections.

Decodes the SIP and the MSRP frames independently of the C++ implementation (the helpers of verify_mcdata_sds.py and
verify_mcdata_media.py).

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), RFC 3515, RFC 4488, RFC 4538, RFC 4975.
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_media import msrp_frames  # noqa: E402
from verify_mcdata_sds import header, parse, sip_messages, tcp_streams  # noqa: E402

PRE_IND = re.compile(r'<pre-established-session-ind>\s*true\s*</pre-established-session-ind>')
STATE = re.compile(r'<mcdata-communication-state>\s*([a-z-]+)\s*</mcdata-communication-state>')
PRIORITY = ('emergency-ind', 'imminentperil-ind', 'alert-ind')
SDS_TAGS = ('+g.3gpp.mcdata.sds', '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds"')


# ------------------------------------------------------------------------------
def info_text(message):
    """The MCData-Info body of a message as text, or ''."""
    body = message['parts'].get('application/vnd.3gpp.mcdata-info+xml', b'')
    return body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body)


# ------------------------------------------------------------------------------
def sdp_text(message):
    body = message['parts'].get('application/sdp', b'')
    return body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body)


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the report; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen, connections = [], set(), []
    for connection, stream in tcp_streams(args.capture, port=None):
        if stream.startswith(b'MSRP ') or b'\r\nMSRP ' in stream[:4096]:
            connections.append((connection, list(msrp_frames(stream))))
            continue
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:
                seen.add(key)
                messages.append(message)
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        (checks if condition else failures).append(label)

    responses = collections.defaultdict(list)
    for message in messages:
        if not message['request']:
            responses[(message['call_id'], header(message, 'cseq'))].append(message)

    # ------------------------------------------------------------------------------
    def final(request):
        """The final response to a request, or None."""
        found = [refer for refer in responses[(request['call_id'], header(request, 'cseq'))] if refer['status'] >= 200]
        return found[0] if found else None

    # Establishment (clause 18.3.2): the client's INVITE and the server's 200 (OK).
    establishing = [
        message
        for message in messages
        if message['request'] and message['method'] == 'INVITE' and PRE_IND.search(info_text(message))
    ]
    sessions = {}  # Call-ID -> (session URI, MSRP port)
    answered = []
    for invite in establishing:
        answer = final(invite)
        if answer and answer['status'] == 200:
            answered.append(answer)
            contact = header(answer, 'contact')
            uri = re.search(r'<([^>]+)>', contact)
            port = re.search(r'm=message (\d+) ', sdp_text(answer))
            sessions[invite['call_id']] = (uri.group(1) if uri else '', int(port.group(1)) if port else 0)
    check(
        'the clients establish pre-established sessions (18.3.2.1 step 9: <pre-established-session-ind> "true")',
        len(establishing) >= 2 and len(answered) >= 2,
    )
    check(
        'the 200 (OK) names the URI identifying the session in Contact with the SDS tags (18.3.2.2 steps 8, 9 a)',
        bool(answered)
        and all(
            ';mcdata-pre-session=' in header(answer, 'contact')
            and all(tag in header(answer, 'contact') for tag in SDS_TAGS)
            for answer in answered
        ),
    )
    check(
        'the 200 (OK) has Supported "norefersub" and the P-Asserted-Identity of the participating function (9 b, c)',
        bool(answered)
        and all(
            'norefersub' in answer['headers']['supported'] and args.service in header(answer, 'p-asserted-identity')
            for answer in answered
        ),
    )
    check(
        'the SDP answer is "m=message" over MSRP with "a=setup:passive" and "a=sendrecv" (18.3.1.2, TS 24.582 12)',
        bool(answered)
        and all(
            re.search(r'm=message \d+ TCP/(TLS/)?MSRP', sdp_text(answer))
            and 'a=setup:passive' in sdp_text(answer)
            and 'a=sendrecv' in sdp_text(answer)
            for answer in answered
        ),
    )

    # ------------------------------------------------------------------------------
    def indications(message):
        """The priority indications of a message's MCData-Info (TS 24.282 annex D.1), by element name."""
        return {name: message['info'][name] for name in PRIORITY if message['info'].get(name)}

    # ------------------------------------------------------------------------------
    def refused_priority(refer):
        answer = final(refer)
        return bool(indications(refer)) and answer is not None and answer['status'] == 403

    # The session a Request-URI names, by its "mcdata-pre-session" parameter.
    def session_id(uri):
        found = re.search(r';mcdata-pre-session=([^;>?]+)', uri or '')
        return found.group(1) if found else None

    uris = {session_id(uri): call_id for call_id, (uri, _) in sessions.items()}
    # The client's REFERs (clauses 9.2.5.2.1.1, 9.2.5.3.1.1, 9.2.5.4.1.1).
    refers = [
        message
        for message in messages
        if message['request'] and message['method'] == 'REFER' and session_id(message['target']) in uris
    ]
    starts = [refer for refer in refers if header(refer, 'refer-to').startswith('<cid:')]
    leaves = [refer for refer in refers if 'method=bye' in header(refer, 'refer-to').lower()]
    check('the clients\' REFERs go to the URI identifying the session (9.2.5.2.1.1 step 1)', len(starts) >= 3)
    check(
        'a REFER that starts a communication names a resource list by its Content-ID, with the entry\'s hname '
        '"body" (9.2.5.2.1.1 steps 2 to 4, RFC 2392, RFC 5366)',
        bool(starts)
        and all(
            refer['targets'] and all('?' in (target or '') and 'body=' in (target or '') for target in refer['targets'])
            for refer in starts
        ),
    )
    check(
        'the REFERs ask for no implicit subscription and name the session in Target-Dialog (RFC 4488, RFC 4538)',
        bool(refers)
        and all(
            header(refer, 'refer-sub').lower() == 'false'
            and 'norefersub' in refer['headers']['supported']
            and header(refer, 'target-dialog').split(';')[0] == uris[session_id(refer['target'])]
            for refer in refers
        ),
    )
    # A REFER refused for its priority (9.2.5.3.2.1 step 6B) is checked with the priority communications below.
    refer_answers = [final(refer) for refer in refers if not refused_priority(refer)]
    check(
        'the participating function accepts them with 200 (OK), Refer-Sub "false" and Supported "norefersub" '
        '(9.2.5.2.2.1 steps 8 to 10, 9.2.5.4.2.1 step 4)',
        bool(refer_answers)
        and all(
            answer is not None
            and answer['status'] == 200
            and header(answer, 'refer-sub').lower() == 'false'
            and 'norefersub' in answer['headers']['supported']
            for answer in refer_answers
        ),
    )
    check('a client leaves a communication with a REFER "BYE" (9.2.5.4.1.1)', len(leaves) >= 2)

    # The server's re-INVITEs in the session's dialogs (clauses 9.2.5.1.2, 9.2.5.1.3).
    reinvites = collections.defaultdict(list)
    for message in messages:
        if message['request'] and message['method'] == 'INVITE' and message['call_id'] in sessions:
            found = STATE.search(info_text(message))
            if found:
                reinvites[found.group(1)].append(message)
    observed = {state: len(found) for state, found in reinvites.items()}
    for state in ('establish-success', 'establish-request', 'terminated', 'terminate-request'):
        check(f'the participating function sends re-INVITEs "{state}" in the session\'s dialog', bool(reinvites[state]))
    every = [message for found in reinvites.values() for message in found]
    check(
        'each re-INVITE carries the participating function\'s P-Asserted-Identity and the SDS P-Asserted-Service',
        bool(every)
        and all(
            args.service in header(message, 'p-asserted-identity')
            and 'urn:urn-7:3gpp-service.ims.icsi.mcdata.sds' in message['headers']['p-asserted-service']
            for message in every
        ),
    )
    focused = reinvites['establish-success'] + reinvites['establish-request']
    check(
        '"establish-success" and "establish-request" name the MCData session identity with isfocus and the SDS tags '
        'in Contact (9.2.5.1.3 step 6, 9.2.5.2.2.2 step 3 iii)',
        bool(focused)
        and all(
            ';mcdata-session=' in header(message, 'contact')
            and re.search(r';isfocus(;|$)', header(message, 'contact'))
            and all(tag in header(message, 'contact') for tag in SDS_TAGS)
            for message in focused
        ),
    )
    check(
        '"establish-request" has the two Accept-Contact header fields and the communication\'s MCData-Info '
        '(9.2.5.1.3 steps 4, 5; 9.2.5.2.2.2 step 3 ii)',
        bool(reinvites['establish-request'])
        and all(
            any('g.3gpp.mcdata.sds' in value and 'require' in value for value in message['headers']['accept-contact'])
            and any('icsi-ref' in value and 'require' in value for value in message['headers']['accept-contact'])
            and message['info'].get('request-type', '').endswith(('sds', 'sds-session'))
            and message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-calling-user-id')
            for message in reinvites['establish-request']
        ),
    )
    ended = reinvites['terminated'] + reinvites['terminate-request']
    check(
        '"terminated" and "terminate-request" name the session\'s own URI in Contact again',
        bool(ended) and all(header(message, 'contact').find(sessions[message['call_id']][0]) >= 0 for message in ended),
    )
    unanswered = [message['line'] for message in every if not final(message) or final(message)['status'] // 100 != 2]
    check('the clients answer every re-INVITE with 2xx', bool(every) and not unanswered)

    # Emergency and imminent peril communications over the sessions (clauses 9.2.5.2.1.1 1a), 9.2.5.2.2.1 step 4,
    # 9.2.5.3.2.1 steps 6A and 6B, 6.2.8.1.16, 9.2.5.2.2.3 and 9.2.5.2.2.4). Checked when the clients used them.
    priority_refers = [refer for refer in starts if indications(refer)]
    priority_observed = dict(refers=len(priority_refers))
    if priority_refers:
        check(
            'a priority REFER carries the indications in its own MCData-Info and in the entry\'s (9.2.5.2.1.1 1a), '
            '9.2.5.1.1 step 9 a))',
            all(
                any(re.search(r'(emergency|imminentperil)-ind', unquote(target or '')) for target in refer['targets'])
                for refer in priority_refers
            ),
        )
        refused = [refer for refer in priority_refers if refused_priority(refer)]
        check(
            'an unauthorised emergency group request is refused at its REFER with 403 and warning 233 (9.2.5.3.2.1 6B)',
            any('233' in header(final(refer), 'warning') for refer in refused),
        )
        granted = [refer for refer in priority_refers if final(refer) and final(refer)['status'] == 200]

        # The captured streams are read one after the other, not in time order: each granted REFER is matched with an
        # "establish-success" of its session that grants what it asked, each such re-INVITE used once.
        def grants(refer, success):
            asked = [name for name, value in indications(refer).items() if value == 'true' and name != 'alert-ind']
            return all(
                indications(success).get(name) == 'true'
                or (name == 'imminentperil-ind' and indications(success).get('emergency-ind') == 'true')
                for name in asked
            )

        successes, used = [], set()
        for refer in granted:
            call_id = uris[session_id(refer['target'])]
            match = next(
                (
                    message
                    for message in reinvites['establish-success']
                    if message['call_id'] == call_id
                    and id(message) not in used
                    and indications(message)
                    and grants(refer, message)
                ),
                None,
            )
            if match is not None:
                used.add(id(match))
            successes.append((refer, match))
        check(
            'each granted priority REFER is followed by "establish-success" with the granted indications '
            '(6.2.8.1.16; 9.2.5.2.2.1, 2xx step 2)',
            bool(successes) and all(success is not None for _, success in successes),
        )
        check(
            '"establish-success" of a priority communication carries a Resource-Priority (6.3.7.1.4, 6.3.7.1.11)',
            bool(successes) and all(success and header(success, 'resource-priority') for _, success in successes),
        )
        offered = [message for message in reinvites['establish-request'] if indications(message)]
        check(
            'a priority communication is offered over a session with its indications and a Resource-Priority '
            '(9.2.5.2.2.2 step 3 ii, 6.3.7.1.11)',
            bool(offered) and all(header(message, 'resource-priority') for message in offered),
        )
        in_dialog = [
            message
            for message in messages
            if message['request']
            and message['method'] == 'INVITE'
            and message['call_id'] in sessions
            and not STATE.search(info_text(message))
            and indications(message)
        ]
        from_clients = [message for message in in_dialog if args.service not in header(message, 'p-asserted-identity')]
        relayed = [message for message in in_dialog if args.service in header(message, 'p-asserted-identity')]
        check(
            'the clients upgrade and cancel by a re-INVITE in the session\'s dialog, answered 200 (OK) with the '
            'session\'s media (9.2.5.2.2.3, 6.3.7.1.18)',
            len(from_clients) >= 4
            and all(
                final(message)
                and final(message)['status'] == 200
                and 'a=setup:passive' in sdp_text(final(message))
                and args.service in header(final(message), 'p-asserted-identity')
                for message in from_clients
            ),
        )
        check(
            'the change reaches a member within its own session: a re-INVITE with the indications and the '
            'communication\'s session identity in Contact, answered 2xx (9.2.5.2.2.4, 6.3.7.1.17)',
            bool(relayed)
            and all(
                ';mcdata-session=' in header(message, 'contact')
                and final(message)
                and final(message)['status'] // 100 == 2
                for message in relayed
            ),
        )
        priority_observed.update(
            refused=len(refused),
            granted=len(granted),
            offered=len(offered),
            client_reinvites=len(from_clients),
            relayed=len(relayed),
        )

    # The sessions' end (clauses 18.3.3.1.1 and 18.3.3.2.2): a BYE in a session's dialog, answered 200.
    byes = [
        message
        for message in messages
        if message['request'] and message['method'] == 'BYE' and message['call_id'] in sessions
    ]
    check(
        'sessions end with a BYE in their dialogs, answered 200 (18.3.3)',
        len(byes) >= 2 and all(final(bye) and final(bye)['status'] == 200 for bye in byes),
    )

    # Media (TS 24.582 clause 12): connections to the sessions' MSRP ports, one per communication.
    ports = {port for _, port in sessions.values() if port}
    to_sessions = [
        (connection, frames) for connection, frames in connections if connection[3] in ports or connection[1] in ports
    ]
    with_data = [
        frames for _, frames in to_sessions if any(frame['kind'] == 'SEND' and frame['body'] for frame in frames)
    ]
    check(
        'the clients connect to the sessions\' MSRP URIs anew for each communication (TS 24.582 12)',
        len(to_sessions) >= 4,
    )
    check('the SDS bodies go over the sessions\' MSRP connections', len(with_data) >= 3)

    report = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        observations=dict(
            sessions=len(sessions),
            refers=len(refers),
            leaves=len(leaves),
            reinvites=observed,
            unanswered=unanswered[:10],
            byes=len(byes),
            msrp_connections=len(to_sessions),
            msrp_connections_with_data=len(with_data),
            priority=priority_observed,
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
