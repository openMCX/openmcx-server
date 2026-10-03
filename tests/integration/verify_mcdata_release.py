#!/usr/bin/env python3
"""Check a capture of MCData communication release against TS 24.282 clause 13.

Reads clear TCP/5060 SIP (debug SIP) and decodes, independently of the C++ implementation, the COMMUNICATION RELEASE (TS
24.282 clause 15.1.10), DATA PAYLOAD (clause 15.1.4) and FD HTTP TERMINATION (clause 15.1.13) messages carried in SIP
INFO and MESSAGE requests, the Reason header fields of the BYE requests (IETF RFC 3326), and the INFO package framing.
The procedures under test: release by the controlling function with the reasons of clause 13.2.3.2.4, the intent to
release, data query and extension of clause 13.2.4, release by an authorised user of clauses 13.2.5 and 13.2.6, and
their FD over HTTP counterparts of clause 13.2.6.3.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_sds import decode_payload, header, parse, sip_messages, tcp_streams  # noqa: E402

SIGNALLING = 'application/vnd.3gpp.mcdata-signalling'
PAYLOAD = 'application/vnd.3gpp.mcdata-payload'
PACKAGE = 'g.3gpp.mcdata-com-release'
TYPES = {1: 'intent', 2: 'extension-request', 3: 'extension-response', 4: 'auth-user-release'}


# ------------------------------------------------------------------------------
def communication_release(data):
    """TS 24.282 table 15.1.10.1-1: message type 0x0a, the Comm release information type (clause 15.2.20), and the type
    1 Data query type (IEI B, clause 15.2.19) and Extension response type (IEI C, clause 15.2.21) IEs.
    """
    if len(data) < 2 or data[0] != 0x0A or data[1] not in TYPES:
        raise ValueError('not a COMMUNICATION RELEASE')
    out, seen = dict(type=TYPES[data[1]], query=False, extension=None), set()
    for octet in data[2:]:
        iei, value = octet >> 4, octet & 0x0F
        if iei in seen:
            raise ValueError('repeated IE')
        seen.add(iei)
        if iei == 0xB and value == 1:
            out['query'] = True
        elif iei == 0xC and value in (1, 2):
            out['extension'] = 'accepted' if value == 1 else 'rejected'
        else:
            raise ValueError(f'unexpected IE {octet:#04x}')
    return out


# ------------------------------------------------------------------------------
def fd_termination(data):
    """TS 24.282 table 15.1.13.1-1: type 0x0d, Conversation ID, Message ID, Termination information type (clause
    15.2.22), then the type 1 Extension (C) and Release (D) response IEs.
    """
    if len(data) < 34 or data[0] != 0x0D or not 1 <= data[33] <= 7:
        raise ValueError('not an FD HTTP TERMINATION')
    out = dict(type=data[33], message=data[17:33].hex(), extension=None, release=None)
    at = 34
    while at < len(data):
        octet = data[at]
        if octet >> 4 == 0xC:
            out['extension'] = octet & 0x0F
            at += 1
        elif octet >> 4 == 0xD:
            out['release'] = octet & 0x0F
            at += 1
        elif octet in (0x78, 0x7D):
            at += 3 + int.from_bytes(data[at + 1 : at + 3], 'big')
        elif octet == 0x22:
            at += 2
        else:
            raise ValueError(f'unexpected IE {octet:#04x}')
    return out


# ------------------------------------------------------------------------------
def reason_text(value):
    """The text parameter of a Reason header field value, or None."""
    found = re.search(r'text="([^"]*)"', value)
    return found.group(1) if found else None


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the report; exit status 1 on any failure or decode error."""
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
    checks, failures, errors = [], [], []

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
    def from_server(message):
        """The request message was sent by the MCData server rather than a client."""
        # The server's own requests name its service URI in From (its in-dialog INFO
        # requests also assert it in P-Asserted-Identity); a client's name the client.
        return args.service in header(message, 'from') or args.service in header(message, 'p-asserted-identity')

    infos = [
        message
        for message in messages
        if message['request'] and message['method'] == 'INFO' and header(message, 'info-package') == PACKAGE
    ]
    # Each body's decode errors are reported under its own check (and all of them in decode_errors).
    releases, release_errors = [], []
    for message in infos:
        try:
            if SIGNALLING in message['parts']:
                releases.append((message, communication_release(message['parts'][SIGNALLING])))
        except ValueError as error:
            release_errors.append(f'{message["call_id"]}: {error}')
    errors.extend(release_errors)
    payloads = []
    for message in infos:
        if PAYLOAD in message['parts']:
            try:
                payloads.append((message, decode_payload(message['parts'][PAYLOAD])))
            except ValueError as error:
                errors.append(f'{message["call_id"]}: {error}')

    # ------------------------------------------------------------------------------
    def sent(kind, server):
        """The decoded COMMUNICATION RELEASE messages of kind sent by the server (server true) or by a client."""
        return [
            (message, release)
            for message, release in releases
            if release['type'] == kind and from_server(message) == server
        ]

    check(
        'every com-release INFO names the g.3gpp.mcdata-com-release package with Content-Disposition '
        'Info-Package (13.2.4.4.1 steps 2 and 3a)',
        bool(infos) and all(header(message, 'content-disposition').startswith('Info-Package') for message in infos),
    )
    check('every COMMUNICATION RELEASE body decodes by table 15.1.10.1-1', bool(releases) and not release_errors)
    intents = sent('intent', True)
    check(
        'the server sends INTENT TO RELEASE with the Data query type when it asks for the remaining data, '
        'and without it otherwise (13.2.4.4.1)',
        any(release['query'] for _, release in intents) and any(not release['query'] for _, release in intents),
    )
    check(
        'the intent carries the reason of the release (13.2.4.4.1 step 4)',
        any(reason_text(header(message, 'reason')) for message, _ in intents),
    )
    check(
        'the originator answers the data query with a DATA PAYLOAD of one TEXT payload (13.2.4.2.1 step 2c)',
        any(
            not from_server(message) and len(payload_list) == 1 and payload_list[0][0] == 1
            for message, payload_list in payloads
        ),
    )
    check('the originator sends EXTENSION REQUEST (13.2.4.2.2)', bool(sent('extension-request', False)))
    responses_sent = sent('extension-response', True)
    check(
        'the server answers EXTENSION RESPONSE with ACCEPTED and, from the authorised user, REJECTED '
        '(13.2.4.4.4, 13.2.6.2.4.4)',
        any(release['extension'] == 'accepted' for _, release in responses_sent)
        and any(release['extension'] == 'rejected' for _, release in responses_sent),
    )
    auth = sent('auth-user-release', False)
    check(
        'an authorised user sends AUTH USER RELEASE REQ with its client ID in mcdata-info (13.2.5.2.2.1)',
        bool(auth) and all(message['info'].get('mcdata-client-id') for message, _ in auth),
    )
    check(
        'the server accepts it with 200 and refuses an unauthorised user with 403 (13.2.5.2.4.1)',
        any(response['status'] == 200 for message, _ in auth for response in answers(message))
        and any(response['status'] == 403 for message, _ in auth for response in answers(message)),
    )
    client_intents = sent('intent', False)
    check(
        'an authorised user announces the release with its client ID and reason (13.2.6.2.2.1)',
        any(
            message['info'].get('mcdata-client-id') and reason_text(header(message, 'reason'))
            for message, _ in client_intents
        ),
    )
    check(
        'the server passes the remaining data and the extension request to the authorised user, naming it in '
        '<mcdata-request-uri> (13.2.6.2.4.2, 13.2.6.2.4.3)',
        any(from_server(message) and message['info'].get('mcdata-request-uri') for message, _ in payloads)
        and any(message['info'].get('mcdata-request-uri') for message, _ in sent('extension-request', True)),
    )
    check(
        'the authorised user answers EXTENSION RESPONSE (13.2.6.2.2.4)',
        any(release['extension'] for _, release in sent('extension-response', False)),
    )

    byes = [message for message in messages if message['request'] and message['method'] == 'BYE']
    server_reasons = {reason_text(header(message, 'reason')) for message in byes if header(message, 'reason')}
    for text in (
        'data volume limit',
        'time limit expiry',
        'maintenance window',
        'quota reached',
        'operator decision',
        'supervisor request',
        'tunnel audit',
    ):
        check(f'a BYE carries the reason "{text}" (13.2.3.2.4)', text in server_reasons)
    # The SIP core may re-space the parameters of a header field it forwards.
    check(
        'every Reason header field is "SIP;cause=200;text=..." (IETF RFC 3326)',
        all(
            re.fullmatch(r'SIP\s*;\s*cause=200\s*;\s*text="[^"]*"', header(message, 'reason'))
            for message in byes
            if header(message, 'reason')
        ),
    )
    check(
        'an authorised participant ends an ad hoc communication with "User requested release" (13.2.2.2.4.3 step 3A)',
        'User requested release' in server_reasons,
    )

    terminations = []
    for message in messages:
        if message['request'] and message['method'] == 'MESSAGE':
            for body in message['signalling_bodies']:
                if body[:1] == b'\x0d':
                    try:
                        terminations.append((message, fd_termination(body)))
                    except ValueError as error:
                        errors.append(f'{message["call_id"]}: {error}')
    by_type = collections.defaultdict(list)
    for message, termination in terminations:
        by_type[(termination['type'], from_server(message))].append((message, termination))
    check(
        'an authorised user sends INTENT TO RELEASE COMM OVER HTTP with a reason (13.2.6.3.2.1)',
        any(reason_text(header(message, 'reason')) for message, _ in by_type[(4, False)]),
    )
    check(
        'the server passes the intent to the originator with that reason (13.2.6.3.4.1)',
        any(reason_text(header(message, 'reason')) for message, _ in by_type[(4, True)]),
    )
    check(
        'the server passes the originator\'s EXTENSION REQUEST to the authorised user (13.2.6.3.4.2)',
        bool(by_type[(5, True)]),
    )
    check(
        'the authorised user sends EXTENSION RESPONSE REJECTED, which reaches the originator (13.2.6.3.4.3)',
        any(termination['extension'] == 2 for _, termination in by_type[(6, False)])
        and any(termination['extension'] == 2 for _, termination in by_type[(6, True)]),
    )
    check(
        'the originator is told the transmission was stopped and the authorised user receives RELEASE SUCCESS',
        bool(by_type[(3, True)]) and any(termination['release'] == 1 for _, termination in by_type[(2, True)]),
    )

    report = dict(
        capture=str(args.capture),
        passed=not failures and not errors,
        checks=checks,
        failures=failures,
        decode_errors=errors,
        observations=dict(
            com_release_infos=len(infos),
            communication_release=len(releases),
            data_payloads=len(payloads),
            byes_with_reason=len([bye for bye in byes if header(bye, 'reason')]),
            fd_terminations=len(terminations),
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
