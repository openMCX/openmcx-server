#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Check a capture of MCData file distribution over HTTP against TS 24.282.

Decodes the clause 15 binary bodies independently of the C++ codec: FD SIGNALLING PAYLOAD (TS 24.282 clause 15.1.3), FD
NOTIFICATION (clause 15.1.6), FD NETWORK NOTIFICATION (clause 15.1.9) and FD HTTP TERMINATION (clause 15.1.13). The
procedures under test: media storage function discovery (clause 10.2.1.3), FD over HTTP by the client and the
controlling function (clauses 10.2.4.2.1, 10.2.4.4.1 and 10.2.4.4.2), disposition and network notifications (clauses
12.2 and 12.4.2) and the release of an FD over HTTP (clause 13.2), with the MCData warning codes of clause 4.9. The SIP
parsing is shared with verify_mcdata_sds.py.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_sds import header, parse, sip_messages, tcp_streams  # noqa: E402

FD_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcdata.fd'


# ------------------------------------------------------------------------------
def decode_fd(data):
    """Decode an FD message by tables 15.1.3.1-1, 15.1.6.1-1, 15.1.9.1-1 and 15.1.13.1-1 of TS 24.282: a dict, or
    ValueError for a protected, malformed or unexpected message.
    """
    kind = data[0]
    if kind & 0xC0:
        raise ValueError('protected')
    if kind == 0x02:
        out = dict(
            type='FD SIGNALLING PAYLOAD',
            time=int.from_bytes(data[1:6], 'big'),
            conversation=data[6:22].hex(),
            message=data[22:38].hex(),
            mandatory=False,
            completion=False,
        )
        at = 38
        while at < len(data):
            iei = data[at]
            if iei >> 4 == 0x9 or iei >> 4 == 0xA:
                if iei & 0x0F != 1:
                    raise ValueError('reserved half-octet value')
                out['completion' if iei >> 4 == 0x9 else 'mandatory'] = True
                at += 1
            elif iei == 0x21:
                out['in_reply_to'] = data[at + 1 : at + 17].hex()
                at += 17
            elif iei == 0x22:
                out['application_id'] = data[at + 1]
                at += 2
            elif iei in (0x78, 0x79, 0x7D, 0x7E, 0x51, 0x53):
                length = int.from_bytes(data[at + 1 : at + 3], 'big')
                value = data[at + 3 : at + 3 + length]
                if len(value) != length:
                    raise ValueError('truncated TLV-E')
                if iei == 0x78:
                    if not value or value[0] != 0x04:
                        raise ValueError('payload content type is not FILEURL')
                    out['file_url'] = value[1:].decode()
                elif iei == 0x79:
                    out['metadata'] = value.decode()
                at += 3 + length
            else:
                raise ValueError(f'unknown IEI {iei:#x}')
        if at != len(data):
            raise ValueError('trailing octets')
        if 'file_url' not in out:
            raise ValueError('no FILEURL payload')
        return out
    if kind == 0x0D:
        # TS 24.282 table 15.1.13.1-1: no date and time; conversation, message, then the termination type.
        out = dict(
            type='FD HTTP TERMINATION', conversation=data[1:17].hex(), message=data[17:33].hex(), termination=data[33]
        )
        if not 1 <= out['termination'] <= 7:
            raise ValueError('reserved termination information type')
        at = 34
        while at < len(data):
            iei = data[at]
            if iei >> 4 in (0xC, 0xD):
                if iei & 0x0F not in (1, 2):
                    raise ValueError('reserved release or extension response type')
                out['release' if iei >> 4 == 0xD else 'extension'] = iei & 0x0F
                at += 1
            elif iei == 0x22:
                out['application_id'] = data[at + 1]
                at += 2
            elif iei in (0x78, 0x7D):
                length = int.from_bytes(data[at + 1 : at + 3], 'big')
                value = data[at + 3 : at + 3 + length]
                if len(value) != length:
                    raise ValueError('truncated TLV-E')
                if iei == 0x78:
                    if not value or value[0] != 0x04:
                        raise ValueError('payload content type is not FILEURL')
                    out['file_url'] = value[1:].decode()
                at += 3 + length
            else:
                raise ValueError(f'unknown IEI {iei:#x}')
        if at != len(data):
            raise ValueError('trailing octets')
        return out
    if kind in (0x06, 0x09):
        if len(data) < 39 or data[1] == 0 or data[1] > (4 if kind == 0x06 else 2):
            raise ValueError('bad FD notification')
        return dict(
            type='FD NOTIFICATION' if kind == 0x06 else 'FD NETWORK NOTIFICATION',
            notification=data[1],
            conversation=data[7:23].hex(),
            message=data[23:39].hex(),
        )
    raise ValueError(f'unexpected message type {kind:#x}')


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
    discovery_up = [
        message
        for message in requests
        if message['method'] == 'MESSAGE' and message['info'].get('request-type') == 'msf-disc-req'
    ]
    discovery_down = [
        message
        for message in requests
        if message['method'] == 'MESSAGE' and message['info'].get('request-type') == 'msf-disc-res'
    ]
    check(
        'a media storage function discovery request carries the FD ICSI and no signalling body (10.2.1.3)',
        bool(discovery_up)
        and all(
            header(message, 'p-preferred-service') == FD_ICSI and not message['signalling_bodies']
            for message in discovery_up
        ),
    )
    check(
        'the answer is a separate MESSAGE with <mcdata-controller-psi> and request-type msf-disc-res (step 7d)',
        bool(discovery_down)
        and all(
            message['info'].get('mcdata-controller-psi', '').startswith('https://')
            and header(message, 'p-asserted-service') == FD_ICSI
            for message in discovery_down
        ),
    )
    discovery_warnings = [
        header(response, 'warning')
        for message in discovery_up
        for response in answers(message)
        if response['status'] >= 300
    ]
    check(
        'a discovery request is answered 200, and refused with 403 for a group without FD or a user that may not transmit',
        any(response['status'] == 200 for message in discovery_up for response in answers(message))
        and any('"213 ' in warning for warning in discovery_warnings)
        and any('"200 ' in warning for warning in discovery_warnings),
    )
    fd = []
    for message in requests:
        if message['method'] != 'MESSAGE' or not message['signalling_bodies']:
            continue
        if FD_ICSI not in header(message, 'p-preferred-service') + header(message, 'p-asserted-service'):
            continue
        try:
            message['fd'] = decode_fd(message['signalling_bodies'][0])
            fd.append(message)
        except (KeyError, ValueError, IndexError, UnicodeDecodeError) as error:
            decode_errors.append(f"{message['line']}: {error}")
    check('every FD signalling body decodes by the clause 15 tables', bool(fd) and not decode_errors)

    uplink = [message for message in fd if message['target'] == args.service]
    downlink = [
        message for message in fd if message['target'] != args.service and args.service in header(message, 'from')
    ]
    requests_up = [message for message in uplink if message['fd']['type'] == 'FD SIGNALLING PAYLOAD']
    one = [message for message in requests_up if message['info'].get('request-type') == 'one-to-one-fd']
    group = [message for message in requests_up if message['info'].get('request-type') == 'group-fd']
    check(
        'an FD request carries the FD feature tag, ICSI and P-Preferred-Service (6.2.4.1, 10.2.4.2.1 step 1)',
        bool(requests_up)
        and all(
            any('g.3gpp.mcdata.fd' in contact for contact in message['headers']['accept-contact'])
            and any(
                'icsi-ref' in contact and 'mcdata.fd' in contact for contact in message['headers']['accept-contact']
            )
            and header(message, 'p-preferred-service') == FD_ICSI
            for message in requests_up
        ),
    )
    check(
        'the FD SIGNALLING PAYLOAD carries one FILEURL payload and the file metadata (10.2.4.2.1 step 4)',
        bool(requests_up)
        and all(
            message['fd']['file_url'].startswith('https://') and 'file-selector:' in message['fd'].get('metadata', '')
            for message in requests_up
            if message['fd'].get('metadata')
        ),
    )
    hashes = [message for message in requests_up if 'hash:sha-256:' in message['fd'].get('metadata', '')]
    check(
        'the file selector carries name, size and an RFC 5547 SHA-256 hash of upper-case hex pairs (15.2.17)',
        bool(hashes)
        and all(
            re.search(
                r'name:"[^"]+" type:\S+ size:\d+ hash:sha-256:([0-9A-F]{2}:){31}[0-9A-F]{2}', message['fd']['metadata']
            )
            for message in hashes
        ),
    )
    availability = [message for message in requests_up if 'file-availability:' in message['fd'].get('metadata', '')]
    check(
        'file-availability is an RFC 5322 date-time (15.2.17)',
        bool(availability)
        and all(
            re.search(
                r'file-availability:[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} '
                r'\d{2}:\d{2}:\d{2} \+0000',
                message['fd']['metadata'],
            )
            for message in availability
        ),
    )
    check(
        'one-to-one FD names exactly one target in resource-lists (10.2.4.2.1 step 2)',
        bool(one) and all(message['targets'] and len(message['targets']) == 1 for message in one),
    )
    check(
        'group FD names the group in mcdata-request-uri with the client ID and no resource-lists (step 3)',
        bool(group)
        and all(
            message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-client-id')
            and message['targets'] is None
            for message in group
        ),
    )
    accepted = [response for message in requests_up for response in answers(message) if response['status'] == 202]
    check('an accepted FD request gets 202 Accepted (10.2.4.4.2 steps 15-16)', len(accepted) >= 4)
    delivered = [message for message in downlink if message['fd']['type'] == 'FD SIGNALLING PAYLOAD']
    check(
        'a delivered FD request names the recipient and the originator with the FD ICSI (10.2.4.4.1)',
        bool(delivered)
        and all(
            message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-calling-user-id')
            and header(message, 'p-asserted-service') == FD_ICSI
            and any('g.3gpp.mcdata.fd' in contact for contact in message['headers']['accept-contact'])
            for message in delivered
        ),
    )
    check(
        'a delivered group FD names the calling group (10.2.4.4.1 step 6b)',
        any(message['info'].get('mcdata-calling-group-id') for message in delivered),
    )
    check(
        'the file URL is relayed unchanged to the recipients (step 4)',
        all(any(sent['fd']['file_url'] == message['fd']['file_url'] for sent in requests_up) for message in delivered),
    )
    check(
        'auto-receive adds the Mandatory download IE for a small file (11.2, 15.2.16)',
        any(message['fd']['mandatory'] for message in delivered)
        and any(
            not sent['fd']['mandatory']
            for sent in requests_up
            for message in delivered
            if message['fd']['message'] == sent['fd']['message'] and message['fd']['mandatory']
        ),
    )
    notices_up = [message for message in uplink if message['fd']['type'] == 'FD NOTIFICATION']
    notices_down = [message for message in downlink if message['fd']['type'] == 'FD NOTIFICATION']
    check(
        'FD notifications carry accepted, rejected, completed and deferred (15.2.6, 12.2.1.1)',
        {message['fd']['notification'] for message in notices_up} == {1, 2, 3, 4},
    )
    single_down = [message for message in notices_down if message['info'].get('mcdata-calling-user-id')]
    aggregated_down = [message for message in notices_down if not message['info'].get('mcdata-calling-user-id')]
    check(
        'FD notifications name the originator in resource-lists and are relayed with the notifier (12.2.2.1, 12.2.3)',
        bool(notices_up)
        and all(message['targets'] and len(message['targets']) == 1 for message in notices_up)
        and bool(single_down)
        and all(
            len(message['signalling_bodies']) == 1 and header(message, 'p-asserted-service') == FD_ICSI
            for message in single_down
        ),
    )
    check(
        'aggregated FD notifications carry one signalling body per notification with the calling group (12.2.3 step 15c)',
        any(len(message['signalling_bodies']) > 1 for message in aggregated_down)
        and all(
            message['info'].get('mcdata-calling-group-id')
            and header(message, 'p-asserted-service') == FD_ICSI
            and all(decode_fd(body)['type'] == 'FD NOTIFICATION' for body in message['signalling_bodies'])
            for message in aggregated_down
        ),
    )
    network = [message for message in downlink if message['fd']['type'] == 'FD NETWORK NOTIFICATION']
    check(
        'TDC2 expiry sends an FD NETWORK NOTIFICATION of type FILE EXPIRED with request-type notify (12.4.2)',
        any(message['fd']['notification'] == 1 for message in network)
        and all(message['info'].get('request-type') == 'notify' for message in network),
    )
    releases_up = [message for message in uplink if message['fd']['type'] == 'FD HTTP TERMINATION']
    releases_down = [message for message in downlink if message['fd']['type'] == 'FD HTTP TERMINATION']
    requested = [message for message in releases_up if message['fd']['termination'] == 1]
    answered = [message for message in releases_down if message['fd']['termination'] == 2]
    check(
        'a release request names the conversation, message and file URL with TERMINATION REQUEST (6.2.2.4, 15.1.13)',
        bool(requested)
        and all(message['fd'].get('file_url') and int(message['fd']['conversation'], 16) for message in requested),
    )
    check(
        'the server answers a release with TERMINATION RESPONSE and RELEASE SUCCESS (10.2.4.4.2 step 17b, 6.3.6.1)',
        bool(answered)
        and all(message['fd'].get('release') == 1 and message['fd'].get('file_url') for message in answered)
        and all(header(message, 'p-asserted-service') == FD_ICSI for message in releases_down),
    )
    check(
        'a released file is announced as FILE DELETED UNAVAILABLE TO DOWNLOAD (12.4.2.1, 15.2.18)',
        any(message['fd']['notification'] == 2 for message in network),
    )
    kinds = collections.Counter(message['fd']['termination'] for message in releases_down)
    check(
        'the server announces its intent to release and stops a transmission, each with a Reason header (13.2.3.3.4, 13.2.4.5)',
        kinds[3]
        and kinds[4]
        and all(header(message, 'reason') for message in releases_down if message['fd']['termination'] in (3, 4)),
    )
    check(
        'an extension request is answered with EXTENSION RESPONSE ACCEPTED (13.2.4.5, 15.2.21)',
        any(message['fd']['termination'] == 5 for message in releases_up)
        and any(message['fd']['termination'] == 6 and message['fd'].get('extension') == 1 for message in releases_down),
    )
    check(
        'an authorised user releases another user\'s distribution and is answered RELEASE SUCCESS (13.2.5.3)',
        any(message['fd']['termination'] == 7 for message in releases_up)
        and any(
            status == 403
            for message in releases_up
            if message['fd']['termination'] == 7
            for status in [response['status'] for response in answers(message)]
        )
        and any(
            response['status'] == 202
            for message in releases_up
            if message['fd']['termination'] == 7
            for response in answers(message)
        ),
    )
    released_ok = [response for message in releases_up for response in answers(message) if response['status'] == 202]
    released_bad = [
        (response['status'], header(response, 'warning'))
        for message in releases_up
        for response in answers(message)
        if response['status'] >= 300
    ]
    check(
        'a release is accepted with 202 and an unknown transmission rejected with 404/224 (step 11b)',
        bool(released_ok) and any(status == 404 and '"224 ' in warning for status, warning in released_bad),
    )
    redirects = [response for message in one for response in answers(message) if response['status'] == 300]
    check(
        'an FD request to a functional alias gets 300 naming the selected MCData ID (10.2.4.4.2 step 10b)',
        bool(redirects) and all(response['info'].get('mcdata-request-uri') for response in redirects),
    )
    check(
        'the follow-up names the selected user and carries <called-functional-alias-URI>',
        any(message['info'].get('called-functional-alias-URI') for message in one),
    )
    # 300 Multiple Choices is an alias redirect, not a rejection.
    rejected = [
        (response['status'], header(response, 'warning'))
        for message in requests_up
        for response in answers(message)
        if response['status'] > 300
    ]
    # The warnings of the refusals mcdata_fd_scenario.py provokes (TS 24.282 table 4.9.2-2).
    provoked = ('200', '202', '208', '212', '213', '214', '163', '229', '230')
    seen_codes = sorted({(status, code) for status, warning in rejected for code in provoked if f'"{code} ' in warning})
    check(
        'the refusals carry the warnings 200, 202, 208, 212, 213, 214, 163, 229 and 230',
        {code for _, code in seen_codes} == set(provoked),
    )
    check(
        'every FD rejection carries an MCData warning code', bool(rejected) and all(warning for _, warning in rejected)
    )
    report = dict(
        capture=str(args.capture),
        passed=not failures and not decode_errors,
        checks=checks,
        failures=failures,
        decode_errors=decode_errors,
        observations=dict(
            requests=len(requests_up),
            delivered=len(delivered),
            notifications=len(notices_up),
            network_notifications=len(network),
            rejections=len(rejected),
            rejection_codes=[f'{status}/{code}' for status, code in seen_codes],
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
