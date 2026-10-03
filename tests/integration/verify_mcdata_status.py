#!/usr/bin/env python3
"""Check a capture of MCData enhanced status against TS 24.282 clause 14.2.

Reads clear TCP/5060 SIP (debug SIP) and decodes the DATA PAYLOAD of each group standalone SDS independently of the C++
implementation: an enhanced status is a "group-sds" to the MCData PSI (TS 24.282 clause 14.2.1.1 with clause 9.2.2.2.1)
whose one Payload IE has the content type ENHANCED STATUS (6, table 15.2.13-2) and carries the "id" of an operational
value; the controlling function delivers it to each member with the calling group (clause 14.2.3 with clause 9.2.2.4.2).
The DATA PAYLOAD is decoded by table 15.1.4.1-1.

Specifications: TS 24.282 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_sds import decode_payload, header, parse, sip_messages, tcp_streams  # noqa: E402

PAYLOAD = 'application/vnd.3gpp.mcdata-payload'
ENHANCED_STATUS = 6


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

    statuses = []
    for message in messages:
        if message['request'] and message['method'] == 'MESSAGE' and PAYLOAD in message['parts']:
            try:
                payloads = decode_payload(message['parts'][PAYLOAD])
            except ValueError as error:
                errors.append(f'{message["call_id"]}: {error}')
                continue
            if any(kind == ENHANCED_STATUS for kind, _ in payloads):
                statuses.append((message, payloads))
    sent = [(message, payload_list) for message, payload_list in statuses if message['target'] == args.service]
    delivered = [
        (message, payload_list)
        for message, payload_list in statuses
        if message['target'] != args.service and args.service in header(message, 'from')
    ]
    check(
        'an enhanced status is a group standalone SDS to the MCData PSI (14.2.1.1 with 9.2.2.2.1)',
        bool(sent)
        and all(
            message['info'].get('request-type') == 'group-sds' and message['info'].get('mcdata-request-uri')
            for message, _ in sent
        ),
    )
    check(
        'its DATA PAYLOAD holds one Payload IE of content type ENHANCED STATUS carrying an id (table 15.2.13-2)',
        bool(sent)
        and all(
            len(payload_list) == 1 and payload_list[0][0] == ENHANCED_STATUS and payload_list[0][1]
            for _, payload_list in sent
        ),
    )
    ids = {bytes(payload_list[0][1]).decode() for _, payload_list in sent}
    check(
        'the ids sent are those of the operational values, and one that is not (the discard test)',
        {'1', '2', '9'} <= ids,
    )
    check(
        'the server delivers the same payload to each member with the calling group (14.2.3 with 9.2.2.4.2)',
        bool(delivered)
        and all(
            message['info'].get('mcdata-calling-group-id') and message['info'].get('mcdata-calling-user-id')
            for message, _ in delivered
        )
        and {bytes(payload_list[0][1]).decode() for _, payload_list in delivered} == {'1', '2', '9'},
    )
    check('each accepted status reaches three members', len(delivered) >= 9)
    check('the DATA PAYLOAD bodies decode by table 15.1.4.1-1', not errors)
    report = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        decode_errors=errors,
        observations=dict(sent=len(sent), delivered=len(delivered), ids=sorted(ids)),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
