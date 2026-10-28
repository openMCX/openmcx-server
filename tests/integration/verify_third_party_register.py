#!/usr/bin/env python3
"""Verify the SIP core's third-party REGISTERs to the MCPTT server from a clear-SIP capture at the server.

Checks (TS 24.379 clause 7.3.2, TS 24.229 clause 5.4.1.7):
  - every REGISTER the server receives is a third-party REGISTER: From and Contact the SIP core, To a client's public
    user identity, Content-Type message/sip;
  - its message/sip body is the client's REGISTER: the request line, the same To, and an
    application/vnd.3gpp.mcptt-info+xml body with the access token and the client ID (with --protected both are
    encrypted, TS 24.379 clause 7.2.1 step 6: type="Encrypted" with an EncryptedData, never in clear); the client's
    Authorization header is not in it;
  - with --integrity, the client's REGISTER also carries an application/vnd.3gpp.mcptt-signed+xml body (TS 24.379
    clause 7.2.1 step 7, clause 6.6.3);
  - each is answered 200 (OK), and no client authorised by a poc-settings PUBLISH (clause 7.2.2) instead;
  - a de-registration (Expires 0, a client's log-off) carries the client's REGISTER with Expires 0 and no Authorization;
  - at least --users users were authorised so.

Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--users', type=int, default=4)
    parser.add_argument('--protected', action='store_true', help='the access token and client ID are encrypted')
    parser.add_argument('--integrity', action='store_true', help='the client REGISTER bodies are signed')
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
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        (checks if condition else failures).append(label)

    registers = [message for message in messages if message['request'] and message['method'] == 'REGISTER']
    finals = {
        (message['call_id'], header(message, 'cseq')): message['status']
        for message in messages
        if not message['request'] and message['status'] >= 200
    }
    check('third-party REGISTERs reach the server', bool(registers))
    check(
        'each comes from the SIP core (From and Contact) with a message/sip body',
        all(
            'sip-core' in header(message, 'from')
            and 'sip-core' in header(message, 'contact')
            and header(message, 'content-type').split(';')[0].strip().lower() == 'message/sip'
            for message in registers
        ),
    )
    # A de-registration (Expires 0, the client's log-off) carries the client's REGISTER without a body.
    removals = [message for message in registers if header(message, 'expires').strip() == '0']
    registers = [message for message in registers if message not in removals]
    check(
        'each de-registration is the client REGISTER with Expires 0 and without its Authorization, answered 200',
        all(
            message['body'].startswith('REGISTER ')
            and 'expires: 0' in message['body'].lower()
            and 'authorization:' not in message['body'].lower()
            and finals.get((message['call_id'], header(message, 'cseq'))) == 200
            for message in removals
        ),
    )
    # ------------------------------------------------------------------------------
    def encrypted(body, element):
        """The element is present with type="Encrypted" and an EncryptedData (TS 24.379 clause 6.6.2.3.3)."""
        match = re.search(rf'<(?:[\w.-]+:)?{element}\b([^>]*)>(.*?)</(?:[\w.-]+:)?{element}\s*>', body, re.S)
        return bool(match) and 'type="Encrypted"' in match.group(1) and 'EncryptedData' in match.group(2)

    inner_ok, users = [], set()
    for message in registers:
        body = message['body']
        to = header(message, 'to')
        tokens = (
            encrypted(body, 'mcptt-access-token') and encrypted(body, 'mcptt-client-id')
            if args.protected
            else 'mcptt-access-token' in body and 'mcptt-client-id' in body
        )
        inner_ok.append(
            body.startswith('REGISTER ')
            and to.split(';')[0].strip('<> ') in body
            and 'application/vnd.3gpp.mcptt-info+xml' in body
            and tokens
            and (not args.integrity or 'application/vnd.3gpp.mcptt-signed+xml' in body)
            and 'authorization:' not in body.lower()
        )
        if finals.get((message['call_id'], header(message, 'cseq'))) == 200:
            users.add(to.split(';')[0].strip('<> '))
    check(
        'the body is the client REGISTER with its mcptt-info (access token, client ID'
        + (', encrypted' if args.protected else '')
        + (', signed' if args.integrity else '')
        + ') and without its Authorization',
        bool(inner_ok) and all(inner_ok),
    )
    check('each third-party REGISTER is answered 200', bool(registers) and all(
        finals.get((message['call_id'], header(message, 'cseq'))) == 200 for message in registers))
    check(f'at least {args.users} users authorised by third-party REGISTER', len(users) >= args.users)
    publishes = [
        message
        for message in messages
        if message['request'] and message['method'] == 'PUBLISH' and 'poc-settings' in header(message, 'event')
    ]
    check('no client authorised by a poc-settings PUBLISH instead', not publishes)
    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            third_party_registers=len(registers),
            deregistrations=len(removals),
            users=sorted(users),
            poc_settings_publishes=len(publishes),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
