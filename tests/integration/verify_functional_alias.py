#!/usr/bin/env python3
"""Verify functional alias signaling from a clear-SIP server-side capture.

Functional alias status changes (TS 24.379 clause 9A.2.1.2): PUBLISH with the presence event and the functional alias
PIDF extension (clause 9A.3.1), Expires 4294967295 to activate and 0 to deactivate, take-over requests, accepted or
refused by alias policy (clause 9A.2.2). Private calls to an alias are redirected with 300 naming the selected MCPTT ID
(clause 11.1.1.4.2 step 8a), and the caller re-invites it with the called alias; an alias without activated users is
rejected with warning 145 (table 4.4.2-2); terminating INVITEs present the caller's alias only when it is activated
(clause 10.1.1.3.1.1 step 6a).

Usage: verify_functional_alias.py capture.pcap --service sip:mcptt@DOMAIN --output result.json

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402

FA_NS = 'urn:3gpp:ns:mcpttPresInfoFA:1.0'


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
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    # ------------------------------------------------------------------------------
    def responses(request):
        """The responses to request (same Call-ID and CSeq)."""
        return [
            message
            for message in messages
            if not message['request']
            and message['call_id'] == request['call_id']
            and header(message, 'cseq') == header(request, 'cseq')
        ]

    publishes = [
        message
        for message in messages
        if message['request'] and message['method'] == 'PUBLISH' and FA_NS in message['body']
    ]
    check(
        'functional alias status changes use PUBLISH with the presence event and the FA PIDF extension',
        bool(publishes) and all(header(message, 'event') == 'presence' for message in publishes),
    )
    check(
        'activation requests Expires 4294967295 and deactivation Expires 0',
        all(header(message, 'expires') in ('4294967295', '0') for message in publishes)
        and any(header(message, 'expires') == '0' for message in publishes),
    )
    check(
        'each PUBLISH names the user as the presence entity with a client tuple and alias IDs',
        all(
            re.search(r'<presence[^>]+entity="sip:', message['body'])
            and 'functionalAliasID="sip:' in message['body']
            and re.search(r'<tuple id="[^"]+"', message['body'])
            for message in publishes
        ),
    )
    outcomes = collections.Counter(
        response['status'] for message in publishes for response in responses(message) if response['status'] >= 200
    )
    check(
        'status changes are accepted (200) and refused (403) per alias policy', outcomes[200] > 0 and outcomes[403] > 0
    )
    check(
        'take-over requests carry the take-over element',
        any('take-over>true<' in message['body'] for message in publishes),
    )

    invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and not re.search(r';\s*tag=', header(message, 'to'), re.I)
    ]
    to_alias = [message for message in invites if message['info'].get('call-to-functional-alias-ind') == 'true']
    check(
        'calls to an alias carry call-to-functional-alias-ind true and name the alias',
        bool(to_alias) and all(message['targets'] and len(message['targets']) == 1 for message in to_alias),
    )
    redirects = [
        response
        for message in to_alias
        if message['info'].get('session-type') == 'private'
        for response in responses(message)
        if response['status'] == 300
    ]
    check(
        'a private call to an alias is redirected with 300 naming the selected MCPTT ID and the called alias',
        bool(redirects)
        and all(
            response['info'].get('mcptt-request-uri')
            and response['info'].get('called-functional-alias-URI')
            and header(response, 'contact')
            for response in redirects
        ),
    )
    selected = {response['info'].get('mcptt-request-uri') for response in redirects}
    follow_ups = [
        message
        for message in invites
        if message['target'] == args.service
        and message['targets']
        and message['targets'][0] in selected
        and message['info'].get('called-functional-alias-URI')
    ]
    check(
        'the caller re-invites the selected MCPTT ID with the called alias and without the alias indicator',
        bool(follow_ups) and all('call-to-functional-alias-ind' not in message['info'] for message in follow_ups),
    )
    no_user = [
        response
        for message in to_alias
        for response in responses(message)
        if response['status'] == 403 and '145 ' in header(response, 'warning')
    ]
    check('an alias without activated users is rejected with 403 warning 145', bool(no_user))
    presented = [
        message
        for message in invites
        if message['target'] != args.service and message['info'].get('functional-alias-URI')
    ]
    check('terminating INVITEs present the caller alias', bool(presented))
    requested = [
        message
        for message in invites
        if message['target'] == args.service and message['info'].get('functional-alias-URI')
    ]
    check(
        'an alias requested but not activated is not presented (10.1.1.3.1.1 step 6a)',
        len({message['info']['functional-alias-URI'] for message in requested}) >= 1
        and len(presented) < sum(1 for message in invites if message['target'] != args.service),
    )

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            publishes=len(publishes),
            publish_outcomes=dict(outcomes),
            redirects=len(redirects),
            presented_invites=len(presented),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
