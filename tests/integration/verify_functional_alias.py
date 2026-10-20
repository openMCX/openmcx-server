#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify functional alias signaling from a clear-SIP server-side capture.

Functional alias status changes (TS 24.379 clause 9A.2.1.2): PUBLISH with the presence event and the functional alias
PIDF extension (clause 9A.3.1), Expires 4294967295 to activate and 0 to deactivate, after the client's subscription to
its own functional alias status (clauses 9A.2.1.1 and 9A.2.1.3, <request-type> "functional-alias-status-determination").
The participating server answers 200, or 403 with warning 201 for an alias the user may not change (clause 9A.2.2.2.3
steps 4A, 4B and 8), and tells the outcome by NOTIFY with the PUBLISH's <p-id-fa> (clause 9A.2.2.2.5): "activated",
"take-over-possible", or the alias left out; <take-over> follows only a "take-over-possible" (clause 9A.2.1.2 step
6 d)). Private calls to an alias are redirected with 300 naming the selected MCPTT ID
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
    # TS 24.379 clause 9A.3.1.2 items 7 and 8: one alias ID for each alias the user wants active, so an Expires 0
    # PUBLISH that gives every alias up may list none (clause 9A.2.2.2.3 step 13 deactivates them all).
    check(
        'each PUBLISH names the user as the presence entity with a client tuple, and alias IDs unless Expires 0',
        all(
            re.search(r'<presence[^>]+entity="sip:', message['body'])
            and ('functionalAliasID="sip:' in message['body'] or header(message, 'expires') == '0')
            and re.search(r'<tuple id="[^"]+"', message['body'])
            for message in publishes
        ),
    )
    finals = [
        (message, response) for message in publishes for response in responses(message) if response['status'] >= 200
    ]
    outcomes = collections.Counter(response['status'] for _, response in finals)
    check(
        'status changes are answered 200, or 403 with warning 201 only (9A.2.2.2.3 steps 4B and 8)',
        outcomes[200] > 0
        and outcomes[403] > 0
        and set(outcomes) <= {200, 403}
        and all(
            header(response, 'warning').startswith('399 ')
            and '201 user not authorized to change the functional alias status' in header(response, 'warning')
            for _, response in finals
            if response['status'] == 403
        ),
    )
    subscribes = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'SUBSCRIBE'
        and '<request-type>functional-alias-status-determination</request-type>' in message['body']
    ]
    publishers = {re.search(r'entity="([^"]+)"', message['body']).group(1) for message in publishes}
    check(
        'every publishing user subscribes to its own functional alias status with Expires 4294967295 (9A.2.1.3)',
        all(
            any(
                message['info'].get('mcptt-request-uri') == user and header(message, 'expires') == '4294967295'
                for message in subscribes
            )
            for user in publishers
        ),
    )
    notifies = [
        message
        for message in messages
        if message['request'] and message['method'] == 'NOTIFY' and FA_NS in message['body']
    ]

    # ------------------------------------------------------------------------------
    def pid(body):
        """The <p-id-fa> of a functional alias PIDF, or None."""
        found = re.search(r'<(?:\w+:)?p-id-fa>([^<]+)</', body)
        return found.group(1) if found else None

    accepted = [message for message, response in finals if response['status'] == 200]
    notified = {pid(message['body']) for message in notifies} - {None}
    check(
        'each accepted status change is followed by a NOTIFY with its p-id-fa (9A.2.2.2.5 step 2c)',
        bool(accepted) and all(pid(message['body']) in notified for message in accepted),
    )
    check(
        'the per-user NOTIFYs list activated aliases and offer take-over (status attribute, 9A.3.1.2)',
        any('status="activated"' in message['body'] for message in notifies)
        and any('status="take-over-possible"' in message['body'] for message in notifies),
    )
    offered = {
        (re.search(r'entity="([^"]+)"', message['body']).group(1), alias)
        for message in notifies
        for alias in re.findall(r'functionalAliasID="([^"]+)" status="take-over-possible"', message['body'])
    }
    take_overs = [message for message in publishes if 'take-over>true<' in message['body']]
    check(
        'take-over requests carry the take-over element only for aliases offered as take-over-possible (9A.2.1.2 '
        'step 6 d))',
        bool(take_overs)
        and all(
            (re.search(r'entity="([^"]+)"', message['body']).group(1), alias) in offered
            for message in take_overs
            for alias in re.findall(r'functionalAliasID="([^"]+)"', message['body'])
        ),
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
            status_subscriptions=len(subscribes),
            status_notifies=len(notifies),
            redirects=len(redirects),
            presented_invites=len(presented),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
