#!/usr/bin/env python3
"""Verify group and user regroups using a preconfigured group from a clear-SIP capture.

The regroup procedures of TS 24.379 clause 16: group regroup requests and notifications (clauses 16.2.1.1 to 16.2.1.4,
16.2.3.1 and 16.2.3.2), user regroup requests and notifications (clauses 16.3.1.1, 16.3.1.3, 16.3.1.4 and 16.3.2.4),
refusals with warnings 160, 161, 163 and 165 (table 4.4.2-2), calls on the regroup and the refusal of calls on a
regrouped constituent group with warning 148.

Usage: verify_regroup.py capture.pcap --service sip:mcptt@DOMAIN --output result.json

Independent of the C++ codecs: SIP is split from the reassembled TCP streams and the
application/vnd.3gpp.mcptt-regroup+xml bodies are read here against the schema of TS 24.379 annex F.7.2.

Specifications: TS 24.379 V19.7.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402

REGROUP_NS = '{urn:3gpp:ns:preconfiguredRegroup:1.0}'
REGROUP_MIME = 'application/vnd.3gpp.mcptt-regroup+xml'


# ------------------------------------------------------------------------------
def regroup_body(message):
    """The regroup MIME body of a message (TS 24.379 annex F.7.2), as a dict, or None."""
    match = re.search(r'<(?:[\w.-]+:)?mcpttregroup\b.*?</(?:[\w.-]+:)?mcpttregroup\s*>', message['body'], re.S)
    if not match:
        return None
    root = ET.fromstring(match.group())
    if root.tag != REGROUP_NS + 'mcpttregroup':
        raise ValueError('wrong regroup root element')
    params = root.find(REGROUP_NS + 'mcpttregroup-Params')
    if params is None:
        raise ValueError('no mcpttregroup-Params')

    # ------------------------------------------------------------------------------
    def one(container, name):
        """The text of the element name inside the container element of the regroup parameters, or an empty string."""
        node = params.find(REGROUP_NS + container)
        if node is None:
            return ''
        inner = node.find(REGROUP_NS + name)
        return (inner.text or '').strip() if inner is not None else ''

    # ------------------------------------------------------------------------------
    def entries(container, name):
        """The texts of the name elements inside the container element of the regroup parameters."""
        node = params.find(REGROUP_NS + container)
        return [(entry.text or '').strip() for entry in node.findall(REGROUP_NS + name)] if node is not None else []

    if params.find(REGROUP_NS + 'preconfig-group-id') is None:
        raise ValueError('no preconfig-group-id')
    return dict(
        action=(params.findtext(REGROUP_NS + 'regroup-action') or '').strip(),
        regroup=one('mcptt-regroup-uri', 'mcptt-regroup-uri'),
        preconfigured=one('preconfig-group-id', 'preconfigured-group'),
        groups=entries('groups-for-regroup', 'group'),
        users=entries('users-for-regroup', 'user'),
    )


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
    checks, failures, decode_errors = [], [], []

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

    regroups = []
    for parsed in messages:
        if not parsed['request'] or parsed['method'] != 'MESSAGE':
            continue
        try:
            body = regroup_body(parsed)
        except (ET.ParseError, ValueError) as error:
            decode_errors.append(str(error))
            continue
        if body:
            regroups.append((parsed, body))

    requests = [(message, regroup) for message, regroup in regroups if message['target'] == args.service]
    notices = [(message, regroup) for message, regroup in regroups if message['target'] != args.service]
    check(
        'a regroup request is a SIP MESSAGE to the MCPTT service identity with the regroup MIME body (16.2.1.1)',
        bool(requests),
    )
    check(
        'every regroup body carries an action and a temporary group identity, and a creation its preconfigured group (F.7.2)',
        bool(regroups)
        and all(
            regroup['action'] in ('create', 'remove')
            and regroup['regroup']
            and (regroup['preconfigured'] or regroup['action'] == 'remove')
            for _, regroup in regroups
        ),
    )
    check(
        'no regroup body names both groups and users (F.7.3)',
        all(not (regroup['groups'] and regroup['users']) for _, regroup in regroups),
    )
    check(
        'a group regroup creation names the constituent groups and no users (16.2.1.1)',
        any(
            regroup['action'] == 'create' and len(regroup['groups']) >= 2 and not regroup['users']
            for _, regroup in requests
        ),
    )
    check(
        'a user regroup creation names the users and no groups (16.3.1.1 step 7d)',
        any(regroup['action'] == 'create' and regroup['users'] and not regroup['groups'] for _, regroup in requests),
    )
    check(
        'a removal request names only the regroup and the action (16.2.1.2 step 9)',
        any(regroup['action'] == 'remove' for _, regroup in requests)
        and all(
            not regroup['groups'] and not regroup['users'] for _, regroup in requests if regroup['action'] == 'remove'
        ),
    )
    check(
        'the request carries the MCPTT client ID and the service identity (16.2.1.1 steps 5-6)',
        all(message['info'].get('mcptt-client-id') for message, _ in requests)
        and all(
            'mcptt' in header(message, 'p-preferred-service') or 'mcptt' in header(message, 'p-asserted-service')
            for message, _ in requests
        ),
    )
    outcomes = collections.Counter(
        response['status'] for message, _ in requests for response in responses(message) if response['status'] >= 200
    )
    check('a regroup is created and removed with 200 (16.2.3.1 step 6, 16.2.3.2)', outcomes[200] >= 2)
    warnings = [
        header(response, 'warning')
        for message, _ in requests
        for response in responses(message)
        if response['status'] >= 300
    ]
    for code, text in (('160', 'creation'), ('161', 'removal'), ('165', 'already in use'), ('163', 'unknown regroup')):
        check(
            f'refusal {code} ({text}) is returned 403 in a Warning header field (clause 4.4)',
            any(f'"{code} ' in warning for warning in warnings),
        )

    group_tgis = {regroup['regroup'] for _, regroup in requests if regroup['action'] == 'create' and regroup['groups']}
    user_requests = [regroup for _, regroup in requests if regroup['action'] == 'create' and regroup['users']]
    user_tgis = {regroup['regroup'] for regroup in user_requests}
    group_notices = [(message, regroup) for message, regroup in notices if regroup['regroup'] in group_tgis]
    user_notices = [(message, regroup) for message, regroup in notices if regroup['regroup'] in user_tgis]
    check(
        'every member of a constituent group is told of the creation and of the removal (16.2.1.3, 16.2.1.4)',
        bool(group_notices) and {regroup['action'] for _, regroup in group_notices} == {'create', 'remove'},
    )
    check(
        'a group regroup creation notice repeats the temporary group identity, its preconfigured group and its '
        'constituents',
        all(
            regroup['regroup'] and regroup['preconfigured'] and len(regroup['groups']) >= 2
            for _, regroup in group_notices
            if regroup['action'] == 'create'
        ),
    )
    check(
        'a group regroup removal notice carries no <groups-for-regroup> or <users-for-regroup> (16.2.2.5 step 3 e))',
        all(
            not regroup['groups'] and not regroup['users']
            for _, regroup in group_notices
            if regroup['action'] == 'remove'
        ),
    )
    check(
        'every user of a user regroup is told of the creation and of the removal (16.3.1.3, 16.3.1.4)',
        bool(user_notices) and {regroup['action'] for _, regroup in user_notices} == {'create', 'remove'},
    )
    requested_users = {
        user
        for message, regroup in requests
        if regroup['action'] == 'create'
        and regroup['users']
        and any(response['status'] == 200 for response in responses(message))
        for user in regroup['users']
    }
    created = [(message, regroup) for message, regroup in user_notices if regroup['action'] == 'create']
    check(
        'a user regroup creation notice names the users and no groups (16.3.2.4 step 3e)',
        bool(created)
        and all(
            regroup['users']
            and set(regroup['users']) <= requested_users
            and not regroup['groups']
            and regroup['preconfigured']
            for _, regroup in created
        ),
    )
    check(
        'a created user regroup is told to exactly as many users as its request named',
        len({message['target'] for message, _ in created}) == len(requested_users),
    )
    check(
        'a user regroup removal notice names neither users nor groups (16.2.2.5 step 3e)',
        all(
            not regroup['users'] and not regroup['groups']
            for _, regroup in user_notices
            if regroup['action'] == 'remove'
        ),
    )
    check(
        'a notification is sent to the member itself and asserts the MCPTT service',
        all(message['target'].startswith('sip:') and message['target'] != args.service for message, _ in notices)
        and all('mcptt' in header(message, 'p-asserted-service') for message, _ in notices),
    )

    tgis = group_tgis | user_tgis
    constituents = {group for _, regroup in requests for group in regroup['groups']}
    invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and not re.search(r';\s*tag=', header(message, 'to'), re.I)
    ]
    on_regroup = [message for message in invites if message['info'].get('mcptt-request-uri') in tgis]
    on_constituent = [message for message in invites if message['info'].get('mcptt-request-uri') in constituents]
    check('a call is placed on the temporary group identity itself (16.1)', bool(on_regroup))
    check(
        'a call on the regroup is accepted',
        any(response['status'] == 200 for message in on_regroup for response in responses(message)),
    )
    refused = [
        header(response, 'warning')
        for message in on_constituent
        for response in responses(message)
        if response['status'] >= 300
    ]
    check(
        'a call on a regrouped constituent group is refused with warning 148 (10.1.1.4.2 step 5 b))',
        any('"148 ' in warning for warning in refused),
    )
    check(
        'the constituent group carries a call again once the regroup is removed',
        any(response['status'] == 200 for message in on_constituent for response in responses(message)),
    )
    to_members = [
        message
        for message in invites
        if message['info'].get('mcptt-calling-group-id') in user_tgis
        and message['info'].get('mcptt-request-uri') not in tgis
    ]
    check(
        'a member of a user regroup is invited to its call and answers (16.3.2.4 step 3h)',
        any(response['status'] == 200 for message in to_members for response in responses(message)),
    )

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        decode_errors=decode_errors,
        counts=dict(
            sip_messages=len(messages),
            regroup_requests=len(requests),
            regroup_notifications=len(notices),
            outcomes={str(key): value for key, value in outcomes.items()},
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'counts'}, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
