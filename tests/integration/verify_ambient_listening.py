#!/usr/bin/env python3
"""Verify ambient listening call signaling from a clear-SIP capture.

The ambient listening call of TS 24.379 clause 11.1.6: originating INVITEs carry the ambient listening type, one listed
user, Priv-Answer-Mode Auto and an implicit floor request (clause 11.1.6.2.1.1); remote-init offers are recvonly and
local-init offers sendonly (clause 6.2.1 step 2 c)); the listened-to invitee is called without alerting (clause
11.1.6.4.1), the listening invitee and the originator get the g.3gpp.mcptt.ambient-listening-call-release
feature-capability indicator (annex D.3) and the complementary direction; requests are rejected with warnings 154, 144
and 127 (table 4.4.2-2) or 480 to a busy user; server BYEs carry the release reasons (clause 11.1.6.4.3) only in ambient
listening dialogs.

Usage: verify_ambient_listening.py capture.pcap --service sip:mcptt@DOMAIN --output result.json
Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py.

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

FEATURE = 'g.3gpp.mcptt.ambient-listening-call-release'
NULL_ALERT = '<file:///dev/null>'
REASONS = {
    'administrator-action',
    'call-request-initiated-by-listened-to-client',
    'call-request-for-listened-to-client',
    'private-call-expiry',
}


# ------------------------------------------------------------------------------
def audio_direction(message):
    """The direction attribute of the audio media of the SDP in message, or an empty string."""
    sdp = message['body'][message['body'].find('v=0') :] if 'v=0' in message['body'] else ''
    audio = sdp.split('m=application')[0]
    found = re.findall(r'(?m)^a=(sendrecv|sendonly|recvonly|inactive)\r?$', audio)
    return found[0] if found else ''


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen, copies = [], set(), []
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            copies.append(message)  # every hop's copy: the SIP core may change a header field on the way
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:
                seen.add(key)
                messages.append(message)
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    responses = collections.defaultdict(list)
    for parsed in messages:
        if not parsed['request']:
            responses[(parsed['call_id'], header(parsed, 'cseq'))].append(parsed)

    # ------------------------------------------------------------------------------
    def answers(message):
        """The responses to the request message (same Call-ID and CSeq)."""
        return responses[(message['call_id'], header(message, 'cseq'))]

    invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['info'].get('session-type') == 'ambient-listening'
    ]
    originating = [message for message in invites if message['target'] == args.service]
    terminating = [message for message in invites if message['target'] != args.service]
    remote = [message for message in originating if message['info'].get('ambient-listening-type') == 'remote-init']
    local = [message for message in originating if message['info'].get('ambient-listening-type') == 'local-init']

    check(
        'originating INVITEs to the service URI carry session-type ambient-listening, a type, one listed user, '
        'Priv-Answer-Mode Auto and mc_implicit_request',
        bool(remote)
        and bool(local)
        and all(
            message['targets']
            and len(message['targets']) == 1
            and header(message, 'priv-answer-mode') == 'Auto'
            and 'mc_implicit_request' in message['body']
            for message in originating
        ),
    )
    check(
        'remote-init offers are recvonly and local-init offers are sendonly (6.2.1 step c)',
        all(audio_direction(message) == 'recvonly' for message in remote)
        and all(audio_direction(message) == 'sendonly' for message in local),
    )
    listened = [message for message in terminating if message['info'].get('ambient-listening-type') == 'remote-init']
    listening = [message for message in terminating if message['info'].get('ambient-listening-type') == 'local-init']
    check(
        'the listened-to invitee gets Priv-Answer-Mode Auto, a null Alert-Info, no Feature-Caps and a recvonly offer',
        bool(listened)
        and all(
            header(message, 'priv-answer-mode') == 'Auto'
            and header(message, 'alert-info') == NULL_ALERT
            and FEATURE not in header(message, 'feature-caps')
            and audio_direction(message) == 'recvonly'
            and message['info'].get('mcptt-calling-user-id')
            and message['info'].get('mcptt-request-uri')
            for message in listened
        ),
    )
    check(
        'the listening invitee of a local-init call gets Feature-Caps (D.3) and a sendonly offer',
        bool(listening)
        and all(
            header(message, 'priv-answer-mode') == 'Auto'
            and FEATURE in header(message, 'feature-caps')
            and audio_direction(message) == 'sendonly'
            for message in listening
        ),
    )
    ok = [response for message in originating for response in answers(message) if response['status'] == 200]
    check(
        '200 OK to the originator carries Feature-Caps and the complementary direction',
        bool(ok)
        and all(FEATURE in header(response, 'feature-caps') for response in ok)
        and all(
            audio_direction(response) == {'recvonly': 'sendonly', 'sendonly': 'recvonly'}[audio_direction(message)]
            for message in originating
            for response in answers(message)
            if response['status'] == 200
        ),
    )
    # RFC 3261 section 20.4 with RFC 7462: Alert-Info belongs in the INVITE, 180 and 183 only, not in the 200 (OK).
    calls = {(message['call_id'], header(message, 'cseq')) for message in originating}
    check(
        '200 OK to the originator carries no Alert-Info',
        bool(ok)
        and not any(
            copy['status'] == 200 and (copy['call_id'], header(copy, 'cseq')) in calls and header(copy, 'alert-info')
            for copy in copies
        ),
    )
    progress = [response for message in remote for response in answers(message) if response['status'] == 183]
    check(
        'remote-init originators get 183 with a null Alert-Info and no ringing',
        bool(progress)
        and all(header(response, 'alert-info') == NULL_ALERT for response in progress)
        and not any(response['status'] == 180 for message in originating for response in answers(message)),
    )
    rejected = [
        (response['status'], header(response, 'warning'))
        for message in originating
        for response in answers(message)
        if response['status'] >= 300
    ]
    for code, text in [
        ('154', 'unauthorised ambient listening type'),
        ('144', 'target outside <PrivateCall>'),
        ('127', 'uncallable target'),
    ]:
        check(
            f'rejection 403/{code} ({text})',
            any(status_code == 403 and code in warning_text for status_code, warning_text in rejected),
        )
    check(
        'an ambient request to a busy user is rejected with 480', any(status_code == 480 for status_code, _ in rejected)
    )
    byes = [message for message in messages if message['request'] and message['method'] == 'BYE']
    reasons = collections.Counter(
        message['info'].get('release-reason') for message in byes if message['info'].get('release-reason')
    )
    check('server BYEs to the listening user carry each release reason exercised', REASONS <= set(reasons))
    ambient_calls = {message['call_id'] for message in terminating} | {message['call_id'] for message in originating}
    reasoned = [message for message in byes if message['info'].get('release-reason') in REASONS]
    check(
        'release reasons appear only in ambient listening dialogs',
        all(message['call_id'] in ambient_calls for message in reasoned),
    )

    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(
            sip_messages=len(messages),
            originating_invites=len(originating),
            remote_init=len(remote),
            local_init=len(local),
            terminating_invites=len(terminating),
            release_reasons=dict(reasons),
            rejections=collections.Counter(
                f'{status_code} {warning_text}'.strip() for status_code, warning_text in rejected
            ),
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
