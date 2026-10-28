#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify, in a clear-SIP capture at the MCPTT server, that required XML protection is never dropped.

Checks, for the protection the lab requires (--confidentiality, --integrity, either or both):
  - every MCPTT service authorisation (PUBLISH with the poc-settings event, Expires not 0) carries the CSK in an
    application/mikey body (TS 24.379 clause 7.2.2 step 3: "if either confidentiality protection is enabled ... or
    integrity protection is enabled");
  - with --confidentiality, no SIP message carries a clear <mcptt-access-token>, <mcptt-client-id>,
    <mcptt-request-uri> or <mcptt-calling-user-id> (TS 24.379 clauses 4.8, 6.6.2.3.1, 6.6.2.3.2 and 7.2.2 step 4);
  - with --integrity, every service authorisation PUBLISH carries an application/vnd.3gpp.mcptt-signed+xml body
    (TS 24.379 clause 6.6.3.3.1; the other messages are checked by verify_xml_signatures.py);
  - with --integrity and without --confidentiality, no XML body is encrypted (integrity protection alone requires
    signatures, not encryption: TS 24.379 clause 7.2.2 step 5);
  - with --confidentiality and without --integrity, no message carries signatures;
  - at least --users users were service authorised (200 OK to their authorisation PUBLISH).
The messages of the clients' CMS, GMS and GKTP subscriptions without identity hiding are left out (not protected:
TS 24.484 clause 6.3.13.2.2 step d, TS 24.481 clause 6.3.13.2.1 step d).
A client that holds no CSK therefore shows up as a clear or unsigned authorisation, which fails the checks.

Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py and the body parser of
verify_xml_signatures.py.

Specifications: TS 24.379 V19.8.0 (Rel-19), TS 33.180 V19.5.0 (Rel-19).
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, timed_messages  # noqa: E402
from verify_xml_signatures import SIGNED, bare, body_parts, is_xml, subscription_dialogs  # noqa: E402

INFO = 'application/vnd.3gpp.mcptt-info+xml'
SENSITIVE = ('mcptt-access-token', 'mcptt-client-id', 'mcptt-request-uri', 'mcptt-calling-user-id')
ENCRYPTED = 'EncryptedData'


# ------------------------------------------------------------------------------
def clear_elements(body):
    """The sensitive mcptt-info elements of an XML body whose content is clear text (not an EncryptedData)."""
    found = []
    for name in SENSITIVE:
        for match in re.finditer(rf'<(?:\w+:)?{name}\b[^>]*>(.*?)</(?:\w+:)?{name}>', body, re.S):
            if ENCRYPTED not in match.group(1) and match.group(1).strip():
                found.append(name)
    return found


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--confidentiality', action='store_true')
    parser.add_argument('--integrity', action='store_true')
    parser.add_argument('--users', type=int, default=2)
    parser.add_argument(
        '--documents-first',
        action='store_true',
        help='mcptt.documents_on_notify: each user\'s configuration management SUBSCRIBE (TS 24.484 clause 6.3.13.2.2) '
        'goes before its first service authorisation PUBLISH (TS 37.579-1 table 5.3.2.5.1-1 NOTE 1)',
    )
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen = [], set()
    for message in timed_messages(args.capture):
        key = (message['call_id'], header(message, 'cseq'), message['line'])
        if key not in seen:
            seen.add(key)
            messages.append(message)
    checks, failures = [], []

    def check(label, condition):
        (checks if condition else failures).append(label)

    authorisations, authorised = {}, set()
    clear, encrypted, signed = [], 0, 0
    # The CMS, GMS and GKTP subscriptions without identity hiding are not protected (TS 24.484 and TS 24.481 clause
    # 6.3.13.2: "if identity hiding is required"); verify_subscription_protection.py checks them.
    exempt = {call_id for call_id, (_, _, hiding, _) in subscription_dialogs(messages).items() if not hiding}
    for message in messages:
        if message['call_id'] in exempt:
            continue
        parts = body_parts(header(message, 'content-type'), message['body'])
        label = f'{message["line"]} (Call-ID {message["call_id"]})'
        kinds = [kind for kind, _, _ in parts]
        if SIGNED in kinds:
            signed += 1
        for kind, _, content in parts:
            if kind != SIGNED and is_xml(kind) and ENCRYPTED in content:
                encrypted += 1
            if args.confidentiality and kind == INFO and clear_elements(content):
                clear.append(f'{label}: {", ".join(clear_elements(content))}')
        if (
            message['request']
            and message['method'] == 'PUBLISH'
            and header(message, 'event').split(';')[0].strip() == 'poc-settings'
            and header(message, 'expires').strip() != '0'
        ):
            transaction = (message['call_id'], header(message, 'cseq'))
            authorisations[transaction] = (header(message, 'from'), label, kinds)
    for message in messages:
        transaction = (message['call_id'], header(message, 'cseq'))
        if not message['request'] and message['status'] == 200 and transaction in authorisations:
            authorised.add(authorisations[transaction][0].split('>')[0])

    if args.documents_first:
        # The first configuration SUBSCRIBE and the first authorisation PUBLISH of each user, in capture order.
        first_subscribe, first_publish = {}, {}
        for message in messages:
            if not message['request'] or 'tag=' in header(message, 'to'):
                continue
            user = bare(header(message, 'from'))
            if (
                message['method'] == 'SUBSCRIBE'
                and header(message, 'event').split(';')[0].strip() == 'xcap-diff'
                and 'org.3gpp.mcptt.user-profile' in message['body']
            ):
                first_subscribe.setdefault(user, message['time'])
            if (
                message['method'] == 'PUBLISH'
                and header(message, 'event').split(';')[0].strip() == 'poc-settings'
                and header(message, 'expires').strip() != '0'
            ):
                first_publish.setdefault(user, message['time'])
        late = sorted(user for user, at in first_publish.items() if user not in first_subscribe or first_subscribe[user] > at)
        check(f'configuration subscription before the service authorisation ({len(first_publish)} users)',
              first_publish and not late)
    without_csk = [label for _, label, kinds in authorisations.values() if 'application/mikey' not in kinds]
    check(f'every service authorisation carries the CSK ({len(authorisations)} PUBLISH)', not without_csk)
    if args.confidentiality:
        check('no sensitive mcptt-info element in the clear', not clear)
    if args.integrity:
        unsigned = [label for _, label, kinds in authorisations.values() if SIGNED not in kinds]
        check('every service authorisation is signed', not unsigned)
    if args.integrity and not args.confidentiality:
        check('integrity protection alone: no XML encrypted', encrypted == 0)
    if args.confidentiality and not args.integrity:
        check('confidentiality protection alone: no signatures', signed == 0)
    check(f'at least {args.users} users authorised', len(authorised) >= args.users)
    result = dict(
        passed=not failures,
        checks=checks,
        failures=failures,
        observations=dict(
            authorisations=len(authorisations),
            authorised=sorted(authorised),
            without_csk=without_csk[:10],
            clear=clear[:10],
            encrypted_bodies=encrypted,
            signed_messages=signed,
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
