#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify, in a clear-SIP capture at the MCPTT server, the protection of the clients' CMS, GMS and GKTP subscriptions.

The configuration management subscription (TS 24.484 clause 6.3.13), the group document subscription (TS 24.481 clause
6.3.13) and the GKTP subscription (TS 24.481 clause 7.7, the same GMS procedure) are protected "if identity hiding is
required", the subscriber including the CSK in an application/mikey body of the initial SUBSCRIBE (TS 24.484 clause
6.3.13.2.2 step d, TS 24.481 clause 6.3.13.2.1 step d), and the CMS or GMS then protects its NOTIFYs ("if the CSK is
received in an application/mikey MIME body of the initial SIP SUBSCRIBE request", clause 6.3.13.3.2.2 of both). The
OpenMCX clients do not apply identity hiding.

A subscription is told by its initial SUBSCRIBE (Event xcap-diff, no To tag) and the documents its resource list names:
configuration management documents (org.3gpp.mcptt/mcvideo/mcdata application usages), group documents
(org.openmobilealliance.groups) or GKTPs (org.3gpp.MCPTT-GKTP). Checks:
  - every message of a subscription without the CSK in its initial SUBSCRIBE (SUBSCRIBEs, re-SUBSCRIBEs, NOTIFYs and
    their responses) carries no encrypted XML and no signatures;
  - no subscription with the CSK in its initial SUBSCRIBE (identity hiding, not supported) got a NOTIFY;
  - with --require, the listed cases were seen:
      bootstrap   an initial SUBSCRIBE before its user's first service authorisation was answered 200 (OK);
      authorised  a NOTIFY after the user's service authorisation in a subscription created before it (the same
                  subscription after authorisation);
      update      a NOTIFY after the first one of its subscription (a document change);
      refresh     a re-SUBSCRIBE in the dialog with Expires other than 0;
      termination a SUBSCRIBE with Expires 0 or a NOTIFY with Subscription-State terminated;
      gktp        a GKTP subscription whose NOTIFY carries a GKTP document with its MIKEY-SAKKE I_MESSAGE;
      unauthorised-refresh, unauthorised-termination
                  a configuration subscription refreshed (Expires other than 0) or ended (Expires 0) in its dialog
                  while its user holds no service authorisation, answered 200 (OK): the subscription stands apart
                  from the authorisation (TS 24.484 clause 6.3.13.3.2.2 step c, RFC 6665 sections 4.1.2.2 and
                  4.1.2.3). A user is authorised from the 200 (OK) to its PUBLISH for poc-settings until the 200 (OK)
                  to its PUBLISH with Expires 0.

Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py and the body parser of
verify_xml_signatures.py.

Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 33.180 V19.5.0 (Rel-19), RFC 6665, RFC 5875.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, timed_messages  # noqa: E402
from verify_xml_signatures import SIGNED, bare, body_parts, is_xml, subscription_dialogs  # noqa: E402

CASES = ('bootstrap', 'authorised', 'update', 'refresh', 'termination', 'gktp', 'unauthorised-refresh',
         'unauthorised-termination')


# ------------------------------------------------------------------------------
def protected(message):
    """Whether a message carries encrypted XML or signatures."""
    parts = body_parts(header(message, 'content-type'), message['body'])
    return any(kind == SIGNED or (is_xml(kind) and 'EncryptedData' in content) for kind, _, content in parts)


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--require', default='', help='comma-separated cases: ' + ', '.join(CASES))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    required = [case for case in args.require.split(',') if case]
    unknown = [case for case in required if case not in CASES]
    if unknown:
        parser.error(f'unknown cases {unknown}')
    messages, seen = [], set()
    for message in timed_messages(args.capture):
        key = (message['call_id'], header(message, 'cseq'), message['line'], message.get('status'))
        if key not in seen:
            seen.add(key)
            messages.append(message)
    checks, failures = [], []

    def check(label, condition):
        (checks if condition else failures).append(label)

    dialogs = subscription_dialogs(messages)
    # Each user's first accepted service authorisation (PUBLISH poc-settings, Expires not 0), and each change of its
    # authorisation (accepted PUBLISH poc-settings: Expires 0 ends it).
    publishes, authorised_at, changes = {}, {}, {}
    for message in messages:
        if (
            message['request']
            and message['method'] == 'PUBLISH'
            and header(message, 'event').split(';')[0].strip() == 'poc-settings'
        ):
            publishes[(message['call_id'], header(message, 'cseq'))] = (
                bare(header(message, 'from')),
                header(message, 'expires').strip() != '0',
                message['time'],
            )
    # Timed by the request: the responses of a reassembled TCP stream need not carry their own capture time.
    for message in messages:
        transaction = (message['call_id'], header(message, 'cseq'))
        if not message['request'] and message['status'] == 200 and transaction in publishes:
            user, on, sent = publishes[transaction]
            if on:
                authorised_at[user] = min(authorised_at.get(user, sent), sent)
            changes.setdefault(user, []).append((sent, on))
    for timeline in changes.values():
        timeline.sort()

    def authorised(user, when):
        """Whether the user held a service authorisation at that time."""
        state = False
        for time, on in changes.get(user, []):
            if time > when:
                break
            state = on
        return state

    # The answers to SUBSCRIBEs, by transaction.
    answers = {
        (message['call_id'], header(message, 'cseq')): message['status']
        for message in messages
        if not message['request'] and header(message, 'cseq').split()[-1] == 'SUBSCRIBE' and message['status'] >= 200
    }

    seen_cases = {case: [] for case in CASES}
    clear_protected, hiding_notified, notifies = [], [], {}
    for message in messages:
        found = dialogs.get(message['call_id'])
        if not found:
            continue
        kind, user, hiding, created = found
        label = f'{kind} {message["line"]} (Call-ID {message["call_id"]})'
        if not hiding and protected(message):
            clear_protected.append(label)
        if not message['request']:
            if (
                message['status'] == 200
                and header(message, 'cseq').split()[-1] == 'SUBSCRIBE'
                and user in authorised_at
                and created < authorised_at[user]
            ):
                seen_cases['bootstrap'].append(label)
            continue
        if message['method'] == 'NOTIFY':
            if hiding:
                hiding_notified.append(label)
            count = notifies[message['call_id']] = notifies.get(message['call_id'], 0) + 1
            if count > 1:
                seen_cases['update'].append(label)
            if user in authorised_at and created < authorised_at[user] < message['time']:
                seen_cases['authorised'].append(label)
            if header(message, 'subscription-state').startswith('terminated'):
                seen_cases['termination'].append(label)
            if kind == 'gktp' and 'GKTP' in message['body']:
                seen_cases['gktp'].append(label)
        elif message['method'] == 'SUBSCRIBE' and 'tag=' in header(message, 'to'):
            expires = header(message, 'expires').strip()
            seen_cases['termination' if expires == '0' else 'refresh'].append(label)
            if (
                kind == 'configuration'
                and not authorised(user, message['time'])
                and answers.get((message['call_id'], header(message, 'cseq'))) == 200
            ):
                seen_cases['unauthorised-termination' if expires == '0' else 'unauthorised-refresh'].append(label)

    check(f'CMS, GMS and GKTP subscriptions found ({len(dialogs)})', bool(dialogs))
    check('no XML protection in a subscription without identity hiding', not clear_protected)
    check('no NOTIFY in a subscription with identity hiding (not supported)', not hiding_notified)
    for case in required:
        check(f'case {case} seen ({len(seen_cases[case])})', bool(seen_cases[case]))
    kinds = {}
    for kind, _, _, _ in dialogs.values():
        kinds[kind] = kinds.get(kind, 0) + 1
    result = dict(
        passed=not failures,
        checks=checks,
        failures=failures,
        observations=dict(
            subscriptions=kinds,
            authorised_users=sorted(authorised_at),
            cases={case: len(labels) for case, labels in seen_cases.items()},
            protected_without_identity_hiding=clear_protected[:10],
            notified_with_identity_hiding=hiding_notified[:10],
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
