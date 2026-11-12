#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Wire check at an MC server: the MC clients' media feature tags of RFC 3840 in initial INVITEs and their answers.

TS 24.229 clause 5.1.3.1: "The UE shall include the media feature tags defined in RFC 3840 [62] and RFC 5688 [120] for
all supported streaming media types in the initial INVITE request"; clause 5.1.4.1 the same "in the SIP response other
than the 100 (Trying) response to the SIP INVITE request". RFC 3840 section 10 ties each tag to an SDP media type: an
MCPTT client supports audio (speech) and application (the floor control stream, "m=application ... udp MCPTT", TS
24.380 clause 12.1.1), an MCVideo client also video (and its transmission control stream is m=application, TS 24.581).
Checked, in the Contact header field of:
  - every initial INVITE (no To tag) a client sends to the service PSI;
  - every 18x and 2xx a client sends to an initial INVITE of the server;
that it carries the base tags "audio" and "application" (RFC 3840 section 9: in a Contact without "+" and "sip."),
and "video" with --video. At least one of each kind is required.

Self-contained (no tshark): reads the clear SIP over TCP of a debug TCP lab's capture.

Usage: verify_media_feature_tags.py capture.pcap --service sip:mcptt@mcx.test [--video] --output report.json

Specifications: TS 24.229 V19.7.0 (Rel-19), RFC 3840, TS 24.380, TS 24.581.
"""

import argparse
import json
from pathlib import Path
import re
import sys

from verify_private_call import header, parse, sip_messages, tcp_streams


# ------------------------------------------------------------------------------
def tags(contact):
    """The lower-case parameter names of the first Contact value's header field parameters (after the URI)."""
    rest = contact.split('>', 1)[1] if '>' in contact else contact.split(';', 1)[1] if ';' in contact else ''
    return {part.split('=', 1)[0].strip().lower() for part in rest.split(';') if part.strip()}


# ------------------------------------------------------------------------------
def to_tag(message):
    """The To header field's tag, or ''."""
    match = re.search(r';\s*tag=([^;>\s]+)', header(message, 'to'), re.I)
    return match.group(1) if match else ''


# ------------------------------------------------------------------------------
def main():
    """Check the Contacts and write the report; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True, help='The service PSI, e.g. sip:mcptt@mcx.test')
    parser.add_argument('--video', action='store_true', help='Also require the video tag (MCVideo clients)')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    required = {'audio', 'application'} | ({'video'} if args.video else set())
    messages, seen = [], set()
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:
                seen.add(key)
                messages.append(message)
    psi = args.service.split(':', 1)[1].split('@')[0]
    # The server's initial INVITEs to clients, by Call-ID and CSeq: their answers come from clients.
    server_invites = {
        (m['call_id'], header(m, 'cseq'))
        for m in messages
        if m['request'] and m['method'] == 'INVITE' and not to_tag(m) and not m['target'].startswith(args.service)
        and f'sip:{psi}@' not in m['target']
    }
    checked = {'invite': 0, 'answer': 0}
    failures = []
    for m in messages:
        if m['request'] and m['method'] == 'INVITE' and not to_tag(m) and m['target'].split(';')[0] == args.service:
            kind = 'invite'
        elif (
            not m['request']
            and m['method'] == 'INVITE'
            and (100 < m['status'] < 200 or 200 <= m['status'] < 300)
            and (m['call_id'], header(m, 'cseq')) in server_invites
        ):
            kind = 'answer'
        else:
            continue
        contact = header(m, 'contact')
        if not contact:
            failures.append(f'{kind} {m["line"]} (Call-ID {m["call_id"]}): no Contact')
            continue
        checked[kind] += 1
        missing = required - tags(contact)
        if missing:
            failures.append(f'{kind} {m["line"]} (Call-ID {m["call_id"]}): Contact {contact!r} lacks {sorted(missing)}')
    if not checked['invite']:
        failures.append('no initial INVITE from a client to the service seen')
    if not checked['answer']:
        failures.append('no 18x or 2xx from a client to an initial INVITE of the server seen')
    report = dict(passed=not failures, required=sorted(required), checked=checked, failures=failures)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
