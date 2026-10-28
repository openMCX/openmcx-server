#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify the implicit floor requests of implicit_floor_scenario.py from a clear-SIP capture at the MCPTT server.

TS 24.379 clause 6.4 and TS 24.380 clause 14: an initial INVITE whose SDP offer carries "mc_implicit_request" (in
the a=fmtp line of the "m=application" floor control channel) is answered:
  - with "mc_implicit_request" in the 200 (OK) when it initiates the call (TS 24.380 clause 14.3.5), and then with
    "mc_ssrc" equal to the offer's "a=ssrc" (TS 24.380 clause 14.3.6; the server picks another value only on a
    collision, which this lab does not make);
  - without it when it joins a chat group call that exists (TS 24.380 clauses 6.3.2.2 and 14.3.5);
  - never with a 488 for carrying it (TS 24.379 clause 6.4: "regarded as received without an implicit floor
    request").
No 200 (OK) carries "mc_implicit_request" or "mc_ssrc" for an offer without "mc_implicit_request" (TS 24.380 clause
14.3.1), no re-INVITE carries "mc_implicit_request" in this scenario (TS 24.380 clause 14.5: it has meaning only for
the upgrade to emergency, not used here), and no rejoin INVITE (to a session identity) carries it (TS 24.380 clause
6.2.1 item 2). Floor control (TS 24.380 clause 6.3.5.2.2 items 1 and 3a, clause 6.2.4.2.2 step 4): every client
whose implicit floor request was accepted into a call without a talker receives a Floor Granted on its floor
channel whose Audio SSRC field is the "mc_ssrc", before it sends any Floor Request in that call.

Usage: verify_implicit_floor.py capture.pcap --service sip:mcptt@DOMAIN --output result.json
Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py and the floor message decoding of
verify_broadcast_call.py.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
"""

import argparse
import collections
import json
from pathlib import Path
import re
import socket
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_broadcast_call import floor_frame  # noqa: E402
from verify_private_call import header, timed_messages  # noqa: E402

REQUEST, GRANTED = 0, 1
AUDIO_SSRC = 14  # TS 24.380 table 8.2.3.1-2


# ------------------------------------------------------------------------------
def sdp(message):
    """The SDP of the message's body, or an empty string."""
    body = message['body']
    return body[body.find('v=0') :] if 'v=0' in body else ''


# ------------------------------------------------------------------------------
def floor_fmtp(message):
    """The parameters of the a=fmtp:MCPTT line of the message's SDP, as a dict (value '' for a flag)."""
    match = re.search(r'(?m)^a=fmtp:MCPTT ([^\r\n]*)', sdp(message))
    if not match:
        return {}
    parameters = {}
    for item in match.group(1).split(';'):
        key, _, value = item.strip().partition('=')
        if key:
            parameters[key] = value
    return parameters


# ------------------------------------------------------------------------------
def offer_ssrc(message):
    """The a=ssrc of the audio section of the message's SDP, or None."""
    audio = sdp(message).split('m=application')[0]
    match = re.search(r'(?m)^a=ssrc:(\d+)', audio)
    return int(match.group(1)) if match else None


# ------------------------------------------------------------------------------
def floor_endpoint(message):
    """(address, port) of the floor control channel of the message's SDP, or None."""
    text = sdp(message)
    session = re.search(r'(?m)^c=IN IP4 (\S+)', text)
    application = text.split('m=application', 1)
    if len(application) < 2:
        return None
    port = re.match(r' (\d+)', application[1])
    own = re.search(r'(?m)^c=IN IP4 (\S+)', application[1])
    address = (own or session).group(1) if (own or session) else None
    return (address, int(port.group(1))) if port and address else None


# ------------------------------------------------------------------------------
def floor_packets(path):
    """(time, source, destination, subtype, fields) of every floor control message in the classic PCAP at path."""
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = raw[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    offset = 24
    while offset + 16 <= len(raw):
        seconds, fraction, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        if len(packet) < 42 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 17:
            continue
        sport, dport = struct.unpack_from('!HH', ip, ihl)
        source = (socket.inet_ntoa(ip[12:16]), sport)
        destination = (socket.inet_ntoa(ip[16:20]), dport)
        stamp = seconds + fraction / (1e9 if nano else 1e6)
        for subtype, fields in floor_frame(packet):
            yield stamp, source, destination, subtype, fields


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen = [], set()
    for message in timed_messages(args.capture):
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
    for message in messages:
        if not message['request']:
            responses[(message['call_id'], header(message, 'cseq'))].append(message)

    # ------------------------------------------------------------------------------
    def final(message):
        """The final response to the request message, or None."""
        found = [r for r in responses[(message['call_id'], header(message, 'cseq'))] if r['status'] >= 200]
        return found[0] if found else None

    invites = [m for m in messages if m['request'] and m['method'] == 'INVITE']
    initial = [m for m in invites if 'tag=' not in header(m, 'to')]
    reinvites = [m for m in invites if 'tag=' in header(m, 'to')]
    originating = [m for m in initial if m['target'] == args.service and 'mc_implicit_request' in floor_fmtp(m)]
    rejoins = [m for m in initial if ';mcptt-session=' in m['target']]

    # Chat calls in capture order: the first implicit chat INVITE after a release creates the session, a later one
    # while it exists joins it (the scenario has one chat call, created by one client and joined by another).
    chats = [m for m in originating if m['info'].get('session-type') == 'chat']
    creators = chats[:1]
    joiners = chats[1:]
    initiating = [m for m in originating if m not in joiners]

    answered = [(m, final(m)) for m in originating]
    check(
        'no INVITE with mc_implicit_request is refused with 488 (TS 24.379 clause 6.4)',
        bool(answered) and all(r is not None and r['status'] != 488 for _, r in answered),
    )
    accepted = [(m, final(m)) for m in initiating]
    check(
        'the 200 (OK) to an INVITE that initiates a call echoes mc_implicit_request (TS 24.380 clause 14.3.5)',
        bool(accepted)
        and all(r is not None and r['status'] == 200 and 'mc_implicit_request' in floor_fmtp(r) for _, r in accepted),
    )
    check(
        'that 200 (OK) returns the offer a=ssrc in mc_ssrc (TS 24.380 clause 14.3.6)',
        all(
            offer_ssrc(m) is None or floor_fmtp(r).get('mc_ssrc') == str(offer_ssrc(m))
            for m, r in accepted
            if r is not None
        ),
    )
    check(
        'the 200 (OK) to a join of an existing chat group call has no mc_implicit_request (TS 24.380 clause 14.3.5)',
        bool(joiners)
        and all(
            (r := final(m)) is not None and r['status'] == 200 and 'mc_implicit_request' not in floor_fmtp(r)
            for m in joiners
        ),
    )
    check('the chat creator is accepted (TS 24.380 clause 6.3.2.2)', bool(creators))
    plain = [m for m in initial if 'mc_implicit_request' not in floor_fmtp(m)]
    check(
        'no answer to an offer without mc_implicit_request carries it or mc_ssrc (TS 24.380 clause 14.3.1)',
        all(
            (r := final(m)) is None or ('mc_implicit_request' not in floor_fmtp(r) and 'mc_ssrc' not in floor_fmtp(r))
            for m in plain
        ),
    )
    check(
        'no re-INVITE offer or answer carries mc_implicit_request (TS 24.380 clause 14.5)',
        all(
            'mc_implicit_request' not in floor_fmtp(m)
            and ((r := final(m)) is None or 'mc_implicit_request' not in floor_fmtp(r))
            for m in reinvites
        ),
    )
    check(
        'a rejoin INVITE has no mc_implicit_request (TS 24.380 clause 6.2.1 item 2)',
        bool(rejoins) and all('mc_implicit_request' not in floor_fmtp(m) for m in rejoins),
    )

    # Floor control: a grant to each accepted originator without a Floor Request of its own first.
    floor = list(floor_packets(args.capture))
    grants = []
    for message, response in accepted:
        endpoint = floor_endpoint(message)
        if response is None or endpoint is None:
            continue
        expected = floor_fmtp(response).get('mc_ssrc')
        after = [packet for packet in floor if packet[0] >= response['time']]
        first_grant = next((p for p in after if p[2] == endpoint and p[3] == GRANTED), None)
        first_request = next((p for p in after if p[1] == endpoint and p[3] == REQUEST), None)
        grants.append(
            dict(
                endpoint=list(endpoint),
                granted=first_grant is not None,
                request_before_grant=first_request is not None
                and (first_grant is None or first_request[0] < first_grant[0]),
                audio_ssrc=struct.unpack('!I', first_grant[4][AUDIO_SSRC][:4])[0]
                if first_grant and len(first_grant[4].get(AUDIO_SSRC, b'')) >= 4
                else None,
                mc_ssrc=int(expected) if expected else None,
            )
        )
    # The scenario's IF-02 request into a call with a talker is accepted but answered with Floor Taken (TS 24.380
    # clause 6.3.5.2.2 item 3c): it is the one accepted INVITE whose client gets no grant.
    check(
        'accepted originators are granted without sending a Floor Request first (TS 24.380 clause 6.2.4.2.2 step 4)',
        sum(grant['granted'] and not grant['request_before_grant'] for grant in grants) >= len(grants) - 1
        and len(grants) >= 2,
    )
    check(
        'the Floor Granted assigns the mc_ssrc of the 200 (OK) (TS 24.380 clause 14.3.6)',
        all(
            grant['mc_ssrc'] is None or grant['audio_ssrc'] == grant['mc_ssrc'] for grant in grants if grant['granted']
        ),
    )

    result = dict(
        verifier='implicit-floor-request',
        passed=not failures,
        checks=checks,
        failures=failures,
        observations=dict(
            implicit_invites=len(originating), chat_joins=len(joiners), rejoins=len(rejoins), grants=grants
        ),
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
