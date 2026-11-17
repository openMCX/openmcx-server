#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A private call without multiplexing on the wire, as the lab client of --config; run inside its container.

The probe is a raw SIP user agent, digest-authenticated as the client, with its own media plane control channel on a
UDP port of its own. It sends a private call INVITE (automatic commencement) to --target whose SDP offer has no
"mc_floor_ssrc" (TS 24.380 clause 14.2.7: only "if multiplexing is supported"; clause 14.2.1: no fmtp parameter at
all), acknowledges the 200 (OK), runs floor control with an SSRC of its own (clause 4.3.3.1: without multiplexing
the messages carry the sender's SSRC, the "SSRC of floor participant sending", clauses 8.2.4 to 8.2.13; RFC 3550
section 6.7), and ends the call with BYE. It records, for nomux_floor_scenario.py to check:
  - answer: the 200 (OK) status and whether its SDP has "mc_floor_ssrc" (clause 14.3.8: only when the offer had it);
  - joined: the floor control message the server sent on its own when the call started (Floor Idle or Floor Taken,
    TS 24.380 clause 6.3.4.2.2 / 6.3.5), if any, with its SSRC, and whether it asked for a Floor Ack;
  - collision: with such a message, a Floor Request carrying the server's own SSRC (both directions on one SSRC, RFC
    3550 section 8.2): the server's answer, none expected;
  - granted: the server's answer to a Floor Request with the probe's SSRC: its type and SSRC (the server's, not the
    probe's), and the retransmissions of it seen within 2.5 s after the probe's Floor Ack (clause 8.2.13: an Ack the
    server matches stops them);
  - stranger: the server's answer to a Floor Release with another SSRC once the probe's is known: none expected;
  - released: the server's answer to a Floor Release with the probe's SSRC (Floor Idle);
  - bye: the BYE's final status.
Prints one JSON line.

Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 3261, RFC 3550.
"""

import argparse
import json
import pathlib
import secrets
import socket
import struct
import sys
import time
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sip_negative import SipProbe  # noqa: E402

ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcptt'
# TS 24.380 table 8.2.2.1-1: floor control message subtypes (the fifth bit asks for a Floor Ack).
REQUEST, GRANTED, TAKEN, DENY, RELEASE, IDLE, REVOKE, ACK = 0, 1, 2, 3, 4, 5, 6, 10
NAMES = {0: 'Request', 1: 'Granted', 2: 'Taken', 3: 'Deny', 4: 'Release', 5: 'Idle', 6: 'Revoke', 9: 'Queue',
         10: 'Ack'}
# TS 24.380 table 8.2.3.1-2: the Source and Message Type fields of a Floor Ack.
SOURCE, MESSAGE_TYPE = 10, 12


# ------------------------------------------------------------------------------
def floor_message(subtype, ssrc, fields=()):
    """An RTCP APP packet named MCPT (TS 24.380 clause 8.1.2): fields are (id, value) pairs, each padded to 32 bits."""
    body = b''
    for field_id, value in fields:
        field = bytes([field_id, len(value)]) + value
        body += field + bytes(-len(field) % 4)
    length = (12 + len(body)) // 4 - 1
    return struct.pack('!BBHI', 0x80 | subtype, 204, length, ssrc) + b'MCPT' + body


# ------------------------------------------------------------------------------
def floor_ack(ssrc, acknowledged):
    """A Floor Ack of the floor participant (Source 0, TS 24.380 clause 8.2.3.12) naming the message type."""
    return floor_message(ACK, ssrc, [(SOURCE, b'\x00\x00'), (MESSAGE_TYPE, bytes([acknowledged, 0]))])


# ------------------------------------------------------------------------------
def parse_floor(packet):
    """(subtype without the Floor Ack bit, asks for a Floor Ack, SSRC) of a floor control message."""
    first, kind, _, ssrc = struct.unpack('!BBHI', packet[:8])
    if kind != 204 or packet[8:12] != b'MCPT':
        raise ValueError('not a floor control message')
    return first & 0x0F, bool(first & 0x10), ssrc


# ------------------------------------------------------------------------------
class Dialog:
    """A raw INVITE dialog of the probe on SipProbe's connection to the SIP core."""

    # ------------------------------------------------------------------------------
    def __init__(self, sip, cfg):
        self.sip, self.cfg = sip, cfg
        self.call_id = 'nomux-' + secrets.token_hex(12)
        self.from_tag = secrets.token_hex(8)
        self.cseq = 0
        self.identity = cfg['sip']['identity']
        self.contact = (f"sip:nomux-probe-{secrets.token_hex(6)}@{cfg['sip']['advertise']}:{sip.port};"
                        f'transport={sip.transport}')
        self.to_value = None
        self.route, self.target = [], None

    # ------------------------------------------------------------------------------
    def send(self, method, uri, fields, body='', cseq=None, authorization=None):
        """Send one request with the dialog's identifiers; returns the CSeq number used."""
        if cseq is None:
            self.cseq += 1
            cseq = self.cseq
        lines = [
            f'{method} {uri} SIP/2.0',
            f"Via: SIP/2.0/{self.sip.transport.upper()} {self.cfg['sip']['advertise']}:{self.sip.port};"
            f'branch=z9hG4bK{secrets.token_hex(12)}',
            f'From: <{self.identity}>;tag={self.from_tag}',
            f'To: {self.to_value or "<" + uri + ">"}',
            f'Call-ID: {self.call_id}',
            f'CSeq: {cseq} {method}',
            'Max-Forwards: 16',
            f'Contact: <{self.contact}>',
        ] + [f'Route: {route}' for route in self.route] + [f'{name}: {value}' for name, value in fields]
        if authorization:
            lines.append(authorization)
        payload = body.encode()
        self.sip.sock.sendall(('\r\n'.join(lines) + f'\r\nContent-Length: {len(payload)}\r\n\r\n').encode() + payload)
        return cseq

    # ------------------------------------------------------------------------------
    def response(self, method):
        """The next final response to method on the connection: (status, [(name, value)], body); requests and other
        responses on the connection are skipped."""
        while True:
            while b'\r\n\r\n' not in self.sip.buffer:
                chunk = self.sip.sock.recv(65536)
                if not chunk:
                    raise RuntimeError('SIP connection closed')
                self.sip.buffer += chunk
            raw, rest = self.sip.buffer.split(b'\r\n\r\n', 1)
            lines = raw.decode().split('\r\n')
            fields = []
            for line in lines[1:]:
                name, value = line.split(':', 1)
                fields.append((name.strip().lower(), value.strip()))
            length = int(next((value for name, value in fields if name in ('content-length', 'l')), '0'))
            while len(rest) < length:
                chunk = self.sip.sock.recv(65536)
                if not chunk:
                    raise RuntimeError('SIP connection closed')
                rest += chunk
            self.sip.buffer = rest[length:]
            body = rest[:length].decode(errors='replace')
            if not lines[0].startswith('SIP/2.0 '):
                continue
            cseq = next((value for name, value in fields if name == 'cseq'), '')
            code = int(lines[0].split()[1])
            if code >= 200 and cseq.split()[-1] == method:
                return code, fields, body

    # ------------------------------------------------------------------------------
    def request(self, method, uri, fields, body=''):
        """Send method (answering the SIP core's digest challenge once) and return its final response."""
        self.send(method, uri, fields, body)
        code, headers, answer = self.response(method)
        if code in (401, 407):
            # The SIP core's challenge, answered as private_probe.py does (over TCP or TLS the challenge is not
            # retransmitted, so it is not acknowledged).
            authorization = self.sip.digest(method, uri, (code, dict(headers)))
            self.send(method, uri, fields, body, authorization=authorization)
            code, headers, answer = self.response(method)
        return code, headers, answer

    # ------------------------------------------------------------------------------
    def established(self, headers):
        """Take the dialog's remote tag, route set and target from a 2xx response to the INVITE (RFC 3261 section
        12.1.2)."""
        self.to_value = next(value for name, value in headers if name in ('to', 't'))
        self.route = [value for name, value in headers if name == 'record-route'][::-1]
        contact = next(value for name, value in headers if name in ('contact', 'm'))
        self.target = contact[contact.index('<') + 1:contact.index('>')] if '<' in contact else contact.split(';')[0]


# ------------------------------------------------------------------------------
def main():
    """Run the call and print the outcomes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/config/client-a.json')
    parser.add_argument('--disable-tls', action='store_true')
    parser.add_argument('--target', required=True, help='the MCPTT ID the private call is to')
    parser.add_argument('--ssrc', type=lambda text: int(text, 0), default=0x5EED0001,
                        help='the SSRC of the probe\'s floor control messages')
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    sip = SipProbe(cfg, args.disable_tls)
    address = sip.sock.getsockname()[0]
    floor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    floor.bind((address, 0))
    floor_port = floor.getsockname()[1]
    audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    audio.bind((address, 0))
    audio_port = audio.getsockname()[1]
    outcomes = {'ssrc': args.ssrc}
    dialog = Dialog(sip, cfg)
    service = cfg['mcptt']['service_uri']

    # TS 24.379 clause 11.1.1.2.1.1: the private call request, its SDP offer without "mc_floor_ssrc".
    sdp = (f'v=0\r\no=- 1 1 IN IP4 {address}\r\ns=MCPTT\r\nc=IN IP4 {address}\r\nt=0 0\r\n'
           f'm=audio {audio_port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000/1\r\n'
           'a=fmtp:96 octet-align=0;mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\n'
           f'a=sendrecv\r\na=rtcp:{audio_port + 1}\r\nm=application {floor_port} udp MCPTT\r\n')
    info = ('<?xml version="1.0"?><mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
            '<session-type>private</session-type><mcptt-client-id type="Normal"><mcpttString>'
            f"{escape(cfg['mcptt']['client_id'])}</mcpttString></mcptt-client-id></mcptt-Params></mcpttinfo>")
    resources = ('<?xml version="1.0" encoding="UTF-8"?><resource-lists '
                 f'xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri={quoteattr(args.target)}/></list>'
                 '</resource-lists>')
    boundary = 'nomux-' + secrets.token_hex(12)
    body = ''.join(f'--{boundary}\r\nContent-Type: {mime}\r\n\r\n{part}\r\n'
                   for mime, part in [('application/sdp', sdp), ('application/vnd.3gpp.mcptt-info+xml', info),
                                      ('application/resource-lists+xml', resources)]) + f'--{boundary}--\r\n'
    fields = [
        ('Accept-Contact', f'*;+g.3gpp.icsi-ref="{ICSI.replace(":", "%3A")}";+g.3gpp.mcptt;require;explicit'),
        ('P-Preferred-Service', ICSI),
        ('Answer-Mode', 'Auto'),
        ('Content-Type', 'multipart/mixed;boundary=' + boundary),
    ]
    code, headers, answer = dialog.request('INVITE', service, fields, body)
    outcomes['answer'] = {'status': code, 'mc_floor_ssrc': 'mc_floor_ssrc' in answer,
                          'floor_control': 'm=application' in answer}
    if code != 200:
        print(json.dumps(outcomes))
        return 0
    dialog.established(headers)
    invite_cseq = dialog.cseq
    dialog.send('ACK', dialog.target, [], cseq=invite_cseq)
    # The server's media plane control channel: its c= address (the application m-line's, else the session's) and port.
    server_address, server_port = None, None
    for line in answer.split('\r\n'):
        if line.startswith('c=IN IP4 '):
            server_address = line.split()[2]
        if line.startswith('m=application '):
            server_port = int(line.split()[1])
    server = (server_address, server_port)

    # ------------------------------------------------------------------------------
    def receive(seconds):
        """The floor control messages from the server's channel within seconds: [(subtype, ack bit, SSRC)]."""
        found, deadline = [], time.monotonic() + seconds
        while time.monotonic() < deadline:
            floor.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                packet, source = floor.recvfrom(2048)
            except socket.timeout:
                break
            if source == server:
                found.append(parse_floor(packet))
        return found

    # ------------------------------------------------------------------------------
    def first(seconds):
        """The first floor control message from the server within seconds, or None."""
        found, deadline = None, time.monotonic() + seconds
        while found is None and time.monotonic() < deadline:
            messages = receive(min(0.2, deadline - time.monotonic()))
            found = messages[0] if messages else None
        return found

    # ------------------------------------------------------------------------------
    def described(message):
        return None if message is None else {'type': NAMES.get(message[0], message[0]), 'ack': message[1],
                                             'ssrc': message[2]}

    try:
        joined = first(3)
        outcomes['joined'] = described(joined)
        if joined:
            # Both directions on one SSRC (RFC 3550 section 8.2): the server's own SSRC is refused as the probe's.
            floor.sendto(floor_message(REQUEST, joined[2]), server)
            outcomes['collision'] = [described(message) for message in receive(1.5) if message[0] != joined[0]]
        # The probe's own SSRC: Floor Granted with the server's SSRC; its Floor Ack carries the probe's.
        floor.sendto(floor_message(REQUEST, args.ssrc), server)
        if joined and joined[1]:
            # The Floor Ack of the first message, after the probe's first message: matched once its SSRC is learned.
            floor.sendto(floor_ack(args.ssrc, joined[0]), server)
        granted = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (granted is None or granted[0] != GRANTED):
            granted = first(deadline - time.monotonic())
            if granted and granted[1]:
                floor.sendto(floor_ack(args.ssrc, granted[0]), server)
        outcomes['granted'] = described(granted)
        # Within T1 (End of RTP media, 4 s by default; the probe sends no speech): another SSRC once the probe's is
        # learned, which is not the session's, and in the same 2.2 s the retransmissions of Floor Granted (1 s apart)
        # an unmatched Floor Ack would leave.
        floor.sendto(floor_message(RELEASE, args.ssrc ^ 0x00FF00FF), server)
        later = receive(2.2)
        outcomes['stranger'] = [described(message) for message in later if message[0] != GRANTED]
        if granted and granted[0] == GRANTED:
            outcomes['granted']['repeated'] = sum(1 for message in later if message[0] == GRANTED)
        floor.sendto(floor_message(RELEASE, args.ssrc), server)
        released = first(3)
        if released and released[1]:
            floor.sendto(floor_ack(args.ssrc, released[0]), server)
        outcomes['released'] = described(released)
    finally:
        code, _, _ = dialog.request('BYE', dialog.target, [])
        outcomes['bye'] = code
        sip.sock.close()
    print(json.dumps(outcomes))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
