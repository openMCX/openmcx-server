#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The wire checks' view of a scenario capture (tcpdump pcap of Ethernet, IPv4).

TCP payloads are joined per connection (source and destination address and port),
in sequence order. Joining every segment in one stream breaks a SIP message that
spans two segments when another connection's segment falls between them, which
happens once several servers hold SIP connections (split labs).
The messages are then cut at their Content-Length, the framing of SIP over a stream
transport (RFC 3261 section 18.3).

Specifications: RFC 3261 (SIP); no 3GPP procedure is tested here.
"""

from pathlib import Path
import re


# ------------------------------------------------------------------------------
def read(path: Path):
    """The UDP payloads, as (source, destination, payload), and the SIP text of the capture."""
    data = Path(path).read_bytes()
    if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        raise AssertionError(f'{path} is not a little-endian pcap file')
    packets, tcp = [], {}
    offset = 24
    while offset + 16 <= len(data):
        length = int.from_bytes(data[offset + 8 : offset + 12], 'little')
        frame = data[offset + 16 : offset + 16 + length]
        offset += 16 + length
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        header = (ip[0] & 0x0F) * 4
        total = int.from_bytes(ip[2:4], 'big')
        src, dst, protocol, body = '.'.join(map(str, ip[12:16])), '.'.join(map(str, ip[16:20])), ip[9], ip[header:total]
        if protocol == 17 and len(body) >= 8:
            packets.append((src, dst, body[8:]))
        elif protocol == 6 and len(body) >= 20:
            payload = body[(body[12] >> 4) * 4 :]
            if payload:
                tcp.setdefault((src, body[0:2], dst, body[2:4]), []).append((int.from_bytes(body[4:8], 'big'), payload))
    return packets, ''.join(stream(segments).decode('utf-8', 'replace') for segments in tcp.values())


# ------------------------------------------------------------------------------
def stream(segments) -> bytes:
    """A connection's bytes from its (sequence number, payload) segments: in sequence order,
    each byte once, so a retransmitted segment captured twice does not repeat its text."""
    first = segments[0][0]
    data, next_byte = bytearray(), 0
    for offset, payload in sorted(((seq - first) % 2**32, payload) for seq, payload in segments):
        if offset + len(payload) > next_byte:
            data += payload[max(0, next_byte - offset) :]
            next_byte = offset + len(payload)
    return bytes(data)


# ------------------------------------------------------------------------------
def sip_text(path: Path) -> str:
    """The SIP text of the capture, each connection's segments joined in order."""
    return read(path)[1]


START_LINE = r'(?:[A-Z]+ sips?:\S+ SIP/2\.0|SIP/2\.0 \d{3} )'
START = re.compile(r'(?m)^' + START_LINE)
# The next message on a connection follows the body directly, which need not end in CRLF.
NEXT = re.compile(START_LINE)
LENGTH = re.compile(r'(?im)^(?:Content-Length|l)[ \t]*:[ \t]*(\d+)')


# ------------------------------------------------------------------------------
def split(sip: str) -> list:
    """The SIP messages of a capture's SIP text, each cut at its Content-Length (RFC 3261 section 18.3).

    Cutting only at the next start line of one kind (say "INVITE sip:") would run a
    message on into the responses and requests after it on the same connection.
    """
    messages, position = [], 0
    while True:
        start = NEXT.match(sip, position) or START.search(sip, position)
        if not start:
            return messages
        end_of_headers = sip.find('\r\n\r\n', start.start())
        if end_of_headers < 0:
            messages.append(sip[start.start() :])
            return messages
        body = end_of_headers + 4
        length = LENGTH.search(sip, start.start(), body)
        if length is None:
            # No Content-Length: the message runs to the next start line.
            following = START.search(sip, body)
            end = following.start() if following else len(sip)
        else:
            # Content-Length counts octets; the text may hold characters of several.
            end, remaining = body, int(length.group(1))
            while remaining > 0 and end < len(sip):
                remaining -= len(sip[end].encode('utf-8', 'replace'))
                end += 1
        messages.append(sip[start.start() : end])
        position = max(end, start.end())
