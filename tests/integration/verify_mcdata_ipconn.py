#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Check a capture of MCData IP connectivity against TS 24.282 clause 20 and TS 24.582 clause 13.

Signalling: the INVITE to the MCData PSI with the IP connectivity feature tag and ICSI (TS 24.282 clause 20.2.1), the
tunnel offered as "m=application <port> udp MCDATA" with the mcdata-ipconn-s-port fmtp (TS 24.282 clause 20.2.0a, TS
24.582 clauses 13.5 and 13.6), the server's own address in each leg (TS 24.282 clauses 20.3.0a, 20.4.0a and 20.4.0b),
the invitation of the called client (clause 20.4.1), the answers, functional alias redirection and rejections (clauses
20.3.1 and 20.4.2). Media: the GRE-in-UDP encapsulation (TS 24.582 clause 13.4), relayed unchanged by the server (TS
24.582 clauses 13.2 and 13.3).

The SIP is read from clear TCP/5060 (debug SIP). The tunnel is read from the UDP datagrams whose ends appear in the SDP
of those messages, and every layer is decoded here, independently of the C++ implementation: the UDP header and its
checksum, the GRE header of IETF RFC 2784, the IPv4 header and ICMP echo. If tshark is on PATH (or MCX_TSHARK names it),
it must decode the same datagrams as GRE carrying ICMP (the UDP checksums are verified here only).

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19).
"""

import argparse
import collections
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_mcdata_sds import header, parse, sip_messages, tcp_streams  # noqa: E402

ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcdata.ipconn'
ICSI_ENCODED = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.ipconn'


# ------------------------------------------------------------------------------
def checksum(data):
    """The Internet checksum (RFC 1071) of data, padded to an even length."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# ------------------------------------------------------------------------------
def udp_datagrams(path):
    """Yields (index, source, sport, destination, dport, udp checksum, payload). The checksum is "full" when it
    verifies, "partial" when it holds only the pseudo header sum that a sender with checksum offload leaves for its
    interface to complete (a container veth never completes it), and "absent" or "bad" otherwise.
    """
    raw = Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    assert struct.unpack_from(endian + 'I', raw, 20)[0] == 1, 'Ethernet capture required'
    offset, index = 24, 0
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from(endian + 'IIII', raw, offset)
        offset += 16
        packet = raw[offset : offset + captured]
        offset += captured
        index += 1
        if len(packet) < 42 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 17:
            continue
        total = struct.unpack_from('!H', ip, 2)[0]
        udp = ip[ihl:total]
        sport, dport, length, sum_field = struct.unpack_from('!HHHH', udp, 0)
        # RFC 768: the checksum covers a pseudo header, the UDP header and the data.
        pseudo = ip[12:20] + struct.pack('!BBH', 0, 17, length)
        folded = sum(struct.unpack('!6H', pseudo))
        while folded >> 16:
            folded = (folded & 0xFFFF) + (folded >> 16)
        state = (
            'absent'
            if sum_field == 0
            else 'full'
            if checksum(pseudo + udp[:length]) == 0
            else 'partial'
            if sum_field == folded
            else 'bad'
        )
        yield index, socket.inet_ntoa(ip[12:16]), sport, socket.inet_ntoa(ip[16:20]), dport, state, udp[8:length]


# ------------------------------------------------------------------------------
def tunnel_of(sdp):
    """The (address, port, source port) of an "m=application ... udp MCDATA" section (TS 24.582 clause 13.6.2)."""
    address = re.search(r'(?m)^c=IN IP4 (\S+)', sdp)
    media = re.search(r'(?m)^m=application (\d+) udp MCDATA\r?$', sdp)
    fmtp = re.search(r'(?m)^a=fmtp:MCDATA mcdata-ipconn-s-port=(\d+)\r?$', sdp)
    if not (address and media):
        return None
    return address.group(1), int(media.group(1)), int(fmtp.group(1)) if fmtp else None


# ------------------------------------------------------------------------------
def gre(payload):
    """IETF RFC 2784 without key or sequence: (protocol, inner packet)."""
    flags, protocol = struct.unpack_from('!HH', payload, 0)
    if flags & 0x7FFF:
        raise ValueError(f'GRE flags {flags:#06x}')
    offset = 4
    if flags & 0x8000:
        if checksum(payload) != 0:
            raise ValueError('GRE checksum')
        offset = 8
    return protocol, payload[offset:]


# ------------------------------------------------------------------------------
def icmp_echo(packet):
    """The ICMP echo request or reply in an IPv4 packet as a dict, None for another protocol; ValueError if a checksum
    fails.
    """
    if packet[0] >> 4 != 4 or checksum(packet[: (packet[0] & 15) * 4]) != 0:
        raise ValueError('IPv4 header')
    ihl = (packet[0] & 15) * 4
    total = struct.unpack_from('!H', packet, 2)[0]
    if packet[9] != 1:
        return None
    icmp = packet[ihl:total]
    if checksum(icmp) != 0 or icmp[0] not in (0, 8):
        raise ValueError('ICMP')
    ident, sequence = struct.unpack_from('!HH', icmp, 4)
    return dict(
        reply=icmp[0] == 0,
        id=ident,
        seq=sequence,
        source=socket.inet_ntoa(packet[12:16]),
        destination=socket.inet_ntoa(packet[16:20]),
        data=icmp[8:],
    )


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the report; exit status 1 on any failure."""
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
    checks, failures, errors = [], [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label as passed or failed."""
        (checks if condition else failures).append(label)

    responses = collections.defaultdict(list)
    for message in messages:
        if not message['request']:
            responses[(message['call_id'], header(message, 'cseq'))].append(message)

    # ------------------------------------------------------------------------------
    def answers(message):
        """The responses to the request message (same Call-ID and CSeq)."""
        return responses[(message['call_id'], header(message, 'cseq'))]

    # ------------------------------------------------------------------------------
    def sdp_of(message):
        """The SDP body of message as text."""
        return message['parts'].get('application/sdp', b'').decode('utf-8', 'replace')

    invites = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'INVITE'
        and message['info'].get('request-type') == 'one-to-one-ipconn'
    ]
    offers = [message for message in invites if message['target'] == args.service]
    legs = [
        message for message in invites if message['target'] != args.service and args.service in header(message, 'from')
    ]
    accepted = [(message, response) for message in offers for response in answers(message) if response['status'] == 200]
    check(
        'the request is an INVITE to the MCData PSI with the IP connectivity feature tag and ICSI in Contact, '
        'Accept-Contact and P-Preferred-Service (20.2.1 steps 1 to 4, 9)',
        bool(offers)
        and all(
            any(
                '+g.3gpp.mcdata.ipconn' in contact and 'require' in contact and 'explicit' in contact
                for contact in message['headers']['accept-contact']
            )
            and any(ICSI_ENCODED in contact for contact in message['headers']['accept-contact'])
            and header(message, 'p-preferred-service') == ICSI
            and '+g.3gpp.mcdata.ipconn' in header(message, 'contact')
            for message in offers
        ),
    )
    check(
        'the request names one target in resource-lists and "one-to-one-ipconn" (20.2.1 steps 7 and 8)',
        bool(offers) and all(message['targets'] and len(message['targets']) == 1 for message in offers),
    )
    check(
        'the offer is "m=application <port> udp MCDATA" with the mcdata-ipconn-s-port fmtp (20.2.0a, 24.582 13.5, 13.6)',
        bool(offers) and all(tunnel_of(sdp_of(message)) and tunnel_of(sdp_of(message))[2] for message in offers),
    )
    check(
        'the called client is invited with the ICSI, Accept-Contact, Referred-By, the called and calling users '
        '(20.4.1 steps 4 to 11)',
        bool(legs)
        and all(
            header(message, 'p-asserted-service') == ICSI
            and header(message, 'referred-by').startswith('<sip:')
            and any('+g.3gpp.mcdata.ipconn' in contact for contact in message['headers']['accept-contact'])
            and message['info'].get('mcdata-request-uri')
            and message['info'].get('mcdata-calling-user-id')
            for message in legs
        ),
    )
    server_ends = {tunnel_of(sdp_of(message)) for message in legs if tunnel_of(sdp_of(message))}
    server_ends |= {tunnel_of(sdp_of(response)) for _, response in accepted if tunnel_of(sdp_of(response))}
    client_ends = {tunnel_of(sdp_of(message)) for message in offers if tunnel_of(sdp_of(message))}
    client_ends |= {
        tunnel_of(sdp_of(response))
        for message in legs
        for response in answers(message)
        if response['status'] == 200 and tunnel_of(sdp_of(response))
    }
    check(
        'the server puts its own address and port in each leg (20.3.0a, 20.4.0a, 20.4.0b)',
        bool(server_ends) and not (server_ends & client_ends) and len({address for address, _, _ in server_ends}) == 1,
    )
    check(
        'the caller is answered 100 first and then 200 with the tunnel (20.4.2)',
        bool(accepted)
        and all(
            any(
                response['status'] == 100 and 'application/sdp' not in response['parts']
                for response in answers(message)
            )
            and tunnel_of(sdp_of(response))
            for message, response in accepted
        ),
    )

    # TS 24.282 clause 6.3.7.1.23 steps 5 and 6 (the 200 (OK) to the caller) and clause 20.4.1 step 7 (the INVITE to
    # the called client): a SIP URI for the MCData session identity at the controlling function, with the IP
    # connectivity feature tag, its ICSI and isfocus; the same identity on both legs.
    def focus_contact(message):
        contact = header(message, 'contact')
        return bool(
            re.match(r'<sips?:[^@>]+@[^:;>]+;[^>]*>', contact)
            and '+g.3gpp.mcdata.ipconn' in contact
            and f'+g.3gpp.icsi-ref="{ICSI_ENCODED}"' in contact
            and re.search(r';isfocus(;|$)', contact)
            and 'g.3gpp.mcptt' not in contact
        )

    def identity(message):
        return header(message, 'contact').split('>')[0]

    check(
        "the server's 200 to the caller has the session identity Contact with the IP connectivity tags and isfocus "
        '(6.3.7.1.23 steps 5 and 6)',
        bool(accepted) and all(focus_contact(response) for _, response in accepted),
    )
    check(
        "the server's INVITE to the called client has the session identity Contact with isfocus (20.4.1 step 7)",
        bool(legs)
        and all(focus_contact(message) for message in legs)
        and {identity(response) for _, response in accepted} <= {identity(message) for message in legs},
    )
    alias_offers = [message for message in offers if message['info'].get('call-to-functional-alias-ind') == 'true']
    redirects = [response for message in alias_offers for response in answers(message) if response['status'] == 300]
    check(
        'a request to a functional alias is answered 300 naming the selected user, with a session identity Contact '
        '(20.4.2 step 5a1)',
        bool(redirects)
        and all(
            response['info'].get('mcdata-request-uri')
            and re.match(r'<sips?:[^@>]+@[^:;>]+;[^>]*>', header(response, 'contact'))
            for response in redirects
        ),
    )
    check(
        'the caller then invites that user with <called-functional-alias-URI> (20.2.1)',
        any(
            message['info'].get('called-functional-alias-URI') and 'call-to-functional-alias-ind' not in message['info']
            for message in offers
        ),
    )
    rejected = [
        (response['status'], header(response, 'warning'))
        for message in offers
        for response in answers(message)
        if response['status'] >= 300
    ]
    for code in ('200', '229', '230', '145'):
        check(
            f'rejection 403/{code}',
            any(status_code == 403 and f'"{code} ' in warning for status_code, warning in rejected),
        )
    check(
        'a busy called client\'s 486 is passed back to the caller (20.3.1)',
        any(status_code == 486 for status_code, _ in rejected),
    )
    check(
        'sessions are released with BYE on both legs',
        sum(1 for message in messages if message['request'] and message['method'] == 'BYE') >= 2 * len(accepted) - 1,
    )

    # The tunnel itself.
    ends = {(address, port) for address, port, _ in server_ends | client_ends}
    tunnel = [
        datagram
        for datagram in udp_datagrams(args.capture)
        if (datagram[1], datagram[2]) in ends and (datagram[3], datagram[4]) in ends
    ]
    decoded, echoes = [], []
    for index, source, sport, destination, dport, valid, payload in tunnel:
        try:
            protocol, inner = gre(payload)
            if protocol != 0x0800:
                raise ValueError(f'protocol {protocol:#06x}')
            echo = icmp_echo(inner)
            decoded.append((index, source, sport, destination, dport, valid, payload))
            if echo:
                echoes.append(echo)
        except (ValueError, struct.error) as error:
            errors.append(f'{index}: {error}')
    check(
        'tunnel datagrams run between the SDP ends in both directions',
        len({(datagram[1], datagram[3]) for datagram in decoded}) >= 2,
    )
    checksums = collections.Counter(datagram[5] for datagram in decoded)
    check(
        'every tunnel datagram uses the UDP checksum (24.582 13.4 step 1): complete, or left partial by '
        'checksum offload for the interface to complete, never absent or wrong',
        bool(decoded) and set(checksums) <= {'full', 'partial'},
    )
    check(
        'every tunnel datagram is GRE version 0 without key or sequence number, protocol type IPv4 '
        '(24.582 13.4 step 3, RFC 2784)',
        bool(decoded) and not errors,
    )
    check(
        'the tunnel carries IPv4 ICMP echo requests and replies whose checksums verify',
        any(not echoed['reply'] for echoed in echoes) and any(echoed['reply'] for echoed in echoes),
    )
    requests = {
        (echoed['id'], echoed['seq'], echoed['source'], echoed['destination'], bytes(echoed['data']))
        for echoed in echoes
        if not echoed['reply']
    }
    check(
        'every reply answers a request with the same identifier, sequence and data',
        all(
            (echoed['id'], echoed['seq'], echoed['destination'], echoed['source'], bytes(echoed['data'])) in requests
            for echoed in echoes
            if echoed['reply']
        ),
    )
    # TS 24.582 clauses 13.2 and 13.3: what the server receives on one leg it sends on the other, unchanged.
    into_server = collections.Counter(
        datagram[6]
        for datagram in decoded
        if (datagram[3], datagram[4]) in {(address, port) for address, port, _ in server_ends}
    )
    out_of_server = collections.Counter(
        datagram[6]
        for datagram in decoded
        if (datagram[1], datagram[2]) in {(address, port) for address, port, _ in server_ends}
    )
    check(
        'the server relays each datagram unchanged to the other leg (24.582 13.2, 13.3)',
        bool(out_of_server) and all(into_server[payload] >= count for payload, count in out_of_server.items()),
    )
    check(
        'datagrams are sent from the port named in mcdata-ipconn-s-port (24.582 13.6.2.2)',
        all(
            (datagram[1], datagram[2])
            in {(address, source_port or port) for address, port, source_port in server_ends | client_ends}
            for datagram in decoded
        ),
    )

    tshark = os.environ.get('MCX_TSHARK') or shutil.which('tshark')
    tshark_icmp = None
    if tshark:
        ports = sorted({port for _, port in ends})
        decode_as = [arg for port in ports for arg in ('-d', f'udp.port=={port},gre')]
        run = subprocess.run(
            [
                tshark,
                '-r',
                str(args.capture),
                # The UDP checksums are verified above, a partial (offloaded) one included; how tshark judges a
                # partial checksum differs between its versions, so it only decodes here.
                '-o',
                'udp.check_checksum:FALSE',
                *decode_as,
                '-Y',
                'gre && icmp && !_ws.malformed',
                '-T',
                'fields',
                '-e',
                'icmp.type',
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        tshark_icmp = len([line for line in run.stdout.split() if line in ('0', '8')])
        check(
            'tshark decodes the same datagrams as GRE carrying ICMP, malformed-free',
            run.returncode == 0 and tshark_icmp == len(echoes),
        )
    report = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        decode_errors=errors,
        observations=dict(
            requests=len(offers),
            invited_legs=len(legs),
            established=len(accepted),
            rejections=len(rejected),
            tunnel_datagrams=len(decoded),
            icmp_echoes=len(echoes),
            udp_checksums=dict(checksums),
            tshark_icmp=tshark_icmp,
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
