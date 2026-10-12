#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Lab tooling: a recording mock PCRF for the Rx lab (tests/integration/rx_scenario.py). It is the Diameter peer of
# the MCPTT server's Rx client over SCTP without TLS: it answers the capabilities exchange, watchdogs, AA-Requests
# and Session-Termination-Requests, records each request decoded, and on request of the scenario sends
# Re-Auth-Requests and Abort-Session-Requests to the AF. It implements only what the scenario checks of TS 29.214
# (clauses 4.4.1 to 4.4.6, 5.6) and RFC 6733 (sections 3, 4, 5.3, 5.5).
#
# Specifications: TS 29.214 V19.3.0 (Rel-19), RFC 6733.
"""Mock PCRF for the Rx lab.

  mock_pcrf.py --identity mock-pcrf.example.org --realm example.org --record /artifacts/mock-pcrf/requests.jsonl

Control API (HTTP on --control, default :8080):
  GET  /healthz                  200 when the Diameter listener runs
  GET  /mock/requests            the requests received, decoded, in order
  POST /mock/config              {"fail_create": true}: AA-Requests are refused (IP-CAN_SESSION_NOT_AVAILABLE)
  POST /mock/rar                 {"session_id": ..., "specific_action": 9}: a Re-Auth-Request to the AF
  POST /mock/asr                 {"session_id": ..., "abort_cause": 0}: an Abort-Session-Request to the AF
"""

import argparse
import http.server
import itertools
import json
import socket
import struct
import threading
import time

# ------------------------------------------------------------------------------
# RFC 6733 and TS 29.214: codes.
VENDOR_3GPP, VENDOR_ETSI = 10415, 13019
RX_APPLICATION_ID = 16777236
FLAG_VENDOR, FLAG_MANDATORY = 0x80, 0x40
FLAG_REQUEST, FLAG_PROXIABLE = 0x80, 0x40
CER, DWR, DPR, AAR, STR, RAR, ASR = 257, 280, 282, 265, 275, 258, 274
DIAMETER_SUCCESS = 2001
IP_CAN_SESSION_NOT_AVAILABLE = 5065  # TS 29.214 clause 5.5.3
FEATURE_MCPTT, FEATURE_MCVIDEO = 1 << 17, 1 << 22

# The AVPs the scenario reads: (code, vendor) -> (name, kind).
AVPS = {
    (263, 0): ('Session-Id', 'utf8'),
    (264, 0): ('Origin-Host', 'utf8'),
    (296, 0): ('Origin-Realm', 'utf8'),
    (283, 0): ('Destination-Realm', 'utf8'),
    (293, 0): ('Destination-Host', 'utf8'),
    (258, 0): ('Auth-Application-Id', 'u32'),
    (268, 0): ('Result-Code', 'u32'),
    (295, 0): ('Termination-Cause', 'u32'),
    (8, 0): ('Framed-IP-Address', 'ipv4'),
    (504, VENDOR_3GPP): ('AF-Application-Identifier', 'utf8'),
    (507, VENDOR_3GPP): ('Flow-Description', 'utf8'),
    (509, VENDOR_3GPP): ('Flow-Number', 'u32'),
    (511, VENDOR_3GPP): ('Flow-Status', 'u32'),
    (512, VENDOR_3GPP): ('Flow-Usage', 'u32'),
    (513, VENDOR_3GPP): ('Specific-Action', 'u32'),
    (515, VENDOR_3GPP): ('Max-Requested-Bandwidth-DL', 'u32'),
    (516, VENDOR_3GPP): ('Max-Requested-Bandwidth-UL', 'u32'),
    (517, VENDOR_3GPP): ('Media-Component-Description', 'group'),
    (518, VENDOR_3GPP): ('Media-Component-Number', 'u32'),
    (519, VENDOR_3GPP): ('Media-Sub-Component', 'group'),
    (520, VENDOR_3GPP): ('Media-Type', 'u32'),
    (533, VENDOR_3GPP): ('Rx-Request-Type', 'u32'),
    (547, VENDOR_3GPP): ('MCPTT-Identifier', 'utf8'),
    (562, VENDOR_3GPP): ('MCVideo-Identifier', 'utf8'),
    (628, VENDOR_3GPP): ('Supported-Features', 'group'),
    (629, VENDOR_3GPP): ('Feature-List-ID', 'u32'),
    (630, VENDOR_3GPP): ('Feature-List', 'u32'),
    (266, 0): ('Vendor-Id', 'u32'),
    (458, VENDOR_ETSI): ('Reservation-Priority', 'u32'),
}


# ------------------------------------------------------------------------------
def avp(code, data, vendor=0, mandatory=True):
    """RFC 6733 section 4.1: one AVP, padded to 32 bits."""
    flags = (FLAG_MANDATORY if mandatory else 0) | (FLAG_VENDOR if vendor else 0)
    header = struct.pack('!II', code, (flags << 24) | ((12 if vendor else 8) + len(data)))
    if vendor:
        header += struct.pack('!I', vendor)
    return header + data + b'\0' * (-len(data) % 4)


def u32(code, value, vendor=0, mandatory=True):
    return avp(code, struct.pack('!I', value), vendor, mandatory)


def utf8(code, text, vendor=0, mandatory=True):
    return avp(code, text.encode(), vendor, mandatory)


def grouped(code, children, vendor=0, mandatory=True):
    return avp(code, b''.join(children), vendor, mandatory)


def parse_avps(data):
    """RFC 6733 section 4.1: the AVPs of a message body or a Grouped AVP, as (code, vendor, data)."""
    out, index = [], 0
    while index + 8 <= len(data):
        code, word = struct.unpack('!II', data[index : index + 8])
        flags, length = word >> 24, word & 0xFFFFFF
        vendor = struct.unpack('!I', data[index + 8 : index + 12])[0] if flags & FLAG_VENDOR else 0
        start = index + (12 if flags & FLAG_VENDOR else 8)
        out.append((code, vendor, data[start : index + length]))
        index += length + (-length % 4)
    return out


def decode(avps):
    """The known AVPs as a dict of lists (an AVP may repeat), Grouped AVPs decoded in turn."""
    out = {}
    for code, vendor, data in avps:
        name, kind = AVPS.get((code, vendor), (f'{code}/{vendor}', 'hex'))
        if kind == 'u32':
            value = struct.unpack('!I', data)[0]
        elif kind == 'utf8':
            value = data.decode(errors='replace')
        elif kind == 'ipv4':
            value = socket.inet_ntoa(data) if len(data) == 4 else data.hex()
        elif kind == 'group':
            value = decode(parse_avps(data))
        else:
            value = data.hex()
        out.setdefault(name, []).append(value)
    return out


# ------------------------------------------------------------------------------
class Pcrf:
    """The mock PCRF: one AF connection at a time, its requests recorded."""

    def __init__(self, identity, realm, record):
        self.identity, self.realm, self.record = identity, realm, record
        self.lock = threading.Lock()
        self.requests = []
        self.fail_create = False
        self.connection = None
        self.af_host = None
        self.hop = itertools.count(0x1000)
        self.end_to_end = itertools.count(0x5000)

    def origin(self):
        return [utf8(264, self.identity), utf8(296, self.realm)]

    def send(self, command, application, avps, request, hop=None, end_to_end=None, proxiable=True):
        """RFC 6733 section 3: one message on the AF connection."""
        body = b''.join(avps)
        flags = (FLAG_REQUEST if request else 0) | (FLAG_PROXIABLE if proxiable else 0)
        header = struct.pack('!II', (1 << 24) | (20 + len(body)), (flags << 24) | command)
        header += struct.pack(
            '!III',
            application,
            hop if hop is not None else next(self.hop),
            end_to_end if end_to_end is not None else next(self.end_to_end),
        )
        with self.lock:
            if self.connection is None:
                raise ConnectionError('no AF connected')
            self.connection.sendall(header + body)

    def store(self, entry):
        with self.lock:
            self.requests.append(entry)
        with open(self.record, 'a') as out:
            out.write(json.dumps(entry) + '\n')

    def answer(self, command, application, hop, end_to_end, session_avps, result, extra=(), proxiable=True):
        avps = list(session_avps) + self.origin() + [u32(268, result)] + list(extra)
        self.send(command, application, avps, False, hop, end_to_end, proxiable)

    def handle(self, flags, command, application, hop, end_to_end, avps):
        """RFC 6733 sections 5.3, 5.5 and 5.4; TS 29.214 clauses 4.4.1, 4.4.2, 4.4.4."""
        fields = decode(avps)
        session = [avp(263, data) for code, vendor, data in avps if (code, vendor) == (263, 0)]
        if not flags & FLAG_REQUEST:
            self.store(dict(direction='answer', command=command, at=time.time(), **fields))
            return
        if command == CER:
            self.af_host = fields.get('Origin-Host', [None])[0]
            ip = socket.inet_aton(self.connection.getsockname()[0])
            self.answer(
                CER,
                0,
                hop,
                end_to_end,
                [],
                DIAMETER_SUCCESS,
                [
                    avp(257, struct.pack('!H', 1) + ip),
                    u32(266, VENDOR_3GPP),
                    utf8(269, 'openMCX mock PCRF', mandatory=False),
                    u32(258, RX_APPLICATION_ID),
                    grouped(260, [u32(266, VENDOR_3GPP), u32(258, RX_APPLICATION_ID)]),
                ],
                proxiable=False,
            )
        elif command == DWR:
            self.answer(DWR, 0, hop, end_to_end, [], DIAMETER_SUCCESS, proxiable=False)
        elif command == DPR:
            self.answer(DPR, 0, hop, end_to_end, [], DIAMETER_SUCCESS, proxiable=False)
        elif command == AAR:
            initial = fields.get('Rx-Request-Type', [0])[0] == 0
            refuse = initial and self.fail_create
            result = IP_CAN_SESSION_NOT_AVAILABLE if refuse else DIAMETER_SUCCESS
            self.store(dict(direction='request', command='AAR', at=time.time(), result=result, **fields))
            extra = []
            if initial and not refuse:
                offered = fields.get('Supported-Features', [{}])[0].get('Feature-List', [0])[0]
                extra = [
                    grouped(
                        628,
                        [
                            u32(266, VENDOR_3GPP),
                            u32(629, 1, VENDOR_3GPP, False),
                            u32(630, offered & (FEATURE_MCPTT | FEATURE_MCVIDEO), VENDOR_3GPP, False),
                        ],
                        VENDOR_3GPP,
                        False,
                    )
                ]
            if refuse:
                # RFC 6733 section 7.6: an Experimental-Result of the 3GPP vendor.
                avps_out = (
                    session
                    + self.origin()
                    + [u32(258, RX_APPLICATION_ID), grouped(297, [u32(266, VENDOR_3GPP), u32(298, result)])]
                )
                self.send(AAR, RX_APPLICATION_ID, avps_out, False, hop, end_to_end)
            else:
                # As the Open5GS PCRF: IP-CAN-Type (TS 29.212, M flag set) 3GPP-EPS and RAT-Type EUTRAN, which the AF
                # does not read but must know (an unknown mandatory AVP in an answer aborts freeDiameter 1.2.1).
                access = [u32(1027, 5, VENDOR_3GPP), u32(1032, 1004, VENDOR_3GPP, False)]
                self.answer(
                    AAR,
                    RX_APPLICATION_ID,
                    hop,
                    end_to_end,
                    session,
                    result,
                    [u32(258, RX_APPLICATION_ID)] + access + extra,
                )
        elif command == STR:
            self.store(dict(direction='request', command='STR', at=time.time(), result=DIAMETER_SUCCESS, **fields))
            self.answer(
                STR, RX_APPLICATION_ID, hop, end_to_end, session, DIAMETER_SUCCESS, [u32(258, RX_APPLICATION_ID)]
            )
        else:
            self.store(dict(direction='request', command=command, at=time.time(), **fields))
            self.answer(command, application, hop, end_to_end, session, 3001)  # DIAMETER_COMMAND_UNSUPPORTED

    def to_af(self, command, session_id, extra):
        """TS 29.214 clauses 4.4.6.1 and 4.4.6.2: a Re-Auth-Request or Abort-Session-Request on an Rx session."""
        avps = (
            [utf8(263, session_id)]
            + self.origin()
            + [utf8(283, self.realm), utf8(293, self.af_host or ''), u32(258, RX_APPLICATION_ID)]
            + extra
        )
        self.send(command, RX_APPLICATION_ID, avps, True)
        self.store(
            dict(direction='sent', command='RAR' if command == RAR else 'ASR', session_id=session_id, at=time.time())
        )

    def serve(self, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', port))
        listener.listen(4)
        self.listening = True
        while True:
            connection, _ = listener.accept()
            with self.lock:
                self.connection = connection
            try:
                self.read(connection)
            except OSError:
                pass
            with self.lock:
                if self.connection is connection:
                    self.connection = None
            connection.close()

    def read(self, connection):
        buffer = b''
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                return
            buffer += chunk
            while len(buffer) >= 20:
                length = struct.unpack('!I', buffer[:4])[0] & 0xFFFFFF
                if len(buffer) < length:
                    break
                message, buffer = buffer[:length], buffer[length:]
                word = struct.unpack('!I', message[4:8])[0]
                application, hop, end_to_end = struct.unpack('!III', message[8:20])
                self.handle(word >> 24, word & 0xFFFFFF, application, hop, end_to_end, parse_avps(message[20:]))


# ------------------------------------------------------------------------------
def control(pcrf, port):
    """The scenario's control API."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, body=None):
            data = json.dumps(body).encode() if body is not None else b''
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == '/healthz':
                self.reply(200 if getattr(pcrf, 'listening', False) else 503, {})
            elif self.path == '/mock/requests':
                with pcrf.lock:
                    self.reply(200, list(pcrf.requests))
            else:
                self.reply(404, {})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
            try:
                if self.path == '/mock/config':
                    pcrf.fail_create = bool(body.get('fail_create'))
                elif self.path == '/mock/rar':
                    pcrf.to_af(
                        RAR,
                        body['session_id'],
                        [
                            u32(285, 0),  # Re-Auth-Request-Type AUTHORIZE_ONLY
                            u32(513, body.get('specific_action', 9), VENDOR_3GPP),
                        ],
                    )
                elif self.path == '/mock/asr':
                    pcrf.to_af(ASR, body['session_id'], [u32(500, body.get('abort_cause', 0), VENDOR_3GPP)])
                else:
                    self.reply(404, {})
                    return
                self.reply(200, {})
            except (KeyError, ConnectionError, OSError) as error:
                self.reply(409, dict(error=str(error)))

        def log_message(self, *args):
            pass

    http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--identity', required=True)
    parser.add_argument('--realm', required=True)
    parser.add_argument('--port', type=int, default=3868)
    parser.add_argument('--control', type=int, default=8080)
    parser.add_argument('--record', required=True)
    args = parser.parse_args()
    pcrf = Pcrf(args.identity, args.realm, args.record)
    threading.Thread(target=pcrf.serve, args=(args.port,), daemon=True).start()
    control(pcrf, args.control)


if __name__ == '__main__':
    main()
