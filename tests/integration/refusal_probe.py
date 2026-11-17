#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Requests the lab client would refuse to send itself, sent raw as the client of --config; run inside its container.

The clients check the documents they hold before they send (TS 24.282 clause 11.1 for MCData, TS 24.379 clauses
10.1.1.2.1.1 and 10.1.2.2.1.1 for MCPTT group calls), so a request the server must refuse never reaches it from them.
This probe is a raw SIP user agent, digest-authenticated as the client (as sip_negative.py and nomux_probe.py), that
sends such requests anyway, for the scenarios to check the server's own refusal:
  --sds GROUP SIZE   a group standalone SDS over the signalling control plane (TS 24.282 clause 9.2.2.2.1) to GROUP
                     with a text payload of SIZE octets: a SIP MESSAGE to the MCData PSI;
  --chat GROUP       a chat group call (TS 24.379 clause 10.1.2.2.1.1) on GROUP: an INVITE to the MCPTT PSI; one that
                     is accepted after all is acknowledged and ended with BYE;
  --video-adhoc-alert CRITERIA
                     an MCVideo ad hoc group emergency alert (TS 24.281 clause 12.1A.1.1, as TS 24.379 clause
                     12.1A.1.1) to the users the <call-participants-criteria> CRITERIA selects: a SIP MESSAGE to the
                     MCVideo PSI with the client's location;
  --mcdata-alert GROUP
                     an MCData emergency alert (TS 24.282 clause 16.2.1.1) on GROUP: a SIP MESSAGE to the MCData PSI
                     with <alert-ind> "true" and the client's location.
Each option may be repeated. Prints one JSON line: {"sds": [{group, size, status, warning}], "chat": [{group, status,
warning}], "video_adhoc_alert": [{criteria, status, warning}], "mcdata_alert": [{group, status, warning, alert_ind}]},
in the order given (alert_ind: the <alert-ind> of the response's MCData info, true, false or null).

The probe runs with the client's digest credentials and sends its XML in the clear; it does not work in the AKA labs
(the client of --config registers with IMS AKA there) nor where the service's signalling is protected (TS 24.282 clause
6.5, TS 24.379 clause 6.6: the server refuses clear signalling from a client that protects its own): usable() is
false. The scenarios call run_in() on the host, which copies the probe into the client's container and runs it there.

Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 3261.
"""

import argparse
import json
import pathlib
import re
import secrets
import socket
import subprocess
import sys
import time
from xml.sax.saxutils import escape

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from nomux_probe import Dialog  # noqa: E402
from sip_negative import SipProbe  # noqa: E402

MCPTT_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcptt'
MCVIDEO_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcvideo'
SDS_ICSI = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds'


# ------------------------------------------------------------------------------
def usable(compose, role, service):
    """On the host: whether the probe can send requests of the service ("mcptt", "mcvideo" or "mcdata") as the client
    of role in the lab of the compose file: a digest client (the AKA labs' clients register with IMS AKA), and the
    service's <signalling-protection> off, both "false" in the service configuration (absent means on, TS 24.484
    clause 8.4.2.7 NOTE 4)."""
    generated = pathlib.Path(compose).resolve().parent / 'generated'
    cfg = json.loads((generated / f'{role}.json').read_text())
    site = json.loads((generated / 'site.json').read_text())
    protection = site.get('service_config', {}).get(service, {}).get('signalling_protection', {})
    clear = protection.get('confidentiality', True) is False and protection.get('integrity', True) is False
    return cfg['sip'].get('auth', 'digest') != 'aka' and clear


# ------------------------------------------------------------------------------
def run_in(cli, compose, role, arguments):
    """On the host: run the probe with arguments in the container of role as that client (over TLS unless the lab's
    clients run with --disable-tls) and return its outcomes."""
    services = json.loads(pathlib.Path(compose).read_text()).get('services', {})
    tls = '--disable-tls' not in ' '.join(str(part) for part in services.get(role, {}).get('command', []))
    here = pathlib.Path(__file__).resolve().parent
    for name in ('sip_negative.py', 'nomux_probe.py', 'refusal_probe.py'):
        subprocess.run(cli + ['cp', str(here / name), f'{role}:/tmp/{name}'], check=True, capture_output=True)
    run = subprocess.run(
        cli
        + ['exec', '-T', role, 'python3', '/tmp/refusal_probe.py', '--config', f'/config/{role}.json']
        + ([] if tls else ['--disable-tls'])
        + list(arguments),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if run.returncode:
        raise RuntimeError(f'refusal_probe.py in {role}: {run.stderr.strip()[-2000:]}')
    return json.loads(run.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------------------
class BinaryDialog(Dialog):
    """nomux_probe's Dialog with a body of bytes (an MCData binary body is not text)."""

    # ------------------------------------------------------------------------------
    def send(self, method, uri, fields, body=b'', cseq=None, authorization=None):
        """Send one request with the dialog's identifiers; returns the CSeq number used."""
        if cseq is None:
            self.cseq += 1
            cseq = self.cseq
        lines = (
            [
                f'{method} {uri} SIP/2.0',
                f"Via: SIP/2.0/{self.sip.transport.upper()} {self.cfg['sip']['advertise']}:{self.sip.port};"
                f'branch=z9hG4bK{secrets.token_hex(12)}',
                f'From: <{self.identity}>;tag={self.from_tag}',
                f'To: {self.to_value or "<" + uri + ">"}',
                f'Call-ID: {self.call_id}',
                f'CSeq: {cseq} {method}',
                'Max-Forwards: 16',
                f'Contact: <{self.contact}>',
            ]
            + [f'Route: {route}' for route in self.route]
            + [f'{name}: {value}' for name, value in fields]
        )
        if authorization:
            lines.append(authorization)
        head = '\r\n'.join(lines) + f'\r\nContent-Length: {len(body)}\r\n\r\n'
        self.sip.sock.sendall(head.encode() + body)
        return cseq


# ------------------------------------------------------------------------------
def sds_bodies(size):
    """The SDS SIGNALLING PAYLOAD (TS 24.282 clause 15.1.2: message type 1, Date and time, Conversation ID and Message
    ID, no disposition request) and the DATA PAYLOAD (clause 15.1.4: one Payload IE, text) of SIZE octets."""
    uuid = lambda: bytes(secrets.token_bytes(16))  # noqa: E731
    signalling = bytes([0x01]) + int(time.time()).to_bytes(5, 'big') + uuid() + uuid()
    value = bytes([0x01]) + b'x' * size
    data = bytes([0x03, 0x01, 0x78]) + len(value).to_bytes(2, 'big') + value
    return signalling, data


# ------------------------------------------------------------------------------
def warning_of(headers):
    """The Warning header field's value of a response's header fields (a dict or (name, value) pairs), or ''."""
    pairs = headers.items() if isinstance(headers, dict) else headers
    return next((value for name, value in pairs if name.lower() == 'warning'), '')


# ------------------------------------------------------------------------------
def group_sds(sip, cfg, group, size):
    """A group standalone SDS MESSAGE (TS 24.282 clause 9.2.2.2.1): request type "group-sds", the group in
    <mcdata-request-uri>, the client's MCData client ID; the final status and Warning."""
    signalling, data = sds_bodies(size)
    info = (
        '<?xml version="1.0" encoding="UTF-8"?><mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params>'
        '<request-type>group-sds</request-type>'
        f'<mcdata-request-uri type="Normal"><mcdataURI>{escape(group)}</mcdataURI></mcdata-request-uri>'
        f'<mcdata-client-id type="Normal"><mcdataString>{escape(cfg["mcptt"]["client_id"])}</mcdataString>'
        '</mcdata-client-id></mcdata-Params></mcdatainfo>'
    )
    boundary = 'refusal-' + secrets.token_hex(12)
    body = b''
    for content_type, part in [
        ('application/vnd.3gpp.mcdata-info+xml', info.encode()),
        ('application/vnd.3gpp.mcdata-signalling', signalling),
        ('application/vnd.3gpp.mcdata-payload', data),
    ]:
        body += f'--{boundary}\r\nContent-Type: {content_type}\r\n\r\n'.encode() + part + b'\r\n'
    body += f'--{boundary}--\r\n'.encode()
    # TS 24.282 clause 6.2.4.1: the SDS feature tag and the SDS ICSI in Accept-Contact, the ICSI in P-Preferred-Service.
    fields = [
        ('Accept-Contact', '*;+g.3gpp.mcdata.sds;require;explicit'),
        ('Accept-Contact', f'*;+g.3gpp.icsi-ref="{SDS_ICSI}";require;explicit'),
        ('P-Preferred-Service', 'urn:urn-7:3gpp-service.ims.icsi.mcdata.sds'),
        ('Content-Type', 'multipart/mixed; boundary=' + boundary),
    ]
    code, headers, _ = BinaryDialog(sip, cfg).request('MESSAGE', cfg['mcdata']['service_uri'], fields, body)
    return {'group': group, 'size': size, 'status': code, 'warning': warning_of(headers)}


# ------------------------------------------------------------------------------
def chat(sip, cfg, group):
    """A chat group call INVITE (TS 24.379 clause 10.1.2.2.1.1 steps 3 to 14) to the MCPTT PSI for the group, with an
    SDP offer of its own ports; the final status and Warning. A 2xx is acknowledged and the call ended."""
    address = sip.sock.getsockname()[0]
    ports = []
    for _ in range(2):
        held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        held.bind((address, 0))
        ports.append(held)
    audio, floor = (held.getsockname()[1] for held in ports)
    sdp = (
        f'v=0\r\no=- 1 1 IN IP4 {address}\r\ns=MCPTT\r\nc=IN IP4 {address}\r\nt=0 0\r\n'
        f'm=audio {audio} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000/1\r\n'
        'a=fmtp:96 octet-align=0;mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\n'
        f'a=sendrecv\r\na=rtcp:{audio + 1}\r\nm=application {floor} udp MCPTT\r\n'
    )
    info = (
        '<?xml version="1.0"?><mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
        '<session-type>chat</session-type>'
        f'<mcptt-request-uri type="Normal"><mcpttURI>{escape(group)}</mcpttURI></mcptt-request-uri>'
        f'<mcptt-client-id type="Normal"><mcpttString>{escape(cfg["mcptt"]["client_id"])}</mcpttString>'
        '</mcptt-client-id></mcptt-Params></mcpttinfo>'
    )
    boundary = 'refusal-' + secrets.token_hex(12)
    body = ''.join(
        f'--{boundary}\r\nContent-Type: {mime}\r\n\r\n{part}\r\n'
        for mime, part in [('application/sdp', sdp), ('application/vnd.3gpp.mcptt-info+xml', info)]
    )
    body += f'--{boundary}--\r\n'
    fields = [
        ('Accept-Contact', f'*;+g.3gpp.icsi-ref="{MCPTT_ICSI.replace(":", "%3A")}";+g.3gpp.mcptt;require;explicit'),
        ('P-Preferred-Service', MCPTT_ICSI),
        ('Content-Type', 'multipart/mixed;boundary=' + boundary),
    ]
    dialog = Dialog(sip, cfg)
    try:
        code, headers, _ = dialog.request('INVITE', cfg['mcptt']['service_uri'], fields, body)
        if 200 <= code < 300:
            dialog.established(headers)
            dialog.send('ACK', dialog.target, [], cseq=dialog.cseq)
            dialog.request('BYE', dialog.target, [])
        return {'group': group, 'status': code, 'warning': warning_of(headers)}
    finally:
        for held in ports:
            held.close()


# ------------------------------------------------------------------------------
def video_adhoc_alert(sip, cfg, criteria):
    """An MCVideo ad hoc group emergency alert MESSAGE (TS 24.379 clause 12.1A.1.1 steps 1, 2 and 4, which TS 24.281
    clause 12.1A follows): <call-participants-criteria> and <adhoc-alert-ind> "true" in the <anyExt> of the MCVideo
    info, the client's MCVideo client ID, and an Emergency location report (step 5); the final status and Warning."""
    info = (
        '<?xml version="1.0"?><mcvideoinfo xmlns="urn:3gpp:ns:mcvideoInfo:1.0"><mcvideo-Params>'
        f'<mcvideo-client-id type="Normal"><mcvideoString>{escape(cfg["mcptt"]["client_id"])}</mcvideoString>'
        f'</mcvideo-client-id><anyExt><call-participants-criteria>{escape(criteria)}</call-participants-criteria>'
        '<adhoc-alert-ind>true</adhoc-alert-ind></anyExt></mcvideo-Params></mcvideoinfo>'
    )
    location = (
        '<?xml version="1.0"?><location-info xmlns="urn:3gpp:ns:mcvideoLocationInfo:1.0">'
        '<Report ReportType="Emergency"><CurrentLocation><CurrentCoordinate><longitude type="Normal">'
        '<threebytes>2</threebytes></longitude><latitude type="Normal"><threebytes>1</threebytes></latitude>'
        '</CurrentCoordinate></CurrentLocation></Report></location-info>'
    )
    boundary = 'refusal-' + secrets.token_hex(12)
    body = ''.join(
        f'--{boundary}\r\nContent-Type: {mime}\r\n\r\n{part}\r\n'
        for mime, part in [
            ('application/vnd.3gpp.mcvideo-info+xml', info),
            ('application/vnd.3gpp.mcvideo-location-info+xml', location),
        ]
    )
    body += f'--{boundary}--\r\n'
    uri = cfg['mcvideo']['service_uri']
    fields = {
        'P-Preferred-Service': MCVIDEO_ICSI,
        'Accept-Contact': f'*;+g.3gpp.icsi-ref="{MCVIDEO_ICSI.replace(":", "%3A")}";require;explicit',
        'Content-Type': 'multipart/mixed;boundary=' + boundary,
    }
    challenge = sip.request('MESSAGE', uri, fields, body)
    code, headers = challenge
    if code in (401, 407):
        code, headers = sip.request('MESSAGE', uri, fields, body, authorization=sip.digest('MESSAGE', uri, challenge))
    return {'criteria': criteria, 'status': code, 'warning': warning_of(headers)}


# ------------------------------------------------------------------------------
def mcdata_alert(sip, cfg, group):
    """An MCData emergency alert MESSAGE (TS 24.282 clause 16.2.1.1 steps 1 to 6): the MCData ICSI in Accept-Contact
    and P-Preferred-Service, the group in <mcdata-request-uri>, <alert-ind> "true", the client's MCData client ID and an
    Emergency location report; the final status, Warning and the response's <alert-ind> (clause 16.2.3.1)."""
    info = (
        '<?xml version="1.0" encoding="UTF-8"?><mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params>'
        f'<mcdata-request-uri type="Normal"><mcdataURI>{escape(group)}</mcdataURI></mcdata-request-uri>'
        '<alert-ind type="Normal"><mcdataBoolean>true</mcdataBoolean></alert-ind>'
        f'<mcdata-client-id type="Normal"><mcdataString>{escape(cfg["mcptt"]["client_id"])}</mcdataString>'
        '</mcdata-client-id></mcdata-Params></mcdatainfo>'
    )
    location = (
        '<?xml version="1.0"?><location-info xmlns="urn:3gpp:ns:mcdataLocationInfo:1.0"><Report ReportType="Emergency">'
        '<CurrentLocation><CurrentCoordinate><longitude type="Normal"><threebytes>2</threebytes></longitude>'
        '<latitude type="Normal"><threebytes>1</threebytes></latitude></CurrentCoordinate></CurrentLocation></Report>'
        '</location-info>'
    )
    boundary = 'refusal-' + secrets.token_hex(12)
    body = ''.join(
        f'--{boundary}\r\nContent-Type: {mime}\r\n\r\n{part}\r\n'
        for mime, part in [
            ('application/vnd.3gpp.mcdata-info+xml', info),
            ('application/vnd.3gpp.mcdata-location-info+xml', location),
        ]
    )
    body += f'--{boundary}--\r\n'
    fields = [
        ('Accept-Contact', '*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata";require;explicit'),
        ('P-Preferred-Service', 'urn:urn-7:3gpp-service.ims.icsi.mcdata'),
        ('Content-Type', 'multipart/mixed;boundary=' + boundary),
    ]
    code, headers, answer = Dialog(sip, cfg).request('MESSAGE', cfg['mcdata']['service_uri'], fields, body)
    found = re.search(r'<alert-ind[^>]*>\s*<mcdataBoolean>\s*(true|false)\s*</mcdataBoolean>', answer)
    alert_ind = None if not found else found.group(1) == 'true'
    return {'group': group, 'status': code, 'warning': warning_of(headers), 'alert_ind': alert_ind}


# ------------------------------------------------------------------------------
def main():
    """Send the requests and print their outcomes."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', default='/config/client-a.json')
    parser.add_argument('--disable-tls', action='store_true')
    parser.add_argument('--sds', nargs=2, action='append', default=[], metavar=('GROUP', 'SIZE'))
    parser.add_argument('--chat', action='append', default=[], metavar='GROUP')
    parser.add_argument('--video-adhoc-alert', action='append', default=[], metavar='CRITERIA')
    parser.add_argument('--mcdata-alert', action='append', default=[], metavar='GROUP')
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    outcomes = {'sds': [], 'chat': [], 'video_adhoc_alert': [], 'mcdata_alert': []}
    requests = (
        [('sds', group_sds, (group, int(size))) for group, size in args.sds]
        + [('chat', chat, (group,)) for group in args.chat]
        + [('video_adhoc_alert', video_adhoc_alert, (criteria,)) for criteria in args.video_adhoc_alert]
        + [('mcdata_alert', mcdata_alert, (group,)) for group in args.mcdata_alert]
    )
    for kind, send, values in requests:
        sip = SipProbe(cfg, args.disable_tls)
        try:
            outcomes[kind].append(send(sip, cfg, *values))
        finally:
            sip.sock.close()
    print(json.dumps(outcomes))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
