#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Provision ephemeral trust and run native self-loop and two-process SIP tests.

Usage: run_sip_tls.py SIP_TEST_BINARY [tcp] [core]. Creates a one-day self-signed certificate for
127.0.0.1, runs the SIP test binary's self-loop test (over TLS only), its server and client
roles as two processes (registration and call), the BYE authentication test against an
independent raw SIP peer below, and the transaction failure test. The raw peer checks the
SIP digest retry of RFC 3261 section 22.3 with the response of RFC 2617 section 3.2.2.1.
With "core", only the self-loop test and the digest registration run: the engine on reSIProcate until its dialog phases
(prototype/resiprocate/PLAN.md, phases 3c and 3d).

Specifications: RFC 3261, RFC 2617; the SDP offered is an MCPTT offer (TS 24.379 V19.7.0).
"""

import hashlib
import hmac
import os
import re
import select
import socket
import ssl
import pathlib
import subprocess
import sys
import tempfile
import time


# ------------------------------------------------------------------------------
class SipWire:
    """A minimal SIP peer on one connected socket: reads and writes whole SIP messages."""

    # ------------------------------------------------------------------------------
    def __init__(self, connection):
        """Wrap the connection, with a 5 s receive timeout."""
        self.connection = connection
        self.buffer = b''
        self.connection.settimeout(5)

    # ------------------------------------------------------------------------------
    def receive(self):
        """Read one SIP message: (start line, header fields by lower-case name, each a list of
        values, body of Content-Length octets)."""
        while b'\r\n\r\n' not in self.buffer:
            block = self.connection.recv(65536)
            if not block:
                raise AssertionError('SIP peer closed before complete message')
            self.buffer += block
        header, rest = self.buffer.split(b'\r\n\r\n', 1)
        lines = header.decode().split('\r\n')
        fields = {}
        for line in lines[1:]:
            key, value = line.split(':', 1)
            fields.setdefault(key.lower(), []).append(value.strip())
        size = int(fields.get('content-length', ['0'])[0])
        while len(rest) < size:
            rest += self.connection.recv(65536)
        self.buffer = rest[size:]
        return lines[0], fields, rest[:size]

    # ------------------------------------------------------------------------------
    def send(self, first, fields, body=b''):
        """Send one SIP message with the start line, the (name, value) header fields and the body."""
        headers = [first] + [key + ': ' + value for key, value in fields]
        headers.append('Content-Length: ' + str(len(body)))
        self.connection.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode() + body)

    # ------------------------------------------------------------------------------
    def respond(self, request, status, extra=()):
        """Send a response with status to a received request, copying Via, From, To, Call-ID and
        CSeq (RFC 3261 section 8.2.6.2), with the extra header fields."""
        fields = request[1]
        copied = [('Via', value) for value in fields['via']]
        copied += [(key, fields[key.lower()][0]) for key in ['From', 'To', 'Call-ID', 'CSeq']]
        self.send('SIP/2.0 ' + status, copied + list(extra))


# ------------------------------------------------------------------------------
def digest_values(header):
    """The parameters of a Digest credentials header field value."""
    return {match[0].lower(): match[1] or match[2] for match in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', header)}


# ------------------------------------------------------------------------------
def check_digest(header, method, username, password, realm, nonce):
    """RFC 2617 section 3.2.2.1: the response of credentials with qop auth (or without qop)."""
    values = digest_values(header)
    assert values['username'] == username and values['realm'] == realm and values['nonce'] == nonce, header
    digest = lambda value: hashlib.md5(value.encode()).hexdigest()
    ha1 = digest(username + ':' + realm + ':' + password)
    ha2 = digest(method + ':' + values['uri'])
    if values.get('qop') == 'auth':
        expected = digest(':'.join([ha1, nonce, values['nc'], values['cnonce'], 'auth', ha2]))
    else:
        expected = digest(':'.join([ha1, nonce, ha2]))
    assert hmac.compare_digest(values['response'], expected), 'digest response is incorrect: ' + header


# ------------------------------------------------------------------------------
def run_register_digest(binary, directory, env):
    """A raw registrar (RFC 3261 section 10.3) for the "register-digest" role: it challenges every REGISTER without
    credentials with 401 and checks the retry (same Call-ID, higher CSeq, a correct digest); grants 4 s and expects
    the refresh half way; challenges the MESSAGE with 407; and expects the removal with Expires 0."""
    tcp = env.get('OPENMCX_SIP_TEST_TCP') == '1'
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 15063))
    listener.listen(4)
    username, password = 'registering-user', 'registering-test-password'
    realm, nonce = 'openmcx-register-test', 'register-nonce-1'
    role_env = env.copy()
    role_env['OPENMCX_SIP_TEST_ROLE'] = 'register-digest'
    process = subprocess.Popen([binary], env=role_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    wires = {}
    try:
        def accept():
            connection, _ = listener.accept()
            if not tcp:
                server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_tls.load_cert_chain(directory + '/cert.pem', directory + '/key.pem')
                server_tls.load_verify_locations(cafile=directory + '/cert.pem')
                server_tls.verify_mode = ssl.CERT_REQUIRED
                connection = server_tls.wrap_socket(connection, server_side=True)
            wires[connection] = SipWire(connection)

        def receive():
            """The next request on any connection (a new connection is accepted)."""
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                for wire in wires.values():
                    if wire.buffer:
                        return wire, wire.receive()
                ready, _, _ = select.select([listener] + list(wires), [], [], 0.5)
                for item in ready:
                    if item is listener:
                        accept()
                    else:
                        return wires[item], wires[item].receive()
            raise AssertionError('registrar: no request from the engine')

        call_id, cseq, registrations, refreshes = None, 0, 0, 0
        expect_removal = False
        while True:
            wire, request = receive()
            method = request[0].split()[0]
            fields = request[1]
            number = int(fields['cseq'][0].split()[0])
            if method == 'REGISTER':
                assert request[0] == 'REGISTER sip:openmcx.test SIP/2.0', request[0]
                assert '127.0.0.1:15063' in fields['route'][0] and ';lr' in fields['route'][0], fields.get('route')
                assert call_id in (None, fields['call-id'][0]), 'the registration keeps its Call-ID'
                assert number > cseq, 'every REGISTER of the registration has a higher CSeq'
                call_id, cseq = fields['call-id'][0], number
                expires = int(fields['expires'][0])
                if 'authorization' not in fields:
                    wire.respond(request, '401 Unauthorized',
                                 [('WWW-Authenticate', f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth"')])
                    continue
                check_digest(fields['authorization'][0], 'REGISTER', username, password, realm, nonce)
                if expires == 0:
                    assert expect_removal, 'removal before the MESSAGE'
                    wire.respond(request, '200 OK')
                    break
                assert expires == 4, 'Expires asks for what register_account asked'
                registrations += 1
                if registrations == 1:
                    first_at = time.monotonic()
                else:
                    refreshes += 1
                    elapsed = time.monotonic() - first_at
                    assert 1.0 <= elapsed <= 3.5, f'refresh half way through 4 s, not after {elapsed:.1f} s'
                wire.respond(request, '200 OK', [('Contact', fields['contact'][0] + ';expires=4')])
            elif method == 'MESSAGE':
                if 'proxy-authorization' not in fields:
                    wire.respond(request, '407 Proxy Authentication Required',
                                 [('Proxy-Authenticate', f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth"')])
                    continue
                check_digest(fields['proxy-authorization'][0], 'MESSAGE', username, password, realm, nonce)
                wire.respond(request, '200 OK')
                expect_removal = True
            else:
                raise AssertionError('registrar: unexpected ' + request[0])
        assert refreshes >= 1, 'the registration was refreshed'
        output, _ = process.communicate(timeout=10)
        print(output, end='')
        assert process.returncode == 0, 'digest registration regression failed'
        print('digest registration, refresh, 407 retry and removal verified over ' + ('tcp' if tcp else 'tls'))
    finally:
        for connection in wires:
            connection.close()
        listener.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


# ------------------------------------------------------------------------------
def run_uas_bye_auth(binary, directory, env):
    """An independent raw peer challenges a BYE sent by a native UAS dialog: it calls the native
    UAS, answers its BYE with 407 Proxy Authentication Required and checks the retried BYE's
    Proxy-Authorization (RFC 3261 section 22.3, RFC 2617 section 3.2.2.1)."""
    tcp = env.get('OPENMCX_SIP_TEST_TCP') == '1'
    transport = 'tcp' if tcp else 'tls'
    ready = pathlib.Path(directory) / 'ready-bye-auth'
    server_env = env.copy()
    server_env['OPENMCX_SIP_TEST_ROLE'] = 'bye-auth-server'
    server_env['OPENMCX_SIP_TEST_READY_FILE'] = str(ready)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 15062))
    listener.listen(2)
    listener.settimeout(5)
    connections = []
    server = subprocess.Popen([binary], env=server_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists():
            if server.poll() is not None or time.monotonic() > deadline:
                raise AssertionError('BYE authentication UAS did not start')
            time.sleep(0.02)
        outgoing = socket.create_connection(('127.0.0.1', 15061), timeout=5)
        if not tcp:
            client_tls = ssl.create_default_context(cafile=directory + '/cert.pem')
            client_tls.load_cert_chain(directory + '/cert.pem', directory + '/key.pem')
            outgoing = client_tls.wrap_socket(outgoing, server_hostname='127.0.0.1')
        connections.append(outgoing)
        wire = SipWire(outgoing)
        target = 'sip:uas@127.0.0.1:15061;transport=' + transport
        contact = 'sip:raw-peer@127.0.0.1:15062;transport=' + transport
        caller = '<sip:raw-peer@openmcx.test>;tag=auth-peer-tag'
        call_id = 'uas-bye-digest-regression@openmcx.test'
        sdp = (
            'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=MCPTT\r\n'
            'c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 43000 RTP/AVP 96\r\n'
            'i=speech\r\na=rtpmap:96 AMR-WB/16000/1\r\n'
            'a=fmtp:96 octet-align=0;mode-change-capability=2\r\n'
            'a=ptime:20\r\na=maxptime:240\r\na=sendrecv\r\na=rtcp:43001\r\n'
            'm=application 43002 udp MCPTT\r\na=fmtp:MCPTT mc_floor_ssrc=43002\r\n'
        ).encode()
        wire.send(
            'INVITE ' + target + ' SIP/2.0',
            [
                ('Via', 'SIP/2.0/' + transport.upper() + ' 127.0.0.1:15062;branch=z9hG4bK-auth-invite;rport'),
                ('Max-Forwards', '10'),
                ('From', caller),
                ('To', '<sip:uas@openmcx.test>'),
                ('Call-ID', call_id),
                ('CSeq', '1 INVITE'),
                ('Contact', '<' + contact + '>'),
                ('Supported', 'timer'),
                ('Session-Expires', '1800'),
                ('Content-Type', 'application/sdp'),
            ],
            sdp,
        )
        while True:
            response = wire.receive()
            code = int(response[0].split()[1])
            if code >= 200:
                assert code == 200, 'native UAS rejected raw INVITE: ' + response[0]
                break
        remote_contact = response[1]['contact'][0]
        remote_target = remote_contact.split('<', 1)[1].split('>', 1)[0]
        wire.send(
            'ACK ' + remote_target + ' SIP/2.0',
            [
                ('Via', 'SIP/2.0/' + transport.upper() + ' 127.0.0.1:15062;branch=z9hG4bK-auth-ack;rport'),
                ('Max-Forwards', '10'),
                ('From', caller),
                ('To', response[1]['to'][0]),
                ('Call-ID', call_id),
                ('CSeq', '1 ACK'),
            ],
        )
        # PJSIP can reuse the established transport or open a connection to the
        # Contact. Exercise the dialog independently of either transport choice.
        available, _, _ = select.select([listener, outgoing], [], [], 5)
        assert available, 'native UAS did not originate BYE'
        if listener in available:
            incoming, _ = listener.accept()
            if not tcp:
                server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_tls.load_cert_chain(directory + '/cert.pem', directory + '/key.pem')
                server_tls.load_verify_locations(cafile=directory + '/cert.pem')
                server_tls.verify_mode = ssl.CERT_REQUIRED
                incoming = server_tls.wrap_socket(incoming, server_side=True)
            connections.append(incoming)
            wire = SipWire(incoming)
        first = wire.receive()
        assert first[0].startswith('BYE '), 'expected UAS-originated BYE, got ' + first[0]
        assert first[1]['call-id'][0] == call_id
        assert 'proxy-authorization' not in first[1], 'first BYE unexpectedly authenticated without challenge'
        realm, nonce = 'openmcx-bye-auth-test', 'native-uas-bye-nonce'
        wire.respond(
            first,
            '407 Proxy Authentication Required',
            [('Proxy-Authenticate', f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth"')],
        )
        retried = wire.receive()
        assert retried[0].startswith('BYE '), '407 was not retried as BYE'
        assert retried[1]['call-id'][0] == call_id
        assert int(retried[1]['cseq'][0].split()[0]) > int(first[1]['cseq'][0].split()[0]), (
            'authenticated retry did not increment CSeq'
        )
        header = retried[1].get('proxy-authorization', [''])[0]
        assert header.startswith('Digest '), 'retried BYE lacks Proxy-Authorization Digest'
        values = {
            match[0].lower(): match[1] or match[2] for match in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', header)
        }
        username, password = 'incoming-dialog-user', 'incoming-dialog-test-password'
        assert values['username'] == username and values['realm'] == realm and values['nonce'] == nonce
        assert values['uri'] == retried[0].split()[1] and values['qop'] == 'auth'
        digest = lambda value: hashlib.md5(value.encode()).hexdigest()
        ha1 = digest(username + ':' + realm + ':' + password)
        ha2 = digest('BYE:' + values['uri'])
        expected = digest(':'.join([ha1, nonce, values['nc'], values['cnonce'], 'auth', ha2]))
        assert hmac.compare_digest(values['response'], expected), 'UAS retry proxy digest is incorrect'
        wire.respond(retried, '200 OK')
        pathlib.Path(str(ready) + '.verified').write_text('authenticated retry verified\n')
        output, _ = server.communicate(timeout=5)
        print(output, end='')
        assert server.returncode == 0, 'native UAS BYE authentication regression failed'
        print('UAS-originated BYE authenticated 407 retry verified over ' + transport)
    finally:
        for connection in connections:
            connection.close()
        listener.close()
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=5)


binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='openmcx-sip-tls-') as directory:
    subprocess.run(
        [
            'openssl',
            'req',
            '-x509',
            '-newkey',
            'rsa:2048',
            '-sha256',
            '-nodes',
            '-days',
            '1',
            '-subj',
            '/CN=127.0.0.1',
            '-addext',
            'subjectAltName=IP:127.0.0.1',
            '-keyout',
            directory + '/key.pem',
            '-out',
            directory + '/cert.pem',
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    env = os.environ.copy()
    env['OPENMCX_SIP_TEST_CERT_DIR'] = directory
    if 'tcp' in sys.argv[2:]:
        env['OPENMCX_SIP_TEST_TCP'] = '1'
    else:
        subprocess.run([binary], env=env, check=True, timeout=20)
    run_register_digest(binary, directory, env)
    if 'core' in sys.argv[2:]:
        sys.exit(0)
    for prefix in ('', 'call-'):
        ready = pathlib.Path(directory) / ('ready-' + prefix)
        env['OPENMCX_SIP_TEST_READY_FILE'] = str(ready)
        server_env = env.copy()
        server_env['OPENMCX_SIP_TEST_ROLE'] = prefix + 'server'
        server = subprocess.Popen([binary], env=server_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists():
                if server.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('SIP test server did not start')
                time.sleep(0.02)
            client_env = env.copy()
            client_env['OPENMCX_SIP_TEST_ROLE'] = prefix + 'client'
            try:
                subprocess.run([binary], env=client_env, check=True, timeout=20)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # The server's own checks explain most client failures: show them too.
                server.terminate()
                print(server.communicate(timeout=10)[0], end='')
                raise
            output, _ = server.communicate(timeout=10)
            print(output, end='')
            if server.returncode:
                raise RuntimeError(f'SIP server regression exited {server.returncode}')
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
    run_uas_bye_auth(binary, directory, env)
    failure_env = env.copy()
    failure_env['OPENMCX_SIP_TEST_ROLE'] = 'transaction-failure'
    subprocess.run([binary], env=failure_env, check=True, timeout=15)
