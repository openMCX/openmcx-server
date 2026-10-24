#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Run the IMS AKA UE of the SIP engine against a raw P-CSCF/S-CSCF written here, over real IPsec ESP.

Usage: run_ims_aka.py TEST_IMS_AKA_SIP_BINARY. Needs CAP_NET_ADMIN in its own network namespace, with IPsec allowed
on the loopback interface, which Linux disables by default (disable_xfrm and disable_policy of lo), for example:

  docker run --rm --user 0 --cap-add NET_ADMIN --network none --sysctl net.ipv4.conf.lo.disable_xfrm=0 \
      --sysctl net.ipv4.conf.lo.disable_policy=0 ... python3 tests/run_ims_aka.py build/test_ims_aka_sip

The UE (127.0.0.1) installs its SAs over XFRM and this P-CSCF (127.0.0.2) adds the policies of its own outbound
direction with "ip xfrm" (both ends share one SAD). Without CAP_NET_ADMIN or with IPsec disabled on lo it prints
"skipped" and exits 0.

Scenarios: (1) the initial registration: the unprotected REGISTER (Security-Client, sec-agree, empty-nonce
Authorization, Via and Contact on port 5060), the 401 with an AKAv2-SHA-256 and an AKAv1-MD5 challenge and a
Security-Server preferring hmac-md5-96, the protected REGISTER from port_uc to port_ps (same Call-ID, Security-Verify,
AKAv2-SHA-256 response, Via and Contact port_us), the 200 with Service-Route; then a MESSAGE of the UE with the
preloaded Route, a MESSAGE of the P-CSCF from port_pc to port_us, an unprotected MESSAGE that the UE must not answer,
ESP counters, and the deregistration that removes every SA. (2) a restarted UE with the same SQN file and a replayed
SQN: AUTS, resynchronisation, AKAv1-MD5 this time, registration; then a refresh over the set, a new challenge,
a new set (new port_uc and port_pc) taking over, and the old set deleted 32 s after the first P-CSCF message on it. (3) a wrong key: MAC failure, empty response, 403,
no SA left.

Specifications: TS 24.229 V19.7.0 (Rel-19) clauses 5.1.1.2, 5.1.1.5, 5.1.1.6 and 5.1.2A.1, TS 33.203 V19.1.0
(Rel-19) clauses 7.1 to 7.4 and annexes H and I, TS 33.102 V19.1.0 clause 6.3, RFC 3310, RFC 3329, RFC 4169,
RFC 2617, RFC 7616.
"""

import base64
import hashlib
import hmac
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

UE, PCSCF = "127.0.0.1", "127.0.0.2"
PORT_US = 31900
PORT_PC, PORT_PS = 5101, 6101
SPI_PC, SPI_PS = 7001, 7002
K = "465b5ce8b199b49faa5f0a2ee238a6bc"
OPC = "cd63cb71954a9f4e48a5994e37a02baf"
REALM = "example.org"


# ------------------------------------------------------------------------------
def has_net_admin():
    """Whether this process has CAP_NET_ADMIN (bit 12 of CapEff)."""
    with open("/proc/self/status") as status:
        for line in status:
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) & (1 << 12))
    return False


# ------------------------------------------------------------------------------
class SipWire:
    """A minimal SIP peer on one connected socket: reads and writes whole SIP messages."""

    # ------------------------------------------------------------------------------
    def __init__(self, connection, timeout=10):
        """Wrap the connection."""
        self.connection = connection
        self.buffer = b""
        self.connection.settimeout(timeout)

    # ------------------------------------------------------------------------------
    def receive(self):
        """One SIP message: (start line, header fields by lower-case name, each a list of values, body)."""
        while b"\r\n\r\n" not in self.buffer:
            block = self.connection.recv(65536)
            if not block:
                raise AssertionError("SIP peer closed before a complete message")
            self.buffer += block
        header, rest = self.buffer.split(b"\r\n\r\n", 1)
        lines = header.decode().split("\r\n")
        fields = {}
        for line in lines[1:]:
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
        size = int(fields.get("content-length", ["0"])[0])
        while len(rest) < size:
            rest += self.connection.recv(65536)
        self.buffer = rest[size:]
        return lines[0], fields, rest[:size].decode()

    # ------------------------------------------------------------------------------
    def send(self, text):
        """Send one SIP message (CRLF line ends, Content-Length added)."""
        head, _, body = text.partition("\n\n")
        message = (
            "\r\n".join(head.split("\n"))
            + f"\r\nContent-Length: {len(body)}\r\n\r\n"
            + body
        )
        self.connection.sendall(message.encode())


# ------------------------------------------------------------------------------
def response_to(request, code, reason, extra=""):
    """A response with Via, From, To (tagged), Call-ID and CSeq of the request (RFC 3261 section 8.2.6.2)."""
    fields = request[1]
    to = fields["to"][0] + ("" if ";tag=" in fields["to"][0] else ";tag=pcscf")
    vias = "".join(f"Via: {via}\n" for via in fields["via"])
    head = (
        f"SIP/2.0 {code} {reason}\n{vias}From: {fields['from'][0]}\nTo: {to}\nCall-ID: {fields['call-id'][0]}\n"
        f"CSeq: {fields['cseq'][0]}\n{extra}"
    )
    return head.rstrip("\n") + "\n\n"


# ------------------------------------------------------------------------------
def parameters(value):
    """The name=value parameters of a header field value (quotes removed)."""
    return {
        name.lower(): quoted if quoted else plain
        for name, quoted, plain in re.findall(
            r'([\w-]+)\s*=\s*(?:"([^"]*)"|([^\s,;]+))', value
        )
    }


# ------------------------------------------------------------------------------
def vector(binary, k, sqn, rand):
    """AUTN, XRES, CK, IK of the vector from the program's network role."""
    out = subprocess.run(
        [binary, "vector", k, OPC, rand.hex(), sqn, "8000"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    return [bytes.fromhex(value) for value in out]


# ------------------------------------------------------------------------------
def digest(algorithm, password, nonce, fields, method="REGISTER", uri=f"sip:{REALM}"):
    """The request-digest of RFC 2617 (MD5) or RFC 7616 (SHA-256) with the Authorization's qop, nc and cnonce."""
    h = (
        (lambda data: hashlib.md5(data).hexdigest())
        if algorithm == "AKAv1-MD5"
        else (lambda data: hashlib.sha256(data).hexdigest())
    )
    ha1 = h(b"alice@example.org:" + REALM.encode() + b":" + password)
    ha2 = h(f"{method}:{uri}".encode())
    return h(f"{ha1}:{nonce}:{fields['nc']}:{fields['cnonce']}:auth:{ha2}".encode())


# ------------------------------------------------------------------------------
def xfrm(*arguments):
    """Run "ip xfrm" with the arguments; returns its output."""
    return subprocess.run(
        ["ip", "xfrm", *arguments], check=True, capture_output=True, text=True
    ).stdout


# ------------------------------------------------------------------------------
def pcscf_policies(client, add=True, port_ps=PORT_PS, port_pc=PORT_PC):
    """The P-CSCF's outbound policies towards the UE (port_ps to port_uc with spi_uc, port_pc to port_us with
    spi_us), on the SAs the UE installed; or their removal."""
    for sport, dport, spi in (
        (port_ps, client["port-c"], client["spi-c"]),
        (port_pc, PORT_US, client["spi-s"]),
    ):
        selector = [
            "src",
            f"{PCSCF}/32",
            "dst",
            f"{UE}/32",
            "proto",
            "tcp",
            "sport",
            str(sport),
            "dport",
            str(dport),
            "dir",
            "out",
        ]
        if add:
            xfrm(
                "policy",
                "add",
                *selector,
                "tmpl",
                "src",
                PCSCF,
                "dst",
                UE,
                "proto",
                "esp",
                "spi",
                str(spi),
                "reqid",
                str(spi),
                "mode",
                "transport",
            )
        else:
            subprocess.run(
                ["ip", "xfrm", "policy", "delete", *selector],
                capture_output=True,
                check=False,
            )


# ------------------------------------------------------------------------------
def check(condition, what):
    """Fail the test with what when the condition does not hold."""
    if not condition:
        raise AssertionError(what)


# ------------------------------------------------------------------------------
def challenge(wire, request, binary, sqn, rand, server, k=K):
    """Send the 401 of TS 37.579-1 table 5.5.2.19.7-1 for the vector; returns (nonce, XRES, CK, IK)."""
    autn, res, ck, ik = vector(binary, k, sqn, rand)
    nonce = base64.b64encode(rand + autn).decode()
    wire.send(
        response_to(
            request,
            401,
            "Unauthorized",
            f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=AKAv2-SHA-256, '
            f'qop="auth"\n'
            f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=AKAv1-MD5, '
            f'qop="auth"\n'
            f"Security-Server: {server}",
        )
    )
    return nonce, res, ck, ik


# ------------------------------------------------------------------------------
def start_ue(binary, sqn_file, k=K):
    """Start the UE role; returns the process."""
    env = dict(os.environ, MCX_LOG=os.environ.get("MCX_LOG", "info"))
    return subprocess.Popen(
        [binary, "ue", sqn_file, k, OPC],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )


# ------------------------------------------------------------------------------
def stop_ue(process):
    """End the UE if it still runs and print what it wrote that was not read yet."""
    if process.poll() is None:
        process.kill()
    rest = process.stdout.read()
    if rest:
        print("\n".join("ue: " + line for line in rest.splitlines()))


# ------------------------------------------------------------------------------
def accept_initial(listener):
    """The unprotected REGISTER: (wire, request, Security-Client parameters) after its checks."""
    connection, _ = listener.accept()
    wire = SipWire(connection)
    request = wire.receive()
    fields = request[1]
    check(
        request[0] == f"REGISTER sip:{REALM} SIP/2.0", "Request-URI is the home domain"
    )
    check("route" not in fields, "no Route on REGISTER (TS 37.579-1 table 5.5.2.13-1)")
    check(
        fields["require"] == ["sec-agree"] and fields["proxy-require"] == ["sec-agree"],
        "sec-agree required",
    )
    check("path" in fields["supported"][0], "Supported path")
    check(
        f"{UE}:5060" in fields["via"][0] and "TCP" in fields["via"][0],
        "Via sent-by UE:5060 over TCP",
    )
    check(
        f"@{UE}:5060;transport=tcp" in fields["contact"][0],
        "Contact on the unprotected port",
    )
    authorization = parameters(fields["authorization"][0])
    check(
        authorization["username"] == "alice@example.org"
        and authorization["realm"] == REALM
        and authorization["uri"] == f"sip:{REALM}"
        and 'nonce=""' in fields["authorization"][0]
        and 'response=""' in fields["authorization"][0],
        "initial Authorization (TS 24.229 clause 5.1.1.2.2 a)",
    )
    check(
        fields["security-client"][0].startswith(
            "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;"
        ),
        "Security-Client",
    )
    client = {
        name: int(value)
        for name, value in parameters(fields["security-client"][0]).items()
        if name in ("spi-c", "spi-s", "port-c", "port-s")
    }
    check(
        client["port-s"] == PORT_US and client["port-c"] not in (5060, 5061, PORT_US),
        "protected ports",
    )
    return wire, request, client


# ------------------------------------------------------------------------------
def protected_register(protected_listener, initial, client, server):
    """The protected REGISTER from port_uc to port_ps: (wire, request) after the sec-agree checks."""
    connection, peer = protected_listener.accept()
    check(
        peer[1] == client["port-c"],
        f"connection from port_uc {client['port-c']}, not {peer[1]}",
    )
    wire = SipWire(connection)
    request = wire.receive()
    fields = request[1]
    check(
        fields["call-id"] == initial[1]["call-id"],
        "same Call-ID (TS 24.229 clause 5.1.1.5.1 step 4)",
    )
    check(
        fields["security-client"] == initial[1]["security-client"],
        "same Security-Client",
    )
    check(
        fields["security-verify"] == [server], "Security-Verify mirrors Security-Server"
    )
    check(
        f"{UE}:{PORT_US}" in fields["via"][0]
        and f"@{UE}:{PORT_US};transport=tcp" in fields["contact"][0],
        "Via and Contact on port_us",
    )
    return wire, request


# ------------------------------------------------------------------------------
def wait_line(process, prefix, seconds=15):
    """The next line of the UE that starts with prefix (other lines are printed)."""
    end = time.time() + seconds
    while time.time() < end:
        line = process.stdout.readline()
        if not line:
            break
        if line.startswith(prefix):
            return line.strip()
        print("ue:", line.rstrip())
    raise AssertionError(f"UE did not print {prefix!r}")


# ------------------------------------------------------------------------------
def scenario_register(binary, listener, protected_listener, sqn_file):
    """Scenario 1 (see the module text)."""
    process = start_ue(binary, sqn_file)
    try:
        wire, request, client = accept_initial(listener)
        server = (
            f"ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=aes-cbc;spi-c=9001;spi-s=9002;port-c=5102;port-s=6102, "
            f"ipsec-3gpp;q=0.7;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c={SPI_PC};spi-s={SPI_PS};"
            f"port-c={PORT_PC};port-s={PORT_PS}"
        )
        rand = os.urandom(16)
        nonce, res, ck, ik = challenge(
            wire, request, binary, "000000000020", rand, server
        )
        pcscf_policies(client)
        protected, second = protected_register(
            protected_listener, request, client, server
        )
        authorization = parameters(second[1]["authorization"][0])
        check(
            authorization["algorithm"] == "AKAv2-SHA-256",
            "the topmost supported challenge is answered",
        )
        password = base64.b64encode(
            hmac.new(
                res + ik + ck, b"http-digest-akav2-password", hashlib.sha256
            ).digest()
        )
        check(
            authorization["nonce"] == nonce
            and authorization["qop"] == "auth"
            and authorization["nc"] == "00000001",
            "nonce, qop, nc",
        )
        check(
            authorization["response"]
            == digest("AKAv2-SHA-256", password, nonce, authorization),
            "AKAv2-SHA-256 response (RFC 4169)",
        )
        expires = second[1]["expires"][0]
        protected.send(
            response_to(
                second,
                200,
                "OK",
                f"Contact: {second[1]['contact'][0]};expires={expires}\n"
                f"Service-Route: <sip:orig@scscf.{REALM};lr>\n"
                f"P-Associated-URI: <sip:alice@{REALM}>",
            )
        )
        check(
            "hmac-sha-1-96 aes-cbc" in wait_line(process, "sa "),
            "hmac-sha-1-96 with aes-cbc chosen",
        )
        message = protected.receive()
        check(
            message[0].startswith("MESSAGE sip:bob@example.org"),
            "MESSAGE of the UE on port_uc",
        )
        routes = [
            route.strip() for value in message[1]["route"] for route in value.split(",")
        ]
        check(
            len(routes) == 2
            and routes[0].startswith(f"<sip:{PCSCF}:{PORT_PS};")
            and ";lr" in routes[0]
            and "transport=tcp" in routes[0]
            and routes[1] == f"<sip:orig@scscf.{REALM};lr>",
            f"preloaded Route: P-CSCF port_ps, then Service-Route (TS 24.229 clause 5.1.2A.1.1): {routes}",
        )
        protected.send(response_to(message, 200, "OK"))
        check("200" in wait_line(process, "message answered"), "MESSAGE answered")

        # TS 33.203 clause 7.1 rule 4: an unprotected MESSAGE to the UE is not answered.
        stray = socket.create_connection((UE, 5060), timeout=5)
        stray_wire = SipWire(stray, timeout=1.5)
        stray_wire.send(
            f"MESSAGE sip:alice@{UE}:5060;transport=tcp SIP/2.0\nVia: SIP/2.0/TCP {PCSCF}:40000;"
            f"branch=z9hG4bKstray\nFrom: <sip:mallory@{REALM}>;tag=m\nTo: <sip:alice@{REALM}>\n"
            f"Call-ID: stray\nCSeq: 1 MESSAGE\nMax-Forwards: 70\nContent-Type: text/plain\n\nunprotected"
        )
        try:
            stray_wire.receive()
            raise AssertionError("the UE answered an unprotected MESSAGE")
        except TimeoutError:
            pass
        stray.close()

        # TS 33.203 clause 7.1 TCP case: the P-CSCF connects from port_pc to port_us.
        inbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        inbound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        inbound.bind((PCSCF, PORT_PC))
        inbound.connect((UE, PORT_US))
        inbound_wire = SipWire(inbound)
        inbound_wire.send(
            f"MESSAGE sip:alice@{UE}:{PORT_US};transport=tcp SIP/2.0\nVia: SIP/2.0/TCP "
            f"{PCSCF}:{PORT_PC};branch=z9hG4bKdereg\nFrom: <sip:bob@{REALM}>;tag=b\n"
            f"To: <sip:alice@{REALM}>\nCall-ID: pcscf-message\nCSeq: 1 MESSAGE\nMax-Forwards: 70\n"
            f"Content-Type: text/plain\n\nderegister"
        )
        answer = inbound_wire.receive()
        check(answer[0] == "SIP/2.0 200 OK", "the UE answers on port_us")
        state = subprocess.run(
            [
                "ip",
                "-s",
                "xfrm",
                "state",
                "get",
                "src",
                UE,
                "dst",
                PCSCF,
                "proto",
                "esp",
                "spi",
                str(SPI_PS),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        used = re.search(r"lifetime current:\s+(\d+)\(bytes\)", state)
        check(used and int(used.group(1)) > 0, f"ESP used on spi_ps: {state}")

        # TS 24.229 clause 5.1.1.6.2: the deregistration over the set; its 200 removes every SA.
        dereg = protected.receive()
        check(
            dereg[0].startswith("REGISTER") and dereg[1]["expires"] == ["0"],
            "deregistration",
        )
        check(
            dereg[1]["security-verify"] == [server]
            and parameters(dereg[1]["authorization"][0])["response"]
            == authorization["response"],
            "deregistration Security-Verify and last response (clause 5.1.1.6.2)",
        )
        protected.send(
            response_to(
                dereg, 200, "OK", f"Contact: {dereg[1]['contact'][0]};expires=0"
            )
        )
        wait_line(process, "deregistered")
        check(process.wait(10) == 0, "UE exit")
        check(
            xfrm("state", "list").strip() == "", "every SA removed after deregistration"
        )
        pcscf_policies(client, add=False)
        inbound.close()
    finally:
        stop_ue(process)


# ------------------------------------------------------------------------------
def scenario_resync(binary, listener, protected_listener, sqn_file):
    """Scenario 2: a replayed SQN after a restart: AUTS, then a fresh vector; AKAv1-MD5 only this time."""
    process = start_ue(binary, sqn_file)
    try:
        wire, request, client = accept_initial(listener)
        server = (
            f"ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c={SPI_PC};spi-s={SPI_PS};port-c={PORT_PC};"
            f"port-s={PORT_PS}"
        )
        rand = os.urandom(16)
        autn, _, _, _ = vector(binary, K, "000000000020", rand)
        nonce = base64.b64encode(rand + autn).decode()
        wire.send(
            response_to(
                request,
                401,
                "Unauthorized",
                f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=AKAv1-MD5, '
                f'qop="auth"\nSecurity-Server: {server}',
            )
        )
        again = wire.receive()
        authorization = parameters(again[1]["authorization"][0])
        check(
            "auts" in authorization and 'response=""' in again[1]["authorization"][0],
            "auts (clause 5.1.1.5.3)",
        )
        check(
            "security-verify" not in again[1]
            and again[1]["security-client"] != request[1]["security-client"],
            "new Security-Client, unprotected",
        )
        auts = base64.b64decode(authorization["auts"])
        sqn_ms = subprocess.run(
            [binary, "auts", K, OPC, rand.hex(), auts.hex()],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        check(sqn_ms == "000000000020", f"SQN_MS from AUTS: {sqn_ms}")
        client = {
            name: int(value)
            for name, value in parameters(again[1]["security-client"][0]).items()
            if name in ("spi-c", "spi-s", "port-c", "port-s")
        }
        rand = os.urandom(16)
        autn, res, _ck, _ik = vector(binary, K, "000000000040", rand)
        nonce = base64.b64encode(rand + autn).decode()
        wire.send(
            response_to(
                again,
                401,
                "Unauthorized",
                f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=AKAv1-MD5, '
                f'qop="auth"\nSecurity-Server: {server}',
            )
        )
        pcscf_policies(client)
        protected, second = protected_register(
            protected_listener, again, client, server
        )
        authorization = parameters(second[1]["authorization"][0])
        check(
            authorization["algorithm"] == "AKAv1-MD5"
            and authorization["response"]
            == digest("AKAv1-MD5", res, nonce, authorization),
            "AKAv1-MD5 response with RES as the password (RFC 3310)",
        )
        # A registration of 4 s: the UE refreshes it after 2 s (TS 24.229 clause 5.1.1.4.1, half way).
        protected.send(
            response_to(
                second, 200, "OK", f"Contact: {second[1]['contact'][0]};expires=4"
            )
        )
        wait_line(process, "sa ")
        message = protected.receive()
        protected.send(response_to(message, 200, "OK"))
        reregister_new_set(
            binary, process, protected, second, client, server, authorization
        )
        process.kill()
        process.wait(5)
        pcscf_policies(client, add=False)
        subprocess.run(["ip", "xfrm", "state", "flush"], check=True)
        subprocess.run(["ip", "xfrm", "policy", "flush"], check=True)
    finally:
        stop_ue(process)


# ------------------------------------------------------------------------------
def reregister_new_set(
    binary, process, protected, second, client, server, authorization
):
    """TS 24.229 clause 5.1.1.4.2 and TS 33.203 clause 7.4: the refresh goes over the set in use (Security-Verify of
    the last authentication, its response, a new Security-Client); a new challenge makes a new set with new port_uc
    and port_pc, the same port_us; the old set goes 32 s after the first message of the P-CSCF on the new one."""
    refresh = protected.receive()
    fields = refresh[1]
    check(
        refresh[0].startswith("REGISTER") and fields["call-id"] == second[1]["call-id"],
        "refresh on the set",
    )
    check(
        fields["security-verify"] == [server],
        "refresh Security-Verify (clause 5.1.1.4.2 e)",
    )
    check(
        parameters(fields["authorization"][0])["response"] == authorization["response"],
        "refresh repeats the last response (clause 5.1.1.4.2 a)",
    )
    client2 = {
        name: int(value)
        for name, value in parameters(fields["security-client"][0]).items()
        if name in ("spi-c", "spi-s", "port-c", "port-s")
    }
    check(
        client2["port-s"] == PORT_US
        and client2["port-c"] != client["port-c"]
        and client2["spi-c"] not in (client["spi-c"], client["spi-s"]),
        "new port_uc and SPIs, same port_us",
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((PCSCF, 6103))
    listener.listen(1)
    listener.settimeout(15)
    server2 = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=7003;spi-s=7004;port-c=5103;port-s=6103"
    challenge(protected, refresh, binary, "000000000060", os.urandom(16), server2)
    pcscf_policies(client2, port_ps=6103, port_pc=5103)
    connection, peer = listener.accept()
    check(peer[1] == client2["port-c"], "the new set connects from the new port_uc")
    protected2 = SipWire(connection)
    third = protected2.receive()
    check(
        third[1]["security-verify"] == [server2]
        and third[1]["call-id"] == second[1]["call-id"],
        "protected REGISTER of the new set",
    )
    protected2.send(
        response_to(third, 200, "OK", f"Contact: {third[1]['contact'][0]};expires=600")
    )
    check("ps 6103" in wait_line(process, "sa "), "the new set is in use")
    message = protected2.receive()
    check(
        message[0].startswith("MESSAGE") and "6103" in message[1]["route"][0],
        "requests move to the new set",
    )
    protected2.send(response_to(message, 200, "OK"))
    check(
        len(re.findall(r"^src ", xfrm("state", "list"), re.MULTILINE)) == 8,
        "old and new sets meanwhile",
    )
    inbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    inbound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    inbound.bind((PCSCF, 5103))
    inbound.connect((UE, PORT_US))
    inbound_wire = SipWire(inbound)
    inbound_wire.send(
        f"MESSAGE sip:alice@{UE}:{PORT_US};transport=tcp SIP/2.0\nVia: SIP/2.0/TCP {PCSCF}:5103;"
        f"branch=z9hG4bKnewset\nFrom: <sip:bob@{REALM}>;tag=b\nTo: <sip:alice@{REALM}>\n"
        f"Call-ID: new-set\nCSeq: 1 MESSAGE\nMax-Forwards: 70\nContent-Type: text/plain\n\nnew set"
    )
    check(
        inbound_wire.receive()[0] == "SIP/2.0 200 OK",
        "P-CSCF request on the new set answered",
    )
    time.sleep(34)
    check(
        len(re.findall(r"^src ", xfrm("state", "list"), re.MULTILINE)) == 4,
        "old set deleted (clause 7.4.1a)",
    )
    pcscf_policies(client2, add=False, port_ps=6103, port_pc=5103)
    inbound.close()
    listener.close()


# ------------------------------------------------------------------------------
def scenario_mac_failure(binary, listener, sqn_file):
    """Scenario 3: a challenge made with another K: no SA, an empty response without auts, then 403."""
    process = start_ue(binary, sqn_file)
    try:
        wire, request, _ = accept_initial(listener)
        rand = os.urandom(16)
        challenge(
            wire,
            request,
            binary,
            "000000000060",
            rand,
            f"ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c={PORT_PC};port-s={PORT_PS}",
            k="00112233445566778899aabbccddeeff",
        )
        again = wire.receive()
        check(
            'response=""' in again[1]["authorization"][0]
            and "auts" not in again[1]["authorization"][0],
            "MAC failure: empty response, no auts (clause 5.1.1.5.3)",
        )
        check(xfrm("state", "list").strip() == "", "no temporary SA on a MAC failure")
        wire.send(response_to(again, 403, "Forbidden"))
        check("403" in wait_line(process, "registered"), "registration refused")
        check(process.wait(10) == 3, "UE exit on refusal")
    finally:
        stop_ue(process)


# ------------------------------------------------------------------------------
def main():
    """Run the three scenarios."""
    if not has_net_admin():
        print("ims_aka_sip: no CAP_NET_ADMIN, skipped")
        return 0
    for name in ("disable_xfrm", "disable_policy"):
        with open(f"/proc/sys/net/ipv4/conf/lo/{name}") as setting:
            if setting.read().strip() != "0":
                print(
                    f"ims_aka_sip: net.ipv4.conf.lo.{name} is not 0 (no ESP on loopback), skipped"
                )
                return 0
    binary = sys.argv[1]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((PCSCF, 5060))
    listener.listen(4)
    listener.settimeout(15)
    protected_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    protected_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    protected_listener.bind((PCSCF, PORT_PS))
    protected_listener.listen(4)
    protected_listener.settimeout(15)
    with tempfile.TemporaryDirectory() as directory:
        sqn_file = os.path.join(directory, "isim-sqn.json")
        scenario_register(binary, listener, protected_listener, sqn_file)
        print(
            "ims_aka_sip: registration, protected requests, filter and deregistration ok"
        )
        scenario_resync(binary, listener, protected_listener, sqn_file)
        print("ims_aka_sip: resynchronisation, re-registration with a new set ok")
        scenario_mac_failure(binary, listener, sqn_file)
        print("ims_aka_sip: MAC failure ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
