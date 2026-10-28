#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""An MC UE without a SIP listener (RFC 5626 SIP Outbound); runs inside a client container.

It exercises the SIP core's flow routing (RFC 5626 section 4.2 registrations with
+sip.instance and reg-id) under the MCPTT procedures of TS 24.379 clause 7.2.2 (SIP PUBLISH
request for service authorisation and MCPTT service settings) and clause 9.2.1.3
(affiliation status determination procedure), after an IdMS login per TS 24.482
clause 6.2.1 and TS 33.180 annex B.4.2 (native MCX client, authorization code with PKCE).

Specifications: TS 24.379 V19.7.0, TS 24.482 V19.1.0, TS 33.180 V19.4.0 (Rel-19); RFC 5626.

Example: python3 outbound_flow_client.py --config /config/client-b.json --output /artifacts/outbound-flow
It opens one connection (the flow) to the SIP core and never accepts one. It registers
over the flow with +sip.instance, reg-id and ob, and names itself with an unresolvable
.invalid host in Via and Contact, as the Android client does. Then:

1. it is authorised for MCPTT (IdMS login, PUBLISH poc-settings) and subscribes to its
   affiliation status: the MCPTT server's NOTIFY is an in-dialog request, which reaches
   it only if the core routes the aliased remote target over the flow;
2. it answers the next INVITE (a private call to it, started by the scenario) with 486;
   the INVITE is an initial request to its AoR, routed by the registration;
3. it closes the flow and listens on the flow's former address and port until the
   scenario is done. A core that dialled the registration would connect there.

With --query it only asks the registrar for the user's bindings (a REGISTER without
Contact) and prints them: the scenario reads a listening client's binding this way.

Its progress goes to <output>/status.json, which the scenario reads; <output>/stop ends
step 3. No credential, token or digest is written.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

COMPACT = {
    "v": "Via",
    "f": "From",
    "t": "To",
    "i": "Call-ID",
    "m": "Contact",
    "l": "Content-Length",
    "c": "Content-Type",
    "o": "Event",
    "k": "Supported",
}


# ------------------------------------------------------------------------------
class Message:
    """A SIP request or response read from the flow, compact header names expanded."""

    # ------------------------------------------------------------------------------
    def __init__(self, raw, body):
        """Parse the start line and headers (folded lines joined) of raw; keep body."""
        lines = raw.decode(errors="replace").split("\r\n")
        self.start = lines[0]
        self.headers = []
        for line in lines[1:]:
            if line[:1] in (" ", "\t") and self.headers:
                self.headers[-1] = (self.headers[-1][0], self.headers[-1][1] + " " + line.strip())
                continue
            name, value = line.split(":", 1)
            name = COMPACT.get(name.strip().lower(), name.strip())
            self.headers.append((name, value.strip()))
        self.body = body
        self.is_response = self.start.startswith("SIP/2.0 ")
        self.status = int(self.start.split()[1]) if self.is_response else None
        self.method = None if self.is_response else self.start.split()[0]
        self.uri = None if self.is_response else self.start.split()[1]

    # ------------------------------------------------------------------------------
    def all(self, name):
        """Every value of header name, in order."""
        return [value for header, value in self.headers if header.lower() == name.lower()]

    # ------------------------------------------------------------------------------
    def get(self, name, default=""):
        """The first value of header name, or default."""
        found = self.all(name)
        return found[0] if found else default


# ------------------------------------------------------------------------------
class Flow:
    """One outbound connection to the SIP core, never a listener."""

    # ------------------------------------------------------------------------------
    def __init__(self, cfg, disable_tls):
        """Open the flow (TCP, or TLS with the client certificate) to the SIP core."""
        self.cfg = cfg
        self.transport = "tcp" if disable_tls else "tls"
        core = urllib.parse.urlparse(cfg["sip"]["core_uri"].split(";", 1)[0].replace("sip:", "sip://", 1))
        port = 5060 if disable_tls else core.port or 5061
        address = socket.getaddrinfo(core.hostname, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # The flow's address is listened on after the flow closes (step 3); both need
        # SO_REUSEADDR while the closed connection is in TIME_WAIT.
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.settimeout(10)
        raw.connect(address)
        if disable_tls:
            self.sock = raw
        else:
            tls = cfg["tls"]
            context = ssl.create_default_context(cafile=tls["ca_file"])
            context.load_cert_chain(tls["cert_file"], tls["key_file"])
            self.sock = context.wrap_socket(raw, server_hostname=core.hostname)
        self.local = self.sock.getsockname()[:2]
        self.buffer = b""
        # RFC 5626: a name nobody can resolve; the core reaches us over the flow only.
        self.host = secrets.token_hex(5) + ".invalid"
        self.user = cfg["sip"]["identity"].split(":", 1)[1].split("@", 1)[0]
        self.contact = f"sip:{self.user}@{self.host};transport={self.transport};ob"
        self.cseq = 0
        self.received = []  # requests the core sent us: (method, uri)
        self.inbox = []  # answered requests that serve() has not looked at yet
        self.answers = {}  # method -> status we answer with

    # ------------------------------------------------------------------------------
    def read(self, timeout):
        """The next message on the flow, or None on timeout."""
        deadline = time.monotonic() + timeout
        while True:
            self.buffer = self.buffer.lstrip(b"\r\n")  # CRLF keepalive responses
            if b"\r\n\r\n" in self.buffer:
                raw, rest = self.buffer.split(b"\r\n\r\n", 1)
                length = int(re.search(rb"(?im)^(?:content-length|l)\s*:\s*(\d+)", raw).group(1))
                if len(rest) >= length:
                    self.buffer = rest[length:]
                    return Message(raw, rest[:length])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, TimeoutError):
                return None
            if not chunk:
                raise RuntimeError("the SIP core closed the flow")
            self.buffer += chunk

    # ------------------------------------------------------------------------------
    def answer(self, request):
        """Answer a request the core sent over the flow; ACK is not answered."""
        self.received.append({"method": request.method, "uri": request.uri})
        self.inbox.append(request)
        if request.method == "ACK":
            return
        status = self.answers.get(request.method, 200)
        reason = {200: "OK", 486: "Busy Here"}[status]
        to = request.get("To")
        if ";tag=" not in to:
            to += ";tag=" + secrets.token_hex(6)
        lines = (
            [f"SIP/2.0 {status} {reason}"]
            + [f"Via: {via}" for via in request.all("Via")]
            + [
                f"From: {request.get('From')}",
                f"To: {to}",
                f"Call-ID: {request.get('Call-ID')}",
                f"CSeq: {request.get('CSeq')}",
                "Content-Length: 0",
            ]
        )
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    # ------------------------------------------------------------------------------
    def serve(self, until, timeout):
        """Answer requests until one satisfies until(request), within timeout seconds."""
        deadline = time.monotonic() + timeout
        while True:
            while self.inbox:
                message = self.inbox.pop(0)
                if until(message):
                    return message
            if time.monotonic() >= deadline:
                return None
            message = self.read(deadline - time.monotonic())
            if message is None:
                return None
            if not message.is_response:
                self.answer(message)

    # ------------------------------------------------------------------------------
    def request(self, method, uri, headers=(), body=b"", content_type=None, to=None):
        """Send a request (with digest credentials when challenged) and return its final response."""
        call_id = secrets.token_hex(12) + "@" + self.host
        tag = secrets.token_hex(6)
        authorization = None
        for _ in range(2):
            self.cseq += 1
            branch = "z9hG4bK" + secrets.token_hex(10)
            lines = [
                f"{method} {uri} SIP/2.0",
                f"Via: SIP/2.0/{self.transport.upper()} {self.host};branch={branch};rport",
                "Max-Forwards: 70",
                f"From: <{self.cfg['sip']['identity']}>;tag={tag}",
                f"To: <{to or uri}>",
                f"Call-ID: {call_id}",
                f"CSeq: {self.cseq} {method}",
            ]
            lines += [f"{name}: {value}" for name, value in headers]
            if authorization:
                lines.append(authorization)
            if content_type:
                lines.append(f"Content-Type: {content_type}")
            lines.append(f"Content-Length: {len(body)}")
            self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            while True:
                message = self.read(15)
                if message is None:
                    raise RuntimeError(f"{method}: no response")
                if not message.is_response:
                    self.answer(message)
                    continue
                if message.get("Call-ID") != call_id or message.status < 200:
                    continue
                break
            if message.status in (401, 407) and authorization is None:
                authorization = self.digest(method, uri, message)
                continue
            return message
        return message

    # ------------------------------------------------------------------------------
    def digest(self, method, uri, challenge):
        """The Authorization or Proxy-Authorization header answering a digest challenge (RFC 2617)."""
        name = "WWW-Authenticate" if challenge.status == 401 else "Proxy-Authenticate"
        values = {
            match[0].lower(): match[1] or match[2]
            for match in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', challenge.get(name))
        }
        algorithm = values.get("algorithm", "MD5").upper()
        digest = lambda value: hashlib.new(algorithm.replace("-", "").lower(), value.encode()).hexdigest()
        realm, nonce = values["realm"], values["nonce"]
        ha1 = digest(f"{self.cfg['sip']['username']}:{realm}:{self.cfg['sip']['password']}")
        ha2 = digest(f"{method}:{uri}")
        extras = ""
        if "qop" in values:
            cnonce = secrets.token_hex(16)
            answer = digest(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")
            extras = f', qop=auth, nc=00000001, cnonce="{cnonce}"'
        else:
            answer = digest(f"{ha1}:{nonce}:{ha2}")
        if "opaque" in values:
            extras += f', opaque="{values["opaque"]}"'
        field = "Authorization" if challenge.status == 401 else "Proxy-Authorization"
        return (
            f'{field}: Digest username="{self.cfg["sip"]["username"]}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{answer}", algorithm={algorithm}{extras}'
        )


# ------------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand HTTP redirects back to the caller: the IdMS login answers 302 with the code."""

    # ------------------------------------------------------------------------------
    def redirect_request(self, *args):
        """Follow no redirect."""
        return None


# ------------------------------------------------------------------------------
def access_token(cfg):
    """An MCPTT access token from the IdMS (authorization code with PKCE): TS 24.482 clause 6.2.1,
    TS 33.180 annex B.4.2.2 (authentication request) and annex B.4.2.4 (access token request)."""
    oauth = cfg["oauth"]
    context = ssl.create_default_context(cafile=cfg["tls"]["ca_file"])
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect)

    # ------------------------------------------------------------------------------
    def call(method, url, data=None):
        """One HTTP request to the IdMS: (status, headers, body), errors included."""
        request = urllib.request.Request(
            url, data=urllib.parse.urlencode(data).encode() if data else None, method=method
        )
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    verifier, state = secrets.token_urlsafe(48), secrets.token_hex(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": oauth["client_id"],
            "redirect_uri": oauth["redirect_uri"],
            "scope": "openid 3gpp:mc:ptt_service",
            "state": state,
            "nonce": secrets.token_hex(16),
            "code_challenge": challenge,
            # TS 33.180 table B.4.2.2-1: REQUIRED.
            "acr_values": "3gpp:acr:password",
            "code_challenge_method": "S256",
        }
    )
    code, _, body = call("GET", oauth["issuer"] + "/authorize?" + query)
    if code != 200:
        raise RuntimeError(f"IdMS authorize: {code}")
    code, headers, _ = call(
        "POST",
        oauth["issuer"] + "/login",
        {"request_id": json.loads(body)["request_id"], "username": oauth["username"], "password": oauth["password"]},
    )
    location = urllib.parse.urlparse(headers.get("Location", ""))
    params = urllib.parse.parse_qs(location.query)
    if code != 302 or params.get("state") != [state]:
        raise RuntimeError(f"IdMS login: {code}")
    code, _, body = call(
        "POST",
        oauth["issuer"] + "/token",
        {
            "grant_type": "authorization_code",
            "client_id": oauth["client_id"],
            "redirect_uri": oauth["redirect_uri"],
            "code": params["code"][0],
            "code_verifier": verifier,
        },
    )
    if code != 200:
        raise RuntimeError(f"IdMS token: {code}")
    return json.loads(body)["access_token"]


# ------------------------------------------------------------------------------
def multipart(parts):
    """A multipart/mixed body of (content type, text) parts, and its Content-Type."""
    boundary = "flow-" + secrets.token_hex(8)
    body = (
        "".join(f"--{boundary}\r\nContent-Type: {kind}\r\n\r\n{text}\r\n" for kind, text in parts)
        + f"--{boundary}--\r\n"
    )
    return body.encode(), f"multipart/mixed; boundary={boundary}"


# ------------------------------------------------------------------------------
def main():
    """Run steps 1 to 3 (or the --query), publishing progress to <output>/status.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--query", action="store_true", help="print the user's bindings and exit")
    parser.add_argument("--disable-tls", action="store_true")
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    if args.query:
        flow = Flow(cfg, args.disable_tls)
        response = flow.request("REGISTER", "sip:" + cfg["sip"]["identity"].split("@", 1)[1], to=cfg["sip"]["identity"])
        print(json.dumps({"status": response.status, "bindings": response.all("Contact")}))
        return 0 if response.status == 200 else 1
    args.output.mkdir(parents=True, exist_ok=True)
    status = {"phase": "starting", "checks": []}

    # ------------------------------------------------------------------------------
    def publish(phase=None, **values):
        """Update status.json atomically, with the new phase and values."""
        if phase:
            status["phase"] = phase
        status.update(values)
        path = args.output / "status.json"
        path.with_suffix(".tmp").write_text(json.dumps(status, indent=2) + "\n")
        path.with_suffix(".tmp").replace(path)

    # ------------------------------------------------------------------------------
    def check(name, passed, **detail):
        """Record a check in status.json; raise when it failed."""
        status["checks"].append(dict(name=name, passed=bool(passed), **detail))
        publish()
        if not passed:
            raise AssertionError(f"{name}: {detail}")

    try:
        flow = Flow(cfg, args.disable_tls)
        publish("connected", flow=f"{flow.local[0]}:{flow.local[1]}", transport=flow.transport, contact=flow.contact)
        domain = cfg["sip"]["identity"].split("@", 1)[1]
        registrar, identity = "sip:" + domain, cfg["sip"]["identity"]
        # Remove the AoR's other bindings (the stopped listening client's), so that the
        # registration below is the only way to reach this user.
        response = flow.request("REGISTER", registrar, [("Contact", "*"), ("Expires", "0")], to=identity)
        check("previous bindings removed", response.status == 200, status=response.status)
        # The alias parameter is the core's routing state: a client may not supply it.
        forged = f"<{flow.contact};alias=192.0.2.1~5061~3>"
        response = flow.request("REGISTER", registrar, [("Contact", forged), ("Expires", "600")], to=identity)
        check("Contact with an alias parameter refused", response.status == 400, status=response.status)
        instance = cfg["mcptt"]["client_id"]
        contact = f'<{flow.contact}>;+sip.instance="<{instance}>";reg-id=1;+g.3gpp.mcptt'
        response = flow.request(
            "REGISTER",
            registrar,
            [("Contact", contact), ("Supported", "outbound, path"), ("Expires", "600")],
            to=identity,
        )
        bindings = response.all("Contact")
        received = [
            re.search(r';received="([^"]*)"', binding).group(1) for binding in bindings if ";received=" in binding
        ]
        expected = f"sip:{flow.local[0]}:{flow.local[1]};transport={flow.transport}"
        check("registered over the flow", response.status == 200 and len(bindings) == 1, status=response.status)
        # RFC 5626 section 6: reg-id and Supported: outbound, so the registrar answers with Require: outbound.
        required = [tag.strip().lower() for value in response.all("Require") for tag in value.split(",")]
        check("registrar answered with Require: outbound", "outbound" in required, require=response.all("Require"))
        check(
            "binding records the flow as its received address",
            received == [expected],
            received=received,
            expected=expected,
        )

        token = access_token(cfg)
        info = (
            '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params><mcptt-access-token type="Normal"><mcpttString>'
            f'{token}</mcpttString></mcptt-access-token><mcptt-client-id type="Normal"><mcpttString>{instance}'
            '</mcpttString></mcptt-client-id></mcptt-Params></mcpttinfo>'
        )
        settings = (
            '<poc-settings xmlns="urn:oma:params:xml:ns:poc:poc-settings" xmlns:mc="urn:3gpp:mcsSettings:1.0">'
            f'<entity id="{instance}"><am-settings><answer-mode>manual</answer-mode></am-settings>'
            '<mc:selected-user-profile-index><mc:user-profile-index>0</mc:user-profile-index>'
            '</mc:selected-user-profile-index></entity></poc-settings>'
        )
        body, kind = multipart(
            [("application/vnd.3gpp.mcptt-info+xml", info), ("application/poc-settings+xml", settings)]
        )
        psi = cfg["mcptt"]["service_uri"]
        response = flow.request(
            "PUBLISH",
            psi,
            [
                ("Event", "poc-settings"),
                ("Expires", "4294967295"),
                ("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.mcptt"),
            ],
            body,
            kind,
        )
        check("MCPTT service authorised", response.status == 200, status=response.status)

        # Step 1 (TS 24.379 clause 9.2.1.3): the affiliation status NOTIFY is sent inside the SUBSCRIBE dialog, to

        # the Contact below, which the core has aliased to the flow.
        request_uri = (
            '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params><mcptt-request-uri type="Normal">'
            f'<mcpttURI>{cfg["mcptt"]["user_id"]}</mcpttURI></mcptt-request-uri></mcptt-Params></mcpttinfo>'
        )
        body, kind = multipart([("application/vnd.3gpp.mcptt-info+xml", request_uri)])
        response = flow.request(
            "SUBSCRIBE",
            psi,
            [
                ("Event", "presence"),
                ("Accept", "application/pidf+xml"),
                ("Expires", "600"),
                ("Contact", f"<{flow.contact}>;+g.3gpp.mcptt"),
                ("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.mcptt"),
            ],
            body,
            kind,
        )
        check("affiliation status subscribed", response.status == 200, status=response.status)
        notify = flow.serve(lambda message: message.method == "NOTIFY", 15)
        check("in-dialog NOTIFY arrived over the flow", notify is not None)
        check(
            "NOTIFY Request-URI is the Contact without the core's alias",
            notify.uri.startswith(f"sip:{flow.user}@{flow.host};") and ";alias=" not in notify.uri,
            uri=notify.uri,
        )

        # Step 2: an initial request to the AoR, routed by the registration.
        flow.answers["INVITE"] = 486
        publish("waiting-invite")
        invite = flow.serve(lambda message: message.method == "INVITE", args.timeout)
        check("INVITE to the AoR arrived over the flow", invite is not None)
        check(
            "INVITE Request-URI is the registered Contact",
            invite.uri.startswith(f"sip:{flow.user}@{flow.host};") and ";alias=" not in invite.uri,
            uri=invite.uri,
        )
        flow.serve(lambda message: message.method == "ACK" and message.get("Call-ID") == invite.get("Call-ID"), 5)

        # Step 3: close the flow, and listen where a core that dialled the binding would connect.
        address = flow.local
        flow.sock.close()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(address)
        listener.listen(4)
        listener.settimeout(0.2)
        publish("closed", received_requests=flow.received)
        connections = []
        stop = args.output / "stop"
        deadline = time.monotonic() + args.timeout
        while not stop.exists() and time.monotonic() < deadline:
            try:
                peer, source = listener.accept()
                connections.append(f"{source[0]}:{source[1]}")
                peer.close()
            except (socket.timeout, TimeoutError):
                pass
        listener.close()
        check("scenario ended the wait", stop.exists())
        check("no connection to the closed flow's address", not connections, connections=connections)
        publish("done", passed=True)
    except Exception as error:
        publish("failed", passed=False, error=f"{type(error).__name__}: {str(error)[:300]}")
    print(json.dumps(status))
    return 0 if status.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
