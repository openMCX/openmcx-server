#!/usr/bin/env python3
"""Wire-level authorization probes; run inside the isolated MCPTT Docker network.

SIP: REGISTER and PUBLISH must be challenged and a wrong digest password refused (RFC 3261 section 22), a PUBLISH whose
From does not match the authenticated identity is refused, a service authorisation PUBLISH with an invalid access token
is answered 403 (TS 24.379 clause 7.3.3 step 6), a forged in-dialog BYE must authenticate, and with --peer-config a
CANCEL carrying another connection's transaction identifiers is refused (RFC 3261 section 9.2). HTTP: the CMS requires a
bearer access token (TS 33.180 annex B.10), its internal route is hidden, and the IdMS authorization endpoint accepts a
PKCE request (TS 33.180 annex B.4.2.2) but refuses a wrong password.

Example: python3 sip_negative.py --config /config/client-a.json
The temporary REGISTER Contact uses Expires: 0 and never removes another binding.
No credential, token, SIP payload or digest is written to the result artifact.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
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
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape


# ------------------------------------------------------------------------------
class SipProbe:
    """A raw SIP client on its own TCP or TLS connection to the SIP core, with the client certificate of cfg."""

    # ------------------------------------------------------------------------------
    def __init__(self, cfg, disable_tls=False):
        """Connect to the SIP core named in cfg (TLS on 5061 unless disable_tls)."""
        self.cfg = cfg
        self.transport = "tcp" if disable_tls else "tls"
        self.port = 5060 if disable_tls else 5061
        tls = cfg["tls"]
        context = ssl.create_default_context(cafile=tls["ca_file"])
        context.load_cert_chain(tls["cert_file"], tls["key_file"])
        core = urllib.parse.urlparse(cfg["sip"]["core_uri"].split(";", 1)[0].replace("sip:", "sip://", 1))
        connection = socket.create_connection(
            (core.hostname, self.port if disable_tls else core.port or 5061), timeout=10
        )
        self.sock = connection if disable_tls else context.wrap_socket(connection, server_hostname=core.hostname)
        self.buffer = b""
        self.sequence = 0

    # ------------------------------------------------------------------------------
    def request(self, method, uri, headers=None, body="", identity=None, authorization=None):
        """Send one out-of-dialog request (fresh Contact, Via branch, From tag and Call-ID; headers override or add
        fields) and return the final response code and its headers.
        """
        self.sequence += 1
        identity = identity or self.cfg["sip"]["identity"]
        contact = f"sip:negative-probe-{secrets.token_hex(8)}@{self.cfg['sip']['advertise']}:{self.port};transport={self.transport}"
        fields = [
            f"{method} {uri} SIP/2.0",
            f"Via: SIP/2.0/{self.transport.upper()} {self.cfg['sip']['advertise']}:{self.port};branch=z9hG4bK{secrets.token_hex(12)}",
            f"From: <{identity}>;tag={secrets.token_hex(8)}",
            f"To: <{identity if method == 'REGISTER' else uri}>",
            f"Call-ID: security-{secrets.token_hex(16)}",
            f"CSeq: {self.sequence} {method}",
            "Max-Forwards: 16",
            f"Contact: <{contact}>",
        ]
        if headers:
            for key, value in headers.items():
                existing = next(
                    (
                        index
                        for index, field in enumerate(fields[1:], 1)
                        if field.split(":", 1)[0].lower() == key.lower()
                    ),
                    None,
                )
                if existing is None:
                    fields.append(f"{key}: {value}")
                else:
                    fields[existing] = f"{key}: {value}"
        self.last_request_headers = dict(field.split(": ", 1) for field in fields[1:])
        if authorization:
            fields.append(authorization)
        payload = body.encode()
        self.sock.sendall(("\r\n".join(fields) + f"\r\nContent-Length: {len(payload)}\r\n\r\n").encode() + payload)
        while True:
            while b"\r\n\r\n" not in self.buffer:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise RuntimeError("SIP connection closed before response")
                self.buffer += chunk
            raw, remainder = self.buffer.split(b"\r\n\r\n", 1)
            lines = raw.decode().split("\r\n")
            response_headers = {}
            for line in lines[1:]:
                key, value = line.split(":", 1)
                response_headers[key.lower()] = value.strip()
            length = int(response_headers.get("content-length", "0"))
            while len(remainder) < length:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise RuntimeError("SIP connection closed during response")
                remainder += chunk
            self.buffer = remainder[length:]
            code = int(lines[0].split()[1])
            if code >= 200:
                return code, response_headers

    # ------------------------------------------------------------------------------
    def digest(self, method, uri, challenge, password=None):
        """The Authorization or Proxy-Authorization header field answering the 401 or 407 challenge (RFC 3261 section
        22.4; MD5 or SHA-256, qop=auth when offered), with password or the configured one.
        """
        code, headers = challenge
        name = "www-authenticate" if code == 401 else "proxy-authenticate"
        values = {
            match[0].lower(): match[1] or match[2]
            for match in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', headers[name])
        }
        algorithm = values.get("algorithm", "MD5").upper()
        if algorithm not in ("MD5", "SHA-256"):
            raise RuntimeError("Unsupported digest challenge algorithm")
        digest = lambda value: hashlib.new(algorithm.replace("-", "").lower(), value.encode()).hexdigest()
        username = self.cfg["sip"]["username"]
        password = password if password is not None else self.cfg["sip"]["password"]
        realm, nonce = values["realm"], values["nonce"]
        ha1, ha2 = digest(f"{username}:{realm}:{password}"), digest(f"{method}:{uri}")
        extras = ""
        if "qop" in values:
            if "auth" not in values["qop"].split(","):
                raise RuntimeError("Digest qop=auth not offered")
            cnonce = secrets.token_hex(16)
            answer = digest(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")
            extras = f', qop=auth, nc=00000001, cnonce="{cnonce}"'
        else:
            answer = digest(f"{ha1}:{nonce}:{ha2}")
        if "opaque" in values:
            extras += f', opaque="{values["opaque"]}"'
        field = "Authorization" if code == 401 else "Proxy-Authorization"
        return f'{field}: Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{answer}", algorithm={algorithm}{extras}'


# ------------------------------------------------------------------------------
def main():
    """Run the probes and write the result artifact (check names, statuses and verdicts only)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/config/client-a.json")
    parser.add_argument("--forged-identity")
    parser.add_argument("--peer-config", help="Second TLS client identity for transaction peer-binding probes")
    parser.add_argument("--output", default="/artifacts/integration/security-results.json")
    parser.add_argument("--disable-tls", action="store_true")
    args = parser.parse_args()
    results = {"passed": False, "checks": []}

    # ------------------------------------------------------------------------------
    def check(name, actual, accepted):
        """Record whether actual is one of the accepted statuses."""
        passed = actual in accepted
        results["checks"].append({"name": name, "status": actual, "expected": sorted(accepted), "passed": passed})
        return passed

    try:
        cfg = json.loads(pathlib.Path(args.config).read_text())
        sip = SipProbe(cfg, args.disable_tls)
        domain = cfg["sip"]["identity"].split("@", 1)[1]
        registrar = "sip:" + domain
        options = {"Expires": "0"}
        challenge = sip.request("REGISTER", registrar, options)
        check("sip_register_requires_digest", challenge[0], {401})
        invalid = sip.digest("REGISTER", registrar, challenge, secrets.token_hex(24))
        check(
            "sip_wrong_password_rejected",
            sip.request("REGISTER", registrar, options, authorization=invalid)[0],
            {401, 403},
        )
        challenge = sip.request("REGISTER", registrar, options)
        valid = sip.digest("REGISTER", registrar, challenge)
        check("sip_valid_digest_control", sip.request("REGISTER", registrar, options, authorization=valid)[0], {200})

        service = cfg["mcptt"]["service_uri"]
        bogus = args.forged_identity or f"sip:forged-{secrets.token_hex(6)}@{domain}"
        challenge = sip.request("PUBLISH", service, {"Event": "poc-settings"})
        check("sip_publish_requires_digest", challenge[0], {407})
        valid = sip.digest("PUBLISH", service, challenge)
        check(
            "sip_forged_from_rejected",
            sip.request("PUBLISH", service, {"Event": "poc-settings"}, identity=bogus, authorization=valid)[0],
            {403},
        )

        info = (
            '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params><mcptt-access-token type="Normal"><mcpttString>invalid-security-probe-token</mcpttString></mcptt-access-token><mcptt-client-id type="Normal"><mcpttString>'
            + escape(cfg["mcptt"]["client_id"])
            + '</mcpttString></mcptt-client-id></mcptt-Params></mcpttinfo>'
        )
        settings = (
            '<poc-settings xmlns="urn:oma:params:xml:ns:poc:poc-settings" xmlns:mc="urn:3gpp:mcsSettings:1.0"><entity id="'
            + escape(cfg["mcptt"]["client_id"], {'"': '&quot;'})
            + '"><am-settings><answer-mode>automatic</answer-mode></am-settings><mc:selected-user-profile-index><mc:user-profile-index>0</mc:user-profile-index></mc:selected-user-profile-index><mc:multiplex-support>true</mc:multiplex-support></entity></poc-settings>'
        )
        boundary = "probe-" + secrets.token_hex(12)
        body = f"--{boundary}\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n{info}\r\n--{boundary}\r\nContent-Type: application/poc-settings+xml\r\n\r\n{settings}\r\n--{boundary}--\r\n"
        fields = {
            "Event": "poc-settings",
            "Expires": "4294967295",
            "Content-Type": "multipart/mixed; boundary=" + boundary,
        }
        challenge = sip.request("PUBLISH", service, fields, body)
        valid = sip.digest("PUBLISH", service, challenge)
        check(
            "mcptt_invalid_access_token_rejected",
            sip.request("PUBLISH", service, fields, body, authorization=valid)[0],
            {403},
        )
        core = cfg["sip"]["core_uri"]
        check(
            "sip_dialog_route_requires_authentication",
            sip.request("BYE", service, {"To": f"<{service}>;tag=forged", "Route": f"<{core};lr>"})[0],
            {407},
        )
        if args.peer_config:
            # A malformed INVITE creates a real, harmless failed transaction.
            # Supply its exact public transaction identifiers from a different
            # certificate: TM matching alone must not authorize its CANCEL.
            challenge = sip.request("INVITE", service)
            valid = sip.digest("INVITE", service, challenge)
            failed = sip.request("INVITE", service, authorization=valid)
            check("sip_transaction_probe_failed_invite", failed[0], {400, 403, 415, 488})
            transaction = {name: sip.last_request_headers[name] for name in ("Via", "From", "To", "Call-ID", "CSeq")}
            transaction["CSeq"] = transaction["CSeq"].split()[0] + " CANCEL"
            peer = SipProbe(json.loads(pathlib.Path(args.peer_config).read_text()), args.disable_tls)
            check("sip_cross_peer_cancel_rejected", peer.request("CANCEL", service, transaction)[0], {403})
            peer.sock.close()
            check("sip_same_peer_cancel_control", sip.request("CANCEL", service, transaction)[0], {200})
        sip.sock.close()

        context = ssl.create_default_context(cafile=cfg["tls"]["ca_file"])

        # ------------------------------------------------------------------------------
        def http(method, url, data=None):
            """An HTTPS request trusting the configured CA: the status and body, also for an HTTP error."""
            encoded = urllib.parse.urlencode(data).encode() if data else None
            request = urllib.request.Request(url, data=encoded, method=method)
            try:
                with urllib.request.urlopen(request, context=context, timeout=10) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as error:
                return error.code, error.read()

        cms = cfg["endpoints"]["cms"]
        user_id = urllib.parse.quote(cfg["mcptt"]["user_id"], safe="")
        check(
            "cms_requires_bearer_token",
            http("GET", cms + "/xcap-root/3gpp.mcptt.user-profile/users/" + user_id + "/index")[0],
            {401},
        )
        check("proxy_internal_cms_route_hidden", http("GET", cms + "/internal/user?mcptt_id=" + user_id)[0], {404})
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        oauth = cfg["oauth"]
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": oauth["client_id"],
                "redirect_uri": oauth["redirect_uri"],
                "scope": "openid",
                "state": secrets.token_hex(16),
                "nonce": secrets.token_hex(16),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        code, raw = http("GET", oauth["issuer"] + "/authorize?" + query)
        check("idms_authorization_request_control", code, {200})
        request_id = json.loads(raw)["request_id"]
        code, _ = http(
            "POST",
            oauth["issuer"] + "/login",
            {"request_id": request_id, "username": oauth["username"], "password": secrets.token_hex(24)},
        )
        check("idms_wrong_password_rejected", code, {401})
        results["passed"] = all(item["passed"] for item in results["checks"])
    except Exception as error:
        # Exception class only: remote response bodies can contain sensitive data.
        results["error_type"] = type(error).__name__
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results))
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
