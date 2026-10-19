#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Service authorisation limit, log-off and the end of a binding, on the wire; run inside the lab's network with a
client's configuration (service_logoff_scenario.py).

The IdMS binds the access token to the account's MC client ID, which the server checks (TS 24.379 clause 7.3.3 step 6),
so the probe publishes with the token's client ID.

--phase live (the configuration's client is authorised): a log-off (SIP PUBLISH for poc-settings with Expires 0, clause
7.3.5) that names no publication is answered 400 without an entity tag or body (RFC 3903 section 6 step 5) and 412
with another one (section 6 step 3); the same client publishing anew, as a restarted device, is authorised (200,
clause 7.3.3 step 5a), and its log-off is answered 200 with Expires 0 and its entity tag (clause 7.3.5, RFC 3903
section 6 step 6), the same log-off again 412 (the publication and the binding are gone).

--phase other (MCX Admin gave the account a new first client ID while the configuration's client, with the old one, is
authorised): the new client is answered 486 with "164 maximum number of service authorizations reached" (TS 24.379
clause 7.3.3 steps 3a and 3b; the MCData server with "228 ...", TS 24.282 clause 7.3.3).

--phase free, other-free (the configuration's client logged off with its "log-off" command): the token's client is
authorised at once (200), then logs off (200).

Example: python3 service_logoff.py --config /config/client-a.json --phase live --mcdata
No credential, token or SIP payload is written to the result artifact.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), IETF RFC 3903.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape

from sip_negative import SipProbe

WARNINGS = {
    "mcptt": "164 maximum number of service authorizations reached",
    "mcdata": "228 maximum number of service authorizations reached",
}


# ------------------------------------------------------------------------------
def access_token(cfg):
    """An access token of the configuration's user: the authorisation code flow with PKCE (TS 33.180 annex B.4.2)."""
    oauth = cfg["oauth"]
    context = ssl.create_default_context(cafile=cfg["tls"]["ca_file"])

    # ------------------------------------------------------------------------------
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        """The login's 302 carries the code: it is read, not followed."""

        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect)

    # ------------------------------------------------------------------------------
    def call(method, url, data=None):
        request = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode() if data else None,
                                         method=method)
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    query = urllib.parse.urlencode(dict(response_type="code", client_id=oauth["client_id"],
                                        redirect_uri=oauth["redirect_uri"], state="s",
                                        # TS 33.180 table B.4.2.2-1: the MCPTT and MCData servers check their scope.
                                        scope="openid 3gpp:mc:ptt_service 3gpp:mc:data_service",
                                        nonce=secrets.token_hex(8), code_challenge=challenge,
                                        code_challenge_method="S256"))
    status, _, body = call("GET", oauth["issuer"] + "/authorize?" + query)
    if status != 200:
        raise RuntimeError("authorize")
    status, headers, _ = call("POST", oauth["issuer"] + "/login", dict(
        request_id=json.loads(body)["request_id"], username=oauth["username"], password=oauth["password"]))
    if status != 302:
        raise RuntimeError("login")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers["Location"]).query)["code"][0]
    status, _, body = call("POST", oauth["issuer"] + "/token", dict(
        grant_type="authorization_code", code=code, client_id=oauth["client_id"],
        redirect_uri=oauth["redirect_uri"], code_verifier=verifier))
    if status != 200:
        raise RuntimeError("token")
    return json.loads(body)["access_token"]


# ------------------------------------------------------------------------------
class Service:
    """The poc-settings publications of one MC service (mcptt or mcdata) of the configuration's user."""

    # ------------------------------------------------------------------------------
    def __init__(self, sip, cfg, name, token):
        self.sip, self.cfg, self.name, self.token = sip, cfg, name, token
        self.uri = cfg[name]["service_uri"]

    # ------------------------------------------------------------------------------
    def send(self, fields, body=""):
        """One PUBLISH for poc-settings to the service's PSI, answering the SIP core's digest challenge."""
        fields = {"Event": "poc-settings", **fields}
        challenge = self.sip.request("PUBLISH", self.uri, fields, body)
        if challenge[0] not in (401, 407):
            return challenge
        return self.sip.request("PUBLISH", self.uri, fields, body,
                                authorization=self.sip.digest("PUBLISH", self.uri, challenge))

    # ------------------------------------------------------------------------------
    def authorise(self, client_id):
        """TS 24.379 clause 7.2.2 (TS 24.282 clause 7.2.2): service authorisation by an initial publication (RFC 3903
        section 4.1) with the access token and the client ID; the final status and header fields."""
        root, prefix, string, namespace = (
            ("mcdatainfo", "mcdata", "mcdataString", "urn:3gpp:ns:mcdataInfo:1.0") if self.name == "mcdata"
            else ("mcpttinfo", "mcptt", "mcpttString", "urn:3gpp:ns:mcpttInfo:1.0"))
        info = (f'<{root} xmlns="{namespace}"><{prefix}-Params><{prefix}-access-token type="Normal"><{string}>'
                f"{escape(self.token)}</{string}></{prefix}-access-token><{prefix}-client-id type=\"Normal\"><{string}>"
                f"{escape(client_id)}</{string}></{prefix}-client-id></{prefix}-Params></{root}>")
        settings = ('<poc-settings xmlns="urn:oma:params:xml:ns:poc:poc-settings" xmlns:mc="urn:3gpp:mcsSettings:1.0">'
                    f'<entity id="{escape(client_id, {chr(34): "&quot;"})}"><am-settings><answer-mode>automatic'
                    "</answer-mode></am-settings><mc:selected-user-profile-index><mc:user-profile-index>0"
                    "</mc:user-profile-index></mc:selected-user-profile-index></entity></poc-settings>")
        boundary = "logoff-" + secrets.token_hex(12)
        body = (f"--{boundary}\r\nContent-Type: application/vnd.3gpp.{self.name}-info+xml\r\n\r\n{info}\r\n"
                f"--{boundary}\r\nContent-Type: application/poc-settings+xml\r\n\r\n{settings}\r\n--{boundary}--\r\n")
        return self.send({"Expires": "4294967295", "Content-Type": "multipart/mixed; boundary=" + boundary}, body)

    # ------------------------------------------------------------------------------
    def log_off(self, etag=None):
        """TS 24.379 clause 7.2.1A step 4 (TS 24.282 likewise): the removal of the service settings (RFC 3903
        section 4.5), with SIP-If-Match when etag is given; the final status and header fields."""
        return self.send({"Expires": "0", **({"SIP-If-Match": etag} if etag else {})})


# ------------------------------------------------------------------------------
def main():
    """Run the phase's checks and print the result (check names, statuses and verdicts only)."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="/config/client-a.json")
    parser.add_argument("--phase", choices=["live", "other", "free", "other-free"], required=True)
    parser.add_argument("--disable-tls", action="store_true")
    parser.add_argument("--mcdata", action="store_true", help="also check the MCData server")
    args = parser.parse_args()
    results = {"phase": args.phase, "passed": False, "checks": []}

    # ------------------------------------------------------------------------------
    def check(name, actual, accepted):
        passed = actual in accepted
        results["checks"].append({"name": name, "status": actual, "expected": sorted(accepted, key=str),
                                  "passed": passed})
        return passed

    try:
        cfg = json.loads(pathlib.Path(args.config).read_text())
        token = access_token(cfg)
        # The MC client ID the OpenMCX IdMS bound to the token (mc_client_id, the account's first one; client_id is the
        # OAuth client, TS 33.180 table B.2.2.2-1); a server refuses another one in the PUBLISH (TS 24.379 clause
        # 7.3.3 step 6).
        payload = token.split(".")[1]
        client_id = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["mc_client_id"]
        sip = SipProbe(cfg, args.disable_tls)
        for name in ["mcptt"] + (["mcdata"] if args.mcdata else []):
            service = Service(sip, cfg, name, token)
            if args.phase == "live":
                # RFC 3903 section 6: removals that name no publication of the user.
                check(f"{name}_log_off_without_etag_or_body_400", service.log_off()[0], {400})
                check(f"{name}_log_off_unknown_etag_412", service.log_off("no-such-" + secrets.token_hex(6))[0],
                      {412})
                # The same client publishing anew (a restarted device: no SIP-If-Match) is authorised (clause 7.3.3
                # step 5a), then logs off (clause 7.3.5).
                code, headers = service.authorise(client_id)
                check(f"{name}_same_client_initial_publication_200", code, {200})
                etag = headers.get("sip-etag", "")
                code, headers = service.log_off(etag)
                check(f"{name}_log_off_200", code, {200})
                check(f"{name}_log_off_expires_0", headers.get("expires"), {"0"})
                check(f"{name}_log_off_etag", headers.get("sip-etag") == etag and bool(etag), {True})
                check(f"{name}_log_off_again_412", service.log_off(etag)[0], {412})
                continue
            code, headers = service.authorise(client_id)
            if args.phase == "other":
                # Clause 7.3.3 steps 3a and 3b: the configuration's client is authorised with another client ID.
                check(f"{name}_other_client_refused_486", code, {486})
                check(f"{name}_other_client_warning", WARNINGS[name] in headers.get("warning", ""), {True})
                continue
            # free, other-free: the configuration's client logged off (clause 7.3.5): this one is authorised at once,
            # and logs off.
            check(f"{name}_client_after_log_off_200", code, {200})
            check(f"{name}_client_log_off_200", service.log_off(headers.get("sip-etag", "-"))[0], {200})
        sip.sock.close()
        results["passed"] = all(item["passed"] for item in results["checks"])
    except Exception as error:  # noqa: BLE001 - the result records the failure, not remote content
        results["error_type"] = type(error).__name__
        results["error"] = str(error)[:200]
    print(json.dumps(results))
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
