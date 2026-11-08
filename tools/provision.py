#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Create an isolated lab's credentials and configuration without overwriting it.

From config/lab.json (or --input) it writes, into config/generated (or --output): the lab CA and a
TLS certificate per role, the OIDC signing key, site.json for the identity management, group
management and configuration management servers (users with their MC ID, MCPTT ID, MCData ID and
MCVideo ID, the lab group, the service endpoints), the configuration of every MCPTT, MCData and
MCVideo server and of every client, the Diameter peer configuration of MCPTT-2, the SIP database
with digest hashes and the IMS AKA subscriptions, the Kamailio routing of the SIP core and, when a
user is provisioned for IMS AKA ("auth": "aka"), the configuration of the P-CSCF.

Lab provisioning only: the identities follow TS 23.280 clause 8.1, the public service identities
TS 24.282 clause 4.2.1 and TS 24.281 clause 4.2, the MCData configuration TS 24.484 clauses 10.3
and 10.4, the MCPTT UE (instance ID) of every client TS 24.484 clause 8.2.1A, the MCVideo server roles (participating, controlling) TS 24.281 clause 6.3.

Specifications: TS 23.280 V19.10.1, TS 24.281 V19.6.0, TS 24.282 V19.7.0, TS 24.482 V19.1.0,
TS 24.484 V19.6.0, TS 29.228 V19.2.0, TS 33.203 V19.1.0, TS 33.180 V19.4.0 (all Rel-19); TS 33.210;
TS 35.206; RFC 6733, RFC 2617.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
# TS 33.210 clause 6.2.3 (include/mcx/tls_profile.hpp): the SIP core's and P-CSCF's TLS 1.2 suites, ECDHE with AEAD
# only; the groups (no ffdhe) come from the Kamailio image's OpenSSL configuration (docker/Dockerfile.kamailio).
TLS12_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)
# The protected server port of an IMS AKA client (TS 33.203 clause 7.1: not 5060 or 5061).
AKA_PROTECTED_SERVER_PORT = 5064


# The tables of Kamailio's presence and pua modules (schema versions of Kamailio 6.1.4, which the modules check at
# start-up), for the reg event package of the SIP core (RFC 3680, TS 24.229 clause 5.4.2.1; docker/kamailio.cfg):
# the registration state each user's binding publishes, the subscriptions to it and their NOTIFY dialogs.
PRESENCE_TABLES = """\
CREATE TABLE presentity (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL, username VARCHAR(64) NOT NULL, domain VARCHAR(64) NOT NULL, event VARCHAR(64) NOT NULL, etag VARCHAR(128) NOT NULL, expires INT NOT NULL, received_time INT NOT NULL, body BLOB NOT NULL, sender VARCHAR(255) NOT NULL, priority INT DEFAULT 0 NOT NULL, ruid VARCHAR(64), CONSTRAINT presentity_idx UNIQUE (username, domain, event, etag), CONSTRAINT ruid_idx UNIQUE (ruid));
CREATE INDEX presentity_expires ON presentity (expires);
CREATE INDEX account_idx ON presentity (username, domain, event);
CREATE TABLE active_watchers (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL, presentity_uri VARCHAR(255) NOT NULL, watcher_username VARCHAR(64) NOT NULL, watcher_domain VARCHAR(64) NOT NULL, to_user VARCHAR(64) NOT NULL, to_domain VARCHAR(64) NOT NULL, event VARCHAR(64) DEFAULT 'presence' NOT NULL, event_id VARCHAR(64), to_tag VARCHAR(128) NOT NULL, from_tag VARCHAR(128) NOT NULL, callid VARCHAR(255) NOT NULL, local_cseq INT NOT NULL, remote_cseq INT NOT NULL, contact VARCHAR(255) NOT NULL, record_route TEXT, expires INT NOT NULL, status INT DEFAULT 2 NOT NULL, reason VARCHAR(64), version INT DEFAULT 0 NOT NULL, socket_info VARCHAR(64) NOT NULL, local_contact VARCHAR(255) NOT NULL, from_user VARCHAR(64) NOT NULL, from_domain VARCHAR(64) NOT NULL, updated INT NOT NULL, updated_winfo INT NOT NULL, flags INT DEFAULT 0 NOT NULL, user_agent VARCHAR(255) DEFAULT '', CONSTRAINT active_watchers_idx UNIQUE (callid, to_tag, from_tag));
CREATE INDEX active_watchers_expires ON active_watchers (expires);
CREATE INDEX active_watchers_pres ON active_watchers (presentity_uri, event);
CREATE INDEX updated_idx ON active_watchers (updated);
CREATE INDEX updated_winfo_idx ON active_watchers (updated_winfo, presentity_uri);
CREATE TABLE watchers (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL, presentity_uri VARCHAR(255) NOT NULL, watcher_username VARCHAR(64) NOT NULL, watcher_domain VARCHAR(64) NOT NULL, event VARCHAR(64) DEFAULT 'presence' NOT NULL, status INT NOT NULL, reason VARCHAR(64), inserted_time INT NOT NULL, CONSTRAINT watcher_idx UNIQUE (presentity_uri, watcher_username, watcher_domain, event));
CREATE INDEX time_status_idx ON watchers (inserted_time, status);
CREATE TABLE xcap (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL, username VARCHAR(64) NOT NULL, domain VARCHAR(64) NOT NULL, doc MEDIUMBLOB NOT NULL, doc_type INT NOT NULL, etag VARCHAR(128) NOT NULL, source INT NOT NULL, doc_uri VARCHAR(255) NOT NULL, port INT NOT NULL, CONSTRAINT doc_uri_idx UNIQUE (doc_uri));
CREATE INDEX account_doc_type_idx ON xcap (username, domain, doc_type);
CREATE TABLE pua (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY NOT NULL, pres_uri VARCHAR(255) NOT NULL, pres_id VARCHAR(255) NOT NULL, event INT NOT NULL, expires INT NOT NULL, desired_expires INT NOT NULL, flag INT NOT NULL, etag VARCHAR(128) NOT NULL, tuple_id VARCHAR(64), watcher_uri VARCHAR(255) NOT NULL, call_id VARCHAR(255) NOT NULL, to_tag VARCHAR(128) NOT NULL, from_tag VARCHAR(128) NOT NULL, cseq INT NOT NULL, record_route TEXT, contact VARCHAR(255) NOT NULL, remote_contact VARCHAR(255) NOT NULL, version INT NOT NULL, extra_headers TEXT NOT NULL, CONSTRAINT pua_idx UNIQUE (etag, tuple_id, call_id, from_tag));
CREATE INDEX expires_idx ON pua (expires);
CREATE INDEX dialog1_idx ON pua (pres_id, pres_uri);
CREATE INDEX dialog2_idx ON pua (call_id, from_tag);
CREATE INDEX record_idx ON pua (pres_id);
INSERT INTO version(table_name,table_version) VALUES ('presentity',5),('active_watchers',12),('watchers',3),('xcap',4),('pua',7);
"""


# ------------------------------------------------------------------------------
def mcptt_servers(source, key="servers", prefix="mcptt", default="mcptt-server"):
    """MCPTT servers by name, in order: {"role": both|participating|controlling,
    "users": client roles served}. Without "servers", one combined mcptt-server.
    The MCVideo servers are listed the same way under "mcvideo_servers"."""
    entries = source.get(key) or [{"name": default, "role": "both"}]
    servers = {}
    for entry in entries:
        name, role = entry["name"], entry.get("role", "both")
        if (
            not re.fullmatch(prefix + r"-[a-z0-9-]+", name)
            or name in servers
            or role not in ("both", "participating", "controlling")
        ):
            raise ValueError(f"invalid {prefix} server {entry}")
        servers[name] = {"role": role, "users": list(entry.get("users", []))}
    serving = [server_name for server_name, server in servers.items() if server["role"] != "controlling"]
    if not serving or not any(server["role"] != "participating" for server in servers.values()):
        raise ValueError("a lab needs a server serving users and a controlling server")
    assigned = [user_role for server_name in serving for user_role in servers[server_name]["users"]]
    for entry in source["users"]:
        if entry["role"] not in assigned:
            if len(serving) > 1:
                raise ValueError(f"user {entry['role']} is not assigned to a participating server")
            servers[serving[0]]["users"].append(entry["role"])
    return servers


# ------------------------------------------------------------------------------
def serving_server(servers, role):
    """The participating (or combined) server that serves the client role."""
    return next(
        server_name
        for server_name, server in servers.items()
        if server["role"] != "controlling" and role in server["users"]
    )


# ------------------------------------------------------------------------------
def server_roles(servers, name, service):
    """Role and peer configuration of one server; empty for a single combined server."""
    if len(servers) == 1:
        return {}
    role = servers[name]["role"]
    result = {
        "role": role,
        "servers": {
            peer_name: {"host": peer_name, "service_uri": service, "controlling": peer["role"] != "participating"}
            for peer_name, peer in servers.items()
            if peer_name != name
        },
    }
    if role == "participating":
        result["controller"] = next(peer_name for peer_name, peer in servers.items() if peer["role"] != "participating")
    return result


# ------------------------------------------------------------------------------
def service_servers(mcdata_user, mcvideo_user, video_servers=("mcvideo-server",)):
    """The servers of the MC services other than MCPTT, each with its PSI user:
    MCData (TS 24.282) and MCVideo (TS 24.281, the openmcx-mcvideo-server executable with
    the MCVideo profile), every MCVideo server asserting the MCVideo PSI. A lab without
    mcvideo-server simply never matches it."""
    return [("mcdata-server", mcdata_user)] + [(name, mcvideo_user) for name in video_servers]


# ------------------------------------------------------------------------------
def as_routes(servers, service_user, others):
    """The application servers the core accepts, each asserting only its own PSI:
    the MCPTT servers assert the MCPTT service user, the MCData and MCVideo servers
    their own. The identities are written out here, because this text is
    substituted into the template after the placeholders have been replaced."""
    known = [(name, service_user) for name in servers] + list(others)
    lines = ["#!ifdef SIP_DEBUG_NO_TLS"]
    for name, user in known:
        lines += [
            f'    dns_query("{name}", "as");',
            f'    if ($si == $dns(as=>addr[0])) {{ $var(from_as) = 1; $var(as_user) = "{user}"; return; }}',
        ]
    lines.append("#!else")
    for name, user in known:
        lines += [
            f'    if ($tls_peer_subject_cn == "{name}") {{',
            f'        dns_query("{name}", "as");',
            f'        if ($si == $dns(as=>addr[0])) {{ $var(from_as) = 1; $var(as_user) = "{user}"; return; }}',
            '    }',
        ]
    lines.append("#!endif")
    return "\n".join(lines)


# ------------------------------------------------------------------------------
def service_as_routes(others, video_servers=None, users_by_role=None):
    """Kamailio lines sending a request for a PSI in others to its server. With
    several MCVideo servers, a user's request for the MCVideo PSI goes to the
    participating MCVideo server serving that user (TS 24.281 clause 6.3.2)."""
    video_servers = video_servers or {}
    serving = [
        server_name for server_name, video_server in video_servers.items() if video_server["role"] != "controlling"
    ]
    lines = []
    for debug, port, transport in ((True, 5060, "tcp"), (False, 5061, "tls")):
        lines.append("#!ifdef SIP_DEBUG_NO_TLS" if debug else "#!else")
        done = set()
        for name, user in others:
            if name in video_servers:
                if user in done:
                    continue
                done.add(user)
                if len(serving) > 1:
                    for server in serving:
                        for role in video_servers[server]["users"]:
                            lines.append(
                                f'    if ($rU == "{user}" && $fU == "{users_by_role[role]}") {{ $du = "sip:{server}:{port};transport={transport}"; $var(service_as) = 1; return; }}'
                            )
                name = serving[0]
            lines.append(
                f'    if ($rU == "{user}") {{ $du = "sip:{name}:{port};transport={transport}"; $var(service_as) = 1; return; }}'
            )
    lines.append("#!endif")
    return "\n".join(lines)


# ------------------------------------------------------------------------------
def participating_routes(servers, users_by_role):
    """Kamailio lines sending a request from a user to the participating MCPTT server serving that
    user; with one serving server, every request goes to it."""
    serving = [server_name for server_name, server in servers.items() if server["role"] != "controlling"]
    lines = []
    for debug, port, transport in ((True, 5060, "tcp"), (False, 5061, "tls")):
        lines.append("#!ifdef SIP_DEBUG_NO_TLS" if debug else "#!else")
        if len(serving) > 1:
            for name in serving:
                for role in servers[name]["users"]:
                    lines.append(
                        f'    if ($fU == "{users_by_role[role]}") {{ $du = "sip:{name}:{port};transport={transport}"; return; }}'
                    )
        lines.append(f'    $du = "sip:{serving[0]}:{port};transport={transport}";')
    lines.append("#!endif")
    return "\n".join(lines)


# The Enhanced Status operational values of the IWF lab's groups (TS 24.481 clause 7.2.4.2), numbered as TETRA pre-coded
# statuses.
IWF_ENHANCED_STATUS = {
    "allow_enhanced_status": True,
    "enhanced_status_values": [
        {"id": "1", "value": "On scene"},
        {"id": "2", "value": "En route"},
        {"id": "3", "value": "Available"},
    ],
}


# ------------------------------------------------------------------------------
def iwf_config(
    iwf_source, iwf_psi, iwf_mcptt_id, iwf_mcdata_id, service, group, domain, mcptt_server, spk, tetra_group,
    members, chat_group, tetra_chat_group, mcdata_service, mcdata_ids, mcdata_spk,
):
    """The configuration of openmcx-iwf (its config/iwf.example.json layout): SIP towards the MCPTT and MCData servers
    directly, the lab group bound to a TETRA GSSI controlled by the MC system (its MCPTT and MCData groups), the TETRA
    MSs, and the annex A.1 decisions of TS 100 392-19-1 as the lab sets them."""
    tetra = iwf_source["tetra"]
    return {
        "sip": {
            "listen": "0.0.0.0",
            "advertise": "iwf",
            "port": 5061,
            "identity": iwf_psi,
            "core_uri": "sip:sip-core:5061;transport=tls",
            "username": "",
            "password": "",
        },
        "tls": {"ca_file": "/config/tls/ca.crt", "cert_file": "/config/tls/iwf.crt", "key_file": "/config/tls/iwf.key"},
        "trusted_core": "sip-core",
        "mcptt": {
            "service_uri": iwf_psi,
            "controlling_psi": service,
            # TS 29.379 clause 10.1.4.1.1 step 2: one openmcx server is the users' participating function too.
            "participating_psi": service,
            "route": f"<sip:{mcptt_server}:5061;transport=tls;lr>",
            "spk": {"id": spk["id"], "key": spk["key"]},
        },
        # TS 100 392-19-1 clause 13.4.2: the SDS applications the IWF carries: LIP (clause 13.4.5) as a binary payload
        # with Application ID 5, OTAK key management (clause 13.4.3) as the native TETRA message.
        "sds_applications": [
            {"protocol_identifier": 10, "application_id": 5, "format": "binary"},
            {"protocol_identifier": 1, "format": "lmr_message"},
        ],
        # IWF-2 (TS 29.582 clauses 8.3.2.6 and 8.3.2.7): the MCData server directly, the IWF's PSI the same.
        "mcdata": {
            "service_uri": iwf_psi,
            "controlling_psi": mcdata_service,
            "route": "<sip:mcdata-server:5061;transport=tls;lr>",
            # TS 29.582 clauses 4.5, 6.5 and 6.6: the SPK shared with the MCData server, and the Protected Payload
            # wire profile the servers use (TS 33.180 table 8.5.4.1-1).
            "spk": {"id": mcdata_spk["id"], "key": mcdata_spk["key"]},
            "key_parameter_profile": {
                "message_type": 10, "algorithm": 1, "key_parameters_iei": 0x79, "encrypted_payload_iei": 0x78
            },
        },
        "swmi": {"listen": "0.0.0.0", "port": 15000},
        # IWF-3 (TS 23.283 clause 7.4.3; TS 24.481 clauses 6.2.5.1, 6.2.5.3): the IWF serves the group documents of its
        # groups over XCAP; the MCPTT PSI stands for this lab's GMS subscription proxy and its MCS server.
        "group_management": {
            "listen": "0.0.0.0",
            "port": 8443,
            "xcap_root": "https://iwf:8443/xcap-root",
            "documents_psi": f"sip:iwf-documents@{domain}",
            "authorized_gms": [service],
            "authorized_servers": [service],
            "maximum_duration_s": 3600,
            # TNG2, <on-network-in-progress-emergency-state-cancellation-timeout> (TS 29.379 clause 6.6.3.1.10).
            "emergency_cancellation_timeout_s": 600,
        },
        # The IWF's speech and floor control ports (TS 29.379 clause 6.1.1), advertised by name as the servers do.
        "media": {"address": "iwf", "port_base": 40000},
        "tetra_system": {"mni": tetra["mni"]},
        "mc_system": {
            "mni": tetra["mc_system_mni"],
            "iwf_mcptt_id": iwf_mcptt_id,
            "iwf_mcptt_client_id": f"urn:uuid:{uuid.uuid4()}",
            "iwf_mcdata_id": iwf_mcdata_id,
            "iwf_mcdata_client_id": f"urn:uuid:{uuid.uuid4()}",
        },
        "decisions": iwf_source["decisions"],
        "identities": {
            "tetra_users": [
                {
                    "issi": issi,
                    "mcptt_id": f"sip:tetra-{issi}@{domain}",
                    "mcdata_id": f"sip:tetra-{issi}.mcdata@{domain}",
                }
                for issi in tetra["issis"]
            ],
            # TS 100 392-19-1 clause 8.2.1: the SSIs that represent MCPTT users to the TETRA MSs (individual calls).
            "mc_users": [
                {"ssi": ssi, "mcptt_id": f"sip:{name}@{domain}"}
                # Its MCData ID too (TS 100 392-19-1 clause 8.2.1), the calling party of its SDS (clause 13.2.4.2).
                | ({"mcdata_id": mcdata_ids[f"sip:{name}@{domain}"]} if f"sip:{name}@{domain}" in mcdata_ids else {})
                for name, ssi in tetra.get("mc_users", {}).items()
            ],
            # TS 100 392-19-1 clause 9.2.1: the GSSI stands for the group's MCPTT and MCData groups (one identity here).
            "groups": [{"gssi": tetra["gssi"], "control": "mc_system", "mcptt_group_id": group, "mcdata_group_id": group}]
            # TS 100 392-19-1 clause 9.3.1.2.2: a GSSI mapped to an MCPTT chat group, joined rather than affiliated.
            + (
                [
                    {
                        "gssi": iwf_source["chat_group"]["gssi"],
                        "control": "mc_system",
                        "mcptt_group_id": chat_group,
                        "call_type": "chat",
                    }
                ]
                if chat_group
                else []
            )
            + (
                [
                    {
                        "gssi": iwf_source["tetra_group"]["gssi"],
                        "control": "tetra_system",
                        "mcptt_group_id": tetra_group,
                        # Its MCData group, the IWF owning it too (TS 29.582 clause 8.3.3), with the same identity.
                        "mcdata_group_id": tetra_group,
                        "mc_members": members,
                        "mcdata_members": list(mcdata_ids.values()),
                        # The IWF as controlling function authorises emergency calls and alerts (TS 29.379 clauses
                        # 6.6.3.1.8.1 and 6.6.3.1.8.2).
                        "allow_emergency_call": True,
                        "allow_emergency_alert": True,
                    }
                ]
                if tetra_group
                else []
            )
            # TS 29.379 clause 10.2.3: a chat group controlled by the TETRA system, which the MCPTT users join at the IWF.
            + (
                [
                    {
                        "gssi": iwf_source["tetra_chat_group"]["gssi"],
                        "control": "tetra_system",
                        "mcptt_group_id": tetra_chat_group,
                        "call_type": "chat",
                        "mc_members": members,
                        # TS 29.379 clause 10.2.3.1.1 step 6: the IWF authorises emergency calls (clause 6.6.3.1.8.2).
                        "allow_emergency_call": True,
                    }
                    # <on-network-max-participant-count> (TS 24.481 clause 7.2.4.2), which the IWF enforces.
                    | (
                        {"max_participants": iwf_source["tetra_chat_group"]["max_participants"]}
                        if "max_participants" in iwf_source["tetra_chat_group"]
                        else {}
                    )
                ]
                if tetra_chat_group
                else []
            ),
        },
    }


# ------------------------------------------------------------------------------
def positive_days(text):
    """--certificate-days: a whole number of days, at least 1."""
    days = int(text)
    if days < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return days


# ------------------------------------------------------------------------------
def main():
    """Read the lab description and write the lab's credentials and configuration files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=pathlib.Path, default=ROOT / "config/lab.json")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "config/generated")
    # The validity of the lab CA and of the certificates it signs, in days (OpenMCX's own CA: its validity period is
    # local policy); 30 by default: default pending maintainer choice (no spec value).
    parser.add_argument("--certificate-days", type=positive_days, default=30)
    args = parser.parse_args()
    source = json.loads(args.input.read_text())
    domain = source["domain"]
    mcdata_user = source.get("mcdata_user", "mcdata")
    mcvideo_user = source.get("mcvideo_user", "mcvideo")
    servers = mcptt_servers(source)
    video_servers = mcptt_servers(source, "mcvideo_servers", "mcvideo", "mcvideo-server")
    for value in [domain, source["service_user"], source["group_user"], mcdata_user, mcvideo_user] + [
        source_user[field] for source_user in source["users"] for field in ("role", "username", "mcptt_user")
    ]:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", value):
            raise ValueError("Lab domain and local identifiers must use letters, digits, dots, underscores or hyphens")
    # The authentication scheme of each user's private user identity (TS 29.228 clause 6.3.1 step 4): SIP digest
    # over TLS unless "auth" is "aka", IMS AKA through the P-CSCF (TS 33.203; TS 33.180 clause 6.2.1 for 3GPP access).
    for source_user in source["users"]:
        if source_user.get("auth", "digest") not in ("digest", "aka"):
            raise ValueError(f"user {source_user['role']}: auth must be digest or aka")
    # IMS AKA identities that no client uses ("aka_probes"), for the refusal and challenge checks of a lab
    # (tests/integration/aka_negative.py), so that those never touch a client's registration.
    probes = list(source.get("aka_probes", []))
    for probe in probes:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", probe):
            raise ValueError(f"aka_probes: invalid identity {probe}")
    aka = bool(probes) or any(source_user.get("auth") == "aka" for source_user in source["users"])
    out = args.output.resolve()
    if out.exists():
        raise SystemExit(f"Refusing to overwrite {out}; use existing configuration or choose --output")
    os.umask(0o077)
    out.mkdir(parents=True)
    (out / "tls").mkdir()

    # ------------------------------------------------------------------------------
    def save(name, value):
        """Write a file of the generated configuration: JSON for a dict or list, text otherwise."""
        (out / name).write_text(json.dumps(value, indent=2) + "\n" if isinstance(value, (dict, list)) else value)

    # ------------------------------------------------------------------------------
    def openssl(*cmd):
        """Run one openssl command, quietly, failing on error."""
        subprocess.run(["openssl", *map(str, cmd)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    tlsdir = out / "tls"
    # A CA that signs certificates and revocation lists (the Credential Service's, MCX Admin slice F2). TS 33.310
    # clause 6.1.4a (TLS client/server CA): "Mandatory critical key usage" and "Mandatory critical basic constraints:
    # CA=True, path length 0" (pathLenConstraint, RFC 5280 section 4.2.1.9).
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-keyout",
        tlsdir / "ca.key",
        "-out",
        tlsdir / "ca.crt",
        "-days",
        args.certificate_days,
        "-subj",
        "/CN=OpenMCX local lab CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    roles = (
        [
            "sip-core",
            *servers,
            "mcdata-server",
            *video_servers,
            "mcx-user-db",
            "http-proxy",
            "idms",
            "gms",
            "cms",
            "lms",
            "kms",
            "content-server",
            "message-store",
            "notification-server",
        ]
        + [source_user["role"] for source_user in source["users"]]
        + list(source.get("extra_roles", []))
        + (["iwf"] if "iwf" in source else [])
        + (["pcscf"] if aka else [])
    )
    for role in roles:
        # Use the EC core leaf qualified by repeated outbound mutual TLS tests.
        # An RSA leaf showed intermittent signature failures; its cause is unproven.
        # The CA and OIDC signing keys remain RSA; peer verification is unchanged.
        algorithm = ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if role == "sip-core" else ["rsa:2048"]
        openssl(
            "req",
            "-newkey",
            *algorithm,
            "-nodes",
            "-keyout",
            tlsdir / f"{role}.key",
            "-out",
            tlsdir / f"{role}.csr",
            "-subj",
            f"/CN={role}",
        )
        extension = tlsdir / f"{role}.ext"
        # TS 33.310 clause 6.1.3a (TLS entity): "Mandatory critical key usage: At least digitalSignature shall be set".
        key_usage = "digitalSignature" if role == "sip-core" else "digitalSignature,keyEncipherment"
        names = [role, f"{role}.{domain}"]
        extension.write_text(
            f"subjectAltName={','.join('DNS:' + dns_name for dns_name in names)}\n"
            f"extendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\nkeyUsage=critical,{key_usage}\n"
        )
        openssl(
            "x509",
            "-req",
            "-in",
            tlsdir / f"{role}.csr",
            "-CA",
            tlsdir / "ca.crt",
            "-CAkey",
            tlsdir / "ca.key",
            "-CAcreateserial",
            "-out",
            tlsdir / f"{role}.crt",
            "-days",
            args.certificate_days,
            "-extfile",
            extension,
        )
        extension.unlink()
        (tlsdir / f"{role}.csr").unlink()
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", out / "oidc-private.pem")
    openssl("pkey", "-in", out / "oidc-private.pem", "-pubout", "-out", out / "oidc-public.pem")
    service = f"sip:{source['service_user']}@{domain}"
    # MCData server public service identity (TS 24.282 clause 4.2.1).
    mcdata_service = f"sip:{mcdata_user}@{domain}"
    # MCVideo server public service identity (TS 24.281 clause 4.2).
    mcvideo_service = f"sip:{mcvideo_user}@{domain}"
    group = f"sip:{source['group_user']}@{domain}"
    # An interworking function with a TETRA system (TS 23.283, TS 29.379; the openMCX iwf repository), when the lab
    # names one: its PSI, the MCPTT ID with which it affiliates on behalf of the TETRA MSs (TS 100 392-19-1 clause 9.2.1,
    # a group member, NOTE 5), and its TETRA identities.
    iwf_source = source.get("iwf")
    iwf_psi = f"sip:{iwf_source['psi_user']}@{domain}" if iwf_source else ""
    iwf_mcptt_id = f"sip:{iwf_source['mcptt_user']}@{domain}" if iwf_source else ""
    # The IWF's MCData ID (TS 29.582 clause 8.3.2.6), distinct from its MCPTT ID as every user's are.
    iwf_mcdata_id = f"sip:{iwf_source['mcptt_user']}.mcdata@{domain}" if iwf_source else ""
    # A group controlled by the TETRA system (TS 100 392-19-1 clause 9.2.2), owned by the IWF: the MC system knows it
    # as an interworking group whose controller is the IWF (TS 23.283 clause 10.1.2.4).
    tetra_group = (
        f"sip:{iwf_source['tetra_group']['user']}@{domain}" if iwf_source and "tetra_group" in iwf_source else ""
    )
    # A chat group of the MC system (TS 24.379 clause 10.1.2) that a TETRA GSSI is mapped to (TS 100 392-19-1 clause
    # 9.3.1.2.2): the IWF joins it for the MSs that attach.
    chat_group = (
        f"sip:{iwf_source['chat_group']['user']}@{domain}" if iwf_source and "chat_group" in iwf_source else ""
    )
    # A chat group controlled by the TETRA system, owned by the IWF like tetra_group (TS 29.379 clause 10.2.3).
    tetra_chat_group = (
        f"sip:{iwf_source['tetra_chat_group']['user']}@{domain}"
        if iwf_source and "tetra_chat_group" in iwf_source
        else ""
    )
    # TS 29.379 clause 6.8.1.4 and TS 33.180 clause 5.5: the SPK the IWF and the MCPTT servers share, provisioned
    # directly; its SPK-ID carries purpose tag 3.
    iwf_spk = (
        {"id": (3 << 28) | secrets.randbelow(1 << 28), "key": secrets.token_hex(16), "rand": secrets.token_hex(16)}
        if iwf_source
        else None
    )
    # TS 29.582 clauses 4.5 and 6.6.1: the SPK the IWF and the MCData server share; the IWF opens what it receives by
    # the key ID, so its SPK-ID differs from the MCPTT one.
    iwf_mcdata_spk = None
    while iwf_source and (iwf_mcdata_spk is None or iwf_mcdata_spk["id"] == iwf_spk["id"]):
        iwf_mcdata_spk = {
            "id": (3 << 28) | secrets.randbelow(1 << 28), "key": secrets.token_hex(16), "rand": secrets.token_hex(16)
        }
    endpoints = {function: f"https://{function}:8443" for function in ("idms", "gms", "cms", "lms", "kms")}
    # <MCDataContentServerURI>: the media storage function (TS 24.282 clause 10.2.2.1).
    # Clients and file URLs use the HTTP proxy (TS 24.482 annex A); the servers reach
    # the content server directly for their own operations.
    content_server = "https://content-server:8443"
    endpoints["content"] = "https://http-proxy:8443/content"
    # The MCData message store and notification server (TS 24.282 clause 21, TS 24.484
    # clauses 10.3 and 10.4): the clients through the proxy, the servers directly.
    message_store, notification_server = "https://message-store:8443", "https://notification-server:8443"
    endpoints["msgstore"] = "https://http-proxy:8443/msgstore"
    endpoints["notification"] = "https://http-proxy:8443/notification"
    # TS 24.482 annex A.2.1.2 ("http_proxy_mode": "forward"): the clients name each server by its own URI and send
    # every request but the IdMS's and the KMS's through the home HTTP proxy in absolute-form; the proxy passes them on
    # by authority (A.2.2.2 step 3). Default ("path"): the clients reach the servers at path prefixes of the proxy.
    forward = source.get("http_proxy_mode", "path") == "forward"
    if forward:
        endpoints.update(content=content_server, msgstore=message_store, notification=notification_server)
    users = [
        {
            "username": source_user["username"],
            "password": secrets.token_hex(20),
            "mc_id": f"sip:{source_user['username']}.mc@{domain}",
            "mcptt_id": f"sip:{source_user['mcptt_user']}@{domain}",
            "sip_uri": f"sip:{source_user['username']}@{domain}",
            "sip_password": secrets.token_hex(20),
            "client_id": f"urn:uuid:{uuid.uuid4()}",
            "groups": [group]
            + [extra for extra in (tetra_group, chat_group, tetra_chat_group) if extra],
        }
        for source_user in source["users"]
    ]
    # IMS AKA (decisions D4, D5): a software ISIM per user with random K and OPc (TS 35.206; OP is not kept) and the
    # AMF of the subscription (TS 33.102 annex H), and the private user identity <user>@<domain> (TS 23.003
    # clause 13.3, the ISIM case of TS 37.579-1 table 5.5.2.13-1). Such a user has no SIP digest password. The keys
    # go to the user's client and the SIP database only, not into site.json.
    isims = {}
    for user, entry in zip(users, source["users"]):
        if entry.get("auth") == "aka":
            isims[user["username"]] = {
                "impi": f"{entry['username']}@{domain}",
                "k": secrets.token_hex(16),
                "opc": secrets.token_hex(16),
                "amf": entry.get("amf", "8000"),
            }
            if not re.fullmatch(r"[0-9a-f]{4}", isims[user["username"]]["amf"]):
                raise ValueError(f"user {entry['role']}: amf must be 4 hex digits")
            user["sip_password"] = ""
    probe_isims = {
        probe: {"impi": f"{probe}@{domain}", "k": secrets.token_hex(16), "opc": secrets.token_hex(16), "amf": "8000"}
        for probe in probes
    }
    # Optional TS 24.484 private-call ruleset per user; targets name local MCPTT users.
    for user, entry in zip(users, source["users"]):
        if "private_call" in entry:
            policy = dict(entry["private_call"])
            policy["targets"] = [f"sip:{name}@{domain}" for name in policy.get("targets", [])]
            # TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.2: the recipients of emergency private calls and alerts.
            for listed in ("incoming_from", "emergency_recipients", "alert_recipients"):
                if listed in policy:
                    policy[listed] = [f"sip:{name}@{domain}" for name in policy[listed]]
            user["private_call"] = policy
        if "adhoc_call" in entry:
            user["adhoc_call"] = dict(entry["adhoc_call"])
        if "group_call" in entry:
            user["group_call"] = dict(entry["group_call"])
        # A distinct MCData ID per user (TS 23.280 clause 8.1.2) and its MCData ruleset.
        user["mcdata_id"] = f"sip:{entry['username']}.mcdata@{domain}"
        user["mcdata"] = dict(
            entry.get(
                "mcdata", {"transmit_data": True, "incoming_any": True, "adhoc": True, "adhoc_participation": True}
            )
        )
        # A distinct MCVideo ID per user (TS 23.280 clause 8.1.2, TS 24.281 clause 4.2).
        user["mcvideo_id"] = f"sip:{entry['username']}.mcvideo@{domain}"
        # The user's one MCPTT UE (its client container) by its instance ID (TS 23.003 clause 13.8, a UUID URN for a
        # UE without an IMEI): the CMS serves its MCPTT UE configuration document (TS 24.484 clause 8.2.1A).
        user["ues"] = [f"urn:uuid:{uuid.uuid4()}"]
    site = {
        "domain": domain,
        "service_uri": service,
        "issuer": endpoints["idms"],
        "oauth_client_id": source["oauth_client_id"],
        "oauth_redirect_uris": [source["oauth_redirect_uri"]],
        "server_client_id": source["server_client_id"],
        "server_secret": secrets.token_hex(24),
        # TS 33.180 clauses 5.3.2 and 5.3.3: the key management clients of the MC servers and the GMS, each an OAuth
        # client of the IdMS with its own secret, for the identity it is keyed as and its key management scope.
        "key_clients": [
            {"client_id": f"{name}-key", "secret": secrets.token_hex(24), "identity": identity, "scope": scope}
            for name, identity, scope in (
                ("mcptt", service, "3gpp:mc:ptt_key_management_service"),
                ("mcdata", mcdata_service, "3gpp:mc:data_key_management_service"),
                ("mcvideo", mcvideo_service, "3gpp:mc:video_key_management_service"),
                (
                    "gms",
                    f"{endpoints['gms']}/xcap-root/org.openmobilealliance.groups",
                    "3gpp:mc:ptt_key_management_service",
                ),
            )
        ],
        "token_ttl_seconds": source["token_ttl_seconds"],
        # The IWF's MCPTT ID is a user of the MC system (TS 100 392-19-1 clause 9.2.1 NOTE 5: a group member); no client
        # signs in with it.
        "users": users
        + (
            [
                {
                    "username": iwf_source["mcptt_user"],
                    "password": secrets.token_hex(20),
                    "mc_id": f"sip:{iwf_source['mcptt_user']}.mc@{domain}",
                    "mcptt_id": iwf_mcptt_id,
                    # Its MCData ID too (TS 29.582 clause 8.3.2.6): it affiliates on behalf of the MSs on both planes.
                    "mcdata_id": iwf_mcdata_id,
                    "sip_uri": iwf_mcptt_id,
                    "sip_password": secrets.token_hex(20),
                    "client_id": f"urn:uuid:{uuid.uuid4()}",
                    "groups": [group] + ([chat_group] if chat_group else []),
                }
            ]
            # The MC identities of the TETRA MSs (TS 100 392-19-1 clause 8.2.1): users of the MC system with a
            # profile for their calls, not group members (clause 9.2.1 NOTE 5: the IWF affiliates on their behalf).
            + [
                {
                    "username": f"tetra-{issi}",
                    "password": secrets.token_hex(20),
                    "mc_id": f"sip:tetra-{issi}.mc@{domain}",
                    "mcptt_id": f"sip:tetra-{issi}@{domain}",
                    "sip_uri": f"sip:tetra-{issi}@{domain}",
                    "sip_password": secrets.token_hex(20),
                    "client_id": f"urn:uuid:{uuid.uuid4()}",
                    "groups": [],
                    # Their MCData ID and SDS right (TS 24.282 clause 9.2.2.3.1 step 7a): an MS's SDS through the IWF
                    # (TS 100 392-19-1 clause 13.2.3).
                    "mcdata_id": f"sip:tetra-{issi}.mcdata@{domain}",
                    "mcdata": {"transmit_data": True},
                    # Their emergency rights (TS 24.379 clause 6.3.3.1.13.2): a TETRA emergency call becomes an MCPTT
                    # emergency group call (TS 29.379 clause 6.4.1.1).
                    **(
                        {"group_call": dict(iwf_source["tetra"]["group_call"])}
                        if "group_call" in iwf_source["tetra"]
                        else {}
                    ),
                }
                for issi in iwf_source["tetra"]["issis"]
            ]
            if iwf_source
            else []
        ),
        "groups": [
            {
                "id": group,
                "members": [source_user["mcptt_id"] for source_user in users] + ([iwf_mcptt_id] if iwf_source else []),
                "protect_media": False,
                "protect_floor": False,
                # With an IWF: <allow-MCPTT-emergency-call> for every member (TS 24.481 clause 7.2.12.1), for the
                # emergency calls of the TETRA MSs and of the MC users towards them (TS 100 392-19-1 clause 4.4).
                **({"allow_emergency_call": True} if iwf_source else {}),
                # With an IWF: <allow-MCPTT-emergency-alert> (TS 24.481 clause 7.2.12.1), for the alerts of the TETRA
                # MSs (TS 29.379 clause 12.1.1).
                **({"allow_emergency_alert": True} if iwf_source else {}),
                "mcdata": {
                    # With an IWF: its MCData ID, which affiliates on behalf of the MSs (TS 29.582 clause 8.3.2.6).
                    "members": [source_user["mcdata_id"] for source_user in users]
                    + ([iwf_mcdata_id] if iwf_source else []),
                    "sds_supported": True,
                    "allow_sds": True,
                    # With an IWF: <mcdata-allow-transmit-data-in-this-group> for every member (TS 24.481 clause 7.2.4.2),
                    # for the group SDS between the MSs and the MCData users (TS 100 392-19-1 clause 13.2).
                    **({"transmit_all": True} if iwf_source else {}),
                    # With an IWF: Enhanced Status (TS 24.282 clause 14.2), whose operational value ids are the TETRA
                    # pre-coded statuses (TS 100 392-19-1 clause 13.4.4).
                    **(IWF_ENHANCED_STATUS if iwf_source else {}),
                },
            }
        ]
        + (
            [
                {
                    "id": tetra_group,
                    "members": [source_user["mcptt_id"] for source_user in users],
                    "protect_media": False,
                    "protect_floor": False,
                    # As the IWF's own document states it (<allow-MCPTT-emergency-call>, <allow-MCPTT-emergency-alert>).
                    "allow_emergency_call": True,
                    "allow_emergency_alert": True,
                    # Its MCData group, which the IWF owns too (TS 29.582 clause 8.3.3): the members and the Enhanced
                    # Status values the clients read.
                    "mcdata": {
                        "members": [source_user["mcdata_id"] for source_user in users],
                        "sds_supported": True,
                        "allow_sds": True,
                        "transmit_all": True,
                        "allow_emergency_alert": True,
                        **IWF_ENHANCED_STATUS,
                    },
                }
            ]
            if tetra_group
            else []
        )
        + (
            [
                {
                    "id": chat_group,
                    "type": "chat",
                    # The IWF's MCPTT ID joins on behalf of the MSs (TS 100 392-19-1 clause 9.3.1.2.2 NOTE 2).
                    "members": [source_user["mcptt_id"] for source_user in users] + [iwf_mcptt_id],
                    "protect_media": False,
                    "protect_floor": False,
                    # A short inactivity timer (TS 24.379 T4), so the lab sees the release and the IWF's join again.
                    "call_policy": {"inactivity_timeout_ms": 20000},
                    # <allow-MCPTT-emergency-call> for every member: the chat group's emergency calls with TETRA MSs.
                    "allow_emergency_call": True,
                }
            ]
            if chat_group
            else []
        )
        + (
            [
                {
                    "id": tetra_chat_group,
                    "type": "chat",
                    "members": [source_user["mcptt_id"] for source_user in users],
                    "protect_media": False,
                    "protect_floor": False,
                    # As the IWF's own document states it (<allow-MCPTT-emergency-call>).
                    "allow_emergency_call": True,
                }
            ]
            if tetra_chat_group
            else []
        ),
        "endpoints": {
            **endpoints,
            "msgstore_internal": message_store,
            "notification_internal": notification_server,
            "content_internal": content_server,
        },
        "mcdata_service": {"max_data_size_fd_bytes": 8388608, "service_uri": mcdata_service},
        "mcvideo_service": {"service_uri": mcvideo_service},
    }
    save("site.json", site)
    save(
        "http-proxy.json",
        {
            "endpoints": {
                **endpoints,
                "content": content_server,
                "msgstore": message_store,
                "notification": notification_server,
            },
            # The own MC service provider's servers by the authority of their URIs (A.2.2.2 step 3).
            **(
                {
                    "forward": {
                        "gms:8443": "gms",
                        "cms:8443": "cms",
                        "lms:8443": "lms",
                        "kms:8443": "kms",
                        "content-server:8443": "content",
                        "message-store:8443": "msgstore",
                        "notification-server:8443": "notification",
                    }
                }
                if forward
                else {}
            ),
        },
    )
    # Each MCPTT server pulls user profiles from the user database (MCPTT-2).
    # TS 33.210 with RFC 6733: the Diameter peers of MCPTT-2 connect with TLS on the
    # secure port and authenticate each other with certificates from the lab CA, whose
    # names include each peer's Diameter identity (role.domain). Both ends connect
    # to each other and retry every 5 s (Tc, RFC 6733 section 2.1, 30 s by default): a
    # user database that restarts on a new address connects to the servers itself,
    # so service authorisation resumes within seconds of it coming back. A peer
    # whose name does not resolve yet (a server not started) is only accepted.
    diameter = [
        (
            name,
            ["mcx-user-db"],
            3869,
            5869,
            5868,
            "diameter-server.conf" if name == "mcptt-server" else f"diameter-{name}.conf",
        )
        for name in servers
    ]
    diameter.append(("mcx-user-db", list(servers), 3868, 5868, 5869, "diameter-user-db.conf"))
    for role, peers, port, secure_port, peer_secure_port, filename in diameter:
        connect = "".join(
            f'''ConnectPeer = "{peer}.{domain}" {{ ConnectTo = "{peer}"; TcTimer = 5; Port = {peer_secure_port}; No_TCP; Realm = "{domain}"; }};
'''
            for peer in peers
        )
        save(
            filename,
            f'''# MCPTT-2 over SCTP protected with TLS (TS 33.210, RFC 6733 on the secure port).
Identity = "{role}.{domain}";
Realm = "{domain}";
Port = {port};
SecPort = {secure_port};
No_TCP;
No_IPv6;
NoRelay;
SCTP_streams = 4;
TLS_Cred = "/config/tls/{role}.crt", "/config/tls/{role}.key";
TLS_CA = "/config/tls/ca.crt";
{connect}''',
        )
    save(
        "mcdata-server.json",
        {
            "sip": {
                "listen": "0.0.0.0",
                "advertise": "mcdata-server",
                "port": 5061,
                "core_uri": "sip:sip-core:5061;transport=tls",
                "identity": mcdata_service,
                "username": "",
                "password": "",
            },
            "tls": {
                "ca_file": "/config/tls/ca.crt",
                "cert_file": "/config/tls/mcdata-server.crt",
                "key_file": "/config/tls/mcdata-server.key",
            },
            "control_fifo": "/run/mcx/control",
            "status_file": "/artifacts/mcdata-server/status.json",
            "trusted_core": "sip-core",
            "common": {
                **{function: endpoints[function] for function in ("idms", "gms", "cms")},
                "client_id": site["server_client_id"],
                "secret": site["server_secret"],
            },
            "mcdata": {
                "service_uri": mcdata_service,
                "max_payload_size_sds_cplane_bytes": 1000,
                "max_data_size_sds_bytes": 4000,
                "max_data_size_fd_bytes": 4000,
                "adhoc": {"allow": True, "max_participants": 8, "lifetime_ms": 1800000},
                "redelivery": {"tdp1_ms": 60000, "max_attempts": 3, "retention_ms": 600000, "max_held": 1000},
                "aggregation": {"enabled": True, "tdc1_ms": 5000, "max_per_message": 50},
                "fd": {
                    "content_server": endpoints["content"],
                    "content_server_internal": content_server,
                    "max_data_size_auto_recv_bytes": 0,
                    "max_file_availability_ms": 600000,
                    "default_file_availability_ms": 120000,
                    "intent_before_release_ms": 0,
                    "tdc3_ms": 15000,
                    "extension_ms": 120000,
                },
                "media": {"session_ms": 30000, "idle_ms": 300000},
                "msgstore": {"uri": message_store, "store": "mcdata"},
                # TS 23.283 IWF-2: the IWF is a peer of the MCData server, trusted by its address, affiliating its users
                # in the standard per-group form (TS 29.582 clauses 8.3.2.6, 8.3.2.7; TS 24.282 clauses 8.3.3.3 to
                # 8.3.3.5).
                **(
                    {
                        "servers": {
                            "iwf": {
                                "host": "iwf",
                                "service_uri": iwf_psi,
                                "standard_affiliation": True,
                                # TS 29.582 clauses 4.5 and 6.6.1 (TS 24.282 clause 6.6.1): the SPK the IWF and the
                                # MCData server share, provisioned directly; its own SPK-ID, apart from the MCPTT one.
                                "spk": iwf_mcdata_spk,
                                # The MSs' MCData IDs (TS 100 392-19-1 clause 8.2.1).
                                "users": [
                                    f"sip:tetra-{issi}.mcdata@{domain}" for issi in iwf_source["tetra"]["issis"]
                                ],
                            }
                        }
                    }
                    if iwf_source
                    else {}
                ),
                # The MCData group of the group the IWF controls is owned by the IWF too (TS 29.582 clause 8.3.3).
                **({"group_controllers": {tetra_group: "iwf"}} if tetra_group else {}),
            },
        },
    )
    (ROOT / "artifacts" / "mcdata-server").mkdir(parents=True, exist_ok=True)
    for role in [*servers] + [source_user["role"] for source_user in source["users"]]:
        cfg = {
            "sip": {
                "listen": "0.0.0.0",
                "advertise": role,
                "port": 5061,
                "core_uri": "sip:sip-core:5061;transport=tls",
            },
            "tls": {
                "ca_file": "/config/tls/ca.crt",
                "cert_file": f"/config/tls/{role}.crt",
                "key_file": f"/config/tls/{role}.key",
            },
            "media": {"bind": "0.0.0.0", "advertise": role, "rtp_port": 4000, "floor_port": 5000, "mode": 0},
            "control_fifo": "/run/mcx/control",
            "status_file": f"/artifacts/{role}/status.json",
        }
        if role in servers:
            cfg["sip"].update(identity=service, username="", password="")
            cfg.update(
                common={
                    **{function: endpoints[function] for function in ("idms", "gms", "cms")},
                    "client_id": site["server_client_id"],
                    "secret": site["server_secret"],
                },
                mcptt={
                    "service_uri": service,
                    # TS 24.481 clause 6.3.13.3.1: the PSI of its GMS subscription proxy function, when the lab names
                    # one apart from the MCPTT PSI.
                    **({"gms_subscription_psi": f"sip:{source['gms_user']}@{domain}"} if source.get("gms_user") else {}),
                    "max_talk_ms": 30000,
                    "adhoc_call": {"enabled": True, "max_participants": 8},
                },
                trusted_core="sip-core",
                diameter_config="/config/diameter-server.conf",
                peers={source_user["mcptt_id"]: entry["role"] for source_user, entry in zip(users, source["users"])},
            )
            cfg["mcptt"].update(server_roles(servers, role, service))
            # TS 23.283 IWF-1: the IWF is a peer of the MCPTT servers, trusted by its address (TS 29.379 clause 4.1).
            if iwf_source:
                cfg["mcptt"].setdefault("servers", {})["iwf"] = {
                    "host": "iwf",
                    "service_uri": iwf_psi,
                    "controlling": False,
                    "spk": iwf_spk,
                    # TS 29.379 clause 9.2.1.3: the IWF takes affiliations to its groups in the standard form.
                    "standard_affiliation": True,
                    # TS 100 392-19-1 clause 8.2.1 with TS 29.379 clause 11.1.2.2: the TETRA MSs' MCPTT IDs, reached
                    # through the IWF (a private call to an MS).
                    "users": [f"sip:tetra-{issi}@{domain}" for issi in iwf_source["tetra"]["issis"]],
                }
                for owned in (tetra_group, tetra_chat_group):
                    if owned:
                        cfg["mcptt"].setdefault("group_controllers", {})[owned] = "iwf"
        else:
            user = users[[source_user["role"] for source_user in source["users"]].index(role)]
            cfg["sip"].update(identity=user["sip_uri"], username=user["username"], password=user["sip_password"])
            if user["username"] in isims:
                # IMS AKA through the P-CSCF (TS 24.229 clause 5.1.1.2.2): the ISIM's keys, and the P-CSCF's address
                # and unprotected port, preconfigured (decision D9; not discovered, TS 24.229 clause 9.2.1).
                # sip.port is the UE's protected server port port_us, other than 5060, 5061 and the unprotected port
                # (TS 33.203 clause 7.1); requests to the UE come from the P-CSCF, its trusted core.
                cfg["sip"].update(
                    auth="aka",
                    isim=dict(isims[user["username"]]),
                    pcscf={"address": "pcscf", "port": 5060},
                    port=AKA_PROTECTED_SERVER_PORT,
                )
                # TS 24.229 clause 4.2A: SIP over UDP towards the P-CSCF when the lab asks for it ("aka_transport").
                if source.get("aka_transport", "tcp") == "udp":
                    cfg["sip"]["transport"] = "udp"
            cfg.update(
                mcptt={
                    "user_id": user["mcptt_id"],
                    "client_id": user["client_id"],
                    "service_uri": service,
                    "group_id": group,
                    # The interworking chat group may be selected as well (mcx-client "group").
                    **(
                        {"allowed_groups": [group] + [extra for extra in (chat_group, tetra_chat_group) if extra]}
                        if chat_group or tetra_chat_group
                        else {}
                    ),
                    # TS 24.484 clause 8.2.1A: the MCSUEID of the UE configuration document's XCAP URI.
                    "ue_instance_id": user["ues"][0],
                },
                oauth={
                    "issuer": site["issuer"],
                    # TS 24.484 clause 7.2.2.7 item 4: <idms-auth-endpoint> and <idms-token-endpoint>; the JWKS URI
                    # (OpenID Connect Core 1.0 section 10, "by other means").
                    "idms_auth_endpoint": site["issuer"] + "/authorize",
                    "idms_token_endpoint": site["issuer"] + "/token",
                    "jwks_uri": site["issuer"] + "/jwks",
                    "username": user["username"],
                    "password": user["password"],
                    "client_id": site["oauth_client_id"],
                    "redirect_uri": source["oauth_redirect_uri"],
                },
                mcdata={
                    "user_id": user["mcdata_id"],
                    "service_uri": mcdata_service,
                    "group_id": group,
                    # The MCData group of the group the IWF controls (TS 29.582 clause 8.3.3), affiliated too.
                    **({"groups": [tetra_group]} if tetra_group else {}),
                    # The IWF's LIP application (TS 100 392-19-1 clauses 13.4.2, 13.4.5), Application ID 5.
                    **({"applications": [5]} if iwf_source else {}),
                    "fd": {"auto_receive_bytes": 0},
                    "ipconn": {
                        "address": f"10.77.0.{[source_user['role'] for source_user in source['users']].index(role) + 1}"
                    },
                },
                received_wav=f"/artifacts/{role}/received.wav",
                # TS 24.482 annex A.2.1.2: the home HTTP proxy, one-way TLS tunnel authentication (forward mode).
                **({"http": {"proxy": "https://http-proxy:8443", "tunnel_auth": "one-way"}} if forward else {}),
                trusted_core="sip-core",
                server_address=serving_server(servers, role),
                endpoints={
                    # TS 24.484 clause 7.2.2.7 items 7 and 8: the GMS and CMS XCAP root URIs, used as given.
                    **{
                        function: (f"https://{function}:8443" if forward else "https://http-proxy:8443/" + function)
                        + "/xcap-root"
                        for function in ("cms", "gms")
                    },
                    "content": endpoints["content"],
                    "msgstore": endpoints["msgstore"],
                    "notification": endpoints["notification"],
                },
                msgstore={"store": "mcdata"},
                # TS 24.481 clause 6.3.13.2.1 step b, TS 24.483 clause 8.2.9 GMSURI: the GMS subscription proxy PSI of
                # the group document and group key subscriptions; the MCPTT PSI (the MCPTT server provides that
                # function, as openmcx-admin's <GMS-URI>) unless the lab names one apart ("gms_user").
                gms={
                    "subscription_psi": f"sip:{source['gms_user']}@{domain}" if source.get("gms_user") else service
                },
            )
            if user["username"] in isims:
                cfg["trusted_core"] = "pcscf"
            # TS 24.379 clause 6.2.8.1.1 (with annex F.3): the location an emergency alert carries, when the lab
            # gives the user one.
            source_entry = source["users"][[source_user["role"] for source_user in source["users"]].index(role)]
            if "emergency_location" in source_entry:
                cfg["mcptt"]["emergency_location"] = dict(source_entry["emergency_location"])
            if iwf_source:
                # The service configuration enables signalling protection when it names none (TS 24.379 clause
                # 6.6.2.3.1), so the client provisions its keys at sign-in (TS 33.180 clause 5.3.3), as tutorial 3
                # sets it up; the groups stay unprotected.
                cfg["security"] = {
                    "kms_uri": endpoints["kms"],
                    "key_parameter_profile": {
                        "message_type": 10,
                        "algorithm": 1,
                        "key_parameters_iei": 0x79,
                        "encrypted_payload_iei": 0x78,
                    },
                }
        save(f"{role}.json", cfg)
        (ROOT / "artifacts" / role).mkdir(parents=True, exist_ok=True)
    if iwf_source:
        # With the clients keyed (above), the MC servers need their own key management clients to take the clients'
        # CSKs (TS 33.180 clauses 5.3.3 and 5.3.2), as tools/prepare-prearranged-test.py sets up a protected lab.
        for name, identity in (("mcptt-server", service), ("mcdata-server", mcdata_service)):
            path = out / f"{name}.json"
            if not path.exists():
                continue
            server_cfg = json.loads(path.read_text())
            entry = next(client for client in site["key_clients"] if client["identity"] == identity)
            server_cfg.setdefault("common", {})["kms"] = endpoints["kms"]
            server_cfg["security"] = {
                "kms_uri": endpoints["kms"],
                "gms_uri": endpoints["gms"] + "/xcap-root/org.openmobilealliance.groups",
                "key_parameter_profile": {
                    "message_type": 10,
                    "algorithm": 1,
                    "key_parameters_iei": 0x79,
                    "encrypted_payload_iei": 0x78,
                },
                "key_client": {"client_id": entry["client_id"], "secret": entry["secret"], "scope": entry["scope"]},
            }
            save(f"{name}.json", server_cfg)
        save(
            "iwf.json",
            iwf_config(
                iwf_source, iwf_psi, iwf_mcptt_id, iwf_mcdata_id, service, group, domain, next(iter(servers)), iwf_spk,
                tetra_group, [source_user["mcptt_id"] for source_user in users], chat_group, tetra_chat_group,
                mcdata_service, {source_user["mcptt_id"]: source_user["mcdata_id"] for source_user in users},
                iwf_mcdata_spk,
            ),
        )
    # The MCVideo server: the openmcx-mcvideo-server executable, on the same core as the
    # MCPTT server, with the MCVideo service profile
    # It has no
    # MCVideo-2 Diameter peer, and its users are addressed by their MCVideo IDs.
    # With several MCVideo servers, each has its role and peers as the MCPTT servers do.
    for name in video_servers:
        save(
            f"{name}.json",
            {
                "service": "mcvideo",
                "sip": {
                    "listen": "0.0.0.0",
                    "advertise": name,
                    "port": 5061,
                    "core_uri": "sip:sip-core:5061;transport=tls",
                    "identity": mcvideo_service,
                    "username": "",
                    "password": "",
                },
                "tls": {
                    "ca_file": "/config/tls/ca.crt",
                    "cert_file": f"/config/tls/{name}.crt",
                    "key_file": f"/config/tls/{name}.key",
                },
                "media": {
                    "bind": "0.0.0.0",
                    "advertise": name,
                    "rtp_port": 4000,
                    "floor_port": 5000,
                    "video_port": 6000,
                    "mode": 0,
                },
                "control_fifo": "/run/mcx/control",
                "status_file": f"/artifacts/{name}/status.json",
                "common": {
                    **{function: endpoints[function] for function in ("idms", "gms", "cms")},
                    "client_id": site["server_client_id"],
                    "secret": site["server_secret"],
                },
                "mcvideo": {
                    "service_uri": mcvideo_service,
                    "max_talk_ms": 30000,
                    **server_roles(video_servers, name, mcvideo_service),
                },
                "trusted_core": "sip-core",
                "peers": {user["mcvideo_id"]: entry["role"] for user, entry in zip(users, source["users"])},
            },
        )
        (ROOT / "artifacts" / name).mkdir(parents=True, exist_ok=True)
    dbpassword = secrets.token_hex(24)
    save("mysql-password", dbpassword)
    save("mysql-root-password", secrets.token_hex(24))
    sql = "CREATE TABLE version (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, table_name VARCHAR(32) UNIQUE NOT NULL, table_version INT UNSIGNED NOT NULL);\nINSERT INTO version(table_name,table_version) VALUES ('subscriber',7);\n"
    # The presence tables come before the subscriber table: the sip-db healthcheck reads that table, and the SIP core's
    # presence module checks its tables' versions at start-up (a race otherwise, the import going on while the
    # healthcheck already passes).
    sql += PRESENCE_TABLES
    sql += "CREATE TABLE subscriber (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NOT NULL, domain VARCHAR(64) NOT NULL, password VARCHAR(64) NOT NULL, ha1 VARCHAR(128) NOT NULL DEFAULT '', ha1b VARCHAR(128) NOT NULL DEFAULT '', UNIQUE(username,domain));\n"
    # The per-IMPI subscription (TS 29.228 clause 6.3.1 step 4): its public user identity, its authentication scheme
    # and, for IMS AKA, the K, OPc and AMF of the vectors (TS 33.102 clause 6.3.2). Identities not listed use SIP
    # digest from the subscriber table.
    sql += "CREATE TABLE ims_subscription (impi VARCHAR(128) PRIMARY KEY, impu VARCHAR(128) NOT NULL, domain VARCHAR(64) NOT NULL, auth_scheme ENUM('aka','digest') NOT NULL, k BINARY(16) NULL, opc BINARY(16) NULL, amf BINARY(2) NULL, KEY (impu));\n"
    for user in users:
        if user["username"] in isims:
            isim = isims[user["username"]]
            sql += f"INSERT INTO ims_subscription(impi,impu,domain,auth_scheme,k,opc,amf) VALUES ('{isim['impi']}','{user['sip_uri']}','{domain}','aka',UNHEX('{isim['k']}'),UNHEX('{isim['opc']}'),UNHEX('{isim['amf']}'));\n"
            continue
        # Digest hashes only (RFC 2617 section 3.2.2.2), the realm being the domain; the SIP
        # password stays in the client's configuration.
        ha1 = hashlib.md5(f"{user['username']}:{domain}:{user['sip_password']}".encode()).hexdigest()
        ha1b = hashlib.md5(f"{user['username']}@{domain}:{domain}:{user['sip_password']}".encode()).hexdigest()
        sql += f"INSERT INTO subscriber(username,domain,password,ha1,ha1b) VALUES ('{user['username']}','{domain}','','{ha1}','{ha1b}');\n"
    for probe, isim in probe_isims.items():
        sql += f"INSERT INTO ims_subscription(impi,impu,domain,auth_scheme,k,opc,amf) VALUES ('{isim['impi']}','sip:{probe}@{domain}','{domain}','aka',UNHEX('{isim['k']}'),UNHEX('{isim['opc']}'),UNHEX('{isim['amf']}'));\n"
        save(f"aka-probe-{probe}.json", {"identity": f"sip:{probe}@{domain}", "isim": isim})
    save("sip-db.sql", sql)
    # MySQL drops privileges before reading this bind-mounted initialization file.
    # The containing generated directory remains mode 0700 on the host.
    (out / "sip-db.sql").chmod(0o644)
    template = (ROOT / "docker/kamailio.cfg").read_text()
    users_by_role = {entry["role"]: entry["username"] for entry in source["users"]}
    others = service_servers(mcdata_user, mcvideo_user, list(video_servers))
    # TS 24.229 clauses 5.2.3 and 5.4.2.1: the IOI "that identifies the sending network" in the P-Charging-Vector of the
    # reg event dialogs; its form is the operator's (RFC 7315 gen-value): "charging": {"ioi": ...}, the domain by default
    # (maintainer 2026-11-01).
    ioi = source.get("charging", {}).get("ioi") or domain
    for old, new in {
        "@DOMAIN@": domain,
        "@IOI@": ioi,
        "@SERVICE_USER@": source["service_user"],
        "@GMS_USER@": source.get("gms_user", ""),
        "@MCDATA_USER@": mcdata_user,
        "@MCVIDEO_USER@": mcvideo_user,
        "@DB_PASSWORD@": dbpassword,
        "@AS_ROUTES@": as_routes(servers, source["service_user"], others),
        "@SERVICE_AS_ROUTES@": service_as_routes(others, video_servers, users_by_role),
        "@PARTICIPATING_ROUTES@": participating_routes(servers, users_by_role),
    }.items():
        template = template.replace(old, new)
    # Troubleshooting only, off by default: "sip_core": {"tls_keylog": true} makes the SIP core write its TLS session
    # secrets (docs/USAGE.md section 7). An explicit switch of its own: no log level turns it on.
    if source.get("sip_core", {}).get("tls_keylog") is True:
        template = "#!define TLS_KEYLOG\n" + template
    # A GMS-URI apart from the MCPTT PSI ("gms_user"), served by the MCPTT server (TS 24.481 clause 6.3.13.3.1).
    if source.get("gms_user"):
        template = "#!define GMS_PSI\n" + template
    # The S-CSCF procedures of IMS AKA, only in a lab with an IMS AKA identity.
    if aka:
        template = "#!define WITH_AKA\n" + template
    save("kamailio.cfg", template)
    if aka:
        # The P-CSCF: two pairs of protected ports per IMS AKA user, room for a re-registration's new security
        # associations (TS 33.203 clause 7.4); TLS to the SIP core with its own certificate.
        pcscf = (ROOT / "docker/pcscf.cfg").read_text()
        pcscf = pcscf.replace("@IPSEC_MAX_CONN@", str(2 * len(isims) + 2)).replace("@IOI@", ioi).replace("@DOMAIN@", domain)
        save("pcscf.cfg", pcscf)
        save(
            "pcscf-tls.cfg",
            f"[server:default]\nmethod = TLSv1.2+\ncipher_list = {TLS12_CIPHERS}\nverify_certificate = yes\nrequire_certificate = yes\nprivate_key = /config/tls/pcscf.key\ncertificate = /config/tls/pcscf.crt\nca_list = /config/tls/ca.crt\n[client:default]\nmethod = TLSv1.2+\ncipher_list = {TLS12_CIPHERS}\nverify_certificate = yes\nrequire_certificate = yes\nprivate_key = /config/tls/pcscf.key\ncertificate = /config/tls/pcscf.crt\nca_list = /config/tls/ca.crt\n",
        )
    save(
        "tls.cfg",
        f"[server:default]\nmethod = TLSv1.2+\ncipher_list = {TLS12_CIPHERS}\nverify_certificate = yes\nrequire_certificate = yes\nprivate_key = /config/tls/sip-core.key\ncertificate = /config/tls/sip-core.crt\nca_list = /config/tls/ca.crt\n[client:default]\nmethod = TLSv1.2+\ncipher_list = {TLS12_CIPHERS}\nverify_certificate = yes\nrequire_certificate = yes\nprivate_key = /config/tls/sip-core.key\ncertificate = /config/tls/sip-core.crt\nca_list = /config/tls/ca.crt\n",
    )
    print(f"Provisioned {out}; credentials and CA expire after {args.certificate_days} days. Explicit clear media/floor lab policy.")


if __name__ == "__main__":
    main()
