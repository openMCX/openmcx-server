#!/usr/bin/env python3
"""Create an isolated lab's credentials and configuration without overwriting it.

From config/lab.json (or --input) it writes, into config/generated (or --output): the lab CA and a
TLS certificate per role, the OIDC signing key, site.json for the identity management, group
management and configuration management servers (users with their MC ID, MCPTT ID, MCData ID and
MCVideo ID, the lab group, the service endpoints), the configuration of every MCPTT, MCData and
MCVideo server and of every client, the Diameter peer configuration of MCPTT-2, the SIP database
with digest hashes and the Kamailio routing of the SIP core.

Lab provisioning only: the identities follow TS 23.280 clause 8.1, the public service identities
TS 24.282 clause 4.2.1 and TS 24.281 clause 4.2, the MCData configuration TS 24.484 clauses 10.3
and 10.4, the MCVideo server roles (participating, controlling) TS 24.281 clause 6.3.

Specifications: TS 23.280 V19.10.1, TS 24.281 V19.6.0, TS 24.282 V19.7.0, TS 24.482 V19.1.0,
TS 24.484 V19.6.0 (all Rel-19); TS 33.210; RFC 6733, RFC 2617.
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


# ------------------------------------------------------------------------------
def main():
    """Read the lab description and write the lab's credentials and configuration files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=pathlib.Path, default=ROOT / "config/lab.json")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "config/generated")
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
    # A CA that signs certificates and revocation lists (the Credential Service's, MCX Admin slice F2).
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
        "30",
        "-subj",
        "/CN=openMCX local lab CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
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
        key_usage = "digitalSignature" if role == "sip-core" else "digitalSignature,keyEncipherment"
        names = [role, f"{role}.{domain}"]
        extension.write_text(
            f"subjectAltName={','.join('DNS:' + dns_name for dns_name in names)}\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\nkeyUsage={key_usage}\n"
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
            "30",
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
    users = [
        {
            "username": source_user["username"],
            "password": secrets.token_hex(20),
            "mc_id": f"sip:{source_user['username']}.mc@{domain}",
            "mcptt_id": f"sip:{source_user['mcptt_user']}@{domain}",
            "sip_uri": f"sip:{source_user['username']}@{domain}",
            "sip_password": secrets.token_hex(20),
            "client_id": f"urn:uuid:{uuid.uuid4()}",
            "groups": [group],
        }
        for source_user in source["users"]
    ]
    # Optional TS 24.484 private-call ruleset per user; targets name local MCPTT users.
    for user, entry in zip(users, source["users"]):
        if "private_call" in entry:
            policy = dict(entry["private_call"])
            policy["targets"] = [f"sip:{name}@{domain}" for name in policy.get("targets", [])]
            if "incoming_from" in policy:
                policy["incoming_from"] = [f"sip:{name}@{domain}" for name in policy["incoming_from"]]
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
    site = {
        "domain": domain,
        "service_uri": service,
        "issuer": endpoints["idms"],
        "oauth_client_id": source["oauth_client_id"],
        "oauth_redirect_uris": [source["oauth_redirect_uri"]],
        "server_client_id": source["server_client_id"],
        "server_secret": secrets.token_hex(24),
        "gms_key_client_id": source.get("gms_key_client_id", "gms-key"),
        "gms_key_secret": secrets.token_hex(24),
        "token_ttl_seconds": source["token_ttl_seconds"],
        "users": users,
        "groups": [
            {
                "id": group,
                "members": [source_user["mcptt_id"] for source_user in users],
                "protect_media": False,
                "protect_floor": False,
                "mcdata": {
                    "members": [source_user["mcdata_id"] for source_user in users],
                    "sds_supported": True,
                    "allow_sds": True,
                },
            }
        ],
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
            }
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
                "resource_priority": {"emergency": "mcdata.15", "imminent_peril": "mcdata.10", "normal": "mcdata.0"},
                "msgstore": {"uri": message_store, "store": "mcdata"},
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
                    "max_talk_ms": 30000,
                    "adhoc_call": {"enabled": True, "max_participants": 8},
                },
                trusted_core="sip-core",
                diameter_config="/config/diameter-server.conf",
                peers={source_user["mcptt_id"]: entry["role"] for source_user, entry in zip(users, source["users"])},
            )
            cfg["mcptt"].update(server_roles(servers, role, service))
        else:
            user = users[[source_user["role"] for source_user in source["users"]].index(role)]
            cfg["sip"].update(identity=user["sip_uri"], username=user["username"], password=user["sip_password"])
            cfg.update(
                mcptt={
                    "user_id": user["mcptt_id"],
                    "client_id": user["client_id"],
                    "service_uri": service,
                    "group_id": group,
                },
                oauth={
                    "issuer": site["issuer"],
                    "username": user["username"],
                    "password": user["password"],
                    "client_id": site["oauth_client_id"],
                    "redirect_uri": source["oauth_redirect_uri"],
                },
                mcdata={
                    "user_id": user["mcdata_id"],
                    "service_uri": mcdata_service,
                    "group_id": group,
                    "resource_priority": {
                        "emergency": "mcdata.15",
                        "imminent_peril": "mcdata.10",
                        "normal": "mcdata.0",
                    },
                    "fd": {"auto_receive_bytes": 0},
                    "ipconn": {
                        "address": f"10.77.0.{[source_user['role'] for source_user in source['users']].index(role) + 1}"
                    },
                },
                received_wav=f"/artifacts/{role}/received.wav",
                trusted_core="sip-core",
                server_address=serving_server(servers, role),
                endpoints={
                    **{function: "https://http-proxy:8443/" + function for function in ("cms", "gms")},
                    "content": "https://http-proxy:8443/content",
                    "msgstore": endpoints["msgstore"],
                    "notification": endpoints["notification"],
                },
                msgstore={"store": "mcdata"},
            )
        save(f"{role}.json", cfg)
        (ROOT / "artifacts" / role).mkdir(parents=True, exist_ok=True)
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
    sql = "CREATE TABLE version (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, table_name VARCHAR(32) UNIQUE NOT NULL, table_version INT UNSIGNED NOT NULL);\nINSERT INTO version(table_name,table_version) VALUES ('subscriber',7);\nCREATE TABLE subscriber (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NOT NULL, domain VARCHAR(64) NOT NULL, password VARCHAR(64) NOT NULL, ha1 VARCHAR(128) NOT NULL DEFAULT '', ha1b VARCHAR(128) NOT NULL DEFAULT '', UNIQUE(username,domain));\n"
    for user in users:
        # Digest hashes only (RFC 2617 section 3.2.2.2), the realm being the domain; the SIP
        # password stays in the client's configuration.
        ha1 = hashlib.md5(f"{user['username']}:{domain}:{user['sip_password']}".encode()).hexdigest()
        ha1b = hashlib.md5(f"{user['username']}@{domain}:{domain}:{user['sip_password']}".encode()).hexdigest()
        sql += f"INSERT INTO subscriber(username,domain,password,ha1,ha1b) VALUES ('{user['username']}','{domain}','','{ha1}','{ha1b}');\n"
    save("sip-db.sql", sql)
    # MySQL drops privileges before reading this bind-mounted initialization file.
    # The containing generated directory remains mode 0700 on the host.
    (out / "sip-db.sql").chmod(0o644)
    template = (ROOT / "docker/kamailio.cfg").read_text()
    users_by_role = {entry["role"]: entry["username"] for entry in source["users"]}
    others = service_servers(mcdata_user, mcvideo_user, list(video_servers))
    for old, new in {
        "@DOMAIN@": domain,
        "@SERVICE_USER@": source["service_user"],
        "@MCDATA_USER@": mcdata_user,
        "@MCVIDEO_USER@": mcvideo_user,
        "@DB_PASSWORD@": dbpassword,
        "@AS_ROUTES@": as_routes(servers, source["service_user"], others),
        "@SERVICE_AS_ROUTES@": service_as_routes(others, video_servers, users_by_role),
        "@PARTICIPATING_ROUTES@": participating_routes(servers, users_by_role),
    }.items():
        template = template.replace(old, new)
    save("kamailio.cfg", template)
    save(
        "tls.cfg",
        "[server:default]\nmethod = TLSv1.2+\nverify_certificate = yes\nrequire_certificate = yes\nprivate_key = /config/tls/sip-core.key\ncertificate = /config/tls/sip-core.crt\nca_list = /config/tls/ca.crt\n[client:default]\nmethod = TLSv1.2+\nverify_certificate = yes\nrequire_certificate = yes\nprivate_key = /config/tls/sip-core.key\ncertificate = /config/tls/sip-core.crt\nca_list = /config/tls/ca.crt\n",
    )
    print(f"Provisioned {out}; credentials and CA expire after 30 days. Explicit clear media/floor lab policy.")


if __name__ == "__main__":
    main()
