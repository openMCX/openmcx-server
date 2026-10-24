#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Check a running TLS lab against the 3GPP TLS profile, TS 33.210 V19.3.0 clause 6.2 (TS 33.180 clause 6.1).

  tls_profile_check.py --project P [--artifacts A]

1. Servers: every TCP listener of the lab's containers that completes a TLS 1.2 ECDHE-GCM handshake is probed with
   openssl s_client from the container's own network namespace; it shall refuse TLS 1.2 with RSA key exchange, with
   ECDHE and CBC, with DHE (clause 6.2.1 "Finite field Diffie-Hellman (i.e. DHE) shall not be supported"), TLS 1.3
   with only an ffdhe group (clause 6.2.2 "Ffdhe2048 shall not be supported") and TLS 1.1 (clause 6.2.1).
2. Clients: while tcpdump captures in the SIP core's, HTTP proxy's, IdMS's, KMS's and Credential Service's
   namespaces, the clients, MC servers, the GMS and MCX Admin are restarted; every ClientHello they send shall offer only TLS 1.3 suites, the TLS 1.2 ECDHE
   AEAD suites of clause 6.2.3 (and the RFC 5746 renegotiation SCSV), and no ffdhe or sub-256-bit group.

Prints one JSON line {"scenario": "tls_profile", "passed": ..., "checks": [...], "error": ...}; exit status 0 when
passed. The capture is kept as <artifacts>/tls-profile.pcap.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOLS = 'openmcx-dev:0.3'
# Clause 6.2.3 (include/mcx/tls_profile.hpp): ECDHE-ECDSA/RSA with AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
TLS12 = {0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8}
# RFC 8446 section 9.1 / B.4 (clause 6.2.2): the TLS 1.3 AEAD suites; RFC 5746 TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
TLS13 = {0x1301, 0x1302, 0x1303, 0x1304}
SCSV = {0x00FF}
# Clauses 6.2.1 to 6.2.3: x25519, P-256, P-384, P-521, x448 and the hybrid groups of crypto/tls (SecP256r1MLKEM768,
# X25519MLKEM768, SecP384r1MLKEM1024), none below 256 bits; no ffdhe (0x0100-0x01ff).
GROUPS = {0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x11EB, 0x11EC, 0x11ED}
GOOD = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
REFUSED = [
    ('TLS 1.2 RSA key exchange', ['-tls1_2', '-cipher', 'AES128-GCM-SHA256:AES128-SHA256:AES128-SHA']),
    ('TLS 1.2 ECDHE with CBC', ['-tls1_2', '-cipher', 'ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA']),
    ('TLS 1.2 DHE', ['-tls1_2', '-cipher', 'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384']),
    ('TLS 1.3 ffdhe2048 only', ['-tls1_3', '-groups', 'ffdhe2048']),
    ('TLS 1.1', ['-tls1_1', '-cipher', 'DEFAULT@SECLEVEL=0']),
]
CAPTURED = ['sip-core', 'http-proxy', 'idms', 'kms', 'credentials']
RESTARTED = ['client-a', 'client-b', 'client-c', 'client-d', 'mcptt-server', 'mcdata-server', 'mcvideo-server', 'gms', 'mcxadmin']


# ------------------------------------------------------------------------------
def containers(project):
    """The lab's running containers: service name -> (container id, IPv4 address)."""
    ids = subprocess.run(
        ['docker', 'ps', '-q', '--filter', f'label=com.docker.compose.project={project}'],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    found = {}
    for cid in ids:
        out = subprocess.run(
            ['docker', 'inspect', '-f',
             '{{index .Config.Labels "com.docker.compose.service"}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}',
             cid],
            capture_output=True, text=True, check=True,
        ).stdout.split()
        if len(out) >= 2:
            found[out[0]] = (cid, out[1])
    return found


# ------------------------------------------------------------------------------
def in_namespace(cid, command, timeout=20):
    """Run a command of the tools image in a container's network namespace."""
    return subprocess.run(
        ['docker', 'run', '--rm', '--network', f'container:{cid}', TOOLS] + command,
        capture_output=True, text=True, timeout=timeout,
    )


# ------------------------------------------------------------------------------
def handshake(cid, address, port, options):
    """True when the server answers the ClientHello with a ServerHello (s_client -msg)."""
    script = (
        f'timeout 5 openssl s_client -connect {address}:{port} -msg {" ".join(options)} </dev/null 2>&1 | '
        "grep -c 'ServerHello' || true"
    )
    result = in_namespace(cid, ['bash', '-c', script])
    return result.stdout.strip() not in ('', '0')


# ------------------------------------------------------------------------------
def probe(found, checks, errors):
    """Part 1: the TLS listeners refuse what clause 6.2 forbids."""
    for service, (cid, address) in sorted(found.items()):
        listing = in_namespace(cid, ['ss', '-ltnH'])
        ports = sorted({int(line.split()[3].rsplit(':', 1)[1]) for line in listing.stdout.splitlines() if line.strip()})
        for port in ports:
            if not handshake(cid, address, port, ['-tls1_2', '-cipher', GOOD]):
                continue
            refused = [name for name, options in REFUSED if not handshake(cid, address, port, options)]
            accepted = [name for name, _ in REFUSED if name not in refused]
            if accepted:
                errors.append(f'{service}:{port} accepts {", ".join(accepted)}')
            else:
                checks.append(f'{service}:{port} TLS server refuses RSA key exchange, CBC, DHE, ffdhe and TLS 1.1')


# ------------------------------------------------------------------------------
def capture(project, found, artifacts, checks, errors):
    """Part 2: the ClientHellos of restarted clients and servers offer only the profile's suites and groups."""
    directory = Path(tempfile.mkdtemp(prefix='tls-profile-'))
    names, files = [], []
    try:
        for service in CAPTURED:
            if service not in found:
                continue
            name = f'{project}-tls-{service}'
            path = directory / f'{service}.pcap'
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
            out = open(path, 'wb')
            subprocess.Popen(
                ['docker', 'run', '--rm', '--name', name, '--network', f'container:{found[service][0]}',
                 '--cap-drop', 'ALL', '--cap-add', 'NET_RAW', TOOLS, 'tcpdump', '-Z', 'root', '-i', 'eth0', '-U',
                 '-s', '0', '-w', '-', 'tcp'],
                stdout=out, stderr=subprocess.DEVNULL, start_new_session=True,
            )
            names.append(name)
            files.append((service, path, out))
        time.sleep(3)
        restarted = [found[s][0] for s in RESTARTED if s in found]
        subprocess.run(['docker', 'restart', '-t', '5'] + restarted, capture_output=True, timeout=180)
        time.sleep(40)
    finally:
        for name in names:
            subprocess.run(['docker', 'stop', '-t', '2', name], capture_output=True)
        for _, _, out in files:
            out.close()
    hellos = 0
    bad = {}
    for service, path, _ in files:
        if artifacts:
            Path(artifacts).mkdir(parents=True, exist_ok=True)
            shutil.copy(path, Path(artifacts) / f'tls-profile-{service}.pcap')
        fields = subprocess.run(
            ['tshark', '-r', str(path), '-Y', 'tls.handshake.type == 1', '-T', 'fields', '-E', 'separator=|',
             '-e', 'ip.src', '-e', 'tcp.dstport', '-e', 'tls.handshake.ciphersuite',
             '-e', 'tls.handshake.extensions_supported_group'],
            capture_output=True, text=True,
        ).stdout
        for line in fields.splitlines():
            source, port, suites, groups = (line.split('|') + ['', '', '', ''])[:4]
            offered = {int(value, 0) for value in suites.split(',') if value}
            named = {int(value, 0) for value in groups.split(',') if value}
            hellos += 1
            bad_suites = offered - TLS12 - TLS13 - SCSV
            bad_groups = named - GROUPS
            if bad_suites or bad_groups:
                key = (
                    f'ClientHello {source} -> {service}:{port} offers suites {sorted(hex(s) for s in bad_suites)} '
                    f'groups {sorted(hex(g) for g in bad_groups)}'
                )
                bad[key] = bad.get(key, 0) + 1
    errors.extend(f'{key} (x{count})' for key, count in bad.items())
    shutil.rmtree(directory, ignore_errors=True)
    if hellos == 0:
        errors.append('no ClientHello captured')
    else:
        checks.append(f'{hellos} ClientHellos offer only TLS 1.3 suites, TLS 1.2 ECDHE AEAD suites and allowed groups')


# ------------------------------------------------------------------------------
def main():
    """Run both parts and print the report."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--compose', help='The lab compose file (unused: the project names the containers)')
    parser.add_argument('--project', required=True, help='The lab compose project')
    parser.add_argument('--artifacts', help='Directory for the captures')
    args = parser.parse_args()
    checks, errors = [], []
    found = containers(args.project)
    if not found:
        errors.append(f'no running container of project {args.project}')
    else:
        probe(found, checks, errors)
        if not any('TLS server' in check for check in checks):
            errors.append('no TLS listener found')
        capture(args.project, found, args.artifacts, checks, errors)
    report = {'scenario': 'tls_profile', 'passed': not errors, 'checks': checks, 'error': '; '.join(errors)}
    print(json.dumps(report))
    return 0 if not errors else 1


if __name__ == '__main__':
    sys.exit(main())
