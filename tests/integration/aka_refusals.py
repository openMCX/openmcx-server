#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""AKA-10: the P-CSCF's refusals of requests received over a set go back over that set; run in an IMS AKA UE's network
and PID namespaces (a privileged helper container joined to them), with the UE registered over UDP.

TS 33.203 clause 7.1, UDP case: "The P-CSCF sends requests and responses protected with ESP to a UE on the port
port_pc" (to the UE's port_us), and "No unprotected messages shall be sent from or received on the ports port_ps and
port_pc". The probe takes a duplicate of the UE client's own UDP socket on its protected client port port_uc
(pidfd_getfd), so the requests it sends go out through the UE's security associations to the P-CSCF's port_ps, and
sends two requests the P-CSCF refuses:
  - a MESSAGE inside a dialog (To tag) without a Route: 404 (loose routing fails, docker/pcscf.cfg route[PROTECTED]);
  - a MESSAGE whose Via sent-by address is not the UE's: 403 (TS 33.203 clause 7.1).
For each, on the UE's interface: an ESP packet from the P-CSCF with the SPI of the UE's inbound SA from port_pc to
port_us (spi_us) shall arrive, and no plaintext SIP from the P-CSCF. The UE client receives the refusal and drops it
as a stray response (no transaction of its own).

  aka_refusals.py --pid PID --pcscf ADDRESS --ue ADDRESS --status FILE --identity SIP-URI

Prints one JSON line {"passed": ..., "checks": [...]}.

Specifications: TS 33.203 V19.1.0 (Rel-19); RFC 3261, RFC 4303.
"""

import argparse
import ctypes
import json
import os
import secrets
import socket
import struct
import time

SYS_PIDFD_GETFD = 438  # x86_64 and aarch64 (Linux 5.6)


# ------------------------------------------------------------------------------
def stolen_udp_socket(pid, port):
    """A duplicate of pid's UDP socket bound to port (pidfd_getfd), as a Python socket."""
    inodes = set()
    for name in ('/proc/net/udp', '/proc/net/udp6'):
        try:
            for line in open(name).read().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].split(':')[1], 16) == port:
                    inodes.add(fields[9])
        except FileNotFoundError:
            pass
    target = None
    for fd in os.listdir(f'/proc/{pid}/fd'):
        try:
            link = os.readlink(f'/proc/{pid}/fd/{fd}')
        except OSError:
            continue
        if link.startswith('socket:[') and link[8:-1] in inodes:
            target = int(fd)
            break
    if target is None:
        raise RuntimeError(f'no UDP socket of process {pid} on port {port}')
    libc = ctypes.CDLL(None, use_errno=True)
    pidfd = os.pidfd_open(pid)
    fd = libc.syscall(SYS_PIDFD_GETFD, pidfd, target, 0)
    os.close(pidfd)
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'pidfd_getfd')
    return socket.socket(fileno=fd)


# ------------------------------------------------------------------------------
def message(via_host, port_us, identity, domain, tag):
    """A MESSAGE inside a dialog (To tag), without a Route header field."""
    return (
        f'MESSAGE sip:{domain} SIP/2.0\r\n'
        f'Via: SIP/2.0/UDP {via_host}:{port_us};branch=z9hG4bK{secrets.token_hex(8)}\r\n'
        'Max-Forwards: 70\r\n'
        f'From: <{identity}>;tag={secrets.token_hex(4)}\r\n'
        f'To: <sip:{domain}>;tag={tag}\r\n'
        f'Call-ID: {secrets.token_hex(12)}@aka-refusals\r\n'
        'CSeq: 1 MESSAGE\r\n'
        'Content-Type: text/plain\r\n'
        'Content-Length: 0\r\n\r\n'
    )


# ------------------------------------------------------------------------------
def watch(capture, pcscf, seconds):
    """The packets from the P-CSCF seen on the interface for the given time: ESP SPIs and plaintext SIP first lines."""
    esp, plain = [], []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        capture.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            frame = capture.recv(65535)
        except (TimeoutError, socket.timeout):
            break
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        header = (ip[0] & 0x0F) * 4
        if socket.inet_ntoa(ip[12:16]) != pcscf:
            continue
        payload = ip[header:]
        if ip[9] == 50 and len(payload) >= 4:  # ESP (RFC 4303): the SPI first
            esp.append(struct.unpack('!I', payload[:4])[0])
        elif ip[9] == 17 and len(payload) > 8 and payload[8:15] == b'SIP/2.0':
            plain.append(payload[8:].split(b'\r\n', 1)[0].decode(errors='replace'))
    return esp, plain


# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True, help='the UE client process (mcx-client)')
    parser.add_argument('--pcscf', required=True)
    parser.add_argument('--ue', required=True, help="the UE's address")
    parser.add_argument('--status', required=True)
    parser.add_argument('--identity', required=True)
    parser.add_argument('--interface', default='eth0')
    args = parser.parse_args()
    sa = json.load(open(args.status)).get('sip_security') or {}
    domain = args.identity.split('@', 1)[1]
    checks = []
    sock = stolen_udp_socket(args.pid, int(sa['port_uc']))
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    capture.bind((args.interface, 0))
    for name, via_host in (('404 to an in-dialog request without Route', args.ue),
                           ('403 to a Via not matching the security association', '192.0.2.1')):
        watch(capture, args.pcscf, 0.3)  # drain
        sock.sendto(message(via_host, sa['port_us'], args.identity, domain, secrets.token_hex(4)).encode(),
                    (args.pcscf, int(sa['port_ps'])))
        esp, plain = watch(capture, args.pcscf, 3.0)
        over_sa = int(sa['spi_us']) in esp
        checks.append(dict(name=f'AKA-10 {name}: over the SA to port_us (spi_us {sa["spi_us"]})', passed=over_sa,
                           detail=f'ESP SPIs from the P-CSCF {sorted(set(esp))}'))
        checks.append(dict(name=f'AKA-10 {name}: nothing unprotected', passed=not plain,
                           detail='; '.join(plain) or 'no plaintext SIP'))
    sock.close()
    print(json.dumps(dict(passed=all(check['passed'] for check in checks), checks=checks)))


if __name__ == '__main__':
    main()
