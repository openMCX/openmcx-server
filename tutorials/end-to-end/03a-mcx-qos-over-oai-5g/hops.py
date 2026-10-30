#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Per-hop loss and one-way delay of an MC media stream (RTP), from a capture of qos.sh measure:
<name>.pcapng (the core and N6 bridges) and <name>-ue1.pcap, <name>-ue2.pcap (the TUN of the talker, UE 1, and of the
listener, UE 2). All are taken on one host, so their clocks agree and the delays are one-way.

  ./hops.py captures/<name>.pcapng [--port 6700]

Uplink (talker to the MCPTT server):   UE 1 TUN -> N3 (gNB to UPF, GTP-U) -> N6 (to the MCPTT server)
Downlink (MCPTT server to listener):   N6 (from the MCPTT server) -> N3 (UPF to gNB, GTP-U) -> UE 2 TUN
A packet is the same packet at every point by its RTP SSRC and sequence number. For each hop: the packets lost
(seen before the hop, not after it) and the delay (median, 95th and 99th percentile, maximum). The RAN hop is UE TUN <-> N3,
which includes the UE's and the gNB's SDAP/PDCP/RLC/MAC, the rfsim radio and the gNB's GTP-U; the core hop is N3 <->
N6 (the UPF, and for the uplink the host's NAT on the way to the server).
"""
import argparse
import os
import statistics
import subprocess
import sys

GNB, UPF = '192.168.71.140', '192.168.71.134'
SERVER_NET = '192.168.72.128/26'
UE_MEDIA_PORT = 4500


PORT = UE_MEDIA_PORT


def packets(pcap, display_filter):
    """{(ssrc, seq): time} of the RTP packets matching the filter (the innermost RTP of GTP-U packets)."""
    if not os.path.exists(pcap):
        return {}
    out = subprocess.run(
        ['tshark', '-r', pcap, '-n', '-o', 'rtp.heuristic_rtp:TRUE', '-d', f'udp.port=={PORT},rtp',
         '-Y', f'rtp && ({display_filter})', '-T', 'fields', '-E', 'occurrence=l', '-e', 'frame.time_epoch',
         '-e', 'rtp.ssrc', '-e', 'rtp.seq'],
        capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stderr.strip())
    seen = {}
    for line in out.stdout.splitlines():
        t, ssrc, seq = line.split('\t')
        seen.setdefault((ssrc, int(seq)), float(t))  # first sight, if a bridge shows it twice
    return seen


def delays(a, b):
    d = sorted((b[k] - a[k]) * 1000 for k in a if k in b)
    if not d:
        return '-'
    p95 = d[min(len(d) - 1, int(0.95 * len(d)))]
    p99 = d[min(len(d) - 1, int(0.99 * len(d)))]
    return f'median {statistics.median(d):6.1f}  p95 {p95:6.1f}  p99 {p99:6.1f}  max {d[-1]:6.1f} ms'


def report(name, points):
    print(name)
    for label, seen in points:
        print(f'    {label:34} {len(seen):5} packets')
    for (la, a), (lb, b) in zip(points, points[1:]):
        lost = sum(1 for k in a if k not in b)
        print(f'    {la} -> {lb}: lost {lost}/{len(a)}  delay {delays(a, b)}')
    (la, a), (lb, b) = points[0], points[-1]
    lost = sum(1 for k in a if k not in b)
    print(f'    end to end: lost {lost}/{len(a)} ({100 * lost / max(len(a), 1):.1f} %)  delay {delays(a, b)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('pcap')
    parser.add_argument('--port', type=int, default=UE_MEDIA_PORT,
                        help='the UE port of the RTP stream: 4500 MCPTT speech (default), 6700 MCVideo video, 4700 its audio')
    args = parser.parse_args()
    global PORT
    PORT = args.port
    base = args.pcap[:-len('.pcapng')] if args.pcap.endswith('.pcapng') else args.pcap
    ue1, ue2 = f'{base}-ue1.pcap', f'{base}-ue2.pcap'
    # The talker sends its speech from its media port, the listener receives on it
    ul_ue = f'udp.srcport == {args.port}'
    dl_ue = f'udp.dstport == {args.port}'
    report('Uplink: talker (UE 1) -> MCPTT server', [
        ('UE 1 TUN (sent)', packets(ue1, ul_ue)),
        ('N3 gNB -> UPF', packets(args.pcap, f'gtp && ip.src == {GNB} && ip.dst == {UPF} && ({ul_ue})')),
        ('N6 -> MCPTT server', packets(args.pcap, f'!gtp && ip.dst == {SERVER_NET} && ({ul_ue})')),
    ])
    report('Downlink: MCPTT server -> listener (UE 2)', [
        ('N6 MCPTT server ->', packets(args.pcap, f'!gtp && ip.src == {SERVER_NET} && ({dl_ue})')),
        ('N3 UPF -> gNB', packets(args.pcap, f'gtp && ip.src == {UPF} && ip.dst == {GNB} && ({dl_ue})')),
        ('UE 2 TUN (received)', packets(ue2, dl_ue)),
    ])


if __name__ == '__main__':
    main()
