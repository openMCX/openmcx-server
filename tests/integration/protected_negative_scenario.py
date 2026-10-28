#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Bounded replay and tamper tests of protected media and floor control, confined to the isolated lab of --project.

During a protected group call it captures live ciphertext in the server's network namespace and injects four invalid
packets: an SRTP media packet towards client-b and an SRTCP floor control packet towards the server, each once replayed
and once tampered (a later sequence number or SRTCP index with one ciphertext bit flipped). Each must be rejected by the
receiver's SRTP or SRTCP replay and authentication checks (TS 33.180 clause 7.5.2 for media, clause 9.4.7 for floor
control signalling, both with the replay list of RFC 3711 section 3.3.2), counted in media_rejected_packets or
floor_rejected_packets, while the valid speech continues.

Requires image counters floor_rejected_packets/media_rejected_packets. Sends the packets with NET_RAW in the server
namespace. Never accesses production containers or reads/exports cryptographic keys.

Specifications: TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import wave
from verify_protected import parse_srtp, parse_srtcp

from lab_wait import holds

ROOT = Path(__file__).resolve().parents[2]
PROJECT = 'openmcx-protected'


# ------------------------------------------------------------------------------
def checksum(data):
    """The Internet checksum (RFC 1071) of data, padded to an even length."""
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + str(len(data) // 2) + 'H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


# ------------------------------------------------------------------------------
def ipv4_udp(source, destination, sport, dport, payload):
    """A raw IPv4/UDP datagram from source:sport to destination:dport carrying payload, with a valid IPv4 header
    checksum.
    """
    if not 0 < sport < 65536 or not 0 < dport < 65536 or len(payload) > 65507:
        raise ValueError('invalid captured UDP packet')
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(destination).packed
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    # A zero UDP checksum is permitted for IPv4; AES-GCM still verifies payload integrity.
    return header + struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


# ------------------------------------------------------------------------------
def self_test():
    """Check the datagram builder and the checksum offline (--self-test)."""
    raw = ipv4_udp('192.0.2.1', '192.0.2.2', 1234, 5678, b'test')
    assert len(raw) == 32 and raw[20:24] == struct.pack('!HH', 1234, 5678), 'exact captured UDP endpoint encoding'
    assert raw[-4:] == b'test', 'opaque packet retained'
    assert checksum(raw[:20]) == 0, 'valid IPv4 header checksum'
    print('protected negative helper tests passed')


RAW_PROGRAM = '''import base64,json,socket,sys
request=json.load(sys.stdin)
packet=base64.b64decode(request["packet"],validate=True)
with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) as sock:
 sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
 count=sock.sendto(packet,(request["destination"],0))
print(json.dumps({"bytes_sent":count}))
'''


# ------------------------------------------------------------------------------
def complete_pcap(source, destination):
    """Copy the complete records of the classic PCAP file being written at source to destination; true if any packet was
    copied.
    """
    data = source.read_bytes()
    if len(data) < 24:
        return False
    if data[:4] in (bytes.fromhex('d4c3b2a1'), bytes.fromhex('4d3cb2a1')):
        order = '<'
    elif data[:4] in (bytes.fromhex('a1b2c3d4'), bytes.fromhex('a1b23c4d')):
        order = '>'
    else:
        raise ValueError('tcpdump capture must use classic PCAP')
    end = 24
    while end + 16 <= len(data):
        included = struct.unpack_from(order + 'I', data, end + 8)[0]
        if included > 1 << 20:
            raise ValueError('unexpected captured packet size')
        if end + 16 + included > len(data):
            break
        end += 16 + included
    destination.write_bytes(data[:end])
    return end > 24


# ------------------------------------------------------------------------------
def captured_packets(tshark, path):
    """The UDP packets of the capture at path, decoded by tshark, as dicts of frame, addresses, ports and payload.
    tshark reads a copy in a temporary directory: an AppArmor profile may confine it to /tmp (as in wire_check.py)."""
    fields = ['frame.number', 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'udp.payload']
    with tempfile.TemporaryDirectory(prefix='openmcx-protected-negative-') as scratch:
        copy = Path(scratch) / Path(path).name
        shutil.copyfile(path, copy)
        command = [tshark, '-r', str(copy), '-Y', 'udp', '-T', 'fields', '-E', 'occurrence=f']
        for field in fields:
            command += ['-e', field]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10).stdout
    packets = []
    for line in output.splitlines():
        values = line.split('\t')
        if len(values) != 6 or not all(values):
            continue
        frame, src, dst, sport, dport, payload = values
        packets.append(
            dict(
                frame=int(frame),
                src=src,
                dst=dst,
                sport=int(sport),
                dport=int(dport),
                payload=bytes.fromhex(payload.replace(':', '')),
            )
        )
    return packets


# ------------------------------------------------------------------------------
def verify_captured_injections(tshark, pcap, records):
    """Find each injected packet in the capture by its endpoints and payload hash: a replay twice (original and copy), a
    tamper once.
    """
    packets = captured_packets(tshark, pcap)
    for record in records:
        frames = [
            packet['frame']
            for packet in packets
            if packet['src'] == record['source']
            and packet['dst'] == record['destination']
            and packet['sport'] == record['source_port']
            and packet['dport'] == record['destination_port']
            and hashlib.sha256(packet['payload']).hexdigest() == record['payload_sha256']
        ]
        if len(frames) < (2 if record['mode'] == 'replay' else 1):
            raise AssertionError('injected packet absent from scoped capture')
        record['captured_matching_frames'] = frames


# ------------------------------------------------------------------------------
def main():
    """Inject the four invalid packets during a protected call, check each is rejected and speech continues, and write
    integration/protected-negative-results.json.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--project', default=PROJECT)
    parser.add_argument('--tshark', default=os.environ.get('MCX_TSHARK') or shutil.which('tshark'))
    parser.add_argument('--capture-image', default='openmcx-dev:0.4')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    if args.compose is None or args.artifacts is None or not args.tshark:
        parser.error('--compose, --artifacts and tshark/MCX_TSHARK are required')
    compose = json.loads(args.compose.read_text())
    if compose.get('name') != args.project:
        parser.error('compose must identify the isolated protected fixture')
    project = args.project
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', project, '-f', str(args.compose.resolve())]
    output = args.artifacts.resolve() / 'integration'
    output.mkdir(parents=True, exist_ok=True)
    result = dict(
        scenario='protected-wire-replay-tamper',
        passed=False,
        checks=[],
        injections=[],
        limitations=[
            'Four bounded invalid packets test this isolated fixture, not exhaustive malformed-packet coverage.',
            'Rejection counters and continued speech are checked; no cryptographic keys are exported.',
        ],
    )
    capture_name = project + '-negative-capture-' + str(os.getpid())
    capture = None
    capture_file = None
    capture_log = None
    call_started = False
    roles = ['client-a', 'client-b', 'mcptt-server']
    auxiliaries = ['client-c', 'client-d']
    deaffiliated = []

    # ------------------------------------------------------------------------------
    def run(command, **kwargs):
        """Run a command, raising on failure, with a 20 s timeout."""
        return subprocess.run(command, check=True, capture_output=True, text=True, timeout=20, **kwargs)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=10):
        """Poll predicate every 0.1 s until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                result['checks'].append(label)
                return
            time.sleep(0.1)
        raise AssertionError(label)

    # ------------------------------------------------------------------------------
    def command(role, text):
        """Run one mcx-client command in a client container of the fixture (and only there)."""
        if role not in ('client-a', 'client-b', 'client-c', 'client-d'):
            raise ValueError('command target outside isolated test fixture')
        run(cli + ['exec', '-T', role, 'mcx-client', '--config', f'/config/{role}.json', '--command', text])

    try:
        containers = {}
        for role in roles + auxiliaries:
            identifier = run(cli + ['ps', '-q', role]).stdout.strip()
            if not identifier or '\n' in identifier:
                raise AssertionError('missing or ambiguous fixture container ' + role)
            info = json.loads(run(['docker', 'inspect', identifier]).stdout)[0]
            labels = info['Config']['Labels']
            if labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.service') != role:
                raise AssertionError('container does not belong to isolated fixture')
            networks = info['NetworkSettings']['Networks']
            if len(networks) != 1 or next(iter(networks)) != project + '_mcx':
                raise AssertionError('fixture container has unexpected network scope')
            containers[role] = dict(
                id=identifier, ip=next(iter(networks.values()))['IPAddress'], image=info['Config']['Image']
            )
        wait(
            'protected pair authorized and ready',
            lambda: all(
                status(role).get('authorized')
                and status(role).get('affiliated')
                and status(role).get('protected_media')
                and status(role).get('protected_floor')
                and status(role).get('protected_ready')
                for role in roles[:2]
            ),
            30,
        )
        if any(status(role).get('call_state') != 'idle' for role in roles[:2]) or status('mcptt-server').get(
            'participants'
        ):
            raise AssertionError('fixture must be idle before negative test')
        instance = status('mcptt-server')['instance_id']
        source = args.artifacts / 'speech/alpha.wav'
        target = args.artifacts / 'speech/protected-negative.wav'
        with wave.open(str(source), 'rb') as wav:
            params = wav.getparams()
            raw = wav.readframes(wav.getnframes())
        if not raw or params.nchannels != 1 or params.framerate != 16000 or params.sampwidth != 2:
            raise AssertionError('expected mono 16kHz PCM16 speech fixture')
        total = 16000 * 2 * 60
        with wave.open(str(target), 'wb') as wav:
            wav.setparams(params)
            wav.writeframes((raw * ((total + len(raw) - 1) // len(raw)))[:total])
        for role in auxiliaries:
            if status(role).get('affiliated') and status(role).get('group_id') == status('client-a').get('group_id'):
                command(role, 'deaffiliate')
                deaffiliated.append(role)
        wait(
            'auxiliary group members deaffiliated for two-party test',
            lambda: all(not status(role).get('affiliated') for role in deaffiliated),
        )
        command('client-a', 'call')
        call_started = True
        wait(
            'two protected call participants active',
            lambda: (
                all(status(role).get('call_state') == 'active' for role in roles[:2])
                and len(status('mcptt-server').get('participants', [])) == 2
            ),
            30,
        )
        pcap = output / 'protected-negative.pcap'
        capture_file = pcap.open('wb')
        capture_log = (output / 'protected-negative-capture.log').open('w')
        capture = subprocess.Popen(
            [
                'docker',
                'run',
                '--rm',
                '--name',
                capture_name,
                '--network',
                'container:' + containers['mcptt-server']['id'],
                '--cap-drop',
                'ALL',
                '--cap-add',
                'NET_RAW',
                '--security-opt',
                'no-new-privileges',
                '--entrypoint',
                'tcpdump',
                args.capture_image,
                '-Z',
                'root',
                '-p',
                '-n',
                '-i',
                'any',
                '-U',
                '-s',
                '0',
                '-w',
                '-',
                'udp and (host ' + containers['client-a']['ip'] + ' or host ' + containers['client-b']['ip'] + ')',
            ],
            stdout=capture_file,
            stderr=capture_log,
        )
        wait('scoped UDP capture started', lambda: pcap.exists() and pcap.stat().st_size >= 24, 10)
        baseline = status('client-b').get('received_packets', 0)
        command('client-a', 'ptt /artifacts/speech/protected-negative.wav')
        wait(
            'valid protected speech arrives before injection',
            lambda: (
                status('client-a').get('talking') and status('client-b').get('received_packets', 0) >= baseline + 25
            ),
            10,
        )
        snapshot = output / 'protected-negative-selection.pcap'
        selected = {}
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(selected) < 2:
            if complete_pcap(pcap, snapshot):
                for packet in captured_packets(args.tshark, snapshot):
                    try:
                        if (
                            packet['src'] == containers['mcptt-server']['ip']
                            and packet['dst'] == containers['client-b']['ip']
                        ):
                            parse_srtp(packet['payload'])
                            selected.setdefault('media', packet)
                        elif (
                            packet['src'] == containers['client-a']['ip']
                            and packet['dst'] == containers['mcptt-server']['ip']
                        ):
                            parse_srtcp(packet['payload'])
                            selected.setdefault('floor', packet)
                    except ValueError:
                        continue
            if len(selected) < 2:
                time.sleep(0.1)
        if len(selected) != 2:
            raise AssertionError('capture lacks both live protected packet directions')
        for channel, target_role, counter in [
            ('media', 'client-b', 'media_rejected_packets'),
            ('floor', 'mcptt-server', 'floor_rejected_packets'),
        ]:
            packet = selected[channel]
            for mode in ('replay', 'tamper'):
                payload = bytearray(packet['payload'])
                if mode == 'tamper':
                    if channel == 'media':
                        sequence = (int.from_bytes(payload[2:4], 'big') + 1000) & 65535
                        payload[2:4] = sequence.to_bytes(2, 'big')
                        payload[12] ^= 1
                    else:
                        index = (int.from_bytes(payload[-8:-4], 'big') & 0x7FFFFFFF) + 1000
                        payload[-8:-4] = (0x80000000 | index).to_bytes(4, 'big')
                        payload[8] ^= 1
                before = status(target_role).get(counter, 0)
                delivered = status('client-b').get('received_packets', 0)
                if not status('client-a').get('talking'):
                    raise AssertionError('valid floor ended before negative injection')
                raw = ipv4_udp(packet['src'], packet['dst'], packet['sport'], packet['dport'], payload)
                injection = run(
                    [
                        'docker',
                        'run',
                        '--rm',
                        '-i',
                        '--network',
                        'container:' + containers['mcptt-server']['id'],
                        '--cap-drop',
                        'ALL',
                        '--cap-add',
                        'NET_RAW',
                        '--security-opt',
                        'no-new-privileges',
                        '--entrypoint',
                        'python3',
                        containers['mcptt-server']['image'],
                        '-c',
                        RAW_PROGRAM,
                    ],
                    input=json.dumps(dict(packet=base64.b64encode(raw).decode('ascii'), destination=packet['dst'])),
                )
                if json.loads(injection.stdout).get('bytes_sent') != len(raw):
                    raise AssertionError('raw packet injection incomplete')
                wait(
                    channel + ' ' + mode + ' rejected',
                    lambda role=target_role, name=counter, previous=before: status(role).get(name, 0) >= previous + 1,
                    6,
                )
                # The injected packet is the only one rejected: a valid call rejects nothing else meanwhile.
                if not holds(
                    lambda role=target_role, name=counter, previous=before: status(role).get(name, 0) == previous + 1, 1
                ):
                    raise AssertionError(f'{channel} {mode}: {counter} rose by more than the injected packet')
                wait(
                    'valid speech continues after ' + channel + ' ' + mode,
                    lambda: (
                        status('client-b').get('received_packets', 0) >= delivered + 10
                        and status('client-a').get('call_state') == 'active'
                        and status('client-b').get('call_state') == 'active'
                    ),
                    5,
                )
                result['injections'].append(
                    dict(
                        channel=channel,
                        mode=mode,
                        captured_frame=packet['frame'],
                        source=packet['src'],
                        destination=packet['dst'],
                        source_port=packet['sport'],
                        destination_port=packet['dport'],
                        payload_sha256=hashlib.sha256(payload).hexdigest(),
                        counter=counter,
                        rejected_delta=status(target_role).get(counter, 0) - before,
                        subsequent_speech_packets=status('client-b').get('received_packets', 0) - delivered,
                    )
                )
        if status('mcptt-server').get('instance_id') != instance:
            raise AssertionError('server restarted during invalid traffic')
        result['checks'].append('server instance unchanged after all four injections')
        result['passed'] = True
    except (AssertionError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    finally:
        if call_started:
            try:
                command('client-a', 'release')
                command('client-a', 'hangup')
                wait(
                    'test call cleaned up',
                    lambda: all(status(role).get('call_state') == 'idle' for role in roles[:2]),
                    10,
                )
            except (AssertionError, OSError, subprocess.SubprocessError) as error:
                result['cleanup_error'] = str(error)
                result['passed'] = False
        if deaffiliated:
            try:
                for role in deaffiliated:
                    command(role, 'affiliate')
                wait(
                    'auxiliary affiliation restored',
                    lambda: all(status(role).get('affiliated') for role in deaffiliated),
                    15,
                )
            except (AssertionError, OSError, subprocess.SubprocessError) as error:
                result['affiliation_cleanup_error'] = str(error)
                result['passed'] = False
        if capture is not None:
            try:
                run(['docker', 'stop', '--time', '3', capture_name])
                capture.wait(timeout=5)
            except (OSError, subprocess.SubprocessError) as error:
                result['capture_cleanup_error'] = str(error)
                result['passed'] = False
        if capture_file:
            capture_file.close()
        if capture_log:
            capture_log.close()
        if result['passed']:
            try:
                verify_captured_injections(args.tshark, output / 'protected-negative.pcap', result['injections'])
                result['checks'].append('all injected packet fingerprints independently found in scoped capture')
            except (AssertionError, ValueError, OSError, subprocess.SubprocessError) as error:
                result['capture_verification_error'] = str(error)
                result['passed'] = False
        result['status'] = {role: status(role) for role in roles}
        (output / 'protected-negative-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
