#!/usr/bin/env python3
# Tutorial tooling: turns a lab that tools/prepare-prearranged-test.py generated into the Docker Compose file of a
# unit test tutorial (tutorials/unit-tests/NN-*/). It implements no 3GPP procedure.
"""Write a unit test tutorial's compose file from a generated lab's compose.json.

The tutorial runs the same lab as the regression, from the published images: its setup service runs the same
generator with the same flags inside openmcx-setup and copies the generated configuration to ./config. This tool
rewrites the lab's compose.json for that: published image names, ./config instead of the generated directory, named
volumes instead of ./artifacts (the images run as root), a fixed address per role (so the capture reads by role), and
a capture service that records the lab's bridge with tcpdump.

  tools/tutorial-compose.py LAB/compose.json tutorials/unit-tests/01-group-call-basics --number 1 --title '...' \\
      --capture 01-group-call-full [-- FLAGS]
"""

import argparse
import json
from pathlib import Path

import yaml

# The published openMCX images on Docker Hub, written out in full in the tutorial (no variables): the tag of the
# openMCX programs and the SIP core's own version.
HUB = 'docker.io/openmcx'
OPENMCX_TAG = 'v1'
KAMAILIO_TAG = '6.1.4-2'
# The published image of each program of the lab's all-in-one image.
PROGRAMS = {
    'mcx-common': 'openmcx-common',
    'mcx-http-proxy': 'openmcx-http-proxy',
    'mcx-user-db': 'openmcx-user-db',
    'openmcx-mcptt-server': 'openmcx-mcptt-server',
    'openmcx-mcdata-server': 'openmcx-mcdata-server',
    'openmcx-mcvideo-server': 'openmcx-mcvideo-server',
}
# tcpdump, published on Docker Hub (openmcx-dev, which has it, is not); pinned by digest.
NETSHOOT = 'docker.io/nicolaka/netshoot@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b'
# The lab's address plan: the last octet of each role on the tutorial's /24.
ADDRESSES = {
    'sip-core': 10,
    'mcptt-server': 20,
    'mcdata-server': 21,
    'mcvideo-server': 22,
    'sip-db': 30,
    'mcx-user-db': 31,
    'idms': 40,
    'gms': 41,
    'cms': 42,
    'kms': 43,
    'lms': 44,
    'http-proxy': 45,
    'content-server': 46,
    'message-store': 47,
    'notification-server': 48,
    'credentials': 49,
    'mcxadmin': 50,
    'client-a': 101,
    'client-b': 102,
    'client-c': 103,
    'client-d': 104,
    'client-e': 105,
}
# Every leg in clear: SIP (with SDP, MIKEY and XML bodies) on 5060/tcp, every UDP flow (RTP, RTCP, floor control,
# MCVideo; their ports come from the SDP), and ICMP (media sent to a closed port). DNS and HTTPS (TLS) are left out,
# and so is the host's own traffic on the bridge (its gateway address .1: mDNS, WS-Discovery).
DEFAULT_FILTER = 'tcp port 5060 or (udp and not port 53) or icmp'


# ------------------------------------------------------------------------------
def capture_filter(protocols, subnet):
    """The tcpdump filter: the protocols, between the lab's containers only (IPv4, not the gateway)."""
    return f'ip and not host {subnet}.1 and ({protocols})'


# ------------------------------------------------------------------------------
class Dumper(yaml.SafeDumper):
    """Short lists of plain values on one line, as a person writes them."""


def represent_list(dumper, data):
    """A list in flow style when it is short and holds only plain values."""
    flow = all(isinstance(item, (str, int)) for item in data) and len(json.dumps(data)) <= 80
    return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=flow)


Dumper.add_representer(list, represent_list)


# ------------------------------------------------------------------------------
def image(name, entrypoint):
    """The published image for a lab image name; the lab's all-in-one image (openmcx:TAG) by the program it runs."""
    if name.startswith('mysql@'):
        return 'docker.io/library/' + name
    program, tag = name.split(':', 1)
    if program == 'openmcx-kamailio':
        return f'{HUB}/openmcx-kamailio:{KAMAILIO_TAG}'
    if program == 'openmcx':
        program = PROGRAMS[Path(entrypoint[0]).name]
    return f'{HUB}/{program}:{OPENMCX_TAG}'


# ------------------------------------------------------------------------------
def volume(entry, generated):
    """A lab volume as a short-syntax tutorial volume; status files go to the named volume 'status'."""
    if entry['type'] == 'volume':
        return f"{entry['source']}:{entry['target']}"
    source = entry['source']
    if source.endswith('/artifacts'):
        return f"status:{entry['target']}"
    assert source.startswith(generated + '/'), source
    return f"./config/{source[len(generated) + 1 :]}:{entry['target']}" + (':ro' if entry.get('read_only') else '')


# ------------------------------------------------------------------------------
def main():
    """Read the lab, write the tutorial's compose file."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('lab', type=Path, help="the generated lab's compose.json")
    parser.add_argument('tutorial', type=Path, help='the tutorial folder')
    parser.add_argument('--number', required=True, help='the unit test tutorial number, e.g. 1')
    parser.add_argument('--title', required=True)
    parser.add_argument('--capture', required=True, help='the capture file name, without .pcap')
    parser.add_argument('--filter', default=DEFAULT_FILTER, help='the tcpdump capture filter')
    parser.add_argument('flags', nargs='*', help='the generator flags of the lab (after --)')
    args = parser.parse_args()
    lab = json.loads(args.lab.read_text())
    # The generator ran in the setup image with --directory /work/lab.
    generated = '/work/lab/generated'
    # Unit test tutorial N: project openmcx-utNN on 172.31.N.0/24, bridge openmcx-utNN; tutorials can run side by side.
    number = f'{int(args.number):02d}'
    subnet = f'172.31.{int(args.number)}'
    bridge = f'openmcx-ut{number}'
    flags = ' '.join(['--debug-sip', *args.flags])

    services = {
        # One-off: the lab's generator, as the regression runs it, writes ./config. Not started by `up`.
        'setup': {
            'image': f'{HUB}/openmcx-setup:{OPENMCX_TAG}',
            'profiles': ['setup'],
            'entrypoint': ['sh', '-c'],
            'command': [
                'set -e; '
                'if [ -e /work/config ]; then echo "./config exists: remove it to start over" >&2; exit 1; fi; '
                f'python3 /opt/mcxserver/tools/prepare-prearranged-test.py --directory /tmp/lab {flags} >/dev/null; '
                'cp -r /tmp/lab/generated /work/config; chown -R "$$(stat -c %u:%g /work)" /work/config; '
                'echo "wrote ./config (certificates last 30 days)"'
            ],
            'volumes': ['.:/work'],
            'network_mode': 'none',
        },
        # tcpdump on the lab's bridge: every leg between the containers. run.sh copies the file out.
        'capture': {
            'image': NETSHOOT,
            'network_mode': 'host',
            'cap_add': ['NET_RAW', 'NET_ADMIN'],
            'command': [
                'tcpdump',
                '-Z',
                'root',
                '-i',
                bridge,
                '-U',
                '-s',
                '0',
                '-w',
                f'/captures/{args.capture}.pcap',
                capture_filter(args.filter, subnet),
            ],
            'volumes': ['captures:/captures'],
            'depends_on': {'sip-core': {'condition': 'service_started'}},
        },
    }
    for name, lab_service in sorted(lab['services'].items(), key=lambda item: ADDRESSES[item[0]]):
        service = {'image': image(lab_service['image'], lab_service.get('entrypoint') or [''])}
        for key in ('profiles', 'entrypoint', 'command', 'environment', 'init', 'tmpfs', 'healthcheck'):
            if lab_service.get(key) is not None:
                service[key] = lab_service[key]
        service['networks'] = {'mcx': {'ipv4_address': f'{subnet}.{ADDRESSES[name]}'}}
        service['volumes'] = [volume(entry, generated) for entry in lab_service.get('volumes', [])]
        # The spoken test messages, for tutorials that send speech (without the folder, Docker would create an
        # empty root-owned one in the reader's checkout).
        if name.startswith('client-') and (args.tutorial / 'speech').is_dir():
            service['volumes'].append('./speech:/speech:ro')
        depends = {
            other: {'condition': condition['condition']}
            for other, condition in lab_service.get('depends_on', {}).items()
        }
        if depends:
            service['depends_on'] = depends
        services[name] = service
    services['client-a']['depends_on']['capture'] = {'condition': 'service_started'}

    compose = {
        'name': f'openmcx-ut{number}',
        'services': services,
        'networks': {
            'mcx': {
                'driver_opts': {'com.docker.network.bridge.name': bridge},
                'ipam': {'config': [{'subnet': f'{subnet}.0/24'}]},
            }
        },
        'volumes': {name: None for name in sorted({*lab.get('volumes', {}), 'status', 'captures'})},
    }
    servers = [
        label
        for name, label in (('mcptt-server', 'MCPTT'), ('mcdata-server', 'MCData'), ('mcvideo-server', 'MCVideo'))
        if name in lab['services']
    ]
    roles = ('sip-core', 'mcptt-server', *(['mcvideo-server'] if 'mcvideo-server' in lab['services'] else []),
             'client-a', 'client-b', 'client-c', 'client-d')
    first_line = len(roles) - 3
    header = [
        f'# openMCX: {args.title} (tutorials/unit-tests/{args.tutorial.name}/README.md).',
        '#',
        '# The regression lab of this feature, from the published images: the '
        + ' and '.join([', '.join(servers[:-1]), servers[-1]] if len(servers) > 1 else servers)
        + ' servers, the common',
        '# services, the SIP core and four headless clients (client-a to client-d), with SIP in clear (5060/tcp, no',
        f'# TLS) and a capture of the lab network ({bridge}) for Wireshark. Nothing is published on this computer.',
        '#',
        '#   docker compose run --rm setup      once: writes ./config',
        '#   docker compose up -d --wait',
        '#   ./run.sh                           the steps; copies the capture to captures/',
        '#',
        f'# Addresses on {subnet}.0/24: ' + ', '.join(f'{role} .{ADDRESSES[role]}' for role in roles[:first_line]) + ',',
        '# ' + ', '.join(f'{role} .{ADDRESSES[role]}' for role in roles[first_line:]) + '.',
        '# Generated by tools/tutorial-compose.py from the lab of tools/prepare-prearranged-test.py ' + flags + '.',
        '',
    ]
    text = yaml.dump(compose, Dumper=Dumper, sort_keys=False, width=120, default_flow_style=False)
    (args.tutorial / 'docker-compose.yaml').write_text('\n'.join(header) + text.replace(': null\n', ':\n'))


if __name__ == '__main__':
    main()
