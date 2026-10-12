#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The OpenMCX chart's configuration Secret.

In the cluster (the chart's setup Job, in the openmcx-setup image): when the Secret does not exist, write a new
system's configuration with the tutorial's setup (/opt/tutorials/configure.py, for HOST_IP), set the external ports
the chart exposes, and create the Secret. An existing Secret is kept: a new configuration is a new CA, which no
activated phone trusts.

From a directory (a tutorial's ./config, written by its setup container): print the Secret as JSON, for
`kubectl apply -f -`:

    python3 openmcx-config.py --from-dir tutorials/end-to-end/01-mcx-over-wlan-android/config \
        --name openmcx-config --namespace openmcx | kubectl apply -f -

The Secret's keys are the configuration's file names; the pods mount the files they need at their Compose paths.
"""

import argparse
import base64
import json
import os
import pathlib
import re
import runpy
import ssl
import sys
import tempfile
import urllib.error
import urllib.request

# The external ports and media of tutorial 1 (configure.py writes these).
DEFAULT_PORTS = {'sip': 5061, 'idms': 8443, 'httpProxy': 8444, 'kms': 8445, 'admin': 8446, 'credentials': 8447}
DEFAULT_MEDIA = {'mcptt': {'rtpPort': 4000, 'floorPort': 5000},
                 'mcvideo': {'rtpPort': 7000, 'floorPort': 7200, 'videoPort': 7400}}
MEDIA_FIELDS = {'rtpPort': 'rtp_port', 'floorPort': 'floor_port', 'videoPort': 'video_port'}

# Files every pod set needs; the Secret is refused without them.
REQUIRED = [
    'site.json', 'oidc-private.pem', 'oidc-public.pem', 'kamailio.cfg', 'tls.cfg', 'http-proxy.json',
    'diameter-server.conf', 'diameter-user-db.conf', 'mcptt-server.json', 'mcdata-server.json', 'mcvideo-server.json',
    'mcxadmin.json', 'mcxadmin-dsn', 'credentials-dsn', 'server-secret', 'mysql-password', 'mysql-root-password',
    'sip-db.sql', 'mcxadmin.sql', 'ca.crt', 'issuer.ca.key', 'devices.crl', 'idms-credentials.json',
] + [f'{name}.{ext}' for name in (
    'sip-core', 'idms', 'gms', 'cms', 'kms', 'lms', 'credentials', 'content-server', 'message-store',
    'notification-server', 'http-proxy', 'mcx-user-db', 'mcptt-server', 'mcdata-server', 'mcvideo-server', 'mcxadmin',
) for ext in ('crt', 'key')]

SA = pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')


def secret_files(config):
    """The configuration's files by Secret key: the top-level files, the servers' certificates and keys, the
    Credential Service's CA key, the device CRL and IdMS's credential file. Not the test clients' files, the CA's
    own working files or runtime state."""
    files = {}
    for path in sorted(config.rglob('*')):
        if not path.is_file():
            continue
        parts = path.relative_to(config).parts
        if len(parts) == 1:
            if re.fullmatch(r'client-[a-z]\.json|ADMIN\.txt', parts[0]):
                continue
            key = parts[0]
        elif parts[0] == 'tls' and len(parts) == 2:
            if parts[1].startswith('client-') or parts[1] in ('ca.key', 'ca.srl'):
                continue
            key = parts[1]
        elif parts == ('issuer', 'ca.key'):
            key = 'issuer.ca.key'
        elif parts == ('crl', 'devices.crl'):
            key = 'devices.crl'
        elif parts == ('idms-data', 'idms-credentials.json'):
            key = 'idms-credentials.json'
        else:
            continue
        files[key] = path.read_bytes()
    missing = [key for key in REQUIRED if key not in files]
    if missing:
        sys.exit(f'not a complete openMCX configuration: missing {", ".join(missing)} (a directory a system '
                 'has run with holds root-owned files: read it with sudo)')
    admin = config / 'ADMIN.txt'
    if admin.is_file():
        files['ADMIN.txt'] = admin.read_bytes()
    return files


def set_ports(config, host, ports, media):
    """Write the chart's external ports into the configuration, where they differ from the tutorial's: MCX Admin's
    activation codes and console, IdMS's links and redirect URIs, the console's address in ADMIN.txt, and the MC
    servers' media ports (announced in SDP)."""
    remap = {DEFAULT_PORTS[name]: int(ports.get(name, DEFAULT_PORTS[name])) for name in DEFAULT_PORTS}
    pattern = re.compile(re.escape(host) + r':(\d+)\b')
    for name in ('mcxadmin.json', 'site.json', 'ADMIN.txt'):
        path = config / name
        if not path.is_file():
            continue
        text = path.read_text()
        path.write_text(pattern.sub(lambda m: f'{host}:{remap.get(int(m[1]), m[1])}', text))
    for service in ('mcptt', 'mcvideo'):
        path = config / f'{service}-server.json'
        cfg = json.loads(path.read_text())
        for field, value in {**DEFAULT_MEDIA[service], **media.get(service, {})}.items():
            cfg['media'][MEDIA_FIELDS[field]] = int(value)
        path.write_text(json.dumps(cfg, indent=2) + '\n')


def manifest(name, namespace, files, host, ports, media):
    metadata = {
        'name': name,
        'labels': {'app.kubernetes.io/name': 'openmcx', 'app.kubernetes.io/component': 'config'},
        'annotations': {
            'openmcx.org/external-address': host,
            'openmcx.org/external-ports': json.dumps({'ports': ports, 'media': media}, sort_keys=True),
        },
    }
    if namespace:
        metadata['namespace'] = namespace
    return {
        'apiVersion': 'v1',
        'kind': 'Secret',
        'metadata': metadata,
        'type': 'Opaque',
        'data': {key: base64.b64encode(value).decode() for key, value in sorted(files.items())},
    }


def api(method, path, body=None):
    """A request to the Kubernetes API with the pod's service account."""
    url = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT']}{path}"
    request = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode())
    request.add_header('Authorization', 'Bearer ' + (SA / 'token').read_text().strip())
    request.add_header('Content-Type', 'application/json')
    context = ssl.create_default_context(cafile=str(SA / 'ca.crt'))
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return response.status, json.loads(response.read() or b'{}')
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b'{}')


def generate(host):
    """Run the tutorial's setup into /work/config, as `docker compose run --rm setup` does. It hands the files to
    /work's owner, which an unprivileged pod (OpenShift) cannot and need not do: here they are read once, as they are."""
    os.environ['HOST_IP'] = host
    os.environ.setdefault('HOME', tempfile.gettempdir())
    if os.geteuid() != 0:
        os.chown = lambda *args, **kwargs: None
    try:
        runpy.run_path('/opt/tutorials/configure.py', run_name='__main__')
    except SystemExit as stop:
        if stop.code not in (None, 0):
            raise
    return pathlib.Path('/work/config')


def in_cluster(args, host, ports, media):
    namespace = args.namespace or (SA / 'namespace').read_text().strip()
    base = f'/api/v1/namespaces/{namespace}/secrets'
    status, existing = api('GET', f'{base}/{args.name}')
    if status == 200:
        annotations = existing.get('metadata', {}).get('annotations', {})
        was = annotations.get('openmcx.org/external-address')
        if was and was != host:
            sys.exit(
                f'Secret {namespace}/{args.name} holds a configuration for {was}, not externalAddress {host}. '
                'Set externalAddress back, or delete the Secret for a new system (new CA: activate the phones again).'
            )
        print(f'Secret {namespace}/{args.name} exists ({was or "address unknown"}): kept.')
        return
    if status != 404:
        sys.exit(f'reading Secret {namespace}/{args.name}: HTTP {status} {existing.get("message", "")}')
    config = generate(host)
    set_ports(config, host, ports, media)
    body = manifest(args.name, namespace, secret_files(config), host, ports, media)
    status, answer = api('POST', base, body)
    if status not in (200, 201):
        sys.exit(f'creating Secret {namespace}/{args.name}: HTTP {status} {answer.get("message", "")}')
    print(f'Secret {namespace}/{args.name} created for {host}. The administrator\'s password:\n'
          f'  kubectl -n {namespace} get secret {args.name} -o jsonpath=\'{{.data.ADMIN\\.txt}}\' | base64 -d')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--from-dir', type=pathlib.Path, help='print the Secret of this configuration directory')
    parser.add_argument('--name', default=os.environ.get('OPENMCX_SECRET', 'openmcx-config'))
    parser.add_argument('--namespace', default=os.environ.get('OPENMCX_NAMESPACE', ''))
    parser.add_argument('--host', default=os.environ.get('HOST_IP', ''),
                        help="the external address (from a directory: the one it was made for, from mcxadmin.json)")
    parser.add_argument('--ports', default=os.environ.get('OPENMCX_PORTS', '{}'), help='JSON: expose.ports')
    parser.add_argument('--media', default=os.environ.get('OPENMCX_MEDIA', '{}'), help='JSON: expose.media')
    args = parser.parse_args()
    ports = {**DEFAULT_PORTS, **{k: int(v) for k, v in json.loads(args.ports).items()}}
    given = json.loads(args.media)
    media = {service: {**DEFAULT_MEDIA[service], **{k: int(v) for k, v in given.get(service, {}).items()}}
             for service in DEFAULT_MEDIA}
    if args.from_dir:
        host = args.host or json.loads((args.from_dir / 'mcptt-server.json').read_text())['media']['advertise']
        with tempfile.TemporaryDirectory() as tmp:
            # Work on a copy: the directory stays as the tutorial's Compose file uses it.
            config = pathlib.Path(tmp) / 'config'
            config.mkdir()
            for key_path in args.from_dir.rglob('*'):
                target = config / key_path.relative_to(args.from_dir)
                if key_path.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                elif key_path.is_file() and os.access(key_path, os.R_OK):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(key_path.read_bytes())
            set_ports(config, host, ports, media)
            json.dump(manifest(args.name, args.namespace, secret_files(config), host, ports, media), sys.stdout, indent=2)
            print()
        return
    if not args.host:
        sys.exit('HOST_IP (externalAddress) is not set')
    in_cluster(args, args.host, ports, media)


if __name__ == '__main__':
    main()
