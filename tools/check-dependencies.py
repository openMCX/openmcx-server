#!/usr/bin/env python3
"""Check that the pinned archives the Dockerfiles fetch are those of dependencies.lock.json.

Each Dockerfile names an archive with three build arguments, <NAME>_FILE, <NAME>_URL and <NAME>_SHA256 (fetched by
docker/fetch). Every such triple must equal an entry of the lock file marked "use": "image", and every such entry
must be used by a Dockerfile, so that the lock file stays the one list of what the builds download. Exits 1 on any
difference. The Ubuntu base images are pinned the same way: "base_images" lists each supported release, "base_image"
is the default, which every Dockerfile's BASE_IMAGE/RUNTIME_BASE default must equal, and docker/packages must have a
package list for every release. openMCX build tooling, no 3GPP behaviour.

  tools/check-dependencies.py
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------------------
def dockerfile_archives():
    """The (file, url, sha256) triples of the build arguments in docker/Dockerfile*, with the Dockerfile naming them."""
    found = {}
    for dockerfile in sorted((ROOT / 'docker').glob('Dockerfile*')):
        arguments = dict(re.findall(r'^ARG (\w+)=(\S*)$', dockerfile.read_text(), re.MULTILINE))
        for name in arguments:
            if name.endswith('_FILE'):
                prefix = name[: -len('_FILE')]
                triple = (arguments[name], arguments.get(f'{prefix}_URL'), arguments.get(f'{prefix}_SHA256'))
                found[triple] = dockerfile.name
    return found


# ------------------------------------------------------------------------------
def base_image_problems(lock):
    """Differences between the pinned Ubuntu base images and the Dockerfiles' defaults and docker/packages."""
    problems = []
    default, releases = lock['base_image'], lock.get('base_images', {})
    if default not in releases.values():
        problems.append(f'dependencies.lock.json: base_image {default} is not one of base_images')
    for release, image in releases.items():
        if not image.startswith(f'ubuntu:{release}@sha256:'):
            problems.append(f'dependencies.lock.json: base_images {release} is {image}')
    packages = (ROOT / 'docker' / 'packages').read_text()
    problems += [
        f'docker/packages: no package list for {release}' for release in releases if f'{release})' not in packages
    ]
    for dockerfile in sorted((ROOT / 'docker').glob('Dockerfile*')):
        arguments = dict(re.findall(r'^ARG (\w+)=(\S*)$', dockerfile.read_text(), re.MULTILINE))
        for name in ('BASE_IMAGE', 'RUNTIME_BASE'):
            if name in arguments and arguments[name] != default:
                problems.append(f'{dockerfile.name}: {name} is not the base_image of dependencies.lock.json')
        # docker/Dockerfile.centos: the CentOS Stream builder and runtime images ("centos_images").
        for name, key in (('BUILDER_IMAGE', 'builder'), ('RUNTIME_IMAGE', 'runtime')):
            if name in arguments and arguments[name] != lock.get('centos_images', {}).get(key):
                problems.append(f'{dockerfile.name}: {name} is not centos_images.{key} of dependencies.lock.json')
    return problems


# ------------------------------------------------------------------------------
def main():
    """Compare the Dockerfiles with the lock file and report each difference."""
    lock = json.loads((ROOT / 'dependencies.lock.json').read_text())['software']
    pinned = {(item['file'], item['url'], item['sha256']) for item in lock if item.get('use') == 'image'}
    used = dockerfile_archives()
    problems = [
        f'{dockerfile}: {triple[0]} is not pinned as such in dependencies.lock.json'
        for triple, dockerfile in used.items()
        if triple not in pinned
    ]
    problems += [f'dependencies.lock.json: {triple[0]} is used by no Dockerfile' for triple in pinned - used.keys()]
    problems += base_image_problems(json.loads((ROOT / 'dependencies.lock.json').read_text()))
    for problem in problems:
        print(problem)
    print(f'{len(used)} archives checked, {len(problems)} differences')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
