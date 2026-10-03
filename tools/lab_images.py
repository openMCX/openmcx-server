"""The per-program images of the lab (docker/Dockerfile targets, docs/IMAGES.md): which image runs which program.

Used by the lab preparation tools for --images TAG: every service of the openMCX application image runs the image
of the program its entrypoint starts. openMCX lab tooling, no 3GPP behaviour.
"""

from pathlib import PurePosixPath

# The program a service's entrypoint starts -> the docker/Dockerfile target (image name) holding it.
PROGRAM_IMAGES = {
    'openmcx-mcptt-server': 'openmcx-mcptt-server',
    'openmcx-mcvideo-server': 'openmcx-mcvideo-server',
    'openmcx-mcdata-server': 'openmcx-mcdata-server',
    'mcx-common': 'openmcx-common',
    'mcx-http-proxy': 'openmcx-http-proxy',
    'mcx-user-db': 'openmcx-user-db',
}

# The image each regression summary identifies the run by (the programs most labs exercise).
SUMMARY_IMAGES = ['openmcx-mcptt-server', 'openmcx-mcvideo-server', 'openmcx-mcdata-server', 'openmcx-common']


# ------------------------------------------------------------------------------
def use_program_images(services, application_image, tag):
    """Give every service that runs application_image the image of its program, tagged tag; an error for a service
    whose entrypoint names no known program."""
    for name, service in services.items():
        if service.get('image') != application_image:
            continue
        entrypoint = service.get('entrypoint') or []
        program = PurePosixPath(entrypoint[0]).name if entrypoint else ''
        if program not in PROGRAM_IMAGES:
            raise RuntimeError(f'service {name}: no per-program image for entrypoint {entrypoint}')
        service['image'] = f'{PROGRAM_IMAGES[program]}:{tag}'
