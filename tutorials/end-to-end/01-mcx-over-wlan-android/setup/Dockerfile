#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# The tutorial's setup image: it writes a new system's configuration (CA and certificates, users, servers, MCX Admin)
# with the lab's own generator, then sets it up for phones on the same network as this computer (configure.py).
#
#   docker build -f tutorials/end-to-end/01-mcx-over-wlan-android/setup/Dockerfile -t openmcx-setup:TAG .          (from the repository root)

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && rm -rf /var/lib/apt/lists/*

# The generator renders docker/compose/compose.yaml with Docker Compose (no Docker daemon is needed for that); the
# version and checksum of dependencies/lock.json.
ARG COMPOSE_URL=https://github.com/docker/compose/releases/download/v2.40.3/docker-compose-linux-x86_64
ARG COMPOSE_SHA256=dba9d98e1ba5bfe11d88c99b9bd32fc4a0624a30fafe68eea34d61a3e42fd372
RUN mkdir -p /opt/mcxserver/.cache/deps \
    && curl -fsSL -o /opt/mcxserver/.cache/deps/docker-compose-linux-x86_64 "$COMPOSE_URL" \
    && echo "$COMPOSE_SHA256  /opt/mcxserver/.cache/deps/docker-compose-linux-x86_64" | sha256sum -c - \
    && chmod +x /opt/mcxserver/.cache/deps/docker-compose-linux-x86_64

COPY config/lab.json /opt/mcxserver/config/lab.json
COPY docker /opt/mcxserver/docker
COPY tools /opt/mcxserver/tools
COPY tutorials/end-to-end/01-mcx-over-wlan-android/setup /opt/tutorials
# Tutorial 7 (Keycloak as IdMS) runs the same image with its own configure.py.
COPY tutorials/end-to-end/07-keycloak-idms/setup /opt/tutorials-07
COPY LICENSE NOTICE /usr/share/doc/openmcx/
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/openMCX/openmcx-server"
ENTRYPOINT ["python3", "/opt/tutorials/configure.py"]
