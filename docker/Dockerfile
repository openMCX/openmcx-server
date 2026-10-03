# openMCX server images: one build stage, then one slim image per program (docs/BUILD.md, docs/IMAGES.md).
#
#   tools/build-images [TAG]                                   all targets, tagged openmcx-<target>:TAG
#   docker build --target openmcx-mcptt-server -t openmcx-mcptt-server:TAG -f docker/Dockerfile .
#
# Targets: openmcx-mcptt-server, openmcx-mcvideo-server, openmcx-mcdata-server, openmcx-common (the common services
# and the key tool), openmcx-http-proxy, openmcx-user-db; openmcx-all holds every program (the former single image).
# The build stage runs on the development image (docker/Dockerfile.dev: compilers, pjsip, wolfSSL, Go); each runtime
# image is Ubuntu with only its program's run-time packages and the program stripped of its debug information (the
# machine code is the same -O2 build), plus curl and Python for the lab's health checks.

ARG DEV_IMAGE=openmcx-dev:0.1
ARG RUNTIME_BASE=ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
# The Ubuntu release of RUNTIME_BASE and of the development image; its package names are in docker/packages.
ARG UBUNTU=24.04

#------------------------------------------------------------------------------
# Build: Go services and tests, C++ programs and unit tests; stripped copies in /install/stripped.
FROM ${DEV_IMAGE} AS build
COPY services /services
RUN cd /services && go test ./... && go build -trimpath -o /install/bin/mcx-common ./cmd/mcx-common \
    && go build -trimpath -o /install/bin/mcx-http-proxy ./cmd/mcx-http-proxy
COPY CMakeLists.txt /src/CMakeLists.txt
COPY include /src/include
COPY src /src/src
COPY tests /src/tests
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    && cmake --build /build -j4 \
    && ctest --test-dir /build --output-on-failure -E diameter_sctp \
    && cmake --install /build --prefix /install \
    && mkdir -p /install/stripped \
    && for program in /install/bin/*; do strip --strip-debug -o /install/stripped/$(basename $program) $program; done

#------------------------------------------------------------------------------
# Runtime base: the health check tools (curl for the HTTPS services, Python for the status-file check).
FROM ${RUNTIME_BASE} AS runtime
ARG UBUNTU
ENV DEBIAN_FRONTEND=noninteractive UBUNTU=${UBUNTU}
COPY docker/packages /usr/local/bin/packages
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" runtime) \
    && rm -rf /var/lib/apt/lists/*
COPY tools/healthcheck.py /healthcheck.py
WORKDIR /workspace

#------------------------------------------------------------------------------
# MCPTT server (TS 24.379, TS 24.380): SIP and media, HTTP to the common services, Diameter to the user database.
FROM runtime AS openmcx-mcptt-server
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" mcptt) \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/stripped/openmcx-mcptt-server /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/openmcx-mcptt-server"]

#------------------------------------------------------------------------------
# MCVideo server (TS 24.281, TS 24.581): as the MCPTT server.
FROM runtime AS openmcx-mcvideo-server
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" mcptt) \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/stripped/openmcx-mcvideo-server /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/openmcx-mcvideo-server"]

#------------------------------------------------------------------------------
# MCData server (TS 24.282, TS 24.582).
FROM runtime AS openmcx-mcdata-server
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" mcdata) \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/stripped/openmcx-mcdata-server /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/openmcx-mcdata-server"]

#------------------------------------------------------------------------------
# Common services (IdMS, GMS, CMS, KMS, LMS, message store, content and notification servers, IS proxy, Credential
# Service; one role per container) with the key tool the KMS, GMS and IS proxy run.
FROM runtime AS openmcx-common
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" common) \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/stripped/mcx-common /install/stripped/mcx-keytool /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/mcx-common"]

#------------------------------------------------------------------------------
# HTTP proxy (TS 24.482 annex A.2.2.2): a Go program, linked to libxml2 for the XML schema checks it shares with the
# common services.
FROM runtime AS openmcx-http-proxy
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" http-proxy) \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/stripped/mcx-http-proxy /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/mcx-http-proxy"]

#------------------------------------------------------------------------------
# User database: MCPTT user profiles over Diameter (TS 29.283).
FROM runtime AS openmcx-user-db
RUN apt-get update && apt-get install -y --no-install-recommends $(packages "$UBUNTU" user-db) \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /install/stripped/mcx-user-db /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/mcx-user-db"]

#------------------------------------------------------------------------------
# Every program in one image, as before the split (labs run with --image, and comparisons with older images); the
# last stage, so a plain docker build without --target still gives it.
FROM ${DEV_IMAGE} AS openmcx-all
COPY --from=build /install/bin/ /usr/local/bin/
COPY tools/healthcheck.py /healthcheck.py
WORKDIR /workspace
CMD ["openmcx-mcptt-server"]
