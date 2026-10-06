# Open5GS v2.8.0 for tutorial 5, with openMCX's PCRF patch (patches/open5gs/, NOTICE): the source is pinned to the
# commit of the release tag (the build stops if the tag no longer points to it) and built on the Debian release of
# gradiant/open5gs:2.8.0, whose binaries and libraries it replaces; the rest of that image (entrypoint, user, layout)
# is kept. Open5GS is under the GNU AGPL v3 (https://github.com/open5gs/open5gs).
#   open5gs/build-images.sh             ->  open5gs:2.8.0-mcx
ARG BASE=gradiant/open5gs:2.8.0@sha256:1942954babfe6dd5094c8047d8dec26009c67168471115136cd0195a3dc11187

FROM debian:bullseye AS build
ARG OPEN5GS_TAG=v2.8.0
ARG OPEN5GS_COMMIT=157f611a530e292e40ec50f9d23f0ef5d4fcd6a6
# Debian 11's packages (the release of gradiant/open5gs:2.8.0) are on archive.debian.org since its support ended.
RUN printf 'deb http://archive.debian.org/debian bullseye main\ndeb http://archive.debian.org/debian-security bullseye-security main\n' \
      > /etc/apt/sources.list && rm -f /etc/apt/sources.list.d/* \
 && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git python3-pip python3-setuptools python3-wheel ninja-build build-essential flex bison cmake \
      pkg-config libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev \
      libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libtins-dev libtalloc-dev \
 && pip3 install --no-cache-dir meson==1.4.1 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${OPEN5GS_TAG} https://github.com/open5gs/open5gs.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${OPEN5GS_COMMIT}" \
 || { echo "open5gs ${OPEN5GS_TAG} is not ${OPEN5GS_COMMIT}" >&2; exit 1; }
ARG OPEN5GS_PATCHES_SHA256=
COPY patches/open5gs/ /patches/
RUN set -e; cd /src; \
    sum=$(cat /patches/*.patch | sha256sum | cut -d' ' -f1); \
    if [ -n "${OPEN5GS_PATCHES_SHA256}" ] && [ "$sum" != "${OPEN5GS_PATCHES_SHA256}" ]; then \
      echo "patches/open5gs/ has SHA-256 $sum, expected ${OPEN5GS_PATCHES_SHA256}" >&2; exit 1; fi; \
    for p in /patches/*.patch; do \
      git -c user.name=openMCX -c user.email=noreply@openmcx.invalid am --3way -q "$p" \
        || { echo "patch $(basename "$p") does not apply to open5gs ${OPEN5GS_COMMIT}" >&2; exit 1; }; \
    done; \
    { echo "Open5GS built by openMCX (tutorials/end-to-end/05-mcx-over-4g-open5gs-oai/open5gs)"; \
      echo "upstream: https://github.com/open5gs/open5gs.git"; \
      echo "tag: ${OPEN5GS_TAG}"; echo "commit: ${OPEN5GS_COMMIT}"; \
      echo "patches (sha256 of all: $sum):"; \
      for p in /patches/*.patch; do echo "  $(sha256sum "$p" | cut -d' ' -f1)  $(basename "$p")"; done; \
      echo "result: $(git rev-parse HEAD)"; } > /SOURCE; cat /SOURCE
RUN cd /src && meson setup build --prefix=/opt/open5gs --libdir=lib/x86_64-linux-gnu \
 && ninja -C build install

FROM ${BASE}
ARG OPEN5GS_TAG=v2.8.0
ARG OPEN5GS_COMMIT=157f611a530e292e40ec50f9d23f0ef5d4fcd6a6
ARG OPEN5GS_PATCHES_SHA256=
USER root
COPY --from=build /opt/open5gs/bin/ /opt/open5gs/bin/
COPY --from=build /opt/open5gs/lib/ /opt/open5gs/lib/
COPY --from=build /SOURCE /usr/share/doc/open5gs/SOURCE
COPY --from=build /patches/ /usr/share/doc/open5gs/patches/
COPY LICENSE NOTICE /usr/share/doc/open5gs/
USER open5gs
LABEL org.opencontainers.image.source="https://github.com/open5gs/open5gs" \
      org.opencontainers.image.version="${OPEN5GS_TAG}" org.opencontainers.image.revision="${OPEN5GS_COMMIT}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" org.openmcx.patches.sha256="${OPEN5GS_PATCHES_SHA256}"
