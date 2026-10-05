# srsRAN Project gNB and srsUE, both with the ZeroMQ virtual radio, for tutorial 4.
# Both are under the GNU AGPL v3 (https://github.com/srsran). Each source is pinned to the commit of its release tag:
# the build stops if the tag no longer points to it; the images carry the tag and the commit as labels. The gNB is
# built with openMCX's patches in patches/srsran-project/ (see NOTICE); srsUE is unmodified.
#   srsran/build-images.sh             both images (computes the patches' SHA-256 for the gNB's label), or:
#   docker build --target gnb -t openmcx-srsran-gnb:25.10-mcx srsran/
#   docker build --target ue  -t openmcx-srsue:25.10 srsran/
ARG UBUNTU=ubuntu:24.04

FROM ${UBUNTU} AS build-gnb
ARG SRSRAN_PROJECT_TAG=release_25_10
ARG SRSRAN_PROJECT_COMMIT=d2f4b70dda8e2c557d5b05a0ac5f92dbddda19bc
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git cmake make g++ pkg-config libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev \
      libgtest-dev libzmq3-dev && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${SRSRAN_PROJECT_TAG} https://github.com/srsran/srsRAN_Project.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${SRSRAN_PROJECT_COMMIT}" \
 || { echo "srsRAN_Project ${SRSRAN_PROJECT_TAG} is not ${SRSRAN_PROJECT_COMMIT}" >&2; exit 1; }
# openMCX's patches, applied in order; the build stops naming the first one that does not apply. SOURCE records what
# the image is built from (AGPL-3.0 corresponding source: the upstream commit plus these patches).
ARG SRSRAN_PROJECT_PATCHES_SHA256=
COPY patches/srsran-project/ /patches/
RUN set -e; cd /src; \
    sum=$(cat /patches/*.patch | sha256sum | cut -d' ' -f1); \
    if [ -n "${SRSRAN_PROJECT_PATCHES_SHA256}" ] && [ "$sum" != "${SRSRAN_PROJECT_PATCHES_SHA256}" ]; then \
      echo "patches/srsran-project/ has SHA-256 $sum, expected ${SRSRAN_PROJECT_PATCHES_SHA256}" >&2; exit 1; fi; \
    for p in /patches/*.patch; do \
      git -c user.name=openMCX -c user.email=noreply@openmcx.invalid am --3way -q "$p" \
        || { echo "patch $(basename "$p") does not apply to srsRAN_Project ${SRSRAN_PROJECT_COMMIT}" >&2; exit 1; }; \
    done; \
    { echo "srsRAN Project gNB built by openMCX (tutorials/04-mcx-over-srsran-5g/srsran)"; \
      echo "upstream: https://github.com/srsran/srsRAN_Project.git"; \
      echo "tag: ${SRSRAN_PROJECT_TAG}"; echo "commit: ${SRSRAN_PROJECT_COMMIT}"; \
      echo "patches (sha256 of all: $sum):"; \
      for p in /patches/*.patch; do echo "  $(sha256sum "$p" | cut -d' ' -f1)  $(basename "$p")"; done; \
      echo "result: $(git rev-parse HEAD)"; } > /SOURCE; cat /SOURCE
# Portable build (x86-64-v3, AVX2), not tuned to the build machine.
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DENABLE_ZEROMQ=ON -DENABLE_UHD=OFF -DENABLE_DPDK=OFF \
      -DAUTO_DETECT_ISA=OFF -DCMAKE_CXX_FLAGS="-march=x86-64-v3" -DCMAKE_C_FLAGS="-march=x86-64-v3" \
      -DBUILD_TESTING=OFF \
 && cmake --build /build --target gnb -j"$(nproc)"

FROM ${UBUNTU} AS gnb
ARG SRSRAN_PROJECT_TAG=release_25_10
ARG SRSRAN_PROJECT_COMMIT=d2f4b70dda8e2c557d5b05a0ac5f92dbddda19bc
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libfftw3-single3 libmbedcrypto7t64 libsctp1 libyaml-cpp0.8 libzmq5 iproute2 procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build-gnb /build/apps/gnb/gnb /usr/local/bin/gnb
ARG SRSRAN_PROJECT_PATCHES_SHA256=
COPY --from=build-gnb /src/LICENSE /usr/share/doc/srsran-project/LICENSE
COPY --from=build-gnb /SOURCE /usr/share/doc/srsran-project/SOURCE
COPY --from=build-gnb /patches/ /usr/share/doc/srsran-project/patches/
COPY NOTICE /usr/share/doc/srsran-project/NOTICE
LABEL org.opencontainers.image.source="https://github.com/srsran/srsRAN_Project" \
      org.opencontainers.image.version="${SRSRAN_PROJECT_TAG}" \
      org.opencontainers.image.revision="${SRSRAN_PROJECT_COMMIT}" org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.openmcx.patches="${SRSRAN_PROJECT_PATCHES_SHA256}"
ENTRYPOINT ["gnb"]

FROM ${UBUNTU} AS build-ue
ARG SRSRAN_4G_TAG=release_25_10
ARG SRSRAN_4G_COMMIT=6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git cmake make g++ pkg-config libfftw3-dev libmbedtls-dev libboost-program-options-dev \
      libconfig++-dev libsctp-dev libzmq3-dev && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${SRSRAN_4G_TAG} https://github.com/srsran/srsRAN_4G.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${SRSRAN_4G_COMMIT}" \
 || { echo "srsRAN_4G ${SRSRAN_4G_TAG} is not ${SRSRAN_4G_COMMIT}" >&2; exit 1; }
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DENABLE_ZEROMQ=ON -DENABLE_UHD=OFF -DENABLE_SOAPYSDR=OFF \
      -DENABLE_BLADERF=OFF -DENABLE_SRSENB=OFF -DENABLE_SRSEPC=OFF -DGCC_ARCH=x86-64-v3 \
 && cmake --build /build --target srsue -j"$(nproc)" \
 && mkdir -p /out && cp /build/srsue/src/srsue /out/ \
 && find /build -name 'libsrsran_rf*.so*' -exec cp -a {} /out/ \;

FROM ${UBUNTU} AS ue
ARG SRSRAN_4G_TAG=release_25_10
ARG SRSRAN_4G_COMMIT=6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libfftw3-single3 libmbedcrypto7t64 libboost-program-options1.83.0 libconfig++9v5 libsctp1 libzmq5 \
      iproute2 iputils-ping procps curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build-ue /out/srsue /usr/local/bin/srsue
COPY --from=build-ue /out/ /usr/local/lib/
COPY --from=build-ue /src/LICENSE /usr/share/doc/srsran-4g/LICENSE
RUN rm -f /usr/local/lib/srsue && ldconfig
LABEL org.opencontainers.image.source="https://github.com/srsran/srsRAN_4G" \
      org.opencontainers.image.version="${SRSRAN_4G_TAG}" \
      org.opencontainers.image.revision="${SRSRAN_4G_COMMIT}" org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["srsue"]
