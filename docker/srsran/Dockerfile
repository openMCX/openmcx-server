#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# The radio of the --srsran lab (tools/prepare-prearranged-test.py): srsRAN 4G 23.11 (srsepc, srsmbms, srsenb, srsue)
# with the ZeroMQ RF driver only, so eNodeB and UE exchange baseband samples over TCP instead of an SDR. One change,
# mch-period-80ms.patch: srsENB sends the MCH scheduling information with the MCCH and rebuilds the MTCH schedule only
# then, every MCCH repetition period (640 ms at the least), which holds speech for up to 640 ms; the patch makes the
# MCH scheduling period and the common subframe allocation period 80 ms (rf8) and repeats the MCCH with them, in the
# eNodeB and the UE alike. smcroute forwards the MCx servers' host groups from the lab network to the MBMS gateway.
#
# docker build -t openmcx-srsran:23.11 docker/srsran
#
FROM ubuntu:22.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates pkg-config \
    libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev libzmq3-dev libczmq-dev
# release_23_11
ARG SRSRAN_COMMIT=eea87b1d893ae58e0b08bc381730c502024ae71f
RUN git init -q /src && cd /src && git remote add origin https://github.com/srsran/srsRAN_4G.git \
    && git fetch -q --depth 1 origin "$SRSRAN_COMMIT" && git checkout -q FETCH_HEAD
COPY mch-period-80ms.patch /src/
RUN cd /src && git apply mch-period-80ms.patch
RUN mkdir /src/build && cd /src/build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_UHD=OFF -DENABLE_BLADERF=OFF -DENABLE_SOAPYSDR=OFF -DENABLE_ZEROMQ=ON \
       -DENABLE_GUI=OFF -DENABLE_RF_PLUGINS=OFF -DBUILD_TESTING=OFF .. \
    && make -j"$(nproc)" srsenb srsue srsepc srsmbms && make install \
    && cp /src/srsenb/sib.conf.mbsfn.example /usr/local/share/srsran/

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends libfftw3-single3 libmbedtls14 \
    libboost-program-options1.74.0 libconfig++9v5 libsctp1 libzmq5 libczmq4 iproute2 nftables smcroute procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/ /usr/local/bin/
COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY --from=build /usr/local/share/srsran/ /usr/local/share/srsran/
RUN ldconfig
