FROM debian:bullseye-slim

ADD docker/assets/dpkg_nodoc /etc/dpkg/dpkg.cfg.d/90_nodoc
ADD docker/assets/dpkg_nolocale /etc/dpkg/dpkg.cfg.d/90_nolocale
ADD docker/assets/apt_nocache /etc/apt/apt.conf.d/90_nocache
ADD docker/assets/apt_mindeps /etc/apt/apt.conf.d/90_mindeps

ARG DEBIAN_FRONTEND=noninteractive

# default dependencies
RUN	set -e \
    && apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates python3 python3-dev python3-setuptools python3-pip unbound net-tools \
    && pip3 install --no-cache-dir uv \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/* /var/log/*

ADD docker/assets/unbound-listener.conf /etc/unbound/unbound.conf.d/listener.conf