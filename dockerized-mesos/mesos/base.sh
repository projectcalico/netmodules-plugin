#!/usr/bin/env bash
set -e
source /build/mesos/buildconfig
set -x

# Upgrade all packages.
apt-get update
apt-get dist-upgrade -y --no-install-recommends

# Determine the list of packages required for the base image.
dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2 >/tmp/base.txt

# Install packages that should not be removed in the cleanup processing.
# - packages required by felix
# - pip (which includes various setuptools package discovery).
# apt-get install -qy \
$minimal_apt_get_install \
  python                           \
  python2.7                        \
  python-protobuf                  \
  libsasl2-modules-gssapi-heimdal  \
  libcurl4-nss-dev                 \
  libtool                          \
  libapr1-dev                      \
  libsvn-dev                       \
  libsasl2-dev                     \
  libgoogle-glog-dev               \
  libboost-dev                     \
  libprotobuf-dev                  \
  wget                             \
  libevent-dev                     \
  libevent-openssl-2.0             \
  libevent-pthreads-2.0            \
  openssl