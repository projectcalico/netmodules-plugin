#!/usr/bin/env bash
set -e
set -x

# Get the current list of required packages (this is used in the clean up
# code to remove the temporary packages that are about to be installed).
dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2 >/tmp/required.txt

# Install temporary packages required for installing Mesos.
apt-get -qy install software-properties-common # (for add-apt-repository)
add-apt-repository ppa:george-edison55/cmake-3.x
apt-get update -q
apt-cache policy cmake
apt-get -qy install \
  build-essential                         \
  autoconf                                \
  automake                                \
  cmake=3.2.2-2~ubuntu14.04.1~ppa1        \
  ca-certificates                         \
  gdb                                     \
  wget                                    \
  git-core                                \
  protobuf-compiler                       \
  make                                    \
  libpython-dev                           \
  python-dev                              \
  python-setuptools                       \
  heimdal-clients                         \
  unzip                                   \
  --no-install-recommends

# Isolator
mv /net-modules/isolator /
cd /isolator

./bootstrap
rm -rf build
mkdir build
cd build
export LD_LIBRARY_PATH=LD_LIBRARY_PATH:/usr/local/lib
../configure --with-mesos=/usr/local --with-protobuf=/usr
make all
make install

mkdir -p /calico
mv /net-modules/calico/modules.json /calico/
