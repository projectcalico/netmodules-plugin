# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# For details and docs - see https://github.com/phusion/baseimage-docker#getting_started

FROM ubuntu:14.04
CMD ["/sbin/my_init"]

ENV HOME /root

# Caution: If the following two environment variables are set to a branch (i.e. master),
# docker builds will need to be done with --no-cache. Failing to do so will cause  docker 
# to not notice the latest commits pushed to said branch, and instead use a stale version of the branch.

###############
##   Mesos   ##
###############
ENV MESOS_BRANCH 0.26.0
ADD /dockerized-mesos/mesos /build/mesos/
RUN /build/mesos/base.sh && \
    /build/mesos/install.sh && \
    /build/mesos/cleanup.sh

#####################
##   Net-modules   ##
#####################
ENV NETMODULES_BRANCH integration/0.26
ADD /dockerized-mesos/net-modules /build/net-modules/
RUN /build/net-modules/base.sh && \
    /build/net-modules/install.sh && \
    /build/net-modules/cleanup.sh

############
## Calico ##
############
ADD packages/sources/modules.json /calico/
ADD dist/binary/calico_mesos /calico/
