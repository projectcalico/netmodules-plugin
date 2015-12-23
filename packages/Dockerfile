FROM centos:7

# Version of calico-mesos plugin
ENV CALICO_DOCKER_VERSION v0.8.0

# Install dependencies
RUN yum install -y wget rpm-build

RUN mkdir -p /root/rpmbuild/SOURCES/

# Add calicoctl
RUN wget https://github.com/projectcalico/calico-docker/releases/download/${CALICO_DOCKER_VERSION}/calicoctl -O /root/rpmbuild/SOURCES/calicoctl

# Add sources
ADD ./sources/ /root/rpmbuild/SOURCES/

# Build RPM
ADD ./calico-mesos.spec /root/calico-mesos.spec
