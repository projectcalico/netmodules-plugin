FROM centos:7

# Version of calico-mesos plugin
ENV CALICO_MESOS_VERSION v0.1.1
ENV CALICO_DOCKER_VERSION v0.8.0

# Install dependencies
RUN yum install -y wget rpm-build

# Add calico-mesos
RUN mkdir -p /root/rpmbuild/SOURCES/
RUN wget https://github.com/projectcalico/calico-mesos/releases/download/${CALICO_MESOS_VERSION}/calico_mesos -O /root/rpmbuild/SOURCES/calico_mesos

# Add calicoctl
RUN wget https://github.com/projectcalico/calico-docker/releases/download/${CALICO_DOCKER_VERSION}/calicoctl -O /root/rpmbuild/SOURCES/calicoctl

# Add modules.json file
RUN wget https://raw.githubusercontent.com/mesosphere/net-modules/master/calico/modules.json -O /root/rpmbuild/SOURCES/modules.json

# Add systemd files
ADD ./sources/calico-mesos.service /root/rpmbuild/SOURCES/calico-mesos.service

# Build RPM
ADD ./calico-mesos.spec /root/calico-mesos.spec
