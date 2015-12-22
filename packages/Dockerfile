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

# Add sources
ADD ./sources/ /root/rpmbuild/SOURCES/

# Build RPM
ADD ./calico-mesos.spec /root/calico-mesos.spec
