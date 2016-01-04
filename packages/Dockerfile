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

# The rpm-builder assumes the calico_mesos binary has been volume mounted to /binary.
# Here, it is copied into the RPM Source directory,then the RPM build is kicked off.
CMD bash -c 'cp /binary/calico_mesos root/rpmbuild/SOURCES && rpmbuild -ba /root/calico-mesos.spec'
