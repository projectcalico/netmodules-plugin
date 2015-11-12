%global __os_install_post %{nil}
%define _rpmfilename %%{NAME}.rpm

Name:          calico-mesos
Version:       0.1.2
Release:       1%{?dist}
Summary:       Calico networking module for Mesos cluster manager
License:       APv2
URL:           http://www.projectcalico.org/

Source0:       calico_mesos
Source1:       %{name}.service
Source2:       modules.json
Source3:       calicoctl

Requires:      docker

%description
Calico provides IP-Per-Container Networking for a Mesos Cluster.

###########################################
%install

mkdir -p %{buildroot}%{_unitdir}
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/

mkdir -p %{buildroot}%{_bindir}
install -m 0755 %{SOURCE3} %{buildroot}%{_bindir}/

mkdir -p -m 0755 %{buildroot}/calico
install -m 0755 %{SOURCE0} %{buildroot}/calico
install -m 0755 %{SOURCE2} %{buildroot}/calico

############################################
%files

/calico/calico_mesos
/calico/modules.json
/%{_unitdir}/%{name}.service
/%{_bindir}/calicoctl

#############################################
%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%changelog
