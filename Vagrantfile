# -*- mode: ruby -*-
# vi: set ft=ruby :

# Size of the cluster created by Vagrant
num_instances = 2

# Change basename of the VM
instance_name_prefix="calico"
calico_node_ver = "v0.8.0"
calicoctl_url = "https://github.com/projectcalico/calico-containers/releases/download/#{calico_node_ver}/calicoctl"


Vagrant.configure("2") do |config|
  config.vm.box = 'centos/7'
  config.ssh.insert_key = false

  # The vagrant centos:7 box has a bug where it automatically tries to sync /home/vagrant/sync using rsync, so disable it:
  # https://github.com/mitchellh/vagrant/issues/6154#issuecomment-135949010
  config.vm.synced_folder ".", "/home/vagrant/sync", disabled: true

  config.vm.provider :virtualbox do |vbox|
    # On VirtualBox, we don't have guest additions or a functional vboxsf
    # in CoreOS, so tell Vagrant that so it can be smarter.
    vbox.functional_vboxsf = false
    vbox.check_guest_additions = false
    vbox.memory = 2048
    vbox.cpus = 2
  end

  # Set up each box
  (1..num_instances).each do |i|
    vm_name = "%s-%02d" % [instance_name_prefix, i]
    config.vm.define vm_name do |host|
      domain = "mesos.test"

      # Provision the FQDN
      host.vm.hostname = "%s.%s" % [vm_name, domain]

      # Assign IP and prepend IP/hostname pair to /etc/hosts for correct FQDN IP resolution
      ip = "172.18.8.#{i+100}"
      host.vm.network :private_network, ip: ip
      (1..num_instances).each do |j|
        host_ip = "172.18.8.#{j+100}"
        host_name = "%s-%02d.mesos.test" % [instance_name_prefix, j]
        host.vm.provision :shell, inline: "echo '#{host_ip}  #{host_name}' | cat - /etc/hosts > tmp && mv tmp /etc/hosts", privileged: true
      end

      # Selinux => permissive
      host.vm.provision :shell, inline: "setenforce permissive", privileged: true

      # Install docker, and load in the custom mesos-calico image
      host.vm.provision :docker

      # If the MESOS_CALICO_TAR environment variable is true, load the local calico-mesos docker image from file
      if ENV["MESOS_CALICO_TAR"] == "true"
        host.vm.provision "file", source: "dist/docker/mesos-calico.tar", destination: "mesos-calico.tar"
        host.vm.provision :shell, inline: "sudo docker load < mesos-calico.tar"
      else
        host.vm.provision :docker, images: ["calico/mesos-calico"]
      end

      # Get the unit files
      ["etcd", "zookeeper", "marathon", "mesos-master"].each do |service_name| 
        host.vm.provision "file", source: "dockerized-mesos/config/units/#{service_name}.service", destination: "#{service_name}.service"
      end

      # Configure the Master node of the cluster.
      # The Master needs to run the mesos-master service, etcd, zookeeper, and marathon.
      if i == 1
        # Set firewall rules
        host.vm.provision :shell, inline: "systemctl restart firewalld", privileged: true
        [2181, 5050, 2379, 4001, 8080].each do |port|
          host.vm.provision :shell, inline: "sudo firewall-cmd --zone=public --add-port=#{port}/tcp --permanent"
        end
      
        host.vm.provision :shell, inline: "systemctl restart firewalld", privileged: true

        host.vm.provision :shell, inline: "systemctl restart docker", privileged: true
          
        # Zookeeper
        host.vm.provision :shell, inline: "mv zookeeper.service /usr/lib/systemd/system/", privileged: true
        host.vm.provision :shell, inline: "systemctl enable zookeeper.service", privileged: true
        host.vm.provision :shell, inline: "systemctl start zookeeper.service", privileged: true

        # Mesos-master
        host.vm.provision :shell, inline: "sh -c 'echo IP=#{ip} > /etc/sysconfig/mesos-master'", privileged: true
        host.vm.provision :shell, inline: "mv mesos-master.service /usr/lib/systemd/system/", privileged: true
        host.vm.provision :shell, inline: "systemctl enable mesos-master.service", privileged: true
        host.vm.provision :shell, inline: "systemctl start mesos-master.service", privileged: true

        # Etcd
        # Set selinux to permissive for etcd to run
        # TODO: make permanent by setting 'SELINUX=permissive' in /etc/selinuc/config.        
        host.vm.provision :shell, inline: "echo FQDN=`hostname -f` > /etc/sysconfig/etcd"
        host.vm.provision :shell, inline: "mv etcd.service /usr/lib/systemd/system/", privileged: true
        host.vm.provision :shell, inline: "systemctl enable etcd.service", privileged: true
        host.vm.provision :shell, inline: "systemctl start etcd.service", privileged: true

        # Marathon
        host.vm.provision :shell, inline: "mv marathon.service /usr/lib/systemd/system/", privileged: true
        host.vm.provision :shell, inline: "systemctl enable marathon.service", privileged: true
        host.vm.provision :shell, inline: "systemctl start marathon.service", privileged: true
      end

      # Configure the Agent nodes of the cluster.
      if i > 1
        # Set firewall rules
        host.vm.provision :shell, inline: "systemctl restart firewalld", privileged: true
        [179, 5051].each do |port|
          host.vm.provision :shell, inline: "firewall-cmd --zone=public --add-port=#{port}/tcp --permanent", privileged: true
        end
        host.vm.provision :shell, inline: "systemctl restart firewalld", privileged: true

        # Calicoctl
        host.vm.provision :shell, inline: "yum install -y wget", privileged: true
        host.vm.provision :shell, inline: "wget -qO /usr/bin/calicoctl #{calicoctl_url}", privileged: true
        host.vm.provision :shell, inline: "chmod +x /usr/bin/calicoctl"
        host.vm.provision :shell, inline: "sh -c 'echo ETCD_AUTHORITY=172.18.8.101:4001 > /etc/sysconfig/calico'", privileged: true

        # Start calico service with systemd and check status
        host.vm.provision "file", source: "dockerized-mesos/config/units/calico.service", destination: "calico.service"
        host.vm.provision :shell, inline: "mv calico.service /usr/lib/systemd/system/", privileged: true
        host.vm.provision :shell, inline: "systemctl enable calico.service", privileged: true
        host.vm.provision :shell, inline: "systemctl start calico.service", privileged: true
        host.vm.provision :shell, inline: "calicoctl status"

        # Configure mesos-agent
        host.vm.provision :shell, inline: "sh -c 'echo ZK=172.18.8.101 > /etc/sysconfig/mesos-agent'", privileged: true
        host.vm.provision :shell, inline: "sh -c 'echo IP=#{ip} >> /etc/sysconfig/mesos-agent'", privileged: true
        host.vm.provision "file", source: "dockerized-mesos/config/units/mesos-agent.service", destination: "mesos-agent.service"
        host.vm.provision :shell, inline: "mv mesos-agent.service /usr/lib/systemd/system/", privileged: true
        host.vm.provision :shell, inline: "systemctl enable mesos-agent.service", privileged: true
        host.vm.provision :shell, inline: "systemctl start mesos-agent.service", privileged: true
      end
    end
  end
end
