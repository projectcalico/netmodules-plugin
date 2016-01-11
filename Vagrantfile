# -*- mode: ruby -*-
# vi: set ft=ruby :

# Size of the cluster created by Vagrant
num_instances=2

# Change basename of the VM
instance_name_prefix="calico"
calico_node_ver = "v0.8.0"
calicoctl_url = "https://github.com/projectcalico/calico-containers/releases/download/#{calico_node_ver}/calicoctl"


Vagrant.configure("2") do |config|
  config.vm.box = 'centos/7'
#  config.vm.box_url = './example_box/dummy.box'
#  config.ssh.username = 'vagrant'
#  config.ssh.password = 'vagrant'
  config.ssh.insert_key = false
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # always use Vagrants insecure key
  # config.ssh.insert_key = false

  config.vm.provider :vsphere do |vsphere|
    vsphere.host = 'PRIVATE'
    vsphere.compute_resource_name = 'PRIVATE'
    vsphere.resource_pool_name = 'PRIVATE'
    vsphere.template_name = 'PRIVATE'
    vsphere.name = 'PRIVATE'
    vsphere.user = 'PRIVATE'
    vsphere.password = 'PRIVATE'
    vsphere.insecure = 'PRIVATE'
  end

  config.vm.provider :virtualbox do |vbox|
    # On VirtualBox, we don't have guest additions or a functional vboxsf
    # in CoreOS, so tell Vagrant that so it can be smarter.
    vbox.check_guest_additions = false
    vbox.memory = 2048
    vbox.cpus = 2
    vbox.functional_vboxsf     = false
  end

  # Set up each box
  (1..num_instances).each do |i|
    vm_name = "%s-%02d" % [instance_name_prefix, i]
    config.vm.define vm_name do |host|
      domain = "mesos.test"
      host.vm.hostname = "%s.%s" % [vm_name, domain]

      # Assign IP and prepend IP/hostname pair to /etc/hosts for correct FQDN IP resolution
      ip = "172.18.8.#{i+100}"
      host.vm.network :private_network, ip: ip
      host.vm.provision :shell, :inline "echo '#{ip}  #{host.vm.hostname}' | cat - /etc/hosts > tmp && mv tmp /etc/hosts", :privileged => true 

      # # Fix stdin: is not a tty error (http://foo-o-rama.com/vagrant--stdin-is-not-a-tty--fix.html)
      # config.vm.provision "fix-no-tty", type: "shell" do |s|
      #   s.privileged = false
      #   s.inline = "sudo sed -i '/tty/!s/mesg n/tty -s \\&\\& mesg n/' /root/.profile"
      # end

      # The docker provisioner installs docker.
      host.vm.provision :docker, images: [
          "busybox:latest",
          "calico/node:#{calico_node_ver}"
      ]

      # Install docker and check it is working for both hosts
      host.vm.provision :shell, inline: <<-SHELL
        sudo yum install docker docker-selinux
        sudo systemctl enable docker.service
        sudo systemctl start docker.service
        sudo docker run hello-world
        sudo groupadd docker
        sudo usermod -aG docker `whoami`
        sudo systemctl restart docker.service
      SHELL

      # Download and untar the mesos and calico service files
      host.vm.provision :shell, inline: <<-SHELL
        sudo yum install -y wget
        sudo wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.2/units.tgz
        sudo tar -xzf units.tgz
      SHELL

      # Configure the Master node of the cluster.
      # The Master needs to run the mesos-master service, etcd, zookeeper, and marathon.
      if i == 1

        # Set firewall rules
        host.vm.provision :shell, inline: <<-SHELL
          sudo systemctl restart firewalld
          sudo firewall-cmd --zone=public --add-port=2181/tcp --permanent
          sudo firewall-cmd --zone=public --add-port=5050/tcp --permanent
          sudo firewall-cmd --zone=public --add-port=2379/tcp --permanent
          sudo firewall-cmd --zone=public --add-port=4001/tcp --permanent
          sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
          sudo systemctl restart firewalld
        SHELL

        # Install and start zookeeper
        host.vm.provision :shell, inline: <<-SHELL
          sudo cp zookeeper.service /usr/lib/systemd/system/
          sudo systemctl enable zookeeper.service
          sudo systemctl start zookeeper.service
        SHELL

        # Set selinux to permissive for etcd to run
        # NOTE: This must be done after reboot! To make this pemanent, set
        # 'SELINUX=permissive' in /etc/selinuc/config.
        host.vm.provision :shell, inline: "setenforce Permissive", :privileged => true

        # Install and start etcd
        host.vm.provision :shell, inline: <<-SHELL
          sudo sh -c 'echo FQDN=`hostname -f` > /etc/sysconfig/etcd'
          sudo cp etcd.service /usr/lib/systemd/system/
          sudo systemctl enable etcd.service
          sudo systemctl start etcd.service
        SHELL

        # Install and start mesos Master
        host.vm.provision :shell, inline: <<-SHELL
          sudo docker load < sync/dist/docker/mesos-calico.tar
          sudo cp mesos-master.service /usr/lib/systemd/system/
          sudo systemctl enable mesos-master.service
          sudo systemctl start mesos-master.service
        SHELL


        # Install and start marathon
        host.vm.provision :shell, inline: <<-SHELL
          sudo docker load < sync/dist/docker/mesos-calico.tar
          sudo cp marathon.service /usr/lib/systemd/system/
          sudo systemctl enable marathon.service
          sudo systemctl start marathon.service
        SHELL

      end

      # Configure the Agent nodes of the cluster.
      # The Agents need to run the mesos-agent service and calico/node
      if i > 1

        # Set firewall rules
        host.vm.provision :shell, inline: <<-SHELL
          sudo systemctl restart firewalld
          sudo firewall-cmd --zone=public --add-port=179/tcp --permanent
          sudo firewall-cmd --zone=public --add-port=5051/tcp --permanent
          sudo systemctl restart firewalld
        SHELL

        # Download calicoctl
        host.vm.provision :shell, inline: <<-SHELL
          sudo wget -qO /usr/bin/calicoctl #{calicoctl_url}
          chmod +x /usr/bin/calicoctl
        SHELL

        # Set calicoctl ETCD info
        host.vm.provision :shell, inline: "sh -c 'echo ETCD_AUTHORITY=172.18.8.101:4001 > /etc/sysconfig/calico'", :privileged => true

        # Start calico service with systemd and check status
        host.vm.provision :shell, inline: <<-SHELL
          sudo cp calico.service /usr/lib/systemd/system/
          sudo systemctl enable calico.service
          sudo systemctl start calico.service
        SHELL

        # Check calicoctl status to ensure it is working (WON'T EXIT WHEN ERROR HIT UNTIL CALICOCTL IS UPDATED TO >=v0.13.0)
        host.vm.provision :shell, inline: "calicoctl status"

        # Set zookeeper info
        host.vm.provision :shell, inline: "sh -c 'echo ZK=172.18.8.101 > /etc/sysconfig/mesos-agent'", :privileged => true

        # Start mesos agent service
        host.vm.provision :shell, inline: <<-SHELL
          sudo docker load < sync/dist/docker/mesos-calico.tar
          sudo cp mesos-agent.service /usr/lib/systemd/system/
          sudo systemctl enable mesos-agent.service
          sudo systemctl start mesos-agent.service
        SHELL
      end

    end
  end
end
