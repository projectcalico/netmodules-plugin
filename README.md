<!--- master only -->
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-mesos/master.svg?label=calico_mesos)](https://circleci.com/gh/projectcalico/calico-mesos/tree/master)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico's Net-Modules Plugin

This repository is home to Calico's [Net-Modules](https://github.com/mesosphere/net-modules) compliant plugin.

## Deprecation Warning!

Note: Mesos has deprecated support for the Net-Modules networking interface in favor of the standardized
[Container Networking Interface (CNI)](https://github.com/containernetworking/cni). 

Calico provides IP-per-container and fine-grain isolation
in Mesos v1.0.0+ with its standard CNI plugin. Learn how to get started with the [Calico for Mesos CNI Install Guide](http://docs.projectcalico.org/master/getting-started/mesos/installation/unified).
