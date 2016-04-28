<!--- master only -->
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-mesos/master.svg?label=calico_mesos)](https://circleci.com/gh/projectcalico/calico-mesos/tree/master)
[![Slack Status](https://calicousers-slackin.herokuapp.com/badge.svg)](https://calicousers-slackin.herokuapp.com)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico Networking in Mesos
**Calico provides an IP-Per-Container Networking for your Mesos Cluster.**

- For information on Calico Networking, see [projectcalico.org](http://projectcalico.org)

Traditional Mesos networking treats ports as resources, and binds each task to its agent's IP. With Calico Networking enabled, each executor is given its own IP in an isolated networking namespace. 

Frameworks (which are responsible for creating the Executor instances) can opt-in for calico-networking by providing [NetworkInfo](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1366) in their [ContainerInfo](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1458) spec. Frameworks which do not provide NetworkInfo will simply be launched with traditional networking. Communication between applications is allowed between applications with the same ["netgroup"](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1389).

Calico-mesos works in conjunction with [net-modules][net-modules], which provides a simple JSON abstraction layer between Calico and Mesos. 

## Architecture
In order to utilize Calico Networking, each slave in the Mesos cluster must install the following dependencies:
- Each slave must run an instance of [calico-node](https://github.com/projectcalico/calico-docker#how-does-it-work), a packaged container of calico core services
- Each slave must have `calicoctl`, a command line tool for easily launching the calico-node service.
- Each slave must have [net-modules][net-modules] libraries installed
- Each slave must have the `calico-mesos` binary installed
- Each slave must have a filled in `modules.json`, which points mesos to the location of `net-modules` libraries, and points `net-modules` to the `calico-mesos` binary.
- Each slave must start the core mesos-slave process with `--modules=file:///path/to/modules.json`

## Demonstration
For information on adding Calico to your Mesos Cluster, see https://github.com/projectcalico/calico-containers/tree/master/docs/mesos


[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[docker]: https://www.docker.com/

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-mesos/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
