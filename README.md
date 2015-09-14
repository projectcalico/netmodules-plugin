# Calico Networking in Mesos
**Calico provides an IP-Per-Container Networking for your Mesos Cluster.**

This is accomplishe by giving each Executor instance its own networking namespace seperate from the Slave's to launch applications in. Frameworks can opt-into calico-networking (in lieu of traditional Networking which shares networking namespace with the Slave) by providing [NetworkInfo](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1366) in their [ContainerInfo](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1458) spec. Communication between applications is allowed between applications with the same ["netgroup"](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1389).

Calico-mesos works in conjunction with [net-modules](https://github.com/mesosphere/net-modules), which provides a simple JSON abstraction layer between Calico and Mesos.

For more information on how Calico works, see: [projectcalico.org/learn](http://projectcalico.org/learn) 

## Architecture
In order to utilize Calico Networking, each slave in the mesos cluster must install the following dependencies:
- Each slave must run an instance of [calico-node](https://github.com/projectcalico/calico-docker#how-does-it-work), a packaged container of calico core services
- Each slave must have `calicoctl`, a command line tool for easily launching the calico-node service.
- Each slave must have [net-modules](https://github.com/mesosphere/net-modules) libraries installed
- Each slave must have the `calico-mesos` binary installed
- Each slave must have a filled in `modules.json`, which points mesos to the location of `net-modules` libraries, and points `net-modules` to the `calico-mesos` binary.
- Each slave must start the core mesos-slave process with `--modules=file:///path/to/modules.json`

## Demo
To simulate a working Mesos cluster with Calico Networking, see [the net-modules demo](https://github.com/mesosphere/net-modules)

## Installation
Stay tuned (or contact us directly on [IRC](http://webchat.freenode.net/?randomnick=1&channels=%23calico&uio=d4) or [Slack](https://calicousers-slackin.herokuapp.com/)) for additional information on installing Calico on your working mesos cluster!
