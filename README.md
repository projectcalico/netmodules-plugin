# Calico Networking in Mesos
**Calico provides an IP-Per-Container Networking for your Mesos Cluster.**

This repository contains code and examples for running [Apache Mesos][mesos] with [Project Calico][calico].

Instead of the Executor sharing its Slave's networking namespace, it is instead given its own to launch applications in.  Frameworks (which are responsible for creating the Executor instances) can opt-in for calico-networking by providing [NetworkInfo](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1366) in their [ContainerInfo](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1458) spec. Frameworks which do not provide NetworkInfo will simply be launched with traditional networking. Communication between applications is allowed between applications with the same ["netgroup"](https://github.com/apache/mesos/blob/0.25.0-rc1/include/mesos/mesos.proto#L1389).

Calico-mesos works in conjunction with [net-modules][net-modules], which provides a simple JSON abstraction layer between Calico and Mesos.

For more information on how Calico works, see: [projectcalico.org/learn](http://projectcalico.org/learn) 

## Architecture
In order to utilize Calico Networking, each slave in the mesos cluster must install the following dependencies:
- Each slave must run an instance of [calico-node](https://github.com/projectcalico/calico-docker#how-does-it-work), a packaged container of calico core services
- Each slave must have `calicoctl`, a command line tool for easily launching the calico-node service.
- Each slave must have [net-modules][net-modules] libraries installed
- Each slave must have the `calico-mesos` binary installed
- Each slave must have a filled in `modules.json`, which points mesos to the location of `net-modules` libraries, and points `net-modules` to the `calico-mesos` binary.
- Each slave must start the core mesos-slave process with `--modules=file:///path/to/modules.json`

## Demo
We highly recommend that your first experiments with Mesos & Project Calico are downloading and running [the demo][net-modules], which uses Docker Compose to start a small Mesos cluster with Calico enabled on your desktop or laptop.

## Deploying a Mesos Cluster with Calico.

However, when you are ready to deploy on actual data center hardware, use [these instructions](docs/deploying.md).

[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[docker]: https://www.docker.com/
