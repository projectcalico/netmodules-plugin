import sys
import os
import errno
import uuid
import traceback
from pycalico import netns
from pycalico.ipam import IPAMClient
from pycalico.datastore import Rules, Rule, Endpoint
from pycalico.util import get_host_ips
from netaddr import IPAddress, AddrFormatError
import json
import logging
import logging.handlers


LOGFILE = "/var/log/calico/isolator.log"
ORCHESTRATOR_ID = "mesos"

datastore = IPAMClient()
_log = logging.getLogger("MESOS")


def main():
    stdin_raw_data = sys.stdin.read()
    _log.info("Received request: %s" % stdin_raw_data)

    # Convert input data to JSON object
    try:
        stdin_json = json.loads(stdin_raw_data)
    except ValueError as e:
        quit_with_error(str(e))

    # Extract command
    try:
        command = stdin_json['command']
    except KeyError:
        quit_with_error("Missing command")

    # Extract args
    try:
        args = stdin_json['args']
    except KeyError:
        quit_with_error("Missing args")

    # Call command with args
    _log.debug("Executing %s" % command)
    if command == 'prepare':
        prepare(args)
    elif command == 'isolate':
        isolate(args)
    elif command == 'update':
        update(args)
    elif command == 'cleanup':
        cleanup(args)
    else:
        quit_with_error("Unknown command: %s" % command)


def setup_logging(logfile):
    # Ensure directory exists.
    try:
        os.makedirs(os.path.dirname(LOGFILE))
    except OSError as oserr:
        if oserr.errno != errno.EEXIST:
            raise

    _log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    _log.addHandler(handler)

    netns.setup_logging(logfile)


def prepare(args):
    """
    Toplevel function which validates and sanitizes json args into variables
    which can be passed to _prepare.

    "args": {
        "hostname": "slave-H3A-1", # Required
        "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a", # Required
        "ipv4_addrs": ["192.168.23.4"], # Required, can be []
        "ipv6_addrs": ["2001:3ac3:f90b:1111::1"], # Required, can be []
        "netgroups": ["prod", "frontend"], # Required.
        "labels": {  # Optional.
            "rack": "3A",
            "pop": "houston"
    }
    """
    hostname = args.get("hostname")
    container_id = args.get("container-id")
    ipv4_addrs = args.get("ipv4_addrs")
    ipv6_addrs = args.get("ipv6_addrs")
    netgroups = args.get("netgroups")
    labels = args.get("labels")

    # Validate Container ID
    if not container_id:
        quit_with_error("Missing container-id")
    if not hostname:
        quit_with_error("Missing hostname")

    # Validate IPv4 Addresses
    if not ipv4_addrs and ipv4_addrs != []:
        # IPv4 Addrs can be an empty list, but must be provided
        quit_with_error("Missing ipv4_addrs")
    else:
        # Confirm provided ipv4_addrs are actually IP addresses
        ipv4_addrs_validated = []
        for ip_addr in ipv4_addrs:
            try:
                ip = IPAddress(ip_addr)
            except AddrFormatError:
                quit_with_error("IP address %s could not be parsed: %s" % ip_addr)

            if ip.version == 6:
                quit_with_error("IPv6 address must not be placed in IPv4 address field.")
            else:
                ipv4_addrs_validated.append(ip)

    # Validate IPv6 Addresses
    if not ipv6_addrs and ipv6_addrs != []:
        # IPv6 Addrs can be an empty list, but must be provided
        quit_with_error("Missing ipv6_addrs")
    else:
        # Confirm provided ipv4_addrs are actually IP addresses
        ipv6_addrs_validated = []
        for ip_addr in ipv6_addrs:
            try:
                ip = IPAddress(ip_addr)
            except AddrFormatError:
                quit_with_error("IP address %s could not be parsed: %s" % ip_addr)

            if ip.version == 4:
                quit_with_error("IPv4 address must not be placed in IPv6 address field.")
            else:
                ipv6_addrs_validated.append(ip)

    _log.debug("Request validated. Executing")
    _prepare(hostname, container_id, ipv4_addrs_validated, ipv6_addrs_validated, netgroups, labels)
    _log.debug("Request completed.")


def _prepare(hostname, container_id, ipv4_addrs, ipv6_addrs, profiles, labels):
    """
    Prepare an endpoint and the virtual interface to which it will be assigned.
    Interface is not configured here since any IP address and gateway settings will
    be dropped when the interface is moved into the new namepace in isolate.

    :param hostname: Hostname of the slave which the container is running on
    :param container_id: The container's ID
    :param ipv4_addrs: List of desired IPv4 addresses to be assigned to the container
    :param ipv6_addrs: List of desired IPv6 addresses to be assigned to the container
    :param profiles: List of desired profiles to be assigned to the container
    :param labels:
    :return: None
    """

    _log.info("Preparing network for Container with ID %s", container_id)
    _log.info("IP: %s, Profile %s", ipv4_addrs, profiles)

    # Confirm the IPv4 Addresses are correctly within the pool, then reserve them.
    for ip in ipv4_addrs:
        _log.debug('Attempting to assign IPv4 address %s', ip)

        # Find the pool which this IP belongs to
        pools = datastore.get_ip_pools(4)
        pool = None
        for candidate_pool in pools:
            if ip in candidate_pool:
                pool = candidate_pool
                _log.debug('Using IP pool %s', pool)
                break
        if not pool:
            quit_with_error("Requested IP %s isn't in any configured pool. "
                            "Container %s"% (ip, container_id))
        if not datastore.assign_address(pool, ip):
            quit_with_error("IP address couldn't be assigned for "
                         "container %s, IP=%s" % (container_id, ip))


    # Confirm the IPv6 Addresses are correctly within the pool, then reserve them.
    for ip in ipv6_addrs:
        _log.debug('Attempting to assign IPv6 address %s', ip)

        # Find the pool which this IP belongs to
        pools = datastore.get_ip_pools(6)
        pool = None
        for candidate_pool in pools:
            if ip in candidate_pool:
                pool = candidate_pool
                _log.debug('Using IP pool %s', pool)
                break
        if not pool:
            quit_with_error("Requested IP %s isn't in any configured pool. "
                            "Container %s"% (ip, container_id))
        if not datastore.assign_address(pool, ip):
            quit_with_error("IP address couldn't be assigned for "
                         "container %s, IP=%s" % (container_id, ip))

    # Create an endpoint
    ep = Endpoint(hostname=hostname,
                  orchestrator_id=ORCHESTRATOR_ID,
                  workload_id=container_id,
                  endpoint_id=uuid.uuid1().hex,
                  state="active",
                  mac=None)

    # Create the veth
    _log.info("Creating veth")
    netns.create_veth(ep.name, ep.temp_interface_name)

    # Assign IPs to the endpoint
    ep.ipv4_nets = set(ipv4_addrs)
    ep.ipv6_nets = set(ipv6_addrs)

    # Assign profiles on the endpoint
    if profiles == []:
        profiles = ["mesos"]
    _log.info("Assigning Profiles: %s" % profiles)
    for profile in profiles:
        if not datastore.profile_exists(profile):
            _log.info("Autocreating profile %s", profile)
            datastore.create_profile(profile)
            prof = datastore.get_profile(profile)

            # Set up the profile rules to allow incoming connections from the host
            # since the slave process will be running there.
            # Also allow connections from others in the profile.
            # Deny other connections (default, so not explicitly needed).
            # TODO: confirm that we're not getting more interfaces than we bargained for
            ipv4 = get_host_ips(4, exclude=["docker0"]).pop()
            host_net = ipv4 + "/32"
            _log.info("adding accept rule for %s" % host_net)
            allow_slave = Rule(action="allow", src_net=host_net)
            allow_self = Rule(action="allow", src_tag=profile)
            allow_all = Rule(action="allow")
            prof.rules = Rules(id=profile,
                               inbound_rules=[allow_slave, allow_self],
                               outbound_rules=[allow_all])
            datastore.profile_update_rules(prof)
        _log.info("Adding container %s to profile %s", container_id, profile)
        ep.profile_ids = [profile]
        _log.info("Finished adding container %s to profile %s",
                  container_id, profile)

    # Save the endpoint into the datastore, thereby registering it
    # (and its profiles) with Felix
    _log.info("Setting the endpoint.")
    datastore.set_endpoint(ep)
    _log.info("Finished networking for container %s, IP=%s", container_id, ip)


def isolate(args):
    """
    Toplevel function which validates and sanitizes json args into variables
    which can be passed to _isolate.

    "args": {
        "hostname": "slave-H3A-1", # Required
        "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a", # Required
        "pid": 3789 # Required
    }
    """
    hostname = args.get("hostname")
    container_id = args.get("container-id")
    pid = args.get("pid")

    if not container_id:
        quit_with_error("Missing container-id")
    if not hostname:
        quit_with_error("Missing hostname")
    if not pid:
        quit_with_error("Missing pid")

    _log.debug("Request validated. Executing")
    _isolate(hostname, container_id, pid)
    _log.debug("Request completed.")


def _isolate(hostname, container_id, pid):
    """
    Push container-end of veth pair into container namespace
    Assign IP address and on container side

    :param hostname: Hostname of the slave which the container is running on
    :param container_id: The container's ID
    :param pid: Process ID of the new network namespace which the container's
    interface should be pushed into.
    """
    _log.info("Isolating executor with Container ID %s, PID %s.",
              container_id, pid)

    # TODO: specify endpoint_id?
    ep = datastore.get_endpoint(hostname=hostname,
                                orchestrator_id=ORCHESTRATOR_ID,
                                workload_id=container_id)
    ep = Endpoint()
    # TODO: confirm that eth0 is the correct interface name
    interface = 'eth0'
    netns.move_veth_into_ns(pid, ep.temp_interface_name, interface)

    # Assign IP Addresses
    for ip in ep.ipv4_nets + ep.ipv6_nets:
        _log.info("Adding %s to %s" % (ip, ep.temp_interface_name))
        netns.add_ip_to_veth(ip, ep.temp_interface_name)

    # Assign default routes on the interface
    _log.info("Adding default route to interface")
    next_hop_ips = datastore.get_default_next_hops(hostname)
    _log.debug("Got nexthops: %s" % next_hop_ips)
    netns.add_default_route(next_hop_ips[4], ep.temp_interface_name)
    # TODO: check that nexthop exists for ipv6
    netns.add_default_route(next_hop_ips[6], ep.temp_interface_name)


def update(args):
    # TODO: implement Update
    quit_with_error("Update is not yet implemented.")


def cleanup(args):
    hostname = args.get("hostname")
    container_id = args.get("container-id")

    if not container_id:
        quit_with_error("Missing container-id")
    if not hostname:
        quit_with_error("Missing hostname")

    _cleanup(hostname, container_id)


def _cleanup(hostname, container_id):
    _log.info("Cleaning executor with Container ID %s.", container_id)

    endpoint = datastore.get_endpoint(hostname=hostname,
                                      orchestrator_id=ORCHESTRATOR_ID,
                                      workload_id=container_id)

    # Unassign any address it has.
    for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
        assert(net.size == 1)
        ip = net.ip
        _log.info("Attempting to un-allocate IP %s", ip)
        pools = datastore.get_ip_pools("v%s" % ip.version)
        for pool in pools:
            if ip in pool:
                # Ignore failure to unassign address, since we're not
                # enforcing assignments strictly in datastore.py.
                _log.info("Un-allocate IP %s from pool %s", ip, pool)
                datastore.unassign_address(pool, ip)

    # Remove the endpoint
    _log.info("Removing veth for endpoint %s", endpoint.endpoint_id)
    netns.remove_endpoint(endpoint.endpoint_id)

    # Remove the container from the datastore.
    datastore.remove_workload(hostname=hostname,
                              orchestrator_id=ORCHESTRATOR_ID,
                              workload_id=container_id)
    _log.info("Cleanup complete for container %s", container_id)


def quit_with_error(msg=None):
    """
    Helper function to convert error messages into the JSON format, print
    to stdout, and then quit.
    """
    error_msg = json.dumps({"error": msg})
    sys.stdout.write(error_msg)
    sys.exit(1)


if __name__ == '__main__':
    setup_logging(LOGFILE)
    main()
    quit_with_error()
