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
    # handler = logging.StreamHandler(sys.stdout)
    # handler.setLevel(logging.INFO)
    # handler.setFormatter(formatter)
    # _log.addHandler(handler)
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    _log.addHandler(handler)

    netns.setup_logging(logfile)


def prepare(args):
    """
    - Create veth pair,
    - Add routes to slave IP forwarding table,
    - Trigger calico agent for routing and firewalling

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

    # Validate data
    if not container_id:
        quit_with_error("Missing container-id")
    if not hostname:
        quit_with_error("Missing hostname")

    # Validate ipv4_addrs
    if ipv4_addrs != [] and not ipv4_addrs:
        quit_with_error("Missing ipv4_addrs")
    else:
        ipv4_addrs_validated = []
        for ip_addr in ipv4_addrs:
            try:
                ip = IPAddress(ip_addr)
                ipv4_addrs_validated.append(ip)
            except AddrFormatError:
                quit_with_error("IP address %s could not be parsed: %s" % ip_addr)

    if ipv6_addrs != [] and not ipv6_addrs:
        quit_with_error("Missing ipv6_addrs")
    _log.debug("Request validated. Executing")
    _prepare(hostname, container_id, ipv4_addrs_validated, ipv6_addrs, netgroups, labels)
    _log.debug("Request completed.")


def _prepare(hostname, container_id, ipv4_addrs, ipv6_addrs, profiles, labels):
    _log.info("Preparing network for Container with ID %s", container_id)
    _log.info("IP: %s, Profile %s", ipv4_addrs, profiles)

    # Confirm the IP Addresses are correctly within the pool, then reserve them.
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


    # TODO: replicate with ipv6_addrs

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

    # Add ips to the endpoint
    for ip in ipv4_addrs:
        _log.info("Adding %s to %s" % (ip, ep.temp_interface_name))
        netns.add_ip_to_veth(ip, ep.temp_interface_name)


    # Assign nexthop on the endpoint
    _log.info("Adding default route to interface")
    next_hop_ips = datastore.get_default_next_hops(hostname)
    _log.debug("Got nexthops: %s" % next_hop_ips)

    netns.add_default_route(next_hop_ips[4], ep.temp_interface_name)
    # netns.add_default_route(next_hop_ips[6], ep.temp_interface_name)

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

    # Register the endpoint (and profiles) with Felix
    _log.info("Setting the endpoint.")
    datastore.set_endpoint(ep)

    _log.info("Finished network for container %s, IP=%s", container_id, ip)


def isolate(args):
    """
    - Push container-end of veth pair into container namespace
    - Assign IP address on container side

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

    _isolate(hostname, container_id, pid)


def _isolate(hostname, container_id, pid):
    """
    - Push container-end of veth pair into container namespace
    - Assign IP address on container side
    """
    _log.info("Isolating executor with Container ID %s, PID %s.",
              container_id, pid)

    # TODO: specify endpoint_id?
    ep = datastore.get_endpoint(hostname=hostname,
                                orchestrator_id=ORCHESTRATOR_ID,
                                workload_id=container_id)

    # TODO: confirm that eth0 is the correct interface name
    interface = 'eth0'

    # pid is the temp namespace
    netns.move_veth_into_ns(pid, ep.temp_interface_name, interface)

    # TODO: get the endpoint, assign its IP Addrs to the interface in the new ns?


def update(args):
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
    Print error JSON, then quit
    """
    error_msg = json.dumps({"error": msg})
    sys.stdout.write(error_msg)
    sys.exit(1)


if __name__ == '__main__':
    setup_logging(LOGFILE)
    main()
    quit_with_error()