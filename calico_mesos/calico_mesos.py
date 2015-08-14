import sys
import os
import errno
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

ERROR_MISSING_COMMAND      = "Missing command"
ERROR_MISSING_CONTAINER_ID = "Missing container-id"
ERROR_MISSING_HOSTNAME     = "Missing hostname"
ERROR_MISSING_IPV4_ADDRS   = "Missing ipv4_addrs"
ERROR_MISSING_IPV6_ADDRS   = "Missing ipv6_addrs"
ERROR_MISSING_PID          = "Missing pid"
ERROR_UNKNOWN_COMMAND      = "Unknown command: %s"
ERROR_MISSING_ARGS = "Missing args"

datastore = IPAMClient()
_log = logging.getLogger("CALICOMESOS")


def calico_mesos():
    stdin_raw_data = sys.stdin.read()
    _log.info("Received request: %s" % stdin_raw_data)

    # Convert input data to JSON object
    try:
        stdin_json = json.loads(stdin_raw_data)
    except ValueError as e:
        raise IsolatorException(str(e))

    # Extract command
    try:
        command = stdin_json['command']
    except KeyError:
        raise IsolatorException(ERROR_MISSING_COMMAND)

    # Extract args
    try:
        args = stdin_json['args']
    except KeyError:
        raise IsolatorException(ERROR_MISSING_ARGS)

    # Call command with args
    _log.debug("Executing %s" % command)
    if command == 'isolate':
        isolate(args)
    elif command == 'cleanup':
        cleanup(args)
    elif command == 'allocate':
        return allocate(args)
    elif command == 'release':
        return release(args)
    else:
        raise IsolatorException(ERROR_UNKNOWN_COMMAND % command)


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


def isolate(args):
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
    pid = args.get("pid")
    ipv4_addrs = args.get("ipv4_addrs")
    ipv6_addrs = args.get("ipv6_addrs")
    netgroups = args.get("netgroups")
    labels = args.get("labels")

    # Validate Container ID
    if not container_id:
        raise IsolatorException(ERROR_MISSING_CONTAINER_ID)
    if not hostname:
        raise IsolatorException(ERROR_MISSING_HOSTNAME)
    if not pid:
        raise IsolatorException(ERROR_MISSING_PID)

    # Validate IPv4 Addresses
    if not ipv4_addrs and ipv4_addrs != []:
        # IPv4 Addrs can be an empty list, but must be provided
        raise IsolatorException(ERROR_MISSING_IPV4_ADDRS)
    else:
        # Confirm provided ipv4_addrs are actually IP addresses
        ipv4_addrs_validated = []
        for ip_addr in ipv4_addrs:
            try:
                ip = IPAddress(ip_addr)
            except AddrFormatError:
                raise IsolatorException("IP address %s could not be parsed: %s" % ip_addr)

            if ip.version == 6:
                raise IsolatorException("IPv6 address must not be placed in IPv4 address field.")
            else:
                ipv4_addrs_validated.append(ip)

    # Validate IPv6 Addresses
    if not ipv6_addrs and ipv6_addrs != []:
        # IPv6 Addrs can be an empty list, but must be provided
        raise IsolatorException("Missing ipv6_addrs")
    else:
        # Confirm provided ipv4_addrs are actually IP addresses
        ipv6_addrs_validated = []
        for ip_addr in ipv6_addrs:
            try:
                ip = IPAddress(ip_addr)
            except AddrFormatError:
                raise IsolatorException("IP address %s could not be parsed: %s" % ip_addr)

            if ip.version == 4:
                raise IsolatorException("IPv4 address must not be placed in IPv6 address field.")
            else:
                ipv6_addrs_validated.append(ip)

    _log.debug("Request validated. Executing")
    _isolate(hostname, pid, container_id, ipv4_addrs_validated, ipv6_addrs_validated, netgroups, labels)
    _log.debug("Request completed.")


def create_profile_with_default_mesos_rules(profile):
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


def _isolate(hostname, ns_pid, container_id, ipv4_addrs, ipv6_addrs, profiles, labels):
    """
    Configure networking for a container.

    This function performs the following steps:
    1.) Create endpoint in memory
    2.) Fill endpoint with data
    3.) Configure network to match the filled endpoint's specifications
    4.) Write endpoint to etcd

    :param hostname: Hostname of the slave which the container is running on
    :param container_id: The container's ID
    :param ipv4_addrs: List of desired IPv4 addresses to be assigned to the endpoint
    :param ipv6_addrs: List of desired IPv6 addresses to be assigned to the endpoint
    :param profiles: List of desired profiles to be assigned to the endpoint
    :param labels: TODO
    :return: None
    """
    _log.info("Preparing network for Container with ID %s", container_id)
    _log.info("IP: %s, Profile %s", ipv4_addrs, profiles)


    # Exit if the endpoint has already been configured
    if len(datastore.get_endpoints(hostname=hostname,
                                   orchestrator_id=ORCHESTRATOR_ID,
                                   workload_id=container_id)) == 1:
        raise IsolatorException("This container has already been configured with Calico Networking.")

    # Create the endpoint
    ep = datastore.create_endpoint(hostname=hostname,
                                   orchestrator_id=ORCHESTRATOR_ID,
                                   workload_id=container_id,
                                   ip_list=ipv4_addrs)

    # Create any profiles in etcd that do not already exist
    if profiles == []:
        profiles = ["mesos"]
    _log.info("Assigning Profiles: %s" % profiles)
    for profile in profiles:
        # Create profile with default rules, if it does not exist
        if not datastore.profile_exists(profile):
            create_profile_with_default_mesos_rules(profile)

    # Set profiles on the endpoint
    _log.info("Adding container %s to profile %s", container_id, profile)
    ep.profile_ids = profiles

    # Call through to complete the network setup matching this endpoint
    ep.mac = ep.provision_veth(ns_pid, container_id)

    datastore.set_endpoint(ep)
    _log.info("Finished networking for container %s", container_id)


def cleanup(args):
    hostname = args.get("hostname")
    container_id = args.get("container-id")

    if not container_id:
        raise IsolatorException("Missing container_id")
    if not hostname:
        raise IsolatorException("Missing hostname")

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


def allocate(args):
    """
    Toplevel function which validates and sanitizes json args into variables
    which can be passed to _allocate.

    args = {
        "hostname": "slave-0-1", # Required
        "num_ipv4": 1, # Required.
        "num_ipv6": 2, # Required.
        "uid": "0cd47986-24ad-4c00-b9d3-5db9e5c02028", # Required
        "netgroups": ["prod", "frontend"], # Optional.
        "labels": {  # Optional.
            "rack": "3A",
            "pop": "houston"
        }
    }

    """
    hostname = args.get("hostname")
    uid = args.get("uid")
    num_ipv4 = args.get("num_ipv4")
    num_ipv6 = args.get("num_ipv6")

    # Validations
    if not uid:
        raise IsolatorException("Missing uid")
    if not isinstance(uid, (str, unicode)):
        raise IsolatorException("uid must be a string, not %s", uid)
    try:
        # Convert to string since libcalico requires uids to be strings
        uid = str(uid)
    except ValueError:
        raise IsolatorException("Invalid UID: %s" % uid)

    if hostname is None:
        raise IsolatorException("Missing hostname")
    if num_ipv4 is None:
        raise IsolatorException("Missing num_ipv4")
    if num_ipv6 is None:
        raise IsolatorException("Missing num_ipv6")
    if not isinstance(num_ipv4, (int, long)):
        raise IsolatorException("num_ip4 must be a number, not %s" % num_ipv4)
    if not isinstance(num_ipv6, (int, long)):
        raise IsolatorException("num_ip4 must be a number, not %s" % num_ipv6)

    return _allocate(num_ipv4, num_ipv6, hostname, uid)


def _allocate(num_ipv4, num_ipv6, hostname, uid):
    """
    Allocate IP addresses from the data store.
    :param num_ipv4: Number of IPv4 addresses to request.
    :param num_ipv6: Number of IPv6 addresses to request.
    :param hostname: The hostname of this host.
    :param uid: A unique ID, which is indexed by the IPAM module and can be
    used to release all addresses with the uid.
    :return: JSON-serialized dictionary of the result in the following
    format:
    {
        "ipv4": ["192.168.23.4"],
        "ipv6": ["2001:3ac3:f90b:1111::1", "2001:3ac3:f90b:1111::2"],
        "error": None  # Not None indicates error and contains error message.
    }
    """
    result = datastore.auto_assign_ips(num_ipv4, num_ipv6, uid, {},
                                       hostname=hostname)
    ipv4_strs = [str(ip) for ip in result[0]]
    ipv6_strs = [str(ip) for ip in result[1]]
    result_json = {"ipv4": ipv4_strs,
                   "ipv6": ipv6_strs,
                   "error": None}
    return json.dumps(result_json)


def release(args):
    """
    Toplevel function which validates and sanitizes json args into variables
    which can be passed to _release_uid or _release_ips.

    args: {
        "uid": "0cd47986-24ad-4c00-b9d3-5db9e5c02028",
        # OR
        "ips": ["192.168.23.4", "2001:3ac3:f90b:1111::1"] # OK to mix 6 & 4
    }

    Must include a uid or ips, but not both.  If a uid is passed, release all
    addresses with that uid.

    If a list of ips is passed, release those IPs.
    """
    uid = args.get("uid")
    ips = args.get("ips")

    if uid is None:
        if ips is None:
            raise IsolatorException("Must supply either uid or ips.")
        else:
            # Validate the IPs.
            ips_validated = set()
            for ip_str in ips:
                try:
                    ip = IPAddress(ip_str)
                except (AddrFormatError, ValueError):
                    raise IsolatorException(
                        "IP address %s could not be parsed: %s" % ip_str)
                else:
                    ips_validated.add(ip)
            # All IPs validated, call procedure
            return _release_ips(ips_validated)

    else:
        # uid supplied.
        if ips is not None:
            raise IsolatorException("Supply either uid or ips, not both.")
        else:
            if not isinstance(uid, (str, unicode)):
                raise IsolatorException("uid must be a string, not %s", uid)
            # uid validated.
            return _release_uid(uid)


def _release_ips(ips):
    """
    Release the given IPs using the data store.

    :param ips: Set of IPAddress objects to release.
    :return: None
    """
    # release_ips returns a set of addresses that were already not allocated
    # when this function was called.  But, Mesos doesn't consume that
    # information, so we ignore it.
    _ = datastore.release_ips(ips)


def _release_uid(uid):
    """
    Release all IP addresses with the given unique ID using the data store.
    :param uid: The unique ID used to allocate the IPs.
    :return: None
    """
    _ = datastore.release_ip_by_handle(uid)


def error_message(msg=None):
    """
    Helper function to convert error messages into the JSON format, print
    to stdout, and then quit.
    """
    return json.dumps({"error": msg})


class IsolatorException(Exception):
    pass

if __name__ == '__main__':
    setup_logging(LOGFILE)
    try:
        response = calico_mesos()
    except IsolatorException as e:
        sys.stdout.write(error_message(str(e)))
        sys.exit(1)
    except Exception as e:
        import traceback
        sys.stdout.write(error_message("Unhandled error %s\n%s" %
                         (str(e), traceback.format_exc())))
        sys.exit(1)
    else:
        sys.stdout.write(error_message(response))
        sys.exit(0)
