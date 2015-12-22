# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import os
import errno
from pycalico import netns
from pycalico.ipam import IPAMClient
from pycalico.datastore import Rules, Rule
from pycalico.block import AlreadyAssignedError
from netaddr import IPAddress, AddrFormatError
import json
import logging
import logging.handlers
import traceback
import re
from subprocess import check_output, CalledProcessError
from netaddr import IPNetwork
import socket

LOGFILE = "/var/log/calico/isolator.log"
ORCHESTRATOR_ID = "mesos"

ERROR_MISSING_COMMAND      = "Missing command"
ERROR_MISSING_CONTAINER_ID = "Missing container_id"
ERROR_MISSING_HOSTNAME     = "Missing hostname"
ERROR_MISSING_PID          = "Missing pid"
ERROR_UNKNOWN_COMMAND      = "Unknown command: %s"
ERROR_MISSING_ARGS = "Missing args"

datastore = IPAMClient()
_log = logging.getLogger("CALICOMESOS")

HOSTNAME = socket.gethostname()

def calico_mesos():
    """
    Module function which parses JSON from stdin and calls the appropriate
    plugin function.
    :return:
    """
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
        return isolate(args)
    elif command == 'cleanup':
        return cleanup(args)
    elif command == 'allocate':
        return allocate(args)
    elif command == 'reserve':
        return reserve(args)
    elif command == 'release':
        return release(args)
    else:
        raise IsolatorException(ERROR_UNKNOWN_COMMAND % command)


def _setup_logging(logfile):
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


def _validate_ip_addrs(ip_addrs, ip_version=None):
    if type(ip_addrs) != list:
        raise IsolatorException("IP addresses must be provided as JSON list, not: %s" % type(ip_addrs))
    validated_ip_addrs = []
    for ip_addr in ip_addrs:
        try:
            ip = IPAddress(ip_addr)
        except AddrFormatError:
            raise IsolatorException("IP address could not be parsed: %s" % ip_addr)

        if ip_version and ip.version != ip_version:
            raise IsolatorException("IPv%d address must not be placed in IPv%d address field." % \
                                        (ip.version, ip_version))
        else:
            validated_ip_addrs.append(ip)
    return validated_ip_addrs

def _create_profile_for_host_communication(profile_name):
    """
    Create a profile which allows traffic to and from the host.
    """
    _log.info("Autocreating profile %s", profile_name)
    datastore.create_profile(profile_name)
    prof = datastore.get_profile(profile_name)

    host_net = str(_get_host_ip_net())
    _log.info("adding accept rule for %s" % host_net)
    allow_from_slave = Rule(action="allow", src_net=host_net)
    allow_to_slave = Rule(action="allow", dst_net=host_net)
    prof.rules = Rules(id=profile_name,
                       inbound_rules=[allow_from_slave],
                       outbound_rules=[allow_to_slave])
    datastore.profile_update_rules(prof)

def _create_profile_for_netgroup(profile_name):
    """
    Create a profile which allows traffic from other Endpoints in the same
    profile.
    """
    _log.info("Autocreating profile %s", profile_name)
    datastore.create_profile(profile_name)
    prof = datastore.get_profile(profile_name)
    allow_from_profile = Rule(action="allow", src_tag=profile_name)
    allow_to_all = Rule(action="allow")
    prof.rules = Rules(id=profile_name,
                       inbound_rules=[allow_from_profile],
                       outbound_rules=[allow_to_all])
    datastore.profile_update_rules(prof)

def _create_profile_for_public_communication(profile_name):
    """
    Create a public profile which allows open traffic from all.
    """
    _log.info("Creating public profile: %s", profile_name)
    datastore.create_profile(profile_name)
    prof = datastore.get_profile(profile_name)
    allow_all = Rule(action="allow")
    prof.rules = Rules(id=profile_name,
                       inbound_rules=[allow_all],
                       outbound_rules=[allow_all])
    datastore.profile_update_rules(prof)

def _get_host_ip_net():
    """
    Gets the IP Address / subnet of the host.

    Ignores Loopback and docker0 Addresses.
    """
    IP_SUBNET_RE = re.compile(r'inet ((?:\d+\.){3}\d+\/\d+)')
    INTERFACE_SPLIT_RE = re.compile(r'(\d+:.*(?:\n\s+.*)+)')
    IFACE_RE = re.compile(r'^\d+: (\S+):')

    # Call `ip addr`.
    try:
        ip_addr_output = check_output(["ip", "-4", "addr"])
    except CalledProcessError, OSError:
        raise IsolatorException("Could not read host IP")

    # Separate interface blocks from ip addr output and iterate.
    for iface_block in INTERFACE_SPLIT_RE.findall(ip_addr_output):
        # Exclude certain interfaces.
        match = IFACE_RE.match(iface_block)
        if match and match.group(1) not in ["docker0", "lo"]:
            # Iterate through Addresses on interface.
            for address in IP_SUBNET_RE.findall(iface_block):
                ip_net = IPNetwork(address)
                if not ip_net.ip.is_loopback():
                    return ip_net.cidr
    raise IsolatorException("Couldn't determine host's IP Address.")


def isolate(args):
    """
    Toplevel function which validates and sanitizes json args into variables
    which can be passed to _isolate.

    "args": {
        "hostname": "slave-H3A-1",                              # Required
        "container_id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a", # Required
        "ipv4_addrs": ["192.168.23.4"],                         # Not Required
        "ipv6_addrs": ["2001:3ac3:f90b:1111::1"],               # Not Required
        "netgroups": ["prod", "frontend"],                      # Required.
        "labels": {                                             # Optional.
            "rack": "3A",
            "pop": "houston"
    }
    """
    hostname = args.get("hostname")
    container_id = args.get("container_id")
    pid = args.get("pid")
    ipv4_addrs = args.get("ipv4_addrs", [])
    ipv6_addrs = args.get("ipv6_addrs", [])
    netgroups = args.get("netgroups", [])
    labels = args.get("labels")

    # Validate Container ID
    if not container_id:
        raise IsolatorException(ERROR_MISSING_CONTAINER_ID)
    if not hostname:
        raise IsolatorException(ERROR_MISSING_HOSTNAME)
    if not pid:
        raise IsolatorException(ERROR_MISSING_PID)

    # Validate IPv4 Addresses
    ipv4_addrs_validated = _validate_ip_addrs(ipv4_addrs, 4)

    # Validate IPv6 Addresses
    ipv6_addrs_validated = _validate_ip_addrs(ipv6_addrs, 6)

    if not ipv4_addrs_validated + ipv6_addrs_validated:
        raise IsolatorException("Must provide at least one IPv4 or IPv6 address.")

    # Validate that netgroups are present
    if type(netgroups) is not list:
        raise IsolatorException("Must provide list of netgroups.")

    _isolate(hostname, pid, container_id, ipv4_addrs_validated, ipv6_addrs_validated, netgroups, labels)
    _log.debug("Request completed.")


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
    if len(datastore.get_endpoints(hostname=HOSTNAME,
                                   orchestrator_id=ORCHESTRATOR_ID,
                                   workload_id=container_id)) == 1:
        raise IsolatorException("This container has already been configured "
                                "with Calico Networking.")

    # Create the endpoint
    ep = datastore.create_endpoint(hostname=HOSTNAME,
                                   orchestrator_id=ORCHESTRATOR_ID,
                                   workload_id=container_id,
                                   ip_list=ipv4_addrs)

    # Create any profiles in etcd that do not already exist
    assigned_profiles = []
    _log.info("Assigning Profiles: %s" % profiles)
    # First remove any keyword profile names
    try:
        profiles.remove("public")
    except ValueError:
        pass
    else:
        _log.info("Assigning Public Profile")
        if not datastore.profile_exists("public"):
            _create_profile_for_public_communication("public")
        assigned_profiles.append("public")

    # Assign remaining netgroup profiles
    for profile in profiles:
        profile = "ng_%s" % profile
        if not datastore.profile_exists(profile):
            _log.info("Assigning Netgroup Profile: %s" % profile)
            _create_profile_for_netgroup(profile)
        assigned_profiles.append(profile)

    # Insert the host-communication profile
    default_profile_name = "default_%s" % hostname
    _log.info("Assigning Default Host Profile: %s" % default_profile_name)
    if not datastore.profile_exists(default_profile_name):
        _create_profile_for_host_communication(default_profile_name)
    assigned_profiles.insert(0, default_profile_name)

    # Call through to complete the network setup matching this endpoint
    ep.profile_ids = assigned_profiles
    try:
        ep.mac = ep.provision_veth(netns.PidNamespace(ns_pid), "eth0")
    except netns.NamespaceError as e:
        raise IsolatorException(e.message)

    datastore.set_endpoint(ep)
    _log.info("Finished networking for container %s", container_id)


def cleanup(args):
    hostname = args.get("hostname")
    container_id = args.get("container_id")

    if not container_id:
        raise IsolatorException(ERROR_MISSING_CONTAINER_ID)
    if not hostname:
        raise IsolatorException(ERROR_MISSING_HOSTNAME)

    _cleanup(hostname, container_id)


def _cleanup(hostname, container_id):
    _log.info("Cleaning executor with Container ID %s.", container_id)

    try:
        endpoint = datastore.get_endpoint(hostname=HOSTNAME,
                                          orchestrator_id=ORCHESTRATOR_ID,
                                          workload_id=container_id)
    except KeyError:
        raise IsolatorException("No endpoint found with container-id: %s" % container_id)

    # Unassign any address it has.
    for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
        assert(net.size == 1)
        ip = net.ip
        _log.info("Attempting to un-allocate IP %s", ip)
        pools = datastore.get_ip_pools(ip.version)
        for pool in pools:
            if ip in pool:
                # Ignore failure to unassign address, since we're not
                # enforcing assignments strictly in datastore.py.
                _log.info("Un-allocate IP %s from pool %s", ip, pool)
                datastore.unassign_address(pool, ip)

    # Remove the endpoint
    _log.info("Removing veth for endpoint %s", endpoint.endpoint_id)
    datastore.remove_endpoint(endpoint)

    # Remove the container from the datastore.
    datastore.remove_workload(hostname=HOSTNAME,
                              orchestrator_id=ORCHESTRATOR_ID,
                              workload_id=container_id)
    _log.info("Cleanup complete for container %s", container_id)


def reserve(args):
    """
    Toplevel function which validates and sanitizes dictionary of  args
    which can be passed to _reserve. Calico's reserve does not make use of
    netgroups or labels, so they are ignored.

    "args": {
		"hostname": "slave-0-1", # Required
		# At least one of "ipv4_addrs" and "ipv6_addrs" must be present.
	 	"ipv4_addrs": ["192.168.23.4"],
		"ipv6_addrs": ["2001:3ac3:f90b:1111::1", "2001:3ac3:f90b:1111::2"],
		"uid": "0cd47986-24ad-4c00-b9d3-5db9e5c02028",
	 	"netgroups": ["prod", "frontend"], # Optional.
	 	"labels": {  # Optional.
	 		"rack": "3A",
	 		"pop": "houston"
	 	}
	}
    """
    hostname = args.get("hostname")
    ipv4_addrs = args.get("ipv4_addrs", [])
    ipv6_addrs = args.get("ipv6_addrs", [])
    uid = args.get("uid")

    # Validations
    if not uid:
        raise IsolatorException("Missing uid")
    try:
        # Convert to string since libcalico requires uids to be strings
        uid = str(uid)
    except ValueError:
        raise IsolatorException("Invalid UID: %s" % uid)

    if hostname is None:
        raise IsolatorException(ERROR_MISSING_HOSTNAME)

    # Validate IP addresses
    ipv4_addrs_validated = _validate_ip_addrs(ipv4_addrs, 4)
    ipv6_addrs_validated = _validate_ip_addrs(ipv6_addrs, 6)

    if not ipv4_addrs_validated + ipv6_addrs_validated:
        raise IsolatorException("Must provide at least one IPv4 or IPv6 address.")

    return _reserve(hostname, uid, ipv4_addrs_validated, ipv6_addrs_validated)


def _reserve(hostname, uid, ipv4_addrs, ipv6_addrs):
    """
    Reserve an IP from the IPAM. 
    :param hostname: The host agent which is reserving this IP
    :param uid: A unique ID, which is indexed by the IPAM module and can be
    used to release all addresses with the uid.
    :param ipv4_addrs: List of IPAddress objects representing requested IPv4
    addresses.
    :param ipv6_addrs: List of IPAddress objects representing requested IPv6
    addresses.
    :return:
    """
    _log.info("Reserving. hostname: %s, uid: %s, ipv4_addrs: %s, ipv6_addrs: %s" % \
              (HOSTNAME, uid, ipv4_addrs, ipv6_addrs))
    assigned_ips = []
    try:
        for ip_addr in ipv4_addrs + ipv6_addrs:
            datastore.assign_ip(ip_addr, uid, {}, host=HOSTNAME)
            assigned_ips.append(ip_addr)
            # Keep track of succesfully assigned ip_addrs in case we need to rollback
    except (RuntimeError, ValueError, AlreadyAssignedError):
        failed_addr = ip_addr
        _log.error("Couldn't reserve %s. Attempting rollback." % (ip_addr))
        # Rollback assigned ip_addrs
        datastore.release_ips(set(assigned_ips))
        raise IsolatorException("IP '%s' already in use." % failed_addr)

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
    try:
        # Convert to string since libcalico requires uids to be strings
        uid = str(uid)
    except ValueError:
        raise IsolatorException("Invalid UID: %s" % uid)

    if hostname is None:
        raise IsolatorException(ERROR_MISSING_HOSTNAME)
    if num_ipv4 is None:
        raise IsolatorException("Missing num_ipv4")
    if num_ipv6 is None:
        raise IsolatorException("Missing num_ipv6")

    if not isinstance(num_ipv4, (int, long)):
        try:
            num_ipv4 = int(num_ipv4)
        except TypeError:
            raise IsolatorException("num_ipv4 must be an integer")

    if not isinstance(num_ipv6, (int, long)):
        try:
            num_ipv6 = int(num_ipv6)
        except TypeError:
            raise IsolatorException("num_ipv6 must be an integer")

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
                                       host=HOSTNAME)
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
            ips_validated = _validate_ip_addrs(ips)
            return _release_ips(set(ips_validated))

    else:
        # uid supplied.
        if ips is not None:
            raise IsolatorException("Supply either uid or ips, not both.")
        else:
            if not isinstance(uid, (str, unicode)):
                raise IsolatorException("uid must be a string")
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


def _error_message(msg=None):
    """
    Helper function to convert error messages into the JSON format.
    """
    return json.dumps({"error": msg})


class IsolatorException(Exception):
    pass



if __name__ == '__main__':
    _setup_logging(LOGFILE)
    try:
        response = calico_mesos()
    except IsolatorException as e:
        _log.error(e)
        sys.stdout.write(_error_message(str(e)))
        sys.exit(1)
    except Exception as e:
        _log.error(e)
        sys.stdout.write(_error_message("Unhandled error %s\n%s" %
                         (str(e), traceback.format_exc())))
        sys.exit(1)
    else:
        if response == None:
            response = _error_message(None)
        _log.info("Request completed with response: %s" % response)
        sys.stdout.write(response)
        sys.exit(0)
