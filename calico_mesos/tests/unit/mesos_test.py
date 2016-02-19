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
import unittest
from mock import patch, MagicMock
from mock import Mock, ANY
import json
from netaddr import IPAddress, IPNetwork
from nose_parameterized import parameterized
from pycalico.datastore_datatypes import Rule, Endpoint, Profile
from pycalico.block import AlreadyAssignedError
import calico_mesos
import socket
from calico_mesos import IsolatorException
from calico_mesos import ERROR_MISSING_COMMAND, \
    ERROR_MISSING_CONTAINER_ID, \
    ERROR_MISSING_HOSTNAME, \
    ERROR_MISSING_PID, \
    ERROR_UNKNOWN_COMMAND, \
    ERROR_MISSING_ARGS

HOSTNAME = socket.gethostname()

class TestIsolate(unittest.TestCase):
    @parameterized.expand([
        ({"hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["abcd::"],
          "pid": 3789},
        ERROR_MISSING_CONTAINER_ID),

        ({"container_id": "abcdef12345",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["abcd::"],
          "pid": 3789},
        ERROR_MISSING_HOSTNAME),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["abcd::"]},
        ERROR_MISSING_PID),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["1.1.1.1.1"],
          "pid": 3789},
         "IP address could not be parsed: %s" % "1.1.1.1.1"),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv6_addrs": ["fe80::fe80::"],
          "pid": 3789},
         "IP address could not be parsed: %s" % "fe80::fe80::"),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["fe80::"],
          "pid": 3789},
         "IPv6 address must not be placed in IPv4 address field."),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv6_addrs": ["192.168.1.1"],
          "pid": 3789},
         "IPv4 address must not be placed in IPv6 address field.")
    ])
    @patch('calico_mesos._isolate')
    def test_error_messages_with_invalid_params(self, args, error, m_isolate):
        with self.assertRaises(IsolatorException) as e:
            calico_mesos.isolate(args)
        self.assertFalse(m_isolate.called)
        self.assertEqual(e.exception.message, error)

    @parameterized.expand([
        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "pid": 3789},),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv6_addrs": ["abcd::"],
          "pid": 3789},),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["abcd::"],
          "pid": 3789},)
    ])
    @patch('calico_mesos._isolate')
    def test_isolate_executes_with_valid_params(self, args, m_isolate):
        result = calico_mesos.isolate(args)
        self.assertEqual(result, None)
        self.assertTrue(m_isolate.called)


class TestAllocate(unittest.TestCase):
    @parameterized.expand([
        ({"hostname": "metaman",
          "num_ipv4": 1,
          "num_ipv6": 1},
        "Missing uid"),

        ({"num_ipv4": 1,
          "num_ipv6": 1,
          "uid": "abc-def-gh"},
        ERROR_MISSING_HOSTNAME),

        ({"hostname": "metaman",
          "num_ipv4": 1,
          "uid": "abc-def-gh"},
        "Missing num_ipv6"),

        ({"hostname": "metaman",
          "num_ipv6": 1,
          "uid": "abc-def-gh"},
        "Missing num_ipv4"),
    ])
    @patch('calico_mesos._allocate')
    def test_error_messages_with_invalid_params(self, args, error, m_allocate):
        with self.assertRaises(IsolatorException) as e:
            calico_mesos.allocate(args)
        self.assertFalse(m_allocate.called)
        self.assertEqual(e.exception.message, error)

    @parameterized.expand([
    ({"hostname": "metaman",
      "num_ipv4": 1,
      "num_ipv6": 1,
      "uid": "abc-def-gh"},),
    ])
    @patch('calico_mesos._allocate')
    def test_allocate_executes_with_valid_params(self, args, m_allocate):
        m_allocate.return_value = {"ipv4": ["192.168.1.1"],
                           "ipv6": "dead:beef::",
                           "error": None}
        result = calico_mesos.allocate(args)
        self.assertTrue(m_allocate.called)
        self.assertEqual(result, '{"error": null, "ipv4": ["192.168.1.1"], "ipv6": "dead:beef::"}') 

    @parameterized.expand([
    ({"hostname": "metaman",
      "num_ipv4": 1,
      "num_ipv6": 1,
      "uid": "abc-def-gh",
      "labels": {"ipv4_addrs": "['192.168.3.1']"}},),
    ])
    @patch('calico_mesos._reserve')
    @patch('calico_mesos._allocate')
    def test_allocate_executes_with_static_addr(self, args, m_allocate, m_reserve):
        m_allocate.return_value = {"ipv4": [],
                           "ipv6": "dead:beef::",
                           "error": None}
        result = calico_mesos.allocate(args)
        self.assertEqual(result, '{"error": null, "ipv4": ["192.168.3.1"], "ipv6": "dead:beef::"}')
    

class TestReserve(unittest.TestCase):
    @parameterized.expand([
        ({"hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["dead::beef"]},
        "Missing uid"),

        ({"ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["dead::beef"],
          "uid": "abc-def-gh"},
        ERROR_MISSING_HOSTNAME),
    ])
    @patch('calico_mesos._reserve')
    def test_error_messages_with_invalid_params(self, args, error, m_reserve):
        with self.assertRaises(IsolatorException) as e:
            calico_mesos.reserve(args)
        self.assertFalse(m_reserve.called)
        self.assertEqual(e.exception.message, error)

    @parameterized.expand([
    ({"hostname": "metaman",
      "ipv4_addrs": ["192.168.1.1"],
      "ipv6_addrs": ["dead::beef"],
      "uid": "abc-def-gh"},),
    ])
    @patch('calico_mesos._reserve')
    def test_reserve_executes_with_valid_params(self, args, m_reserve):
        result = calico_mesos.reserve(args)
        self.assertTrue(m_reserve.called)
        self.assertEqual(result, m_reserve())

    @patch('calico_mesos.datastore', autospec=True)
    def test_reserve_is_functional(self, m_datastore):
        hostname = "metaman"
        ipv4_addrs = ["192.168.1.1", "192.168.1.2"]
        ipv6_addrs = ["dead::beef"]
        uid = "abc-def-gh"
        result = calico_mesos._reserve(hostname, uid, ipv4_addrs, ipv6_addrs)
        self.assertIsNone(result)
        for ip_addr in ipv4_addrs + ipv6_addrs:
            # TODO: workaround until hostname can be passed in
            m_datastore.assign_ip.assert_any_call(ip_addr, uid, {},
                                                  host=HOSTNAME)

    @parameterized.expand([
        [ValueError],
        [RuntimeError],
        [AlreadyAssignedError]
    ])
    @patch('calico_mesos.datastore')
    def test_reserve_rolls_back(self, exception, m_datastore):
        hostname = "metaman"
        ipv4_addrs = [IPAddress("192.168.1.1"), IPAddress("192.168.1.2")]
        ipv6_addrs = [IPAddress("dead::beef")]
        uid = "abc-def-gh"

        def side_effect(address, handle_id, attributes, host=None):
            if address == IPAddress("192.168.1.2"):
                # Arbitrarily throw an error when the second address is passed in
                raise exception

        m_assign_ip = MagicMock(side_effect=side_effect)
        m_datastore.assign_ip = m_assign_ip

        # Test that error for second IP was ack'd
        with self.assertRaises(IsolatorException) as e:
            calico_mesos._reserve(hostname, uid, ipv4_addrs, ipv6_addrs)
        self.assertEqual(e.exception.message, "IP '192.168.1.2' already in use.")

        # Test that only the first IP was released
        m_datastore.release_ips.assert_called_once_with({IPAddress("192.168.1.1")})


class TestRelease(unittest.TestCase):
    @parameterized.expand([
        ({},
        "Must supply either uid or ips."),

        ({"ips": ["192.168.0.1"],
          "uid": "abc-def-gh"},
        "Supply either uid or ips, not both."),

        ({"ips": ["192.9.168.0.1"]},
        "IP address could not be parsed: 192.9.168.0.1"),

        ({"uid": 12345},
        "uid must be a string"),
    ])
    @patch('calico_mesos._release_ips')
    @patch('calico_mesos._release_uid')
    def test_error_messages_with_invalid_params(self, args, error, m_release_ips, m_release_uid):
        with self.assertRaises(IsolatorException) as e:
            calico_mesos.release(args)
        self.assertEqual(e.exception.message, error)

    @parameterized.expand([
    ({"ips": ["192.168.0.1"]},),

    ({"ips": ["192.168.0.1", "192.168.0.2"]},),
    ])
    @patch('calico_mesos._release_ips')
    def test_release_ips(self, args, m_release):
        result = calico_mesos.release(args)

        m_release.assert_called_with(set([IPAddress(ip) for ip in args["ips"]]))
        self.assertEqual(result, m_release())

    @parameterized.expand([
    ({"uid": "abc-def-gh"},),
    ])
    @patch('calico_mesos._release_uid')
    def test_release_uid(self, args, m_release):
        result = calico_mesos.release(args)

        m_release.assert_called_with(args["uid"])
        self.assertEqual(result, m_release())


class TestDispatch(unittest.TestCase):
    @parameterized.expand([
        # Missing command
        ({"args": {}},),

        # Invalid command
        ({"args": {},
         "command": "not-a-real-command"},),

        ({"command": "isolate"},)
    ])
    @patch('sys.stdin')
    def test_dispatch_catches_bad_commands(self, args, m_stdin):
        m_stdin.read.return_value = json.dumps(args)
        self.assertRaises(IsolatorException, calico_mesos.calico_mesos)

    @patch('sys.stdin')
    def test_dispatch_catches_invalid_json(self, m_stdin):
        m_stdin.read.return_value = '{"command: invalidjson'
        self.assertRaises(IsolatorException, calico_mesos.calico_mesos)

    @patch('calico_mesos.isolate')
    @patch('sys.stdin')
    def test_distpach_calls_isolate(self, m_stdin, m_isolate):
        # Load stdin.read to return input string
        input = {"args": {},
                "command": "isolate"}
        m_stdin.read.return_value = json.dumps(input)

        # Call function
        calico_mesos.calico_mesos()
        m_isolate.assert_called_with(input["args"])

    @patch('calico_mesos.cleanup')
    @patch('sys.stdin')
    def test_distpach_calls_cleanup(self, m_stdin, m_cleanup):
        # Load stdin.read to return input string
        input = {"args": {},
                "command": "cleanup"}
        m_stdin.read.return_value = json.dumps(input)

        # Call function
        calico_mesos.calico_mesos()
        m_cleanup.assert_called_with(input["args"])

    @patch('calico_mesos.allocate')
    @patch('sys.stdin')
    def test_distpach_calls_allocate(self, m_stdin, m_allocate):
        # Load stdin.read to return input string
        input = {"args": {},
                "command": "allocate"}
        m_stdin.read.return_value = json.dumps(input)

        # Call function
        calico_mesos.calico_mesos()
        m_allocate.assert_called_with(input["args"])

    @patch('calico_mesos.release')
    @patch('sys.stdin')
    def test_distpach_calls_release(self, m_stdin, m_release):
        # Load stdin.read to return input string
        input = {"args": {},
                "command": "release"}
        m_stdin.read.return_value = json.dumps(input)

        # Call function
        calico_mesos.calico_mesos()
        m_release.assert_called_with(input["args"])


class TestDefaultProfile(unittest.TestCase):
    HOST_IP_NET = "172.16.0.0/16"

    @patch('calico_mesos._get_host_ip_net', return_value=HOST_IP_NET)
    @patch('calico_mesos.datastore', autospec=True)
    def test_correct_rules_for_host_profile(self, m_datastore, m_get_host_ip_net):
        new_profile = Mock(spec=Profile)
        m_datastore.get_profile.return_value = new_profile

        calico_mesos._create_profile_for_host_communication("default")
        new_rules = new_profile.rules
        self.assertIn(Rule(action="allow", src_net=self.HOST_IP_NET), new_rules.inbound_rules)
        self.assertIn(Rule(action="allow", dst_net=self.HOST_IP_NET), new_rules.outbound_rules)
        self.assertEqual(len(new_rules.inbound_rules) + len(new_rules.outbound_rules), 2)

    @patch('calico_mesos.datastore', autospec=True)
    def test_correct_rules_for_netgroup_profile(self, m_datastore):
        new_profile = Mock(spec=Profile)
        m_datastore.get_profile.return_value = new_profile

        calico_mesos._create_profile_for_netgroup("prof_a")
        new_rules = new_profile.rules
        self.assertIn(Rule(action="allow", src_tag="prof_a"), new_rules.inbound_rules)
        self.assertIn(Rule(action="allow"), new_rules.outbound_rules)
        self.assertEqual(len(new_rules.inbound_rules) + len(new_rules.outbound_rules), 2)

    @patch('calico_mesos.datastore', autospec=True)
    def test_correct_rules_for_public_profile(self, m_datastore):
        new_profile = Mock(spec=Profile)
        m_datastore.get_profile.return_value = new_profile

        calico_mesos._create_profile_for_public_communication("public")
        new_rules = new_profile.rules

        self.assertIn(Rule(action="allow"), new_rules.inbound_rules)
        self.assertIn(Rule(action="allow"), new_rules.outbound_rules)
        self.assertEqual(len(new_rules.inbound_rules) + len(new_rules.outbound_rules), 2)


    @patch('calico_mesos.datastore', autospec=True)
    def test_profiles_are_created(self, m_datastore):
        created_endpoint = Mock(spec=Endpoint)
        m_datastore.create_endpoint.return_value = created_endpoint
        m_datastore.profile_exists.return_value = False

        profiles = ["public", "prof_a"]
        calico_mesos._isolate("testhostname", 1234, "container-id-1234", ["192.168.0.0"], [], profiles, None)

        self.assertIn("public", created_endpoint.profile_ids)
        self.assertIn("ng_prof_a", created_endpoint.profile_ids)
        self.assertIn("default_testhostname", created_endpoint.profile_ids)
        self.assertEqual(len(created_endpoint.profile_ids), 3)


class TestCleanup(unittest.TestCase):
    @parameterized.expand([
        ({"container_id": "abcdef-12345"},
        ERROR_MISSING_HOSTNAME),

        ({"hostname": "metaman"},
        ERROR_MISSING_CONTAINER_ID),
    ])
    @patch('calico_mesos._cleanup')
    def test_error_messages_with_invalid_params(self, args, error, m_cleanup):
        with self.assertRaises(IsolatorException) as e:
            calico_mesos.cleanup(args)
        self.assertEqual(e.exception.message, error)

    @patch('calico_mesos._cleanup')
    def test_cleanup(self, m_cleanup):
        args = {"hostname": "metaman", "container_id": "abcdef-12345"}
        calico_mesos.cleanup(args)
        m_cleanup.assert_called_with(args["hostname"], args["container_id"])

    @patch('calico_mesos.datastore', autospec=True)
    def test__cleanup(self, m_datastore):
        ep = Endpoint("test_host",
                      "mesos",
                      "test_workload",
                      "test_endpoint",
                      "active",
                      "aa:bb:cc:dd:ee:ff")
        ipv4_addrs = {IPAddress(ip) for ip in ["192.168.1.1", "192.168.5.4"]}
        ipv6_addrs = {IPAddress("2001:4567::1:1")}
        ep.ipv4_nets = {IPNetwork(ip) for ip in ipv4_addrs}
        ep.ipv6_nets = {IPNetwork(ip) for ip in ipv6_addrs}

        m_datastore.get_endpoint.return_value = ep

        calico_mesos._cleanup("test_host", "test_workload")

        m_datastore.release_ips.assert_called_once_with(ipv4_addrs |
                                                        ipv6_addrs)
        m_datastore.remove_endpoint.assert_called_once_with(ep)
        m_datastore.remove_workload.assert_called_once_with(
            hostname=ANY,
            orchestrator_id=ANY,
            workload_id="test_workload")


class TestGetHostIPNet(unittest.TestCase):
    IP_ADDR1_OUTPUT = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    inet 192.168.10.6/24 brd 192.168.10.255 scope global eth1
       valid_lft forever preferred_lft forever
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    inet 172.17.0.1/16 scope global docker0
       valid_lft forever preferred_lft forever
"""
    IP_ADDR1_NET = IPNetwork("10.0.2.15/32")

    @patch('calico_mesos.check_output')
    def test_get_host_ip_net_mainline(self, m_check_output):
        m_check_output.return_value = self.IP_ADDR1_OUTPUT

        ip_net = calico_mesos._get_host_ip_net()
        self.assertEqual(self.IP_ADDR1_NET, ip_net)

