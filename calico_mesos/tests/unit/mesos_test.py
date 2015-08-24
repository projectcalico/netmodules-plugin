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
from mock import patch
from mock import Mock
import json
from netaddr import IPAddress
from nose_parameterized import parameterized
from pycalico.datastore_datatypes import Rule
from pycalico.util import get_host_ips
import calico_mesos
from calico_mesos import IsolatorException
from calico_mesos import ERROR_MISSING_COMMAND, \
    ERROR_MISSING_CONTAINER_ID, \
    ERROR_MISSING_HOSTNAME, \
    ERROR_MISSING_PID, \
    ERROR_UNKNOWN_COMMAND, \
    ERROR_MISSING_ARGS


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
          "pid": 3789},),

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
          "ipv4_addrs": [],
          "pid": 3789},),

        ({"container_id": "abcdef12345",
          "hostname": "metaman",
          "ipv6_addrs": [],
          "pid": 3789},),
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
        result = calico_mesos.allocate(args)
        self.assertTrue(m_allocate.called)
        self.assertEqual(result, m_allocate())


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
    @patch('calico_mesos.datastore')
    def test_default_profile(self, m_datastore):
        m_update_rules = Mock()
        m_datastore.profile_update_rules = m_update_rules

        m_profile = Mock()
        m_datastore.get_profile.return_value = m_profile

        calico_mesos.create_profile_with_default_mesos_rules("TESTPROF")

        new_rules = m_profile.rules

        host_net = get_host_ips(version=4, exclude=["docker0"]).pop() + "/32"
        self.assertIn(Rule(action="allow", src_net=host_net), new_rules.inbound_rules)
        self.assertIn(Rule(action="allow", src_tag="TESTPROF"), new_rules.inbound_rules)
        self.assertIn(Rule(action="allow"), new_rules.outbound_rules)


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
