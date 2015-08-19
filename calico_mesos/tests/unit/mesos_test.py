import unittest
from mock import patch
import calico_mesos
from calico_mesos import IsolatorException
import json
from nose_parameterized import parameterized

from calico_mesos import ERROR_MISSING_COMMAND, \
    ERROR_MISSING_CONTAINER_ID, \
    ERROR_MISSING_HOSTNAME, \
    ERROR_MISSING_PID, \
    ERROR_UNKNOWN_COMMAND, \
    ERROR_MISSING_ARGS

def error_message(msg=None):
    """
    Helper function to convert error messages into the JSON format, print
    to stdout, and then quit.
    """
    return json.dumps({"error": msg})

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
        ERROR_MISSING_PID)
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
