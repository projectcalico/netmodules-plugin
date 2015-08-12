import unittest
from mock import patch
import calico_mesos
import json
from nose_parameterized import parameterized

from calico_mesos import ERROR_MISSING_COMMAND, \
    ERROR_MISSING_CONTAINER_ID, \
    ERROR_MISSING_HOSTNAME, \
    ERROR_MISSING_IPV4_ADDRS, \
    ERROR_MISSING_IPV6_ADDRS, \
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

        ({"container-id": "abcdef12345",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["abcd::"],
          "pid": 3789},
        ERROR_MISSING_HOSTNAME),

        ({"container-id": "abcdef12345",
          "hostname": "metaman",
          "ipv6_addrs": ["abcd::"],
          "pid": 3789},
        ERROR_MISSING_IPV4_ADDRS),

        ({"container-id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "pid": 3789},
        ERROR_MISSING_IPV6_ADDRS),

        ({"container-id": "abcdef12345",
          "hostname": "metaman",
          "ipv4_addrs": ["192.168.1.1"],
          "ipv6_addrs": ["abcd::"]},
        ERROR_MISSING_PID)
    ])
    @patch('calico_mesos._isolate')
    def test_error_messages_with_invalid_params(self, args, error, m_isolate):
        result = calico_mesos.isolate(args)
        self.assertEqual(result, error_message(error))
        self.assertFalse(m_isolate.called)

    @patch('calico_mesos._isolate')
    def test_isolate_executes_with_valid_params(self, m_isolate):
        args = {"container-id": "abcdef12345",
                "hostname": "metaman",
                "ipv4_addrs": ["192.168.1.1"],
                "ipv6_addrs": ["abcd::"],
                "pid": 3789}
        result = calico_mesos.isolate(args)
        self.assertEqual(result, None)
        self.assertTrue(m_isolate.called)


class TestDispatch(unittest.TestCase):
    @parameterized.expand([
        ({"args": {}},
        ERROR_MISSING_COMMAND),

        ({"args": {},
         "command": "not-a-real-command"},
         ERROR_UNKNOWN_COMMAND % "not-a-real-command"),

        ({"command": "isolate"},
         ERROR_MISSING_ARGS),
    ])
    @patch('sys.stdin')
    def test_dispatch_catches_errors(self, args, error, m_stdin):
        m_stdin.read.return_value = json.dumps(args)
        results = calico_mesos.calico_mesos()
        self.assertEqual(results, error_message(error))

    @patch('calico_mesos.isolate')
    @patch('sys.stdin')
    def test_distpach_calls_isolate(self, m_stdin, m_isolate):
        # Load stdin.read to return input string
        args = {"args": {},
                "command": "isolate"}
        m_stdin.read.return_value = json.dumps(args)

        # Call function
        calico_mesos.calico_mesos()
        self.assertTrue(m_isolate.called)

    @patch('calico_mesos.cleanup')
    @patch('sys.stdin')
    def test_distpach_calls_cleanup(self, m_stdin, m_cleanup):
        # Load stdin.read to return input string
        args = {"args": {},
                "command": "cleanup"}
        m_stdin.read.return_value = json.dumps(args)

        # Call function
        calico_mesos.calico_mesos()
        self.assertTrue(m_cleanup.called)
