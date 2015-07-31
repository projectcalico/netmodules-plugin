from test_base import TestBase
import json
import socket
from sh import calicoctl
from sh import ErrorReturnCode


hostname = socket.gethostname()

class TestMesos(TestBase):
    def test_empty_json(self):
        pass
        return
        output = binary_exec("{}")
        print output
        self.assertEqual(output, error_msg("Missing command"))

    def test_mainline(self):
        # Test prepare
        indata = {
            "command": "prepare",
            "args": {
                "hostname": hostname,
                "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a",
                "ipv4_addrs": ["192.168.23.4"],
                "ipv6_addrs": ["2001:3ac3:f90b:1111::1"],
                "netgroups": ["prod", "frontend"],
                "labels": {
                    "rack": "3A",
                    "pop": "houston"
                }
            }
        }

        # Prepare network environment
        calicoctl("pool", "add", "192.168.0.0/16")

        # Create a network namespace
        from sh import ip
        pid = indata['args']['container-id']
        try:
            ip("netns", "delete", pid)
        except ErrorReturnCode:
            pass

        # Set up bgp host configuration
        calicoctl("node")

        output = self.binary_exec(indata)
        self.assertEqual(self.stderr, '')
        self.assertEqual(output, error_msg())


        indata = {
            "command": "isolate",
            "args": {
                "hostname": hostname, # Required
                "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a", # Required
                "pid": 3789 # Required
            }
        }
        output = self.binary_exec(indata)
        self.assertEqual(self.stderr, '')
        self.assertEqual(output, error_msg())



def error_msg(msg=None):
    error_msg = json.dumps({"error": msg})
    return error_msg