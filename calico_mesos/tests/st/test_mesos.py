import os
from test_base import TestBase
import json
import socket
from docker import Client
from sh import calicoctl, ln, ip
from sh import ErrorReturnCode, ErrorReturnCode_1
import re

class TestMesos(TestBase):
    pid = 3789
    container_id = "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a"

    def tearDown(self):
        # Create a network namespace
        from sh import ip
        ns = ip("netns", "show", self.pid)
        if ns and (str(self.pid) in ns.stdout):
            try:
                ip("netns", "delete", self.pid)
            except (ErrorReturnCode, ErrorReturnCode_1) as e:
                print "Didn't delete ns: %s" % e

        try:
            os.remove("/var/run/netns/%s" % self.pid)
        except OSError:
            pass

        # Wipe all cali interfaces
        regex = r'((?:cali)[0-9a-f]+):'
        interface_names = re.findall(regex, ip('link').stdout)
        for interface in interface_names:
            ip('link', 'del', 'dev', interface)


    def test_prepare(self):
        # Test prepare
        hostname = socket.gethostname()

        indata = {
            "command": "prepare",
            "args": {
                "hostname": hostname,
                "container-id": self.container_id,
                "ipv4_addrs": ["192.168.23.4"],
                "ipv6_addrs": [],
                "netgroups": ["prod", "frontend"],
                "labels": {
                    "rack": "3A",
                    "pop": "houston"
                }
            }
        }

        # Prepare network environment
        calicoctl("pool", "add", "192.168.0.0/16")

        # Set up bgp host configuration
        calicoctl("node")

        output = self.binary_exec(indata)
        self.assertEqual(self.stderr, '')
        self.assertEqual(output, error_msg())


    def test_isolate(self):
        pass
        return
        # # Start a sample container
        # docker_client = Client(version=DOCKER_VERISON, base_url='unix://var/run/docker.sock')
        # container = docker_client.create_container('busybox')
        # container.start()
        # from nose.tools import set_trace; set_trace()
        # Create the netns, which will create a netns at
        # /var/run/netns/{pid}
        ip("netns", "add", self.pid)

        # os.makedirs("/proc/%s/ns/" % self.container_id)
        # os.symlink("/var/run/netns/%s" % self.pid, "/proc/%s/ns/net" % self.container_id)

        # Test isolate
        indata = {
            "command": "isolate",
            "args": {
                "hostname": hostname, # Required
                "container-id": self.container_id, # Required
                "pid": self.pid # Required
            }
        }

        output = self.binary_exec(indata)
        self.assertEqual(self.stderr, '')
        self.assertEqual(output, error_msg())


def error_msg(msg=None):
    return json.dumps({"error": msg})
