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
import os
from test_base import TestBase
import json
import socket
from sh import calicoctl, ip
from sh import ErrorReturnCode, ErrorReturnCode_1
import re
import etcd
from pycalico.util import get_host_ips


class TestMesos(TestBase):
    pid = 3789
    container_id = "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a"

    def tearDown(self):
        # Create a network namespace
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


    def test_isolate(self):
        # Test isolate
        hostname = socket.gethostname()

        indata = {
            "command": "isolate",
            "args": {
                "hostname": hostname,
                "container-id": self.container_id,
                "ipv4_addrs": ["192.168.23.4"],
                "ipv6_addrs": [],
                "netgroups": ["prod", "frontend"],
                "labels": {
                    "rack": "3A",
                    "pop": "houston"
                },
                "pid": 3789
            }
        }

        # Prepare network environment
        calicoctl("pool", "add", "192.168.0.0/16")

        # Set up bgp host configuration
        calicoctl("node")

        output = self.binary_exec(indata)
        self.assertEqual(self.stderr, '')
        self.assertEqual(output, error_msg())

        # Check if the endpoint was correctly written to etcd
        host = "127.0.0.1"
        port = 4001
        etcd_client = etcd.Client(host=host, port=port)
        leaves = etcd_client.read('/calico/v1/host/%s/workload/%s/%s/endpoint' % \
                                  (hostname, "mesos", self.container_id), recursive=True).leaves
        values = [leaf for leaf in leaves]
        self.assertEqual(len(values), 1, "Only 1 endpoint should exist: %d were found" % len(values))
        endpoint = values.pop()
        endpoint_dict = json.loads(endpoint.value)
        self.assertEqual(endpoint_dict["ipv4_gateway"], get_host_ips(exclude="docker0").pop())
        self.assertEqual(endpoint_dict["ipv4_nets"], ["192.168.23.4"])
        self.assertEqual(endpoint_dict["profile_ids"], ["prod", "frontend"])


def error_msg(msg=None):
    return json.dumps({"error": msg})
