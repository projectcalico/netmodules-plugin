from unittest import TestCase
import os
import json
import subprocess
import etcd
import logging

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:4001"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"

sh_log = logging.getLogger('sh')
sh_log.setLevel('WARN')


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        self.stderr = ''
        etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
        (host, port) = etcd_authority.split(":", 1)
        self.etcd_client = etcd.Client(host=host,
                                       port=int(port))
        try:
            self.etcd_client.delete('/calico/', recursive=True)
        except etcd.EtcdKeyNotFound:
            pass

    def binary_exec(self, request, binary=True):
        # Convert request to string
        json_string = json.dumps(request)
        etcd_auth = "ETCD_AUTHORITY=%s:2379" % "localhost"

        # Call binary
        calico_mesos_binary = "dist/calico_mesos"

        command = "export %s; %s" % (etcd_auth, calico_mesos_binary)
        try:
             p = subprocess.Popen(command, shell=True,
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
             stdout, stderr = p.communicate(input=json_string)
             self.stderr = stderr
             return stdout

        except subprocess.CalledProcessError as e:
            # Wrap the original exception with one that gives a better error
            # message (including command output).
            print (e.called_process_error.cmd,
            e.called_process_error.returncode,
            e.called_process_error.output)
            raise e
