# -*- coding: utf-8 -*-

# Copyright 2014 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os.path
import sys

from os_net_config import cli
from os_net_config.tests import base
import six


SAMPLE_BASE = os.path.join('.', 'etc', 'os-net-config', 'samples')


class TestCli(base.TestCase):

    def run_cli(self, argstr, exitcodes=(0,)):
        orig = sys.stdout
        orig_stderr = sys.stderr
        try:
            sys.stdout = six.StringIO()
            sys.stderr = six.StringIO()
            cli.main(argstr.split())
        except SystemExit:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.assertIn(exc_value.code, exitcodes)
        finally:
            stdout = sys.stdout.getvalue()
            sys.stdout.close()
            sys.stdout = orig
            stderr = sys.stderr.getvalue()
            sys.stderr.close()
            sys.stderr = orig_stderr
        return (stdout, stderr)

    def test_bond_noop_output(self):
        bond_yaml = os.path.join(SAMPLE_BASE, 'bond.yaml')
        bond_json = os.path.join(SAMPLE_BASE, 'bond.json')
        stdout_yaml, stderr = self.run_cli('ARG0 -d --noop -c %s' % bond_yaml)
        stdout_json, stderr = self.run_cli('ARG0 -d --noop -c %s' % bond_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_bridge_noop_output(self):
        bridge_yaml = os.path.join(SAMPLE_BASE, 'bridge_dhcp.yaml')
        bridge_json = os.path.join(SAMPLE_BASE, 'bridge_dhcp.json')
        stdout_yaml, stderr = self.run_cli('ARG0 -d --noop -c %s' %
                                           bridge_yaml)
        stdout_json, stderr = self.run_cli('ARG0 -d --noop -c %s' %
                                           bridge_json)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_vlan_noop_output(self):
        vlan_yaml = os.path.join(SAMPLE_BASE, 'bridge_vlan.yaml')
        vlan_json = os.path.join(SAMPLE_BASE, 'bridge_vlan.json')
        stdout_yaml, stderr = self.run_cli('ARG0 -d --noop -c %s' % vlan_yaml)
        stdout_json, stderr = self.run_cli('ARG0 -d --noop -c %s' % vlan_json)
        self.assertEqual(stdout_yaml, stdout_json)
