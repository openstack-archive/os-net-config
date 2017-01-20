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

import os_net_config
from os_net_config import cli
from os_net_config import impl_ifcfg
from os_net_config.tests import base
import six


REALPATH = os.path.dirname(os.path.realpath(__file__))
SAMPLE_BASE = os.path.join(REALPATH, '../../', 'etc',
                           'os-net-config', 'samples')


class TestCli(base.TestCase):

    def run_cli(self, argstr, exitcodes=(0,)):
        orig = sys.stdout
        orig_stderr = sys.stderr

        sys.stdout = six.StringIO()
        sys.stderr = six.StringIO()
        ret = cli.main(argstr.split())
        self.assertIn(ret, exitcodes)

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
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bond_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bond_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-ctlplane',
                          'DEVICE=em2',
                          'DEVICE=em1',
                          'DEVICE=bond1',
                          'DEVICETYPE=ovs']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_ivs_noop_output(self):
        ivs_yaml = os.path.join(SAMPLE_BASE, 'ivs.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'ivs.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=nic2',
                          'DEVICE=nic3',
                          'DEVICE=api201',
                          'DEVICE=storage202',
                          'DEVICETYPE=ivs']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_bridge_noop_output(self):
        bridge_yaml = os.path.join(SAMPLE_BASE, 'bridge_dhcp.yaml')
        bridge_json = os.path.join(SAMPLE_BASE, 'bridge_dhcp.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=eni --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bridge_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=eni --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % bridge_json)
        self.assertEqual('', stderr)
        sanity_devices = ['iface br-ctlplane inet dhcp',
                          'iface em1',
                          'ovs_type OVSBridge']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_vlan_noop_output(self):
        vlan_yaml = os.path.join(SAMPLE_BASE, 'bridge_vlan.yaml')
        vlan_json = os.path.join(SAMPLE_BASE, 'bridge_vlan.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % vlan_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % vlan_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-ctlplane',
                          'DEVICE=em1',
                          'DEVICE=vlan16',
                          'DEVICETYPE=ovs']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_interface_noop_output(self):
        interface_yaml = os.path.join(SAMPLE_BASE, 'interface.yaml')
        interface_json = os.path.join(SAMPLE_BASE, 'interface.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % interface_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % interface_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=em1',
                          'BOOTPROTO=static',
                          'IPADDR=192.0.2.1']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_bridge_noop_rootfs(self):
        for provider in ('ifcfg', 'eni'):
            bond_yaml = os.path.join(SAMPLE_BASE, 'bridge_dhcp.yaml')
            stdout_yaml, stderr = self.run_cli('ARG0 --provider=%s --noop '
                                               '--exit-on-validation-errors '
                                               '--root-dir=/rootfs '
                                               '-c %s' % (provider, bond_yaml))
            self.assertEqual('', stderr)
            self.assertIn('File: /rootfs/', stdout_yaml)

    def test_interface_noop_detailed_exit_codes(self):
        interface_yaml = os.path.join(SAMPLE_BASE, 'interface.yaml')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s --detailed-exit-codes'
                                           % interface_yaml, exitcodes=(2,))

    def test_interface_noop_detailed_exit_codes_no_changes(self):
        interface_yaml = os.path.join(SAMPLE_BASE, 'interface.yaml')

        class TestImpl(os_net_config.NetConfig):

            def add_interface(self, interface):
                pass

            def apply(self, cleanup=False, activate=True):
                # this fake implementation returns no changes
                return {}

        self.stubs.Set(impl_ifcfg, 'IfcfgNetConfig', TestImpl)
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s --detailed-exit-codes'
                                           % interface_yaml, exitcodes=(0,))

    def test_ovs_dpdk_bond_noop_output(self):
        ivs_yaml = os.path.join(SAMPLE_BASE, 'ovs_dpdk_bond.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'ovs_dpdk_bond.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-link',
                          'TYPE=OVSUserBridge',
                          'DEVICE=dpdkbond0',
                          'TYPE=OVSDPDKBond']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_nfvswitch_noop_output(self):
        nfvswitch_yaml = os.path.join(SAMPLE_BASE, 'nfvswitch.yaml')
        nfvswitch_json = os.path.join(SAMPLE_BASE, 'nfvswitch.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % nfvswitch_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % nfvswitch_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=nic2',
                          'DEVICE=nic3',
                          'DEVICE=api201',
                          'DEVICE=storage202',
                          'DEVICETYPE=nfvswitch']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)

    def test_ovs_dpdk_noop_output(self):
        ivs_yaml = os.path.join(SAMPLE_BASE, 'ovs_dpdk.yaml')
        ivs_json = os.path.join(SAMPLE_BASE, 'ovs_dpdk.json')
        stdout_yaml, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_yaml)
        self.assertEqual('', stderr)
        stdout_json, stderr = self.run_cli('ARG0 --provider=ifcfg --noop '
                                           '--exit-on-validation-errors '
                                           '-c %s' % ivs_json)
        self.assertEqual('', stderr)
        sanity_devices = ['DEVICE=br-link',
                          'TYPE=OVSUserBridge',
                          'DEVICE=dpdk0',
                          'TYPE=OVSDPDKPort']
        for dev in sanity_devices:
            self.assertIn(dev, stdout_yaml)
        self.assertEqual(stdout_yaml, stdout_json)
