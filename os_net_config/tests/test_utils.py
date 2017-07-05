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

import os
import os.path
import random
import shutil
import tempfile
import yaml

from os_net_config.tests import base
from os_net_config import utils

from oslo_concurrency import processutils

_PCI_OUTPUT = '''driver: e1000e
version: 3.2.6-k
firmware-version: 0.13-3
expansion-rom-version:
bus-info: 0000:00:19.0
supports-statistics: yes
supports-test: yes
supports-eeprom-access: yes
supports-register-dump: yes
supports-priv-flags: no
'''


class TestUtils(base.TestCase):

    def setUp(self):
        super(TestUtils, self).setUp()
        rand = str(int(random.random() * 100000))
        utils._DPDK_MAPPING_FILE = '/tmp/dpdk_mapping_' + rand + '.yaml'

    def tearDown(self):
        super(TestUtils, self).tearDown()
        if os.path.isfile(utils._DPDK_MAPPING_FILE):
            os.remove(utils._DPDK_MAPPING_FILE)

    def test_ordered_active_nics(self):

        tmpdir = tempfile.mkdtemp()
        self.stubs.Set(utils, '_SYS_CLASS_NET', tmpdir)

        def test_is_available_nic(interface_name, check_active):
            return True
        self.stubs.Set(utils, '_is_available_nic', test_is_available_nic)

        for nic in ['a1', 'em1', 'em2', 'eth2', 'z1',
                    'enp8s0', 'enp10s0', 'enp1s0f0']:
            with open(os.path.join(tmpdir, nic), 'w') as f:
                f.write(nic)

        nics = utils.ordered_active_nics()
        self.assertEqual('em1', nics[0])
        self.assertEqual('em2', nics[1])
        self.assertEqual('eth2', nics[2])
        self.assertEqual('a1', nics[3])
        self.assertEqual('enp1s0f0', nics[4])
        self.assertEqual('enp8s0', nics[5])
        self.assertEqual('enp10s0', nics[6])
        self.assertEqual('z1', nics[7])

        shutil.rmtree(tmpdir)

    def test_get_pci_address_success(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                out = _PCI_OUTPUT
                return out, None
        self.stubs.Set(processutils, 'execute', test_execute)
        pci = utils._get_pci_address('nic2', False)
        self.assertEqual('0000:00:19.0', pci)

    def test_get_pci_address_exception(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                raise processutils.ProcessExecutionError
        self.stubs.Set(processutils, 'execute', test_execute)
        pci = utils._get_pci_address('nic2', False)
        self.assertEqual(None, pci)

    def test_get_pci_address_error(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                return None, 'Error'
        self.stubs.Set(processutils, 'execute', test_execute)
        pci = utils._get_pci_address('nic2', False)
        self.assertEqual(None, pci)

    def test_get_stored_pci_address_success(self):
        def test_get_dpdk_map():
            return [{'name': 'eth1', 'pci_address': '0000:00:09.0',
                     'mac_address': '01:02:03:04:05:06',
                     'driver': 'vfio-pci'}]

        self.stubs.Set(utils, '_get_dpdk_map', test_get_dpdk_map)
        pci = utils.get_stored_pci_address('eth1', False)
        self.assertEqual('0000:00:09.0', pci)

    def test_get_stored_pci_address_empty(self):
        def test_get_dpdk_map():
            return []

        self.stubs.Set(utils, '_get_dpdk_map', test_get_dpdk_map)
        pci = utils.get_stored_pci_address('eth1', False)
        self.assertEqual(None, pci)

    def test_bind_dpdk_interfaces(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                out = _PCI_OUTPUT
                return out, None
            if 'driverctl' in name:
                return None, None

        def test_get_dpdk_mac_address(name):
            return '01:02:03:04:05:06'
        self.stubs.Set(processutils, 'execute', test_execute)
        self.stubs.Set(utils, '_get_dpdk_mac_address',
                       test_get_dpdk_mac_address)
        try:
            utils.bind_dpdk_interfaces('nic2', 'vfio-pci', False)
        except utils.OvsDpdkBindException:
            self.fail("Received OvsDpdkBindException unexpectedly")

    def test_bind_dpdk_interfaces_fail(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                out = _PCI_OUTPUT
                return out, None
            if 'driverctl' in name:
                return None, 'Error'

        def test_get_dpdk_mac_address(name):
            return '01:02:03:04:05:06'
        self.stubs.Set(processutils, 'execute', test_execute)
        self.stubs.Set(utils, '_get_dpdk_mac_address',
                       test_get_dpdk_mac_address)

        self.assertRaises(utils.OvsDpdkBindException,
                          utils.bind_dpdk_interfaces, 'eth1', 'vfio-pci',
                          False)

    def test_bind_dpdk_interfaces_skip_valid_device(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                return None, 'Error'
            if 'driverctl' in name:
                return None, None

        def test_get_dpdk_mac_address(name):
            return '01:02:03:04:05:06'

        def test_get_dpdk_map():
            return [{'name': 'eth1', 'pci_address': '0000:00:09.0',
                     'mac_address': '01:02:03:04:05:06',
                     'driver': 'vfio-pci'}]

        self.stubs.Set(utils, '_get_dpdk_map', test_get_dpdk_map)
        self.stubs.Set(processutils, 'execute', test_execute)
        self.stubs.Set(utils, '_get_dpdk_mac_address',
                       test_get_dpdk_mac_address)
        try:
            utils.bind_dpdk_interfaces('eth1', 'vfio-pci', False)
        except utils.OvsDpdkBindException:
            self.fail("Received OvsDpdkBindException unexpectedly")

    def test_bind_dpdk_interfaces_fail_invalid_device(self):
        def test_execute(name, dummy1, dummy2=None, dummy3=None):
            if 'ethtool' in name:
                return None, 'Error'
            if 'driverctl' in name:
                return None, None

        def test_get_dpdk_mac_address(name):
            return '01:02:03:04:05:06'

        def test_get_dpdk_map():
            return [{'name': 'eth1', 'pci_address': '0000:00:09.0',
                     'mac_address': '01:02:03:04:05:06',
                     'driver': 'vfio-pci'}]

        self.stubs.Set(utils, '_get_dpdk_map', test_get_dpdk_map)
        self.stubs.Set(processutils, 'execute', test_execute)
        self.stubs.Set(utils, '_get_dpdk_mac_address',
                       test_get_dpdk_mac_address)

        self.assertRaises(utils.OvsDpdkBindException,
                          utils.bind_dpdk_interfaces, 'eth2', 'vfio-pci',
                          False)

    def test__update_dpdk_map_new(self):
        utils._update_dpdk_map('eth1', '0000:03:00.0', '01:02:03:04:05:06',
                               'vfio-pci')
        contents = utils.get_file_data(utils._DPDK_MAPPING_FILE)

        dpdk_map = yaml.load(contents) if contents else []
        self.assertEqual(1, len(dpdk_map))
        dpdk_test = [{'name': 'eth1', 'pci_address': '0000:03:00.0',
                      'mac_address': '01:02:03:04:05:06',
                      'driver': 'vfio-pci'}]
        self.assertListEqual(dpdk_test, dpdk_map)

    def test_update_dpdk_map_exist(self):
        dpdk_test = [{'name': 'eth1', 'pci_address': '0000:03:00.0',
                      'mac_address': '01:02:03:04:05:06',
                      'driver': 'vfio-pci'}]
        utils.write_yaml_config(utils._DPDK_MAPPING_FILE, dpdk_test)

        utils._update_dpdk_map('eth1', '0000:03:00.0', '01:02:03:04:05:06',
                               'vfio-pci')
        contents = utils.get_file_data(utils._DPDK_MAPPING_FILE)

        dpdk_map = yaml.load(contents) if contents else []
        self.assertEqual(1, len(dpdk_map))
        self.assertListEqual(dpdk_test, dpdk_map)

    def test_update_dpdk_map_value_change(self):
        dpdk_test = [{'name': 'eth1', 'pci_address': '0000:03:00.0',
                      'driver': 'vfio-pci'}]
        utils.write_yaml_config(utils._DPDK_MAPPING_FILE, dpdk_test)

        dpdk_test = [{'name': 'eth1', 'pci_address': '0000:03:00.0',
                      'mac_address': '01:02:03:04:05:06',
                      'driver': 'vfio-pci'}]
        utils._update_dpdk_map('eth1', '0000:03:00.0', '01:02:03:04:05:06',
                               'vfio-pci')
        try:
            contents = utils.get_file_data(utils._DPDK_MAPPING_FILE)
        except IOError:
            pass

        dpdk_map = yaml.load(contents) if contents else []
        self.assertEqual(1, len(dpdk_map))
        self.assertListEqual(dpdk_test, dpdk_map)

    def test_ordered_active_nics_with_dpdk_mapping(self):

        tmpdir = tempfile.mkdtemp()
        self.stubs.Set(utils, '_SYS_CLASS_NET', tmpdir)

        def test_is_available_nic(interface_name, check_active):
            return True
        self.stubs.Set(utils, '_is_available_nic', test_is_available_nic)

        for nic in ['a1', 'em1', 'em2', 'eth2', 'z1',
                    'enp8s0', 'enp10s0', 'enp1s0f0']:
            with open(os.path.join(tmpdir, nic), 'w') as f:
                f.write(nic)

        utils._update_dpdk_map('eth1', '0000:03:00.0', '01:02:03:04:05:06',
                               'vfio-pci')
        utils._update_dpdk_map('p3p1', '0000:04:00.0', '01:02:03:04:05:07',
                               'igb_uio')

        nics = utils.ordered_active_nics()

        self.assertEqual('em1', nics[0])
        self.assertEqual('em2', nics[1])
        self.assertEqual('eth1', nics[2])  # DPDK bound nic
        self.assertEqual('eth2', nics[3])
        self.assertEqual('a1', nics[4])
        self.assertEqual('enp1s0f0', nics[5])
        self.assertEqual('enp8s0', nics[6])
        self.assertEqual('enp10s0', nics[7])
        self.assertEqual('p3p1', nics[8])  # DPDK bound nic
        self.assertEqual('z1', nics[9])

        shutil.rmtree(tmpdir)

    def test_interface_mac_raises(self):
        self.assertRaises(IOError, utils.interface_mac, 'ens20f2p3')

    def test_is_active_nic_for_sriov_vf(self):

        tmpdir = tempfile.mkdtemp()
        self.stubs.Set(utils, '_SYS_CLASS_NET', tmpdir)

        # SR-IOV PF = ens802f0
        # SR-IOV VF = enp129s2
        for nic in ['ens802f0', 'enp129s2']:
            nic_path = os.path.join(tmpdir, nic)
            os.makedirs(nic_path)
            os.makedirs(os.path.join(nic_path, 'device'))
            with open(os.path.join(nic_path, 'operstate'), 'w') as f:
                f.write('up')
            with open(os.path.join(nic_path, 'address'), 'w') as f:
                f.write('1.2.3.4')

        nic_path = os.path.join(tmpdir, 'enp129s2', 'device', 'physfn')
        os.makedirs(nic_path)

        self.assertEqual(utils._is_active_nic('ens802f0'), True)
        self.assertEqual(utils._is_active_nic('enp129s2'), False)

        shutil.rmtree(tmpdir)
