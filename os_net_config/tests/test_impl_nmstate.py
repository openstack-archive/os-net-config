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
import yaml

from os_net_config import impl_nmstate
from os_net_config import objects
from os_net_config.tests import base

TEST_ENV_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__),
                                             'environment'))

_BASE_IFACE_CFG = """
  -
    type: interface
    name: em1
  -
    type: interface
    name: eno2
    addresses:
     - ip_netmask: 2001:abc:a::2/64
     - ip_netmask: 192.168.1.2/24
"""

_BASE_IFACE_CFG_APPLIED = """
  em1:
    name: em1
    type: ethernet
    state: up
    ethernet: {}
    ipv4:
      enabled: false
      dhcp: False
    ipv6:
      enabled: false
      dhcp: False
      autoconf: False
  eno2:
    name: eno2
    type: ethernet
    state: up
    ethernet: {}
    ipv4:
      address:
      - ip: 192.168.1.2
        prefix-length: 24
      dhcp: false
      enabled: true
    ipv6:
      address:
      - ip: 2001:abc:a::2
        prefix-length: 64
      autoconf: false
      dhcp: false
      enabled: true
"""


_BASE_NMSTATE_IFACE_CFG = """- name: em1
  type: ethernet
  state: up
"""

_NO_IP = _BASE_NMSTATE_IFACE_CFG + """  ethernet: {}
  ipv4:
    enabled: false
    dhcp: False
  ipv6:
    enabled: false
    dhcp: False
    autoconf: False
"""

_V4_NMCFG = _BASE_NMSTATE_IFACE_CFG + """  ethernet: {}
  ipv6:
    enabled: False
    autoconf: False
    dhcp: False
  ipv4:
    enabled: True
    dhcp: False
    address:
    - ip: 192.168.1.2
      prefix-length: 24
"""

_V4_NMCFG_MULTIPLE = _V4_NMCFG + """    - ip: 192.168.2.2
      prefix-length: 32
    - ip: 10.0.0.2
      prefix-length: 8
"""

_V4_NMCFG_MAPPED = _V4_NMCFG + """
  802-3-Ethernet.cloned-mac-address: a1:b2:c3:d4:e5
"""

_V4_V6_NMCFG = _BASE_NMSTATE_IFACE_CFG + """  ipv6:
    enabled: True
    autoconf: False
    dhcp: False
    address:
    - ip: 2001:abc:a::2
      prefix-length: 64
  ipv4:
    enabled: True
    dhcp: False
    address:
    - ip: 192.168.1.2
      prefix-length: 24
  ethernet: {}
"""

_V6_NMCFG = _BASE_NMSTATE_IFACE_CFG + """  ethernet: {}
  ipv4:
    enabled: False
    dhcp: False
  ipv6:
    enabled: True
    autoconf: False
    dhcp: False
    address:
    - ip: "2001:abc:a::"
      prefix-length: 64
"""

_V6_NMCFG_MULTIPLE = _V6_NMCFG + """    - ip: 2001:abc:b::1
      prefix-length: 64
    - ip: 2001:abc:c::2
      prefix-length: 96
"""


class TestNmstateNetConfig(base.TestCase):
    def setUp(self):
        super(TestNmstateNetConfig, self).setUp()

        self.provider = impl_nmstate.NmstateNetConfig()

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

    def get_interface_config(self, name='em1'):
        return self.provider.interface_data[name]

    def get_dns_data(self):
        return self.provider.dns_data

    def test_add_base_interface(self):
        interface = objects.Interface('em1')
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_NO_IP)[0],
                         self.get_interface_config())

    def test_add_interface_with_v6(self):
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('em1', addresses=[v6_addr])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V6_NMCFG)[0],
                         self.get_interface_config())

    def test_add_interface_with_v4_v6(self):
        addresses = [objects.Address('2001:abc:a::2/64'),
                     objects.Address('192.168.1.2/24')]
        interface = objects.Interface('em1', addresses=addresses)
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V4_V6_NMCFG)[0],
                         self.get_interface_config())

    def test_add_interface_with_v6_multiple(self):
        addresses = [objects.Address('2001:abc:a::/64'),
                     objects.Address('2001:abc:b::1/64'),
                     objects.Address('2001:abc:c::2/96')]
        interface = objects.Interface('em1', addresses=addresses)
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V6_NMCFG_MULTIPLE)[0],
                         self.get_interface_config())

    def test_interface_defroute(self):
        interface1 = objects.Interface('em1')
        interface2 = objects.Interface('em2', defroute=False)
        self.provider.add_interface(interface1)
        self.provider.add_interface(interface2)
        em1_config = """- name: em1
  type: ethernet
  state: up
  ethernet: {}
  ipv4:
    enabled: False
    dhcp: False
  ipv6:
    enabled: False
    autoconf: False
    dhcp: False
"""
        em2_config = """- name: em2
  type: ethernet
  state: up
  ethernet: {}
  ipv4:
    enabled: False
    auto-gateway: False
    dhcp: False
  ipv6:
    auto-gateway: False
    enabled: False
    autoconf: False
    dhcp: False
"""
        self.assertEqual(yaml.safe_load(em1_config)[0],
                         self.get_interface_config('em1'))
        self.assertEqual(yaml.safe_load(em2_config)[0],
                         self.get_interface_config('em2'))

    def test_interface_dns_server(self):
        interface1 = objects.Interface('em1', dns_servers=['1.2.3.4'])
        self.provider.add_interface(interface1)
        em1_config = """- name: em1
  type: ethernet
  state: up
  ethernet: {}
  ipv4:
    auto-dns: False
    enabled: False
    dhcp: False
  ipv6:
    auto-dns: False
    enabled: False
    autoconf: False
    dhcp: False
"""
        test_dns_config1 = """
  server:
    - 1.2.3.4
  domain: []
"""
        self.assertEqual(yaml.safe_load(em1_config)[0],
                         self.get_interface_config('em1'))

        self.assertEqual(yaml.safe_load(test_dns_config1),
                         self.get_dns_data())
        interface2 = objects.Interface('em2',
                                       dns_servers=['1.2.3.4',
                                                    '2001:4860:4860::8888'],
                                       domain=['example.com', 'server.org'])
        self.provider.add_interface(interface2)
        test_dns_config2 = """
  server:
    - 1.2.3.4
    - 2001:4860:4860::8888
  domain:
    - example.com
    - server.org
"""
        self.assertEqual(yaml.safe_load(test_dns_config2),
                         self.get_dns_data())
        interface3 = objects.Interface('em3',
                                       dns_servers=['1.2.3.4',
                                                    '2001:4860:4860::8888'],
                                       domain='testdomain.com')
        self.provider.add_interface(interface3)
        test_dns_config3 = """
  server:
    - 1.2.3.4
    - 2001:4860:4860::8888
  domain:
    - example.com
    - server.org
    - testdomain.com
"""
        self.assertEqual(yaml.safe_load(test_dns_config3),
                         self.get_dns_data())


class TestNmstateNetConfigApply(base.TestCase):

    def setUp(self):
        super(TestNmstateNetConfigApply, self).setUp()

        def test_iface_state(iface_data='', verify_change=True):
            # This function returns None
            return None
        self.stub_out(
            'libnmstate.netapplier.apply', test_iface_state)
        self.provider = impl_nmstate.NmstateNetConfig()

    def add_object(self, nic_config):
        iface_array = yaml.safe_load(nic_config)
        for iface_json in iface_array:
            obj = objects.object_from_json(iface_json)
            self.provider.add_object(obj)

    def get_running_info(self, yaml_file):
        with open(yaml_file) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
            return data

    def tearDown(self):
        super(TestNmstateNetConfigApply, self).tearDown()

    def test_base_interface(self):

        def show_running_info_stub():
            running_info_path = os.path.join(
                os.path.dirname(__file__),
                'environment/netinfo_running_info_1.yaml')
            running_info = self.get_running_info(running_info_path)
            return running_info
        self.stub_out('libnmstate.netinfo.show_running_config',
                      show_running_info_stub)

        self.add_object(_BASE_IFACE_CFG)
        updated_files = self.provider.apply()
        self.assertEqual(yaml.load(_BASE_IFACE_CFG_APPLIED,
                                   Loader=yaml.SafeLoader),
                         updated_files)
