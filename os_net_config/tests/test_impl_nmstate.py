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

from libnmstate.schema import Ethernet
from libnmstate.schema import Ethtool
import os.path
import tempfile
import yaml

import os_net_config
from os_net_config import impl_nmstate
from os_net_config import objects
from os_net_config.tests import base
from os_net_config import utils


TEST_ENV_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__),
                                             'environment'))

_RT_DEFAULT = """# reserved values
#
255\tlocal
254\tmain
253\tdefault
0\tunspec
#
# local
#
#1\tinr.ruhep\n"""

_RT_CUSTOM = _RT_DEFAULT + "# Custom\n10\tcustom # Custom table\n20\ttable1\n"

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
        self.temp_route_table_file = tempfile.NamedTemporaryFile()
        self.provider = impl_nmstate.NmstateNetConfig()

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

        def test_route_table_path():
            return self.temp_route_table_file.name
        self.stub_out(
            'os_net_config.impl_nmstate.route_table_config_path',
            test_route_table_path)
        utils.write_config(self.temp_route_table_file.name, _RT_CUSTOM)

    def get_interface_config(self, name='em1'):
        return self.provider.interface_data[name]

    def get_nmstate_ethtool_opts(self, name):
        data = {}
        data[Ethernet.CONFIG_SUBTREE] = \
            self.provider.interface_data[name][Ethernet.CONFIG_SUBTREE]
        data[Ethtool.CONFIG_SUBTREE] = \
            self.provider.interface_data[name][Ethtool.CONFIG_SUBTREE]
        return data

    def get_dns_data(self):
        return self.provider.dns_data

    def get_route_table_config(self, name='custom', table_id=200):
        return self.provider.route_table_data.get(name, table_id)

    def get_rule_config(self):
        return self.provider.rules_data

    def get_route_config(self, name):
        return self.provider.route_data.get(name, '')

    def test_add_base_interface(self):
        interface = objects.Interface('em1')
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_NO_IP)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_interface_with_v6(self):
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('em1', addresses=[v6_addr])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V6_NMCFG)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_interface_with_v4_v6(self):
        addresses = [objects.Address('2001:abc:a::2/64'),
                     objects.Address('192.168.1.2/24')]
        interface = objects.Interface('em1', addresses=addresses)
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V4_V6_NMCFG)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

    def test_add_interface_with_v6_multiple(self):
        addresses = [objects.Address('2001:abc:a::/64'),
                     objects.Address('2001:abc:b::1/64'),
                     objects.Address('2001:abc:c::2/96')]
        interface = objects.Interface('em1', addresses=addresses)
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(_V6_NMCFG_MULTIPLE)[0],
                         self.get_interface_config())
        self.assertEqual('', self.get_route_config('em1'))

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
        self.assertEqual('', self.get_route_config('em1'))
        self.assertEqual(yaml.safe_load(em2_config)[0],
                         self.get_interface_config('em2'))
        self.assertEqual('', self.get_route_config('em2'))

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

    def test_ethtool_opts(self):
        interface1 = objects.Interface('em1',
                                       ethtool_opts='speed 1000 duplex full '
                                                    'autoneg on')
        interface2 = objects.Interface('em2',
                                       ethtool_opts='--set-ring \
                                       ${DEVICE} rx 1024 tx 1024')
        interface3 = objects.Interface('em3',
                                       ethtool_opts='-G $DEVICE '
                                       'rx 1024 tx 1024;'
                                       '-A ${DEVICE} autoneg on;'
                                       '--offload ${DEVICE} '
                                       'hw-tc-offload on')
        interface4 = objects.Interface('em4',
                                       ethtool_opts='-K ${DEVICE} '
                                       'hw-tc-offload on;'
                                       '-C ${DEVICE} adaptive-rx off '
                                       'adaptive-tx off')
        interface5 = objects.Interface('em5',
                                       ethtool_opts='-s ${DEVICE} speed '
                                       '100 duplex half autoneg off')
        # Mismatch in device name
        interface6 = objects.Interface('em6',
                                       ethtool_opts='-s em3 speed 100 '
                                       'duplex half autoneg off')
        # Unhandled option -U
        interface7 = objects.Interface('em7',
                                       ethtool_opts='-U ${DEVICE} '
                                       'flow-type tcp4 tos 1 action 10')
        # Unsupported option `advertise`
        interface8 = objects.Interface('em8',
                                       ethtool_opts='advertise 0x100000')
        # Unsupported format
        interface9 = objects.Interface('em9',
                                       ethtool_opts='s $DEVICE rx 78')

        self.provider.add_interface(interface1)
        self.provider.add_interface(interface2)
        self.provider.add_interface(interface3)
        self.provider.add_interface(interface4)
        self.provider.add_interface(interface5)

        em1_config = """
  - ethernet:
      speed: 1000
      duplex: full
      auto-negotiation: true
    ethtool: {}
"""
        em2_config = """
  - ethernet: {}
    ethtool:
      ring:
        rx: 1024
        tx: 1024
"""
        em3_config = """
  - ethernet: {}
    ethtool:
      ring:
        rx: 1024
        tx: 1024
      pause:
        autoneg: true
      feature:
        hw-tc-offload: true
"""
        em4_config = """
  - ethernet: {}
    ethtool:
      feature:
        hw-tc-offload: true
      coalesce:
        adaptive-rx: false
        adaptive-tx: false
"""
        em5_config = """
  - ethernet:
      speed: 100
      duplex: half
      auto-negotiation: false
    ethtool: {}
"""
        self.assertEqual(yaml.safe_load(em1_config)[0],
                         self.get_nmstate_ethtool_opts('em1'))
        self.assertEqual(yaml.safe_load(em2_config)[0],
                         self.get_nmstate_ethtool_opts('em2'))
        self.assertEqual(yaml.safe_load(em3_config)[0],
                         self.get_nmstate_ethtool_opts('em3'))
        self.assertEqual(yaml.safe_load(em4_config)[0],
                         self.get_nmstate_ethtool_opts('em4'))
        self.assertEqual(yaml.safe_load(em5_config)[0],
                         self.get_nmstate_ethtool_opts('em5'))
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface6)
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface7)
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface8)
        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.add_interface,
                          interface9)

    def test_add_route_table(self):
        route_table1 = objects.RouteTable('table1', 200)
        route_table2 = objects.RouteTable('table2', '201')
        self.provider.add_route_table(route_table1)
        self.provider.add_route_table(route_table2)
        self.assertEqual("table1", self.get_route_table_config(200))
        self.assertEqual("table2", self.get_route_table_config(201))

    def test_add_route_with_table(self):
        expected_route_table = """
            - destination: 172.19.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
              table-id: 200
            - destination: 172.20.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
              table-id: 201
            - destination: 172.21.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
              table-id: 200
        """
        expected_rule = """
            - ip-from: 192.0.2.0/24
              route-table: 200
        """
        route_table1 = objects.RouteTable('table1', 200)
        self.provider.add_route_table(route_table1)

        route_rule1 = objects.RouteRule('from 192.0.2.0/24 table 200',
                                        'test comment')
        # Test route table by name
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24', False,
                               route_table="table1")
        # Test that table specified in route_options takes precedence
        route2 = objects.Route('192.168.1.1', '172.20.0.0/24', False,
                               'table 201', route_table=200)
        # Test route table specified by integer ID
        route3 = objects.Route('192.168.1.1', '172.21.0.0/24', False,
                               route_table=200)
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      routes=[route1, route2, route3],
                                      rules=[route_rule1])
        self.provider.add_interface(interface)

        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))
        self.assertEqual(yaml.safe_load(expected_rule),
                         self.get_rule_config())

    def test_ip_rules(self):
        expected_rule = """
            - action: blackhole
              ip-from: 172.19.40.0/24
              route-table: 200
            - action: unreachable
              iif: em1
              ip-from: 192.168.1.0/24
            - family: ipv4
              iif: em1
              route-table: 200
        """
        rule1 = objects.RouteRule(
            'add blackhole from 172.19.40.0/24 table 200', 'rule1')
        rule2 = objects.RouteRule(
            'add unreachable iif em1 from 192.168.1.0/24', 'rule2')
        rule3 = objects.RouteRule('iif em1 table 200', 'rule3')
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      rules=[rule1, rule2, rule3])
        self.provider.add_interface(interface)

        self.assertEqual(yaml.safe_load(expected_rule),
                         self.get_rule_config())

    def test_network_with_routes(self):
        expected_route_table = """
            - destination: 0.0.0.0/0
              metric: 10
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
            - destination: 172.19.0.0/24
              next-hop-address: 192.168.1.1
              next-hop-interface: em1
            - destination: 172.20.0.0/24
              metric: 100
              next-hop-address: 192.168.1.5
              next-hop-interface: em1
        """
        route1 = objects.Route('192.168.1.1', default=True,
                               route_options="metric 10")
        route2 = objects.Route('192.168.1.1', '172.19.0.0/24')
        route3 = objects.Route('192.168.1.5', '172.20.0.0/24',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr],
                                      routes=[route1, route2, route3])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))

    def test_network_with_ipv6_routes(self):
        expected_route_table = """
            - destination: ::/0
              next-hop-address: 2001:db8::1
              next-hop-interface: em1
            - destination: 2001:db8:dead:beef:cafe::/56
              next-hop-address: fd00:fd00:2000::1
              next-hop-interface: em1
            - destination: 2001:db8:dead:beff::/64
              metric: 100
              next-hop-address: fd00:fd00:2000::1
              next-hop-interface: em1
        """
        route4 = objects.Route('2001:db8::1', default=True)
        route5 = objects.Route('fd00:fd00:2000::1',
                               '2001:db8:dead:beef:cafe::/56')
        route6 = objects.Route('fd00:fd00:2000::1',
                               '2001:db8:dead:beff::/64',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('em1', addresses=[v4_addr, v6_addr],
                                      routes=[route4, route5, route6])
        self.provider.add_interface(interface)
        self.assertEqual(yaml.safe_load(expected_route_table),
                         self.get_route_config('em1'))


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
