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

import tempfile

from oslo_concurrency import processutils

import os_net_config
from os_net_config import impl_eni
from os_net_config import objects
from os_net_config.tests import base
from os_net_config import utils

_AUTO = "auto eth0\n"

_v4_IFACE_NO_IP = _AUTO + "iface eth0 inet manual\n"

_V4_IFACE_STATIC_IP = _AUTO + """iface eth0 inet static
    address 192.168.1.2
    netmask 255.255.255.0
"""

_IFACE_HOTPLUG = """allow-hotplug eth0
iface eth0 inet static
    address 192.168.1.2
    netmask 255.255.255.0
"""

_V4_IFACE_STATIC_IP_MULTIPLE = (_V4_IFACE_STATIC_IP + _AUTO +
                                """iface eth0 inet static
    address 10.0.0.2
    netmask 255.0.0.0
""")

_V6_IFACE_STATIC_IP = _AUTO + """iface eth0 inet6 static
    address fe80::2677:3ff:fe7d:4c
    netmask 128
"""

_V6_IFACE_STATIC_IP_MULTIPLE = (_V6_IFACE_STATIC_IP + _AUTO +
                                """iface eth0 inet6 static
    address 2001:abcd::2
    netmask 64
""")

_IFACE_DHCP = _AUTO + "iface eth0 inet dhcp\n"

_OVS_PORT_BASE = _AUTO + "allow-br0 eth0\n"

_OVS_PORT_IFACE = _OVS_PORT_BASE + """iface eth0 inet manual
    ovs_bridge br0
    ovs_type OVSPort
"""

_OVS_BRIDGE_DHCP = """auto br0
allow-ovs br0
iface br0 inet dhcp
    ovs_type OVSBridge
    ovs_ports eth0
    pre-up ip addr flush dev eth0
"""

_OVS_BRIDGE_DHCP_STANDALONE = _OVS_BRIDGE_DHCP + (
    "    ovs_extra set bridge br0 fail_mode=standalone "
    "-- del-controller br0\n")

_OVS_BRIDGE_DHCP_SECURE = _OVS_BRIDGE_DHCP + \
    "    ovs_extra set bridge br0 fail_mode=secure\n"

_OVS_BRIDGE_DHCP_PRIMARY_INTERFACE = _OVS_BRIDGE_DHCP + \
    "    ovs_extra set bridge br0 other-config:hwaddr=a1:b2:c3:d4:e5\n"

_OVS_BRIDGE_DHCP_OVS_EXTRA = _OVS_BRIDGE_DHCP + \
    "    ovs_extra set bridge br0 other-config:hwaddr=a1:b2:c3:d4:e5" + \
    " -- br-set-external-id br0 bridge-id br0\n"


_VLAN_NO_IP = """auto vlan5
iface vlan5 inet manual
    vlan-raw-device eth0
"""

_VLAN_OVS_PORT = """auto vlan5
allow-br0 vlan5
iface vlan5 inet manual
    ovs_bridge br0
    ovs_type OVSIntPort
    ovs_options tag=5
"""

_RTS = """up route add -net 172.19.0.0 netmask 255.255.255.0 gw 192.168.1.1
down route del -net 172.19.0.0 netmask 255.255.255.0 gw 192.168.1.1
up route add -net 172.20.0.0 netmask 255.255.255.0 gw 192.168.1.5 metric 100
down route del -net 172.20.0.0 netmask 255.255.255.0 gw 192.168.1.5 metric 100
"""


class TestENINetConfig(base.TestCase):

    def setUp(self):
        super(TestENINetConfig, self).setUp()

        self.provider = impl_eni.ENINetConfig()
        self.if_name = 'eth0'

    def tearDown(self):
        super(TestENINetConfig, self).tearDown()

    def get_interface_config(self, name="eth0"):
        return self.provider.interfaces[name]

    def get_route_config(self):
        return self.provider.routes[self.if_name]

    def _default_interface(self, addr=[], rts=[], hotplug=False):
        return objects.Interface(self.if_name, addresses=addr, routes=rts,
                                 hotplug=hotplug)

    def test_interface_no_ip(self):
        interface = self._default_interface()
        self.provider.add_interface(interface)
        self.assertEqual(_v4_IFACE_NO_IP, self.get_interface_config())

    def test_add_interface_with_v4(self):
        v4_addr = objects.Address('192.168.1.2/24')
        interface = self._default_interface([v4_addr])
        self.provider.add_interface(interface)
        self.assertEqual(_V4_IFACE_STATIC_IP, self.get_interface_config())

    def test_add_interface_with_hotplug(self):
        v4_addr = objects.Address('192.168.1.2/24')
        interface = self._default_interface(addr=[v4_addr], hotplug=True)
        self.provider.add_interface(interface)
        self.assertEqual(_IFACE_HOTPLUG, self.get_interface_config())

    def test_add_interface_with_v4_multiple(self):
        v4_addresses = [objects.Address('192.168.1.2/24'),
                        objects.Address('10.0.0.2/8')]
        interface = self._default_interface(v4_addresses)
        self.provider.add_interface(interface)
        self.assertEqual(_V4_IFACE_STATIC_IP_MULTIPLE,
                         self.get_interface_config())

    def test_add_interface_with_v6(self):
        v6_addr = objects.Address('fe80::2677:3ff:fe7d:4c')
        interface = self._default_interface([v6_addr])
        self.provider.add_interface(interface)
        self.assertEqual(_V6_IFACE_STATIC_IP, self.get_interface_config())

    def test_add_interface_with_v6_multiple(self):
        v6_addresses = [objects.Address('fe80::2677:3ff:fe7d:4c'),
                        objects.Address('2001:abcd::2/64')]
        interface = self._default_interface(v6_addresses)
        self.provider.add_interface(interface)
        self.assertEqual(_V6_IFACE_STATIC_IP_MULTIPLE,
                         self.get_interface_config())

    def test_add_interface_dhcp(self):
        interface = self._default_interface()
        interface.use_dhcp = True
        self.provider.add_interface(interface)
        self.assertEqual(_IFACE_DHCP, self.get_interface_config())

    def test_add_interface_with_both_v4_and_v6(self):
        v4_addr = objects.Address('192.168.1.2/24')
        v6_addr = objects.Address('fe80::2677:3ff:fe7d:4c')
        interface = self._default_interface([v4_addr, v6_addr])
        self.provider.add_interface(interface)
        self.assertEqual(_V4_IFACE_STATIC_IP + _V6_IFACE_STATIC_IP,
                         self.get_interface_config())

    def test_add_ovs_port_interface(self):
        interface = self._default_interface()
        interface.ovs_port = True
        interface.bridge_name = 'br0'
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())

    def test_network_with_routes(self):
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24')
        route2 = objects.Route('192.168.1.5', '172.20.0.0/24',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        interface = self._default_interface([v4_addr], [route1, route2])
        self.provider.add_interface(interface)
        self.assertEqual(_V4_IFACE_STATIC_IP, self.get_interface_config())
        self.assertEqual(_RTS, self.get_route_config())

    def test_network_ovs_bridge_with_dhcp(self):
        interface = self._default_interface()
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface])
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP, self.provider.bridges['br0'])

    def test_network_ovs_bridge_with_standalone_fail_mode(self):
        interface = self._default_interface()
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface],
                                   fail_mode='standalone')
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP_STANDALONE,
                         self.provider.bridges['br0'])

    def test_network_ovs_bridge_with_secure_fail_mode(self):
        interface = self._default_interface()
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface],
                                   fail_mode='secure')
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP_SECURE,
                         self.provider.bridges['br0'])

    def test_network_ovs_bridge_with_dhcp_and_primary_interface(self):

        def test_interface_mac(name):
            return "a1:b2:c3:d4:e5"
        self.stubs.Set(utils, 'interface_mac', test_interface_mac)

        interface = objects.Interface(self.if_name, primary=True)
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface])
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP_PRIMARY_INTERFACE,
                         self.provider.bridges['br0'])

    def test_network_ovs_bridge_with_dhcp_and_primary_with_ovs_extra(self):

        def test_interface_mac(name):
            return "a1:b2:c3:d4:e5"
        self.stubs.Set(utils, 'interface_mac', test_interface_mac)

        interface = objects.Interface(self.if_name, primary=True)
        ovs_extra = "br-set-external-id br0 bridge-id br0"
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface],
                                   ovs_extra=[ovs_extra])
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP_OVS_EXTRA,
                         self.provider.bridges['br0'])

    def test_network_ovs_bridge_with_dhcp_and_primary_with_ovs_format(self):

        def test_interface_mac(name):
            return "a1:b2:c3:d4:e5"
        self.stubs.Set(utils, 'interface_mac', test_interface_mac)

        interface = objects.Interface(self.if_name, primary=True)
        ovs_extra = "br-set-external-id {name} bridge-id {name}"
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface],
                                   ovs_extra=[ovs_extra])
        self.provider.add_bridge(bridge)
        self.provider.add_interface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP_OVS_EXTRA,
                         self.provider.bridges['br0'])

    def test_vlan(self):
        vlan = objects.Vlan('eth0', 5)
        self.provider.add_vlan(vlan)
        self.assertEqual(_VLAN_NO_IP, self.get_interface_config('vlan5'))

    def test_vlan_mtu_1500(self):
        vlan = objects.Vlan('eth0', 5, mtu=1500)
        self.provider.add_vlan(vlan)
        expected = _VLAN_NO_IP + '    mtu 1500\n'
        self.assertEqual(expected, self.get_interface_config('vlan5'))

    def test_vlan_ovs_bridge_int_port(self):
        vlan = objects.Vlan('eth0', 5)
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[vlan])
        self.provider.add_bridge(bridge)
        self.provider.add_vlan(vlan)
        self.assertEqual(_VLAN_OVS_PORT, self.get_interface_config('vlan5'))


class TestENINetConfigApply(base.TestCase):

    def setUp(self):
        super(TestENINetConfigApply, self).setUp()
        self.temp_config_file = tempfile.NamedTemporaryFile()
        self.ifup_interface_names = []

        def test_config_path(prefix):
            return self.temp_config_file.name
        self.stubs.Set(impl_eni, '_network_config_path', test_config_path)

        def test_execute(*args, **kwargs):
            if args[0] == '/sbin/ifup':
                self.ifup_interface_names.append(args[1])
            pass

        self.stubs.Set(processutils, 'execute', test_execute)

        self.provider = impl_eni.ENINetConfig()

    def tearDown(self):
        self.temp_config_file.close()
        super(TestENINetConfigApply, self).tearDown()

    def test_network_apply(self):
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24')
        route2 = objects.Route('192.168.1.5', '172.20.0.0/24',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('eth0', addresses=[v4_addr],
                                      routes=[route1, route2])
        self.provider.add_interface(interface)

        self.provider.apply()
        iface_data = utils.get_file_data(self.temp_config_file.name)
        self.assertEqual((_V4_IFACE_STATIC_IP + _RTS), iface_data)
        self.assertIn('eth0', self.ifup_interface_names)

    def test_apply_noactivate(self):
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24')
        route2 = objects.Route('192.168.1.5', '172.20.0.0/24',
                               route_options="metric 100")
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('eth0', addresses=[v4_addr],
                                      routes=[route1, route2])
        self.provider.add_interface(interface)

        self.provider.apply(activate=False)
        iface_data = utils.get_file_data(self.temp_config_file.name)
        self.assertEqual((_V4_IFACE_STATIC_IP + _RTS), iface_data)
        self.assertEqual([], self.ifup_interface_names)

    def test_dhcp_ovs_bridge_network_apply(self):
        interface = objects.Interface('eth0')
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface])
        self.provider.add_interface(interface)
        self.provider.add_bridge(bridge)
        self.provider.apply()
        iface_data = utils.get_file_data(self.temp_config_file.name)
        self.assertEqual((_OVS_BRIDGE_DHCP + _OVS_PORT_IFACE), iface_data)
        self.assertIn('eth0', self.ifup_interface_names)
        self.assertIn('br0', self.ifup_interface_names)

    def _failed_execute(*args, **kwargs):
        if kwargs.get('check_exit_code', True):
            raise processutils.ProcessExecutionError('Test stderr',
                                                     'Test stdout',
                                                     str(kwargs))

    def test_interface_failure(self):
        self.stubs.Set(processutils, 'execute', self._failed_execute)
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr])
        self.provider.add_interface(interface)

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.apply)
        self.assertEqual(1, len(self.provider.errors))

    def test_interface_failure_multiple(self):
        self.stubs.Set(processutils, 'execute', self._failed_execute)
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('em1', addresses=[v4_addr])
        v4_addr2 = objects.Address('192.168.2.2/24')
        interface2 = objects.Interface('em2', addresses=[v4_addr2])
        self.provider.add_interface(interface)
        self.provider.add_interface(interface2)

        self.assertRaises(os_net_config.ConfigurationError,
                          self.provider.apply)
        # Even though the first one failed, we should have attempted both
        self.assertEqual(2, len(self.provider.errors))
