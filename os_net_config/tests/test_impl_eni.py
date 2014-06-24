
# -*- coding: utf-8 -*-

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

from os_net_config import impl_eni
from os_net_config import objects
from os_net_config.openstack.common import processutils
from os_net_config.tests import base
from os_net_config import utils

_AUTO = "auto eth0\n"

_BASE_IFACE = "iface eth0"

_v4_IFACE_NO_IP = _AUTO + _BASE_IFACE + " inet manual\n"

_V4_IFACE_STATIC_IP = _AUTO + _BASE_IFACE + """ inet static
address 192.168.1.2
netmask 255.255.255.0
"""

_V6_IFACE_STATIC_IP = _AUTO + _BASE_IFACE + """ inet6 static
address fe80::2677:3ff:fe7d:4c
netmask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
"""

_OVS_PORT_BASE = "allow-br0 eth0\n"

_OVS_IFACE_DHCP = _BASE_IFACE + " inet dhcp\n"

_OVS_PORT_IFACE = _OVS_PORT_BASE + _OVS_IFACE_DHCP + """ovs_bridge br0
ovs_type OVSPort\n"""

_OVS_BRIDGE_DHCP = """allow-ovs br0
iface br0 inet dhcp
ovs_type OVSBridge
ovs_ports eth0
"""

_RTS = """up route add -net 172.19.0.0 netmask 255.255.255.0 gw 192.168.1.1
down route del -net 172.19.0.0 netmask 255.255.255.0 gw 192.168.1.1
"""


class TestENINetConfig(base.TestCase):

    def setUp(self):
        super(TestENINetConfig, self).setUp()

        self.provider = impl_eni.ENINetConfig()
        self.if_name = 'eth0'

    def tearDown(self):
        super(TestENINetConfig, self).tearDown()

    def get_interface_config(self):
        return self.provider.interfaces[self.if_name]

    def get_route_config(self):
        return self.provider.routes[self.if_name]

    def _default_interface(self, addr=[], rts=[]):
        return objects.Interface(self.if_name, addresses=addr, routes=rts)

    def test_add_base_interface(self):
        interface = self._default_interface()
        self.provider.addInterface(interface)
        self.assertEqual(_v4_IFACE_NO_IP, self.get_interface_config())

    def test_add_ovs_port_interface(self):
        interface = self._default_interface()
        interface.type = 'ovs_port'
        interface.bridge_name = 'br0'
        interface.use_dhcp = True
        self.provider.addInterface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())

    def test_add_interface_with_v4(self):
        v4_addr = objects.Address('192.168.1.2/24')
        interface = self._default_interface([v4_addr])
        self.provider.addInterface(interface)
        self.assertEqual(_V4_IFACE_STATIC_IP, self.get_interface_config())

    def test_add_interface_with_v6(self):
        v6_addr = objects.Address('fe80::2677:3ff:fe7d:4c')
        interface = self._default_interface([v6_addr])
        self.provider.addInterface(interface)
        self.assertEqual(_V6_IFACE_STATIC_IP, self.get_interface_config())

    def test_network_with_routes(self):
        route1 = objects.Route('192.168.1.1', '172.19.0.0/24')
        v4_addr = objects.Address('192.168.1.2/24')
        interface = self._default_interface([v4_addr], [route1])
        self.provider.addInterface(interface)
        self.assertEqual(_V4_IFACE_STATIC_IP, self.get_interface_config())
        self.assertEqual(_RTS, self.get_route_config())

    def test_network_ovs_bridge_with_dhcp(self):
        interface = self._default_interface()
        interface.use_dhcp = True
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface])
        self.provider.addBridge(bridge)
        self.provider.addInterface(interface)
        self.assertEqual(_OVS_PORT_IFACE, self.get_interface_config())
        self.assertEqual(_OVS_BRIDGE_DHCP, self.provider.bridges['br0'])


class TestENINetConfigApply(base.TestCase):

    def setUp(self):
        super(TestENINetConfigApply, self).setUp()
        self.temp_config_file = tempfile.NamedTemporaryFile()

        def test_config_path():
            return self.temp_config_file.name
        self.stubs.Set(impl_eni, '_network_config_path', test_config_path)

        def test_execute(*args, **kwargs):
            pass
        self.stubs.Set(processutils, 'execute', test_execute)

        self.provider = impl_eni.ENINetConfig()

    def tearDown(self):
        self.temp_config_file.close()
        super(TestENINetConfigApply, self).tearDown()

    def test_network_apply(self):
        route = objects.Route('192.168.1.1', '172.19.0.0/24')
        v4_addr = objects.Address('192.168.1.2/24')
        interface = objects.Interface('eth0', addresses=[v4_addr],
                                      routes=[route])
        self.provider.addInterface(interface)

        self.provider.apply()
        iface_data = utils.get_file_data(self.temp_config_file.name)
        self.assertEqual((_V4_IFACE_STATIC_IP + _RTS), iface_data)

    def test_dhcp_ovs_bridge_network_apply(self):
        interface = objects.Interface('eth0')
        interface.use_dhcp = True
        bridge = objects.OvsBridge('br0', use_dhcp=True,
                                   members=[interface])
        self.provider.addInterface(interface)
        self.provider.addBridge(bridge)
        self.provider.apply()
        iface_data = utils.get_file_data(self.temp_config_file.name)
        self.assertEqual((_OVS_PORT_IFACE + _OVS_BRIDGE_DHCP), iface_data)
