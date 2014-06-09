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

from os_net_config import impl_ifcfg
from os_net_config import objects
from os_net_config.tests import base


_BASE_IFCFG = """DEVICE=foo
ONBOOT=yes
HOTPLUG=no
"""

_V4_IFCFG = _BASE_IFCFG + """BOOTPROTO=static
IPADDR=192.168.1.1
NETMASK=255.255.255.0
"""

_V6_IFCFG = _BASE_IFCFG + """IPV6INIT=yes
IPV6_AUTOCONF=no
IPV6ADDR=2001:abc:a::
"""

_OVS_IFCFG = _BASE_IFCFG + "DEVICETYPE=ovs\n"


_OVS_BRIDGE_IFCFG = _BASE_IFCFG + "DEVICETYPE=ovs\n"


class TestIfcfgNetwork(base.TestCase):

    def setUp(self):
        super(TestIfcfgNetwork, self).setUp()
        self.temp_config_file = tempfile.NamedTemporaryFile()

        def test_config_path(name):
            return self.temp_config_file.name
        self.stubs.Set(impl_ifcfg, 'ifcfg_config_path', test_config_path)
        self.provider = impl_ifcfg.IfcfgNetwork()

    def tearDown(self):
        self.temp_config_file.close()
        super(TestIfcfgNetwork, self).tearDown()

    def get_interface_config(self):
        return self.provider.interfaces['foo']

    def test_add_base_interface(self):
        interface = objects.Interface('foo')
        self.provider.addInterface(interface)
        self.assertEqual(_BASE_IFCFG, self.get_interface_config())

    def test_add_ovs_interface(self):
        interface = objects.Interface('foo')
        interface.type = 'ovs'
        self.provider.addInterface(interface)
        self.assertEqual(_OVS_IFCFG, self.get_interface_config())

    def test_add_interface_with_v4(self):
        v4_addr = objects.Address('192.168.1.1/24')
        interface = objects.Interface('foo', addresses=[v4_addr])
        self.provider.addInterface(interface)
        self.assertEqual(_V4_IFCFG, self.get_interface_config())

    def test_add_interface_with_v6(self):
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('foo', addresses=[v6_addr])
        self.provider.addInterface(interface)
        self.assertEqual(_V6_IFCFG, self.get_interface_config())
