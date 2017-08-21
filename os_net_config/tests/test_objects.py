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

import json
import six

from os_net_config import objects
from os_net_config.tests import base
from os_net_config import utils


class TestRoute(base.TestCase):

    def test_from_json(self):
        data = '{"next_hop": "172.19.0.1", "ip_netmask": "172.19.0.0/24", ' \
               '"route_options": "metric 10"}'
        route = objects.Route.from_json(json.loads(data))
        self.assertEqual("172.19.0.1", route.next_hop)
        self.assertEqual("172.19.0.0/24", route.ip_netmask)
        self.assertFalse(route.default)
        self.assertEqual("metric 10", route.route_options)

    def test_from_json_default_route(self):
        data = '{"next_hop": "172.19.0.1", "ip_netmask": "172.19.0.0/24", ' \
               '"default": true, "route_options": "metric 10"}'
        route = objects.Route.from_json(json.loads(data))
        self.assertEqual("172.19.0.1", route.next_hop)
        self.assertEqual("172.19.0.0/24", route.ip_netmask)
        self.assertTrue(route.default)
        self.assertEqual("metric 10", route.route_options)

        data = '{"next_hop": "172.19.0.1", "ip_netmask": "172.19.0.0/24", ' \
               '"default": "true", "route_options": "metric 10"}'
        route = objects.Route.from_json(json.loads(data))
        self.assertEqual("172.19.0.1", route.next_hop)
        self.assertEqual("172.19.0.0/24", route.ip_netmask)
        self.assertTrue(route.default)
        self.assertEqual("metric 10", route.route_options)


class TestAddress(base.TestCase):

    def test_ipv4_address(self):
        address = objects.Address('192.168.1.1/24')
        self.assertEqual("192.168.1.1", address.ip)
        self.assertEqual("255.255.255.0", address.netmask)
        self.assertEqual(4, address.version)

    def test_ipv6_address(self):
        address = objects.Address('2001:abc:a::/64')
        self.assertEqual("2001:abc:a::", address.ip)
        self.assertEqual("ffff:ffff:ffff:ffff::", address.netmask)
        self.assertEqual(6, address.version)

    def test_from_json(self):
        data = '{"ip_netmask": "192.0.2.5/24"}'
        address = objects.Address.from_json(json.loads(data))
        self.assertEqual("192.0.2.5", address.ip)
        self.assertEqual("255.255.255.0", address.netmask)
        self.assertEqual(4, address.version)

    def test_from_json_invalid(self):
        self.assertRaises(objects.InvalidConfigException,
                          objects.Address.from_json,
                          {})
        data = '{"ip_netmask": false}'
        json_data = json.loads(data)
        self.assertRaises(objects.InvalidConfigException,
                          objects.Address.from_json,
                          json_data)


class TestInterface(base.TestCase):

    def test_interface_addresses(self):
        v4_addr = objects.Address('192.168.1.1/24')
        v6_addr = objects.Address('2001:abc:a::/64')
        interface = objects.Interface('foo', addresses=[v4_addr, v6_addr])
        self.assertEqual("192.168.1.1", interface.v4_addresses()[0].ip)
        self.assertEqual("2001:abc:a::", interface.v6_addresses()[0].ip)

    def test_from_json_dhcp(self):
        data = '{"type": "interface", "name": "em1", "use_dhcp": true}'
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", interface.name)
        self.assertTrue(interface.use_dhcp)

    def test_from_json_hotplug(self):
        data = """{
"type": "interface",
"name": "em1",
"hotplug": true
}
"""
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", interface.name)
        self.assertTrue(interface.hotplug)

    def test_from_json_hotplug_off_by_default(self):
        data = """{
"type": "interface",
"name": "em1"
}
"""
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", interface.name)
        self.assertFalse(interface.hotplug)

    def test_from_json_defroute(self):
        data = '{"type": "interface", "name": "em1", "use_dhcp": true}'
        interface1 = objects.object_from_json(json.loads(data))
        data = """{
"type": "interface",
"name": "em1",
"use_dhcp": true,
"defroute": false
}
"""
        interface2 = objects.object_from_json(json.loads(data))
        self.assertTrue(interface1.defroute)
        self.assertFalse(interface2.defroute)

    def test_from_json_dhclient_args(self):
        data = """{
"type": "interface",
"name": "em1",
"use_dhcp": true,
"dhclient_args": "--foobar"
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertEqual("--foobar", interface1.dhclient_args)

    def test_from_json_nm_controlled_false(self):
        data = """{
"type": "interface",
"name": "em1",
"nm_controlled": false
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertFalse(interface1.nm_controlled)

    def test_from_json_nm_controlled_true(self):
        data = """{
"type": "interface",
"name": "em1",
"nm_controlled": true
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertTrue(interface1.nm_controlled)

    def test_from_json_nm_controlled_false_boolstr(self):
        data = """{
"type": "interface",
"name": "em1",
"nm_controlled": "no"
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertFalse(interface1.nm_controlled)

    def test_from_json_nm_controlled_true_boolstr(self):
        data = """{
"type": "interface",
"name": "em1",
"nm_controlled": "yes"
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertTrue(interface1.nm_controlled)

    def test_from_json_dns_servers(self):
        data = """{
"type": "interface",
"name": "em1",
"use_dhcp": true,
"dns_servers": ["1.2.3.4"]
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertEqual(["1.2.3.4"], interface1.dns_servers)

    def test_from_json_dhcp_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em3"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = '{"type": "interface", "name": "nic1", "use_dhcp": true}'
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em3", interface.name)
        self.assertTrue(interface.use_dhcp)

    def test_from_json_with_addresses(self):
        data = """{
"type": "interface",
"name": "em1",
"use_dhcp": false,
"mtu": 1501,
"ethtool_opts": "speed 1000 duplex full",
"addresses": [{
    "ip_netmask": "192.0.2.1/24"
}],
"routes": [{
    "next_hop": "192.0.2.1",
    "ip_netmask": "192.0.2.1/24",
    "route_options": "metric 10"
}]
}
"""
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", interface.name)
        self.assertFalse(interface.use_dhcp)
        self.assertFalse(interface.use_dhcpv6)
        self.assertEqual(1501, interface.mtu)
        self.assertEqual("speed 1000 duplex full", interface.ethtool_opts)
        address1 = interface.v4_addresses()[0]
        self.assertEqual("192.0.2.1", address1.ip)
        self.assertEqual("255.255.255.0", address1.netmask)
        route1 = interface.routes[0]
        self.assertEqual("192.0.2.1", route1.next_hop)
        self.assertEqual("192.0.2.1/24", route1.ip_netmask)
        self.assertEqual("metric 10", route1.route_options)


class TestVlan(base.TestCase):

    def test_from_json_dhcp(self):
        data = '{"type": "vlan", "device": "em1", "vlan_id": 16,' \
               '"use_dhcp": true}'
        vlan = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", vlan.device)
        self.assertEqual(16, vlan.vlan_id)
        self.assertTrue(vlan.use_dhcp)

    def test_from_json_dhcp_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em4"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = '{"type": "vlan", "device": "nic1", "vlan_id": 16,' \
               '"use_dhcp": true}'
        vlan = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", vlan.device)
        self.assertEqual(16, vlan.vlan_id)
        self.assertTrue(vlan.use_dhcp)


class TestBridge(base.TestCase):

    def test_from_json_dhcp(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "interface",
    "name": "em1"
}]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        self.assertTrue(interface1.ovs_port)
        self.assertEqual("br-foo", interface1.bridge_name)

    def test_from_json_dhcp_with_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em5"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "interface",
    "name": "nic1"
}]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em5", interface1.name)
        self.assertTrue(interface1.ovs_port)
        self.assertEqual("br-foo", interface1.bridge_name)

    def test_from_json_primary_interface(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [
    {
    "type": "interface",
    "name": "em1",
    "primary": "true"
    },
    {
    "type": "interface",
    "name": "em2"
    }]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        self.assertEqual("em1", bridge.primary_interface_name)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        self.assertTrue(interface1.ovs_port)
        self.assertTrue(interface1.primary)
        self.assertEqual("br-foo", interface1.bridge_name)
        interface2 = bridge.members[1]
        self.assertEqual("em2", interface2.name)
        self.assertTrue(interface2.ovs_port)
        self.assertEqual("br-foo", interface2.bridge_name)

    def test_from_json_ovs_extra(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"ovs_extra": ["bar"],
"ovs_fail_mode": "standalone"
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertTrue(3 == len(bridge.ovs_extra))
        self.assertItemsEqual(["bar",
                               "set bridge br-foo fail_mode=standalone",
                               "del-controller br-foo"],
                              bridge.ovs_extra)

    def test_from_json_ovs_extra_string(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"ovs_extra": "bar",
"ovs_fail_mode": "standalone"
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertItemsEqual(["bar",
                               "set bridge br-foo fail_mode=standalone",
                               "del-controller br-foo"],
                              bridge.ovs_extra)


class TestLinuxBridge(base.TestCase):

    def test_from_json_dhcp(self):
        data = """{
"type": "linux_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "interface",
    "name": "em1"
}]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        self.assertFalse(interface1.ovs_port)
        self.assertEqual("br-foo", interface1.linux_bridge_name)

    def test_from_json_dhcp_with_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em5"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = """{
"type": "linux_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "interface",
    "name": "nic1"
}]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em5", interface1.name)
        self.assertFalse(interface1.ovs_port)
        self.assertEqual("br-foo", interface1.linux_bridge_name)

    def test_from_json_primary_interface(self):
        data = """{
"type": "linux_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [
    {
    "type": "interface",
    "name": "em1",
    "primary": "true"
    },
    {
    "type": "interface",
    "name": "em2"
    }]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        self.assertEqual("em1", bridge.primary_interface_name)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        self.assertFalse(interface1.ovs_port)
        self.assertTrue(interface1.primary)
        self.assertEqual("br-foo", interface1.linux_bridge_name)
        interface2 = bridge.members[1]
        self.assertEqual("em2", interface2.name)
        self.assertFalse(interface2.ovs_port)
        self.assertEqual("br-foo", interface2.linux_bridge_name)


class TestIvsBridge(base.TestCase):

    def test_from_json(self):
        data = """{
"type": "ivs_bridge",
"members": [
        {"type": "interface", "name": "nic2"},
        {"type": "interface", "name": "nic3"}
    ]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("ivs", bridge.name)
        interface1 = bridge.members[0]
        self.assertEqual("nic2", interface1.name)
        self.assertEqual(False, interface1.ovs_port)
        interface2 = bridge.members[1]
        self.assertEqual("nic3", interface2.name)
        self.assertEqual(False, interface2.ovs_port)
        self.assertEqual("ivs", interface1.ivs_bridge_name)


class TestIvsInterface(base.TestCase):

    def test_ivs_interface_from_json(self):
        data = """{
"type": "ivs_bridge",
"members": [
        {"type": "ivs_interface", "name": "storage", "vlan_id": 202}
    ]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("ivs", bridge.name)
        interface1 = bridge.members[0]
        self.assertEqual("storage202", interface1.name)
        self.assertEqual(False, interface1.ovs_port)
        self.assertEqual("ivs", interface1.ivs_bridge_name)

    def test_bond_interface_from_json(self):
        data = """{
"type": "ivs_bridge",
"members": [{
    "type": "linux_bond",
    "name": "bond1",
    "members": [
        {"type": "interface", "name": "nic2"},
        {"type": "interface", "name": "nic3"}
    ]
}]
}
"""
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.IvsBridge.from_json,
                                json.loads(data))
        expected = 'IVS does not support bond interfaces.'
        self.assertIn(expected, six.text_type(err))


class TestNfvswitchBridge(base.TestCase):

    def test_from_json(self):
        data = """{
"type": "nfvswitch_bridge",
"options": "-c 2,3,4,5",
"members": [
        {"type": "interface","name": "nic1"},
        {"type": "interface","name": "nic2"}
    ]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("nfvswitch", bridge.name)
        self.assertEqual("-c 2,3,4,5", bridge.options)
        interface1 = bridge.members[0]
        self.assertEqual("nic1", interface1.name)
        self.assertEqual(False, interface1.ovs_port)
        interface2 = bridge.members[1]
        self.assertEqual("nic2", interface2.name)
        self.assertEqual(False, interface2.ovs_port)
        self.assertEqual("nfvswitch", interface1.nfvswitch_bridge_name)


class TestNfvswitchInterface(base.TestCase):

    def test_nfvswitch_internal_from_json(self):
        data = """{
"type": "nfvswitch_bridge",
"options": "-c 2,3,4,5",
"members": [
        {"type": "nfvswitch_internal", "name": "storage", "vlan_id": 202},
        {"type": "nfvswitch_internal", "name": "api", "vlan_id": 201}
    ]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("nfvswitch", bridge.name)
        self.assertEqual("-c 2,3,4,5", bridge.options)
        interface1 = bridge.members[0]
        self.assertEqual("storage202", interface1.name)
        interface2 = bridge.members[1]
        self.assertEqual("api201", interface2.name)
        self.assertEqual(False, interface1.ovs_port)
        self.assertEqual("nfvswitch", interface1.nfvswitch_bridge_name)

    def test_bond_interface_from_json(self):
        data = """{
"type": "nfvswitch_bridge",
"options": "-c 2,3,4,5",
"members": [{
        "type": "linux_bond", "name": "bond1", "members":
            [{"type": "interface", "name": "nic2"},
             {"type": "interface", "name": "nic3"}]
        }
    ]
}
"""
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.NfvswitchBridge.from_json,
                                json.loads(data))
        expected = 'NFVSwitch does not support bond interfaces.'
        self.assertIn(expected, six.text_type(err))


class TestBond(base.TestCase):

    def test_from_json_dhcp(self):
        data = """{
"type": "ovs_bond",
"name": "bond1",
"use_dhcp": true,
"members": [
    {
    "type": "interface",
    "name": "em1"
    },
    {
    "type": "interface",
    "name": "em2"
    }
]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("bond1", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        interface2 = bridge.members[1]
        self.assertEqual("em2", interface2.name)

    def test_from_json_dhcp_with_nic1_nic2(self):

        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em1", "nic2": "em2"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = """{
"type": "ovs_bond",
"name": "bond1",
"use_dhcp": true,
"members": [
    {
    "type": "interface",
    "name": "nic1"
    },
    {
    "type": "interface",
    "name": "nic2"
    }
]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("bond1", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        interface2 = bridge.members[1]
        self.assertEqual("em2", interface2.name)

    def _stub_active_nics(self, nics):
        def dummy_ordered_active_nics():
            return nics
        self.stubs.Set(utils, 'ordered_active_nics', dummy_ordered_active_nics)

    def _stub_available_nics(self, nics):
        def dummy_ordered_available_nics():
            return nics
        self.stubs.Set(utils, 'ordered_available_nics',
                       dummy_ordered_available_nics)


class TestLinuxTeam(base.TestCase):

    def test_from_json_dhcp(self):
        data = """{
"type": "team",
"name": "team1",
"use_dhcp": true,
"members": [
    { "type": "interface", "name": "em1", "primary": true },
    { "type": "interface", "name": "em2" }
]
}
"""
        team = objects.object_from_json(json.loads(data))
        self.assertEqual("team1", team.name)
        self.assertTrue(team.use_dhcp)
        interface1 = team.members[0]
        self.assertEqual("em1", interface1.name)
        interface2 = team.members[1]
        self.assertEqual("em2", interface2.name)


class TestLinuxBond(base.TestCase):

    def test_from_json_dhcp(self):
        data = """{
"type": "linux_bond",
"name": "bond1",
"use_dhcp": true,
"members": [
    {
    "type": "interface",
    "name": "em1"
    },
    {
    "type": "interface",
    "name": "em2"
    }
]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("bond1", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        interface2 = bridge.members[1]
        self.assertEqual("em2", interface2.name)

    def test_from_json_dhcp_with_nic1_nic2(self):

        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em1", "nic2": "em2"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = """{
"type": "ovs_bond",
"name": "bond1",
"use_dhcp": true,
"members": [
    {
    "type": "interface",
    "name": "nic1"
    },
    {
    "type": "interface",
    "name": "nic2"
    }
]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("bond1", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.name)
        interface2 = bridge.members[1]
        self.assertEqual("em2", interface2.name)


class TestOvsTunnel(base.TestCase):

    def test_from_json(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"members": [{
    "type": "ovs_tunnel",
    "name": "tun0",
    "tunnel_type": "gre",
    "ovs_options": [
        "remote_ip=192.168.1.1"
    ],
    "ovs_extra": [
        "ovs extra"
    ]
}]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        tun0 = bridge.members[0]
        self.assertEqual("tun0", tun0.name)
        self.assertFalse(tun0.ovs_port)
        self.assertEqual("br-foo", tun0.bridge_name)
        self.assertEqual("gre", tun0.tunnel_type)
        self.assertEqual(
            ["options:remote_ip=192.168.1.1"],
            tun0.ovs_options)
        self.assertEqual(
            ["ovs extra"],
            tun0.ovs_extra)

    def test_ovs_extra_formatting(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"ovs_extra": [
   "set bridge {name} something"
],
"members": [{
    "type": "ovs_tunnel",
    "name": "tun0",
    "tunnel_type": "gre",
    "ovs_options": [
        "remote_ip=192.168.1.1"
    ],
    "ovs_extra": [
        "ovs extra",
        "ovs {name} extra"
    ]
}]
}
"""
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertEqual(["set bridge br-foo something",
                          "set bridge br-foo fail_mode=standalone",
                          "del-controller br-foo"],
                         bridge.ovs_extra)
        tun0 = bridge.members[0]
        self.assertEqual("tun0", tun0.name)
        self.assertFalse(tun0.ovs_port)
        self.assertEqual("br-foo", tun0.bridge_name)
        self.assertEqual("gre", tun0.tunnel_type)
        self.assertEqual(
            ["options:remote_ip=192.168.1.1"],
            tun0.ovs_options)
        self.assertEqual(
            ["ovs extra", "ovs tun0 extra"],
            tun0.ovs_extra)


class TestOvsPatchPort(base.TestCase):

    def test_from_json(self):
        data = """{
"type": "ovs_patch_port",
"name": "br-pub-patch",
"bridge_name": "br-ex",
"peer": "br-ex-patch"
}
"""
        patch_port = objects.object_from_json(json.loads(data))
        self.assertEqual("br-pub-patch", patch_port.name)
        self.assertEqual("br-ex", patch_port.bridge_name)
        self.assertEqual("br-ex-patch", patch_port.peer)

    def test_from_json_with_extra(self):
        data = """{
"type": "ovs_patch_port",
"name": "br-pub-patch",
"bridge_name": "br-ex",
"peer": "br-ex-patch",
"ovs_extra": [
        "ovs {name} extra"
]
}
"""
        patch_port = objects.object_from_json(json.loads(data))
        self.assertEqual(["ovs br-pub-patch extra"],
                         patch_port.ovs_extra)
        self.assertEqual("br-pub-patch", patch_port.name)
        self.assertEqual("br-ex", patch_port.bridge_name)
        self.assertEqual("br-ex-patch", patch_port.peer)


class TestIbInterface(base.TestCase):

    def test_ib_interface_addresses(self):
        v4_addr = objects.Address('192.168.1.1/24')
        v6_addr = objects.Address('2001:abc:a::/64')
        ib_interface = objects.IbInterface('foo', addresses=[v4_addr, v6_addr])
        self.assertEqual("192.168.1.1", ib_interface.v4_addresses()[0].ip)
        self.assertEqual("2001:abc:a::", ib_interface.v6_addresses()[0].ip)

    def test_from_json_dhcp(self):
        data = '{"type": "ib_interface", "name": "ib0", "use_dhcp": true}'
        ib_interface = objects.object_from_json(json.loads(data))
        self.assertEqual("ib0", ib_interface.name)
        self.assertTrue(ib_interface.use_dhcp)

    def test_from_json_defroute(self):
        data = '{"type": "ib_interface", "name": "ib0", "use_dhcp": true}'
        ib_interface1 = objects.object_from_json(json.loads(data))
        data = """{
"type": "ib_interface",
"name": "ib0",
"use_dhcp": true,
"defroute": false
}
"""
        ib_interface2 = objects.object_from_json(json.loads(data))
        self.assertTrue(ib_interface1.defroute)
        self.assertFalse(ib_interface2.defroute)

    def test_from_json_dhclient_args(self):
        data = """{
"type": "ib_interface",
"name": "ib0",
"use_dhcp": true,
"dhclient_args": "--foobar"
}
"""
        ib_interface1 = objects.object_from_json(json.loads(data))
        self.assertEqual("--foobar", ib_interface1.dhclient_args)

    def test_from_json_dns_servers(self):
        data = """{
"type": "ib_interface",
"name": "ib0",
"use_dhcp": true,
"dns_servers": ["1.2.3.4"]
}
"""
        ib_interface1 = objects.object_from_json(json.loads(data))
        self.assertEqual(["1.2.3.4"], ib_interface1.dns_servers)

    def test_from_json_dhcp_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "ib0"}
        self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        data = '{"type": "ib_interface", "name": "nic1", "use_dhcp": true}'
        ib_interface = objects.object_from_json(json.loads(data))
        self.assertEqual("ib0", ib_interface.name)
        self.assertTrue(ib_interface.use_dhcp)

    def test_from_json_with_addresses(self):
        data = """{
"type": "ib_interface",
"name": "ib0",
"use_dhcp": false,
"mtu": 1501,
"addresses": [{
    "ip_netmask": "192.0.2.1/24"
}],
"routes": [{
    "next_hop": "192.0.2.1",
    "ip_netmask": "192.0.2.1/24",
    "route_options": "metric 10"
}]
}
"""
        ib_interface = objects.object_from_json(json.loads(data))
        self.assertEqual("ib0", ib_interface.name)
        self.assertFalse(ib_interface.use_dhcp)
        self.assertFalse(ib_interface.use_dhcpv6)
        self.assertEqual(1501, ib_interface.mtu)
        address1 = ib_interface.v4_addresses()[0]
        self.assertEqual("192.0.2.1", address1.ip)
        self.assertEqual("255.255.255.0", address1.netmask)
        route1 = ib_interface.routes[0]
        self.assertEqual("192.0.2.1", route1.next_hop)
        self.assertEqual("192.0.2.1/24", route1.ip_netmask)
        self.assertEqual("metric 10", route1.route_options)


class TestNicMapping(base.TestCase):

    # We want to test the function, not the dummy..
    stub_mapped_nics = False

    def tearDown(self):
        super(TestNicMapping, self).tearDown()
        objects._MAPPED_NICS = None

    def _stub_active_nics(self, nics):
        def dummy_ordered_active_nics():
            return nics
        self.stubs.Set(utils, 'ordered_active_nics', dummy_ordered_active_nics)

    def _stub_available_nics(self, nics):
        def dummy_ordered_available_nics():
            return nics
        self.stubs.Set(utils, 'ordered_available_nics',
                       dummy_ordered_available_nics)

    def test_mapped_nics_default(self):
        self._stub_active_nics(['em1', 'em2'])
        expected = {'nic1': 'em1', 'nic2': 'em2'}
        self.assertEqual(expected, objects._mapped_nics())

    def test_mapped_nics_mapped(self):
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em2', 'nic2': 'em1'}
        expected = {'nic1': 'em2', 'nic2': 'em1'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_mapped_partial(self):
        self._stub_active_nics(['em1', 'em2', 'em3', 'em4'])
        self._stub_available_nics(['em1', 'em2', 'em3', 'em4'])
        mapping = {'nic1': 'em2', 'nic2': 'em1'}
        expected = {'nic1': 'em2', 'nic2': 'em1', 'nic3': 'em3', 'nic4': 'em4'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_mapped_partial_reordered(self):
        self._stub_active_nics(['em1', 'em2', 'em3', 'em4'])
        self._stub_available_nics(['em1', 'em2', 'em3', 'em4'])
        mapping = {'nic1': 'em1', 'nic2': 'em3'}
        expected = {'nic1': 'em1', 'nic2': 'em3', 'nic4': 'em4'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_mapped_unnumbered(self):
        self._stub_active_nics(['em1', 'em2', 'em3', 'em4'])
        self._stub_available_nics(['em1', 'em2', 'em3', 'em4'])
        mapping = {'John': 'em1', 'Paul': 'em2', 'George': 'em3'}
        expected = {'John': 'em1', 'Paul': 'em2', 'George': 'em3',
                    'nic4': 'em4'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_error_notactive(self):
        self._stub_active_nics(['em2'])
        self._stub_available_nics(['em1', 'em2', 'em3'])
        mapping = {'nic2': 'em1'}
        expected = {'nic1': 'em2', 'nic2': 'em1'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_error_duplicate(self):
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em1', 'nic2': 'em1'}
        err = self.assertRaises(objects.InvalidConfigException,
                                objects._mapped_nics, nic_mapping=mapping)
        expected = 'em1 already mapped, check mapping file for duplicates'
        self.assertIn(expected, six.text_type(err))

    def test_mapped_nics_map_invalid_nic(self):
        self._stub_active_nics(['em1'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em1', 'nic2': 'foo'}
        expected = {'nic1': 'em1'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_mac(self):
        def dummy_interface_mac(name):
            mac_map = {'em1': '12:34:56:78:9a:bc',
                       'em2': '12:34:56:de:f0:12'}
            return mac_map[name]
        self.stubs.Set(utils, 'interface_mac', dummy_interface_mac)
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': '12:34:56:de:f0:12', 'nic2': '12:34:56:78:9a:bc'}
        expected = {'nic1': 'em2', 'nic2': 'em1'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_invalid_mac(self):
        def dummy_interface_mac(name):
            mac_map = {'em1': '12:34:56:78:9a:bc',
                       'em2': '12:34:56:de:f0:12'}
            return mac_map[name]

        self.stubs.Set(utils, 'interface_mac', dummy_interface_mac)
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': '12:34:56:de:f0:12', 'nic2': 'aa:bb:cc:dd:ee:ff'}
        expected = {'nic1': 'em2'}
        self.assertEqual(expected, objects._mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_no_active(self):
        self._stub_active_nics([])
        expected = {}
        # This only emits a warning, so it should still work
        self.assertEqual(expected, objects._mapped_nics())

    # Test that mapping file is passed to interface members from parent object
    def _test_mapped_nics_with_parent(self, type, name):
        self._stub_available_nics(['foo', 'bar'])
        mapping = {"nic1": "foo", "nic2": "bar"}

        data = """{
        "members": [{"type": "interface", "name": "nic1"},
                    {"type": "interface", "name": "nic2"}]
        }
        """
        json_output = json.loads(data)
        json_output.update({'type': type})
        json_output.update({'name': name})
        json_output.update({'nic_mapping': mapping})
        obj = objects.object_from_json(json_output)

        self.assertEqual("foo", obj.members[0].name)
        self.assertEqual("bar", obj.members[1].name)

    def test_mapped_nics_ovs_bond(self):
        self._test_mapped_nics_with_parent("ovs_bond", "bond1")

    def test_mapped_nics_linux_bond(self):
        self._test_mapped_nics_with_parent("linux_bond", "bond1")

    def test_mapped_nics_ovs_bridge(self):
        self._test_mapped_nics_with_parent("ovs_bridge", "br-foo")

    def test_mapped_nics_ovs_user_bridge(self):
        self._test_mapped_nics_with_parent("ovs_user_bridge", "br-foo")

    def test_mapped_nics_linux_bridge(self):
        self._test_mapped_nics_with_parent("linux_bridge", "br-foo")

    def test_mapped_nics_ivs_bridge(self):
        self._test_mapped_nics_with_parent("ivs_bridge", "br-foo")

    def test_mapped_nics_linux_team(self):
        self._test_mapped_nics_with_parent("team", "team-foo")

    def test_mapped_nics_bridge_and_bond(self):
        self._stub_available_nics(['foo', 'bar'])
        mapping = {"nic1": "foo", "nic2": "bar"}

        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"members": [
    {
        "type": "ovs_bond",
        "name": "bond0",
        "members": [{"type": "interface", "name": "nic1"},
                    {"type": "interface", "name": "nic2"}]
    }
]
}
"""
        json_output = json.loads(data)
        json_output.update({'nic_mapping': mapping})
        obj = objects.object_from_json(json_output)

        interface1 = obj.members[0].members[0]
        interface2 = obj.members[0].members[1]
        self.assertEqual("foo", interface1.name)
        self.assertEqual("bar", interface2.name)

    def test_mapped_nics_ovs_dpdk_bond(self):
        self._stub_available_nics(['foo', 'bar'])
        mapping = {"nic2": "foo", "nic3": "bar"}

        data = """{
"type": "ovs_dpdk_bond",
"name": "dpdkbond0",
"members": [
    {
        "type": "ovs_dpdk_port",
        "name": "dpdk0",
        "members": [{"type": "interface", "name": "nic2"}]
    },
    {
        "type": "ovs_dpdk_port",
        "name": "dpdk1",
        "members": [{"type": "interface", "name": "nic3"}]
    }
]
}
"""
        json_output = json.loads(data)
        json_output.update({'nic_mapping': mapping})
        dpdk_port = objects.object_from_json(json_output)
        interface1 = dpdk_port.members[0].members[0]
        interface2 = dpdk_port.members[1].members[0]

        self.assertEqual("foo", interface1.name)
        self.assertEqual("bar", interface2.name)


class TestOvsDpdkBond(base.TestCase):

    # We want to test the function, not the dummy..
    stub_mapped_nics = False

    def _stub_active_nics(self, nics):
        def dummy_ordered_active_nics():
            return nics
        self.stubs.Set(utils, 'ordered_active_nics', dummy_ordered_active_nics)

    def test_from_json_dhcp(self):
        self._stub_active_nics(['eth0', 'eth1', 'eth2'])
        data = """{
"type": "ovs_dpdk_bond",
"name": "dpdkbond0",
"use_dhcp": true,
"members": [
    {
        "type": "ovs_dpdk_port",
        "name": "dpdk0",
        "members": [
            {
                "type": "interface",
                "name": "nic2"
            }
        ]
    },
    {
        "type": "ovs_dpdk_port",
        "name": "dpdk1",
        "members": [
            {
                "type": "interface",
                "name": "nic3"
            }
        ]
    }
]
}
"""
        bond = objects.object_from_json(json.loads(data))
        self.assertEqual("dpdkbond0", bond.name)
        self.assertTrue(bond.use_dhcp)
        dpdk_port0 = bond.members[0]
        self.assertEqual("dpdk0", dpdk_port0.name)
        self.assertEqual("vfio-pci", dpdk_port0.driver)
        iface1 = dpdk_port0.members[0]
        self.assertEqual("eth1", iface1.name)
        dpdk_port1 = bond.members[1]
        self.assertEqual("dpdk1", dpdk_port1.name)
        self.assertEqual("vfio-pci", dpdk_port1.driver)
        iface2 = dpdk_port1.members[0]
        self.assertEqual("eth2", iface2.name)


class TestVppInterface(base.TestCase):
    def test_vpp_interface_from_json(self):
        data = """{
"type": "vpp_interface",
"name": "em1",
"uio_driver": "uio_pci_generic",
"options": "vlan-strip-offload off"
}
"""

        vpp_interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", vpp_interface.name)
        self.assertEqual("uio_pci_generic", vpp_interface.uio_driver)
        self.assertEqual("vlan-strip-offload off", vpp_interface.options)
