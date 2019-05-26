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
import os
import random
import six
import yaml

from os_net_config import objects
from os_net_config import sriov_config
from os_net_config.tests import base
from os_net_config import utils


class TestRoute(base.TestCase):

    def test_from_json(self):
        data = '{"next_hop": "172.19.0.1", "ip_netmask": "172.19.0.0/24", ' \
               '"route_options": "metric 10", "table": "200"}'
        route = objects.Route.from_json(json.loads(data))
        self.assertEqual("172.19.0.1", route.next_hop)
        self.assertEqual("172.19.0.0/24", route.ip_netmask)
        self.assertFalse(route.default)
        self.assertEqual("metric 10", route.route_options)
        self.assertEqual("200", route.route_table)

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

    def test_from_json_neutron_schema(self):
        data = '{"nexthop": "172.19.0.254", "destination": "192.168.1.0/26"}'
        route = objects.Route.from_json(json.loads(data))
        self.assertEqual("172.19.0.254", route.next_hop)
        self.assertEqual("192.168.1.0/26", route.ip_netmask)

        data = {'nexthop': '172.19.0.254',
                'next_hop': '172.19.0.1',
                'destination': '192.168.1.0/26'}
        self.assertRaises(objects.InvalidConfigException,
                          objects.Route.from_json, data)

        data = {'nexthop': '172.19.0.254',
                'destination': '192.168.1.0/26',
                'ip_netmask': '172.19.0.0/24'}
        self.assertRaises(objects.InvalidConfigException,
                          objects.Route.from_json, data)


class TestRouteTable(base.TestCase):

    def test_from_json(self):
        data = '{"type": "route_table", "name": "custom", "table_id": 200}'
        route_table = objects.RouteTable.from_json(json.loads(data))
        self.assertEqual("custom", route_table.name)
        self.assertEqual(200, route_table.table_id)

    def test_from_json_invalid(self):
        self.assertRaises(objects.InvalidConfigException,
                          objects.RouteTable.from_json,
                          {})

        data = '{"type": "route_table", "table_id": 200}'
        json_data = json.loads(data)
        self.assertRaises(objects.InvalidConfigException,
                          objects.RouteTable.from_json,
                          json_data)

        data = '{"type": "route_table", "name": "custom"}'
        json_data = json.loads(data)
        self.assertRaises(objects.InvalidConfigException,
                          objects.RouteTable.from_json,
                          json_data)


class TestRouteRule(base.TestCase):

    def test_rule(self):
        rule1 = objects.RouteRule('from 192.0.2.0/24 table 200 prio 1000')
        self.assertEqual('from 192.0.2.0/24 table 200 prio 1000', rule1.rule)

    def test_rule_from_json(self):
        data = '{"rule":"from 172.19.0.0/24 table 200", "comment":"test"}'
        route_rule = objects.RouteRule.from_json(json.loads(data))
        self.assertEqual("from 172.19.0.0/24 table 200", route_rule.rule)
        self.assertEqual("test", route_rule.comment)


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

    def test_from_json_dhcpv6(self):
        data = '{"type": "interface", "name": "em1", "use_dhcpv6": true}'
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", interface.name)
        self.assertTrue(interface.use_dhcpv6)

    def test_from_json_dotted_vlan(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em3"}
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        data = '{"type": "interface", "name": "nic1.10", "use_dhcp": true}'
        interface = objects.object_from_json(json.loads(data))
        self.assertEqual("em3.10", interface.name)

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

    def test_from_json_onboot_false(self):
        data = """{
"type": "interface",
"name": "em1",
"onboot": false
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertFalse(interface1.onboot)

    def test_from_json_onboot_true(self):
        data = """{
"type": "interface",
"name": "em1",
"onboot": true
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertTrue(interface1.onboot)

    def test_from_json_onboot_false_boolstr(self):
        data = """{
"type": "interface",
"name": "em1",
"onboot": "no"
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertFalse(interface1.onboot)

    def test_from_json_onboot_true_boolstr(self):
        data = """{
"type": "interface",
"name": "em1",
"onboot": "yes"
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertTrue(interface1.onboot)

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

    def test_from_json_domain(self):
        data = """{
"type": "interface",
"name": "em1",
"use_dhcp": true,
"domain": "openstack.local"
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertEqual("openstack.local", interface1.domain)

    def test_from_json_domain_list(self):
        data = """{
"type": "interface",
"name": "em1",
"use_dhcp": true,
"domain": ["openstack.local", "subdomain.openstack.local"]
}
"""
        interface1 = objects.object_from_json(json.loads(data))
        self.assertEqual(
            ["openstack.local", "subdomain.openstack.local"],
            interface1.domain)

    def test_from_json_dhcp_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em3"}
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

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
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        data = '{"type": "vlan", "device": "nic1", "vlan_id": 16,' \
               '"use_dhcp": true}'
        vlan = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", vlan.device)
        self.assertEqual(16, vlan.vlan_id)
        self.assertTrue(vlan.use_dhcp)

    def test_from_json_ovs_options_extra(self):
        data = '{"type": "vlan", "device": "em1", "vlan_id": 16,' \
               '"use_dhcp": true, "ovs_options": "foo",' \
               '"ovs_extra": ["bar","baz"]}'
        vlan = objects.object_from_json(json.loads(data))
        self.assertEqual("foo", vlan.ovs_options)
        self.assertEqual(["bar", "baz"], vlan.ovs_extra)


class TestBridge(base.TestCase):

    def setUp(self):
        super(TestBridge, self).setUp()
        rand = str(int(random.random() * 100000))
        sriov_config._SRIOV_CONFIG_FILE = '/tmp/sriov_config_' + rand + '.yaml'

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

    def tearDown(self):
        super(TestBridge, self).tearDown()
        if os.path.isfile(sriov_config._SRIOV_CONFIG_FILE):
            os.remove(sriov_config._SRIOV_CONFIG_FILE)

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

    def test_ovs_bridge_with_vf_default(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "sriov_vf",
    "device": "em1",
    "vfid": 1,
    "vlan_id": 111,
    "qos": 1
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'off', 'trust': 'on',
                     'promisc': 'on', 'pci_address': '0000:79:10.2'}]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.device)
        self.assertTrue(interface1.ovs_port)
        self.assertEqual("br-foo", interface1.bridge_name)

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_ovs_bond_with_vf_default(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "ovs_bond",
    "name": "bond1",
    "members": [{
        "type": "sriov_vf",
        "device": "em1",
        "vfid": 1,
        "vlan_id": 111,
        "qos": 1,
        "primary": true
        },
        {
        "type": "sriov_vf",
        "device": "em2",
        "vfid": 1,
        "vlan_id": 111,
        "qos": 1
        }
    ]
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'off', 'trust': 'on',
                     'promisc': 'on'},
                    {'device_type': 'vf', 'name': 'em2_1',
                     'device': {'name': 'em2', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'off', 'trust': 'on',
                     'promisc': 'on'}]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        bond = bridge.members[0]
        interface1 = bond.members[0]
        interface2 = bond.members[1]
        self.assertEqual("em1", interface1.device)
        self.assertEqual("em2", interface2.device)
        self.assertEqual("br-foo", bond.bridge_name)

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_ovs_bond_with_vf_custom(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "ovs_bond",
    "name": "bond1",
    "members": [{
        "type": "sriov_vf",
        "device": "em1",
        "vfid": 1,
        "vlan_id": 111,
        "qos": 1,
        "primary": true,
        "trust": false,
        "spoofcheck": true,
        "promisc": false
        },
        {
        "type": "sriov_vf",
        "device": "em2",
        "vfid": 1,
        "vlan_id": 111,
        "qos": 1,
        "trust": false,
        "spoofcheck": true,
        "promisc": false
        }
    ]
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'on', 'trust': 'off',
                     'promisc': 'off'},
                    {'device_type': 'vf', 'name': 'em2_1',
                     'device': {'name': 'em2', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'on', 'trust': 'off',
                     'promisc': 'off'}]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        objects.object_from_json(json.loads(data))

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_ovs_bridge_with_vf_param_provided(self):
        data = """{
"type": "ovs_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
    "type": "sriov_vf",
    "device": "em1",
    "vfid": 1,
    "vlan_id": 111,
    "qos": 1,
    "spoofcheck": false,
    "trust": false,
    "promisc": false
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'pci_address': '0000:79:10.2',
                     'spoofcheck': 'off', 'trust': 'off',
                     'promisc': 'off'}]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)
        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        interface1 = bridge.members[0]
        self.assertEqual("em1", interface1.device)
        self.assertTrue(interface1.ovs_port)
        self.assertEqual("br-foo", interface1.bridge_name)

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_ovs_user_bridge_with_vf_default(self):
        data = """{
"type": "ovs_user_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
        "type": "ovs_dpdk_port",
        "name": "dpdk0",
        "members": [
            {
                "type": "sriov_vf",
                "device": "em1",
                "vfid": 1,
                "vlan_id": 111,
                "qos": 1
            }
        ]
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'off', 'trust': 'on',
                     'pci_address': '0000:79:10.2'
                     }]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        dpdk_interface = bridge.members[0]
        self.assertEqual("dpdk0", dpdk_interface.name)
        self.assertFalse(dpdk_interface.ovs_port)
        self.assertEqual("br-foo", dpdk_interface.bridge_name)

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_ovs_user_bridge_with_param_set(self):
        data = """{
"type": "ovs_user_bridge",
"name": "br-foo",
"use_dhcp": true,
"members": [{
        "type": "ovs_dpdk_port",
        "name": "dpdk0",
        "members": [
            {
                "type": "sriov_vf",
                "device": "em1",
                "vfid": 1,
                "vlan_id": 111,
                "qos": 1,
                "spoofcheck": false,
                "trust": false,
                "promisc": false
            }
        ]
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'spoofcheck': 'off', 'trust': 'off',
                     'pci_address': '0000:79:10.2'
                     }]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        bridge = objects.object_from_json(json.loads(data))
        self.assertEqual("br-foo", bridge.name)
        self.assertTrue(bridge.use_dhcp)
        dpdk_interface = bridge.members[0]
        self.assertEqual("dpdk0", dpdk_interface.name)
        self.assertFalse(dpdk_interface.ovs_port)
        self.assertEqual("br-foo", dpdk_interface.bridge_name)

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_from_json_dhcp_with_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em5"}
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

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
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

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

    def setUp(self):
        super(TestBond, self).setUp()

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

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
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

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
        self.stub_out('os_net_config.utils.ordered_active_nics',
                      dummy_ordered_active_nics)

    def _stub_available_nics(self, nics):
        def dummy_ordered_available_nics():
            return nics
        self.stub_out('os_net_config.utils.ordered_available_nics',
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

    def setUp(self):
        super(TestLinuxBond, self).setUp()
        rand = str(int(random.random() * 100000))
        sriov_config._SRIOV_CONFIG_FILE = '/tmp/sriov_config_' + rand + '.yaml'

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

    def tearDown(self):
        super(TestLinuxBond, self).tearDown()
        if os.path.isfile(sriov_config._SRIOV_CONFIG_FILE):
            os.remove(sriov_config._SRIOV_CONFIG_FILE)

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
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        data = """{
"type": "linux_bond",
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

    def test_linux_bond_with_vf_default(self):
        data = """{
"type": "linux_bond",
"name": "bond1",
"use_dhcp": true,
"members": [{
    "type": "sriov_vf",
    "device": "em1",
    "vfid": 1,
    "vlan_id": 111,
    "qos": 1,
    "primary": true
    },
    {
    "type": "sriov_vf",
    "device": "em2",
    "vfid": 1,
    "vlan_id": 111,
    "qos": 1
}]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'pci_address': '0000:79:10.1',
                     'spoofcheck': 'on', 'trust': 'on',
                     'promisc': 'off'},
                    {'device_type': 'vf', 'name': 'em2_1',
                     'device': {'name': 'em2', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'pci_address': '0000:79:10.2',
                     'spoofcheck': 'on', 'trust': 'on',
                     'promisc': 'off'}]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            if ifname == 'em1_1':
                return '0000:79:10.1'
            elif ifname == 'em2_1':
                return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        bond = objects.object_from_json(json.loads(data))
        self.assertEqual("bond1", bond.name)
        self.assertTrue(bond.use_dhcp)
        interface1 = bond.members[0]
        interface2 = bond.members[1]
        self.assertEqual("em1", interface1.device)
        self.assertEqual("em2", interface2.device)

        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)

    def test_linux_bond_with_vf_param_provided(self):
        data = """{
"type": "linux_bond",
"name": "bond1",
"use_dhcp": true,
"members": [{
    "type": "sriov_vf",
    "device": "em1",
    "vfid": 1,
    "vlan_id": 111,
    "qos": 1,
    "trust": false,
    "spoofcheck": false,
    "promisc": false
    },
    {
    "type": "sriov_vf",
    "device": "em2",
    "vfid": 1,
    "vlan_id": 111,
    "qos": 1,
    "trust": false,
    "spoofcheck": false,
    "promisc": false
    }
]
}
"""
        vf_final = [{'device_type': 'vf', 'name': 'em1_1',
                     'device': {'name': 'em1', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'pci_address': '0000:79:10.1',
                     'spoofcheck': 'off', 'trust': 'off',
                     'promisc': 'off'},
                    {'device_type': 'vf', 'name': 'em2_1',
                     'device': {'name': 'em2', 'vfid': 1},
                     'vlan_id': 111, 'qos': 1,
                     'pci_address': '0000:79:10.2',
                     'spoofcheck': 'off', 'trust': 'off',
                     'promisc': 'off'}]

        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            if ifname == 'em1_1':
                return '0000:79:10.1'
            elif ifname == 'em2_1':
                return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        objects.object_from_json(json.loads(data))
        contents = utils.get_file_data(sriov_config._SRIOV_CONFIG_FILE)
        vf_map = yaml.safe_load(contents) if contents else []
        self.assertListEqual(vf_final, vf_map)


class TestOvsTunnel(base.TestCase):

    def setUp(self):
        super(TestOvsTunnel, self).setUp()

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

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

    def setUp(self):
        super(TestOvsPatchPort, self).setUp()

        def stub_is_ovs_installed():
            return True
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      stub_is_ovs_installed)

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
        self.assertIsNone(ib_interface.ethtool_opts)
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

    def test_from_json_ethtool_opts(self):
        data = """{
        "type": "ib_interface",
        "name": "ib0",
        "ethtool_opts": "speed 1000 duplex full"
        }"""
        ib_ifc = objects.object_from_json(json.loads(data))
        self.assertEqual("speed 1000 duplex full", ib_ifc.ethtool_opts)

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
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

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

    def stub_is_ovs_installed(self):
        return True

    def tearDown(self):
        super(TestNicMapping, self).tearDown()
        objects._MAPPED_NICS = None

    def _stub_active_nics(self, nics):
        def dummy_ordered_active_nics():
            return nics
        self.stub_out('os_net_config.utils.ordered_active_nics',
                      dummy_ordered_active_nics)

    def _stub_available_nics(self, nics):
        def dummy_ordered_available_nics():
            return nics
        self.stub_out('os_net_config.utils.ordered_available_nics',
                      dummy_ordered_available_nics)

    def test_mapped_nics_default(self):
        self._stub_active_nics(['em1', 'em2'])
        expected = {'nic1': 'em1', 'nic2': 'em2'}
        self.assertEqual(expected, objects.mapped_nics())

    def test_mapped_nics_mapped(self):
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em2', 'nic2': 'em1'}
        expected = {'nic1': 'em2', 'nic2': 'em1'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_mapped_partial(self):
        self._stub_active_nics(['em1', 'em2', 'em3', 'em4'])
        self._stub_available_nics(['em1', 'em2', 'em3', 'em4'])
        mapping = {'nic1': 'em2', 'nic2': 'em1'}
        expected = {'nic1': 'em2', 'nic2': 'em1', 'nic3': 'em3', 'nic4': 'em4'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_mapped_partial_reordered(self):
        self._stub_active_nics(['em1', 'em2', 'em3', 'em4'])
        self._stub_available_nics(['em1', 'em2', 'em3', 'em4'])
        mapping = {'nic1': 'em1', 'nic2': 'em3'}
        expected = {'nic1': 'em1', 'nic2': 'em3', 'nic4': 'em4'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_mapped_unnumbered(self):
        self._stub_active_nics(['em1', 'em2', 'em3', 'em4'])
        self._stub_available_nics(['em1', 'em2', 'em3', 'em4'])
        mapping = {'John': 'em1', 'Paul': 'em2', 'George': 'em3'}
        expected = {'John': 'em1', 'Paul': 'em2', 'George': 'em3',
                    'nic4': 'em4'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_error_notactive(self):
        self._stub_active_nics(['em2'])
        self._stub_available_nics(['em1', 'em2', 'em3'])
        mapping = {'nic2': 'em1'}
        expected = {'nic1': 'em2', 'nic2': 'em1'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_error_duplicate(self):
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em1', 'nic2': 'em1'}
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.mapped_nics, nic_mapping=mapping)
        expected = 'em1 already mapped, check mapping file for duplicates'
        self.assertIn(expected, six.text_type(err))

    def test_mapped_nics_map_invalid_nic(self):
        self._stub_active_nics(['em1'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em1', 'nic2': 'foo'}
        expected = {'nic1': 'em1'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_mac(self):
        def dummy_interface_mac(name):
            mac_map = {'em1': '12:34:56:78:9a:bc',
                       'em2': '12:34:56:de:f0:12'}
            return mac_map[name]
        self.stub_out('os_net_config.utils.interface_mac', dummy_interface_mac)
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': '12:34:56:de:f0:12', 'nic2': '12:34:56:78:9a:bc'}
        expected = {'nic1': 'em2', 'nic2': 'em1'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_map_invalid_mac(self):
        def dummy_interface_mac(name):
            mac_map = {'em1': '12:34:56:78:9a:bc',
                       'em2': '12:34:56:de:f0:12'}
            return mac_map[name]

        self.stub_out('os_net_config.utils.interface_mac', dummy_interface_mac)
        self._stub_active_nics(['em1', 'em2'])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': '12:34:56:de:f0:12', 'nic2': 'aa:bb:cc:dd:ee:ff'}
        expected = {'nic1': 'em2'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

    def test_mapped_nics_no_active(self):
        self._stub_active_nics([])
        expected = {}
        # This only emits a warning, so it should still work
        self.assertEqual(expected, objects.mapped_nics())

    def test_mapped_nics_mapping_overlap_real_nic_name(self):
        def dummy_is_active_nic(nic):
            if nic == 'em1':
                return True
            elif nic == 'nic1':
                return False

        self.stub_out('os_net_config.utils.is_active_nic', dummy_is_active_nic)
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'nic1': 'em1', 'em1': 'em2'}
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.mapped_nics, nic_mapping=mapping)
        expected = 'cannot map em2 to alias em1, alias overlaps'
        self.assertIn(expected, six.text_type(err))

    def test_mapped_nics_mapping_inactive_name_as_alias(self):
        def dummy_is_active_nic(nic):
            return False

        def dummy_is_real_nic(nic):
            return True

        self.stub_out('os_net_config.utils.is_active_nic', dummy_is_active_nic)
        self.stub_out('os_net_config.utils.is_real_nic', dummy_is_real_nic)
        self._stub_active_nics([])
        self._stub_available_nics(['em1', 'em2'])
        mapping = {'em2': 'em1', 'nic1': 'em2'}
        expected = {'em2': 'em1', 'nic1': 'em2'}
        self.assertEqual(expected, objects.mapped_nics(nic_mapping=mapping))

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
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
        self._test_mapped_nics_with_parent("ovs_bond", "bond1")

    def test_mapped_nics_linux_bond(self):
        self._test_mapped_nics_with_parent("linux_bond", "bond1")

    def test_mapped_nics_ovs_bridge(self):
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
        self._test_mapped_nics_with_parent("ovs_bridge", "br-foo")

    def test_mapped_nics_ovs_user_bridge(self):
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
        self._test_mapped_nics_with_parent("ovs_user_bridge", "br-foo")

    def test_mapped_nics_linux_bridge(self):
        self._test_mapped_nics_with_parent("linux_bridge", "br-foo")

    def test_mapped_nics_ivs_bridge(self):
        self._test_mapped_nics_with_parent("ivs_bridge", "br-foo")

    def test_mapped_nics_linux_team(self):
        self._test_mapped_nics_with_parent("team", "team-foo")

    def test_mapped_nics_bridge_and_bond(self):
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)

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
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
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


class TestSriovPF(base.TestCase):

    def test_from_json_numvfs(self):
        data = '{"type": "sriov_pf", "name": "em1", "numvfs": 16,' \
               '"use_dhcp": false, "promisc": false}'
        pf = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", pf.name)
        self.assertEqual(16, pf.numvfs)
        self.assertEqual("off", pf.promisc)
        self.assertFalse(pf.use_dhcp)
        self.assertEqual("legacy", pf.link_mode)
        self.assertIsNone(pf.ethtool_opts)

    def test_from_json_numvfs_nic1(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em4"}
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        data = '{"type": "sriov_pf", "name": "nic1", "numvfs": 16,' \
               '"use_dhcp": false, "promisc": true}'
        pf = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", pf.name)
        self.assertEqual(16, pf.numvfs)
        self.assertFalse(pf.use_dhcp)
        self.assertEqual('on', pf.promisc)

    def test_from_json_without_promisc(self):
        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em4"}
        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        data = '{"type": "sriov_pf", "name": "nic1", "numvfs": 16,' \
               '"use_dhcp": false}'
        pf = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", pf.name)
        self.assertEqual(16, pf.numvfs)
        self.assertFalse(pf.use_dhcp)
        self.assertEqual('on', pf.promisc)

    def test_from_json_link_mode(self):
        data = '{"type": "sriov_pf", "name": "p6p1", "numvfs": 8,' \
               '"use_dhcp": false, "promisc": false, "link_mode":' \
               '"switchdev"}'
        pf = objects.object_from_json(json.loads(data))
        self.assertEqual("p6p1", pf.name)
        self.assertEqual(8, pf.numvfs)
        self.assertEqual("off", pf.promisc)
        self.assertFalse(pf.use_dhcp)
        self.assertEqual("switchdev", pf.link_mode)

    def test_from_json_link_mode_invalid(self):
        data = '{"type": "sriov_pf", "name": "p6p1", "numvfs": 8,' \
               '"use_dhcp": false, "promisc": false, "link_mode":' \
               '"none_switchdev"}'
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.object_from_json,
                                json.loads(data))
        expected = 'Expecting link_mode to match legacy/switchdev'
        self.assertIn(expected, six.text_type(err))

    def test_from_json_ethtool_opts(self):
        data = '{"type": "sriov_pf", "name": "em1", "numvfs": 16, ' \
               '"use_dhcp": false, "promisc": false, ' \
               '"ethtool_opts": "speed 1000 duplex full"}'
        pf_ifc = objects.object_from_json(json.loads(data))
        self.assertEqual("speed 1000 duplex full", pf_ifc.ethtool_opts)


class TestSriovVF(base.TestCase):

    def setUp(self):
        super(TestSriovVF, self).setUp()

    def tearDown(self):
        super(TestSriovVF, self).tearDown()

    def test_from_json_vfid(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)
        data = '{"type": "sriov_vf", "device": "em1", "vfid": 16,' \
               '"use_dhcp": false}'
        vf = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", vf.device)
        self.assertEqual(16, vf.vfid)
        self.assertFalse(vf.use_dhcp)
        self.assertEqual("em1_16", vf.name)

    def test_from_json_name_ignored(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)
        data = '{"type": "sriov_vf", "device": "em1", "vfid": 16,' \
               '"use_dhcp": false, "name": "em1_7"}'
        vf = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", vf.device)
        self.assertEqual(16, vf.vfid)
        self.assertFalse(vf.use_dhcp)
        self.assertEqual("em1_16", vf.name)

    def test_from_json_vfid_configs_enabled(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        data = '{"type": "sriov_vf", "device": "em4", "vfid": 16,' \
               '"use_dhcp": false, "vlan_id": 100, "qos": 2, "trust": true,' \
               '"state": "auto", "spoofcheck": true,' \
               '"macaddr":"AA:BB:CC:DD:EE:FF", "promisc": true}'
        vf = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", vf.device)
        self.assertEqual(16, vf.vfid)
        self.assertFalse(vf.use_dhcp)
        self.assertEqual("em4_16", vf.name)
        self.assertEqual(100, vf.vlan_id)
        self.assertEqual(2, vf.qos)
        self.assertEqual("on", vf.spoofcheck)
        self.assertEqual("on", vf.trust)
        self.assertEqual("auto", vf.state)
        self.assertEqual("AA:BB:CC:DD:EE:FF", vf.macaddr)
        self.assertEqual("on", vf.promisc)

    def test_from_json_vfid_configs_disabled(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        data = '{"type": "sriov_vf", "device": "em4", "vfid": 16,' \
               '"use_dhcp": false, "vlan_id": 0, "qos": 0, "trust": false,' \
               '"state": "disable", "spoofcheck": false,' \
               '"promisc": false}'
        vf = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", vf.device)
        self.assertEqual(16, vf.vfid)
        self.assertFalse(vf.use_dhcp)
        self.assertEqual("em4_16", vf.name)
        self.assertEqual(0, vf.vlan_id)
        self.assertEqual(0, vf.qos)
        self.assertEqual("off", vf.spoofcheck)
        self.assertEqual("off", vf.trust)
        self.assertEqual("disable", vf.state)
        self.assertEqual(None, vf.macaddr)
        self.assertEqual("off", vf.promisc)

    def test_from_json_vfid_invalid_state(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        data = '{"type": "sriov_vf", "device": "em4", "vfid": 16,' \
               '"use_dhcp": false, "vlan_id": 0, "qos": 0, "trust": false,' \
               '"state": "disabled", ' \
               '"promisc": false}'
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.object_from_json,
                                json.loads(data))
        expected = 'Expecting state to match auto/enable/disable'
        self.assertIn(expected, six.text_type(err))

    def test_from_json_vfid_invalid_qos(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        data = '{"type": "sriov_vf", "device": "em4", "vfid": 16,' \
               '"use_dhcp": false, "vlan_id": 0, "qos": 10, "trust": false,' \
               '"promisc": false}'
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.object_from_json,
                                json.loads(data))
        expected = 'Vlan tag not set for QOS - VF: em4:16'
        self.assertIn(expected, six.text_type(err))

    def test_from_json_vfid_nic1(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)

        def dummy_mapped_nics(nic_mapping=None):
            return {"nic1": "em4"}

        self.stub_out('os_net_config.objects.mapped_nics', dummy_mapped_nics)

        data = '{"type": "sriov_vf", "device": "nic1", "vfid": 16,' \
               '"use_dhcp": false}'
        vf = objects.object_from_json(json.loads(data))
        self.assertEqual("em4", vf.device)
        self.assertEqual(16, vf.vfid)
        self.assertFalse(vf.use_dhcp)
        self.assertEqual("em4_16", vf.name)

    def test_from_json_pci_address_none(self):
        def test_get_vf_devname(device, vfid):
            return device + '_' + str(vfid)

        def test_get_pci_address(ifname, noop):
            return None

        def test_get_stored_pci_address(ifname, noop):
            return '0000:79:10.2'

        self.stub_out('os_net_config.utils.get_vf_devname',
                      test_get_vf_devname)
        self.stub_out('os_net_config.utils.get_pci_address',
                      test_get_pci_address)
        self.stub_out('os_net_config.utils.get_stored_pci_address',
                      test_get_stored_pci_address)
        data = '{"type": "sriov_vf", "device": "em1", "vfid": 16,' \
               '"use_dhcp": false}'
        vf = objects.object_from_json(json.loads(data))
        self.assertEqual("em1", vf.device)
        self.assertEqual(16, vf.vfid)
        self.assertFalse(vf.use_dhcp)
        self.assertEqual("em1_16", vf.name)


class TestOvsDpdkBond(base.TestCase):

    # We want to test the function, not the dummy..
    stub_mapped_nics = False

    def _stub_active_nics(self, nics):
        def dummy_ordered_active_nics():
            return nics
        self.stub_out('os_net_config.utils.ordered_active_nics',
                      dummy_ordered_active_nics)

    def stub_is_ovs_installed(self):
        return True

    def test_from_json_dhcp(self):
        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
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


class TestVppBond(base.TestCase):

    def test_vpp_interface_from_json(self):
        data = """{
"type": "vpp_bond",
"name": "net_bonding0",
"members": [
    {
        "type": "vpp_interface",
        "name": "eth1"
    },
    {
        "type": "vpp_interface",
        "name": "eth2"
    }
],
"bonding_options": "mode=2,xmit_policy=l34"
}
"""

        vpp_bond = objects.object_from_json(json.loads(data))
        self.assertEqual("net_bonding0", vpp_bond.name)
        self.assertEqual("mode=2,xmit_policy=l34", vpp_bond.bonding_options)
        vpp_int1 = vpp_bond.members[0]
        self.assertEqual("eth1", vpp_int1.name)
        vpp_int2 = vpp_bond.members[1]
        self.assertEqual("eth2", vpp_int2.name)

    def test_invalid_vpp_interface_from_json(self):
        data = """{
"type": "vpp_bond",
"name": "net_bonding0",
"members": [
    {
        "type": "vpp_interface",
        "name": "eth1"
    },
    {
        "type": "interface",
        "name": "eth2"
    }
],
"bonding_options": "mode=2,xmit_policy=l34"
}
"""

        err = self.assertRaises(objects.InvalidConfigException,
                                objects.object_from_json,
                                json.loads(data))
        expected = 'Members must be of type vpp_interface'
        self.assertIn(expected, six.text_type(err))


class TestOvsRequiredObjects(base.TestCase):

    def stub_is_ovs_installed(self):
        return False

    def test_ovs_bond(self):
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

        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.OvsBond.from_json,
                                json.loads(data))
        expected = 'OvsBond cannot be created as OpenvSwitch is not installed.'
        self.assertIn(expected, six.text_type(err))

    def test_ovs_bridge(self):
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

        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.OvsBridge.from_json,
                                json.loads(data))
        expected = 'OvsBridge cannot be created as OpenvSwitch is not ' \
                   'installed.'
        self.assertIn(expected, six.text_type(err))

    def test_dpdk_port(self):
        data = """{
            "type": "ovs_dpdk_port",
            "name": "dpdk0",
            "members": [{"type": "interface", "name": "nic"}]
            }
            """

        self.stub_out('os_net_config.utils.is_ovs_installed',
                      self.stub_is_ovs_installed)
        err = self.assertRaises(objects.InvalidConfigException,
                                objects.OvsDpdkPort.from_json,
                                json.loads(data))
        expected = 'OvsDpdkPort cannot be created as OpenvSwitch is not ' \
                   'installed.'
        self.assertIn(expected, six.text_type(err))
