# -*- coding: utf-8 -*-

# Copyright 2017 Red Hat, Inc.
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

import glob
import jsonschema
import os.path
import yaml

from os_net_config.tests import base
from os_net_config import validator


REALPATH = os.path.dirname(os.path.realpath(__file__))
SAMPLE_BASE = os.path.join(REALPATH, '../../', 'etc',
                           'os-net-config', 'samples')


class TestSchemaValidation(base.TestCase):

    def test_schema_is_valid(self):
        schema = validator.get_os_net_config_schema()
        jsonschema.Draft4Validator.check_schema(schema)

    def test__validate_config(self):
        schema = {"type": "string"}
        errors = validator._validate_config(42, "foo", schema, False)
        self.assertEqual(len(errors), 1)
        errors = validator._validate_config("42", "foo", schema, False)
        self.assertEqual(len(errors), 0)

    def test_consistent_error_messages_type(self):
        error = jsonschema.ValidationError(
            "%r is not of type %r" % (u'name', u'string'), validator=u'type',
            validator_value=u'string', instance=u'name')
        msg = validator._get_consistent_error_message(error)
        self.assertEqual(msg, "'name' is not of type 'string'")

    def test_consistent_error_messages_oneOf(self):
        error = jsonschema.ValidationError(
            "%r is not one of %r" % (u'type', [u'vlan', u'interface']),
            validator=u'enum', validator_value=[u'vlan', u'interface'],
            instance=u'type')
        msg = validator._get_consistent_error_message(error)
        self.assertEqual(msg, "'type' is not one of ['vlan','interface']")

    def test_consistent_error_messages_required(self):
        error = jsonschema.ValidationError(
            "%r is a required property" % u'name', validator=u'required')
        msg = validator._get_consistent_error_message(error)
        self.assertEqual(msg, "'name' is a required property")
        error = jsonschema.ValidationError(
            "u'name' is a required property", validator=u'required')
        msg = validator._get_consistent_error_message(error)
        self.assertEqual(msg, "'name' is a required property")

    def test_pretty_print_schema_path(self):
        schema = validator.get_os_net_config_schema()
        path = ['items', 'oneOf', 0, 'properties', 'name']
        path_string = validator._pretty_print_schema_path(path, schema)
        self.assertEqual(path_string, "items/oneOf/interface/name")

    def test_find_type_in_list_of_references(self):
        schemas = [
            {'$ref': '#/definitions/vlan'},
            {'properties': {'type': 'interface'}},
            None
        ]
        result = validator._find_type_in_schema_list(schemas, 'vlan')
        self.assertEqual(result, (True, 0))
        result = validator._find_type_in_schema_list(schemas, 'interface')
        self.assertEqual(result, (True, 1))
        result = validator._find_type_in_schema_list(schemas, 'ovs_bridge')
        self.assertEqual(result, (False, 0))

    def test_missing_required_property(self):
        ifaces = [{"type": "interface"}]
        errors = validator.validate_config(ifaces)
        self.assertEqual(len(errors), 1)
        self.assertIn("'name' is a required property", errors[0])


class TestBaseTypes(base.TestCase):

    def test_param(self):
        schema = validator.get_schema_for_defined_type("bool_or_param")
        v = jsonschema.Draft4Validator(schema)
        self.assertTrue(v.is_valid({"get_param": "foo"}))
        self.assertTrue(v.is_valid({"get_input": "bar"}))
        self.assertFalse(v.is_valid([]))
        self.assertFalse(v.is_valid({}))
        self.assertFalse(v.is_valid(None))
        self.assertFalse(v.is_valid("foo"))

    def test_bool_or_param(self):
        schema = validator.get_schema_for_defined_type("bool_or_param")
        v = jsonschema.Draft4Validator(schema)
        self.assertTrue(v.is_valid(True))
        self.assertTrue(v.is_valid(False))
        self.assertTrue(v.is_valid("TRUE"))
        self.assertTrue(v.is_valid("true"))
        self.assertTrue(v.is_valid("yes"))
        self.assertTrue(v.is_valid("1"))
        self.assertTrue(v.is_valid("on"))
        self.assertTrue(v.is_valid("false"))
        self.assertTrue(v.is_valid("FALSE"))
        self.assertTrue(v.is_valid("off"))
        self.assertTrue(v.is_valid("no"))
        self.assertTrue(v.is_valid("0"))
        self.assertFalse(v.is_valid([]))
        self.assertFalse(v.is_valid({}))
        self.assertFalse(v.is_valid(None))
        self.assertFalse(v.is_valid("falsch"))

    def test_ip_address_string(self):
        schema = validator.get_schema_for_defined_type("ip_address_string")
        v = jsonschema.Draft4Validator(schema)
        self.assertTrue(v.is_valid("0.0.0.0"))
        self.assertTrue(v.is_valid("192.168.0.1"))
        self.assertTrue(v.is_valid("::"))
        self.assertTrue(v.is_valid("fe80::"))
        self.assertTrue(v.is_valid("1:1:1::"))
        self.assertFalse(v.is_valid("192.168.0.1/24"))

    def test_ip_cidr_string(self):
        schema = validator.get_schema_for_defined_type("ip_cidr_string")
        v = jsonschema.Draft4Validator(schema)
        self.assertTrue(v.is_valid("0.0.0.0/0"))
        self.assertTrue(v.is_valid("192.168.0.1/24"))
        self.assertTrue(v.is_valid("::/0"))
        self.assertTrue(v.is_valid("::1/128"))
        self.assertTrue(v.is_valid("fe80::1/64"))
        self.assertFalse(v.is_valid("193.168.0.1"))


class TestDerivedTypes(base.TestCase):

    def test_address(self):
        schema = validator.get_schema_for_defined_type("address")
        v = jsonschema.Draft4Validator(schema)
        data = {"ip_netmask": "127.0.0.1/32"}
        self.assertTrue(v.is_valid(data))
        data = {"ip_netmask": "127.0.0.1"}
        self.assertFalse(v.is_valid(data))
        data = {"ip_netmask": None}
        self.assertFalse(v.is_valid(data))
        data = {"ip_netmask": "127.0.0.1/32", "unkown_property": "value"}
        self.assertFalse(v.is_valid(data))
        self.assertFalse(v.is_valid([]))
        self.assertFalse(v.is_valid(None))

    def test_list_of_address(self):
        schema = validator.get_schema_for_defined_type("list_of_address")
        v = jsonschema.Draft4Validator(schema)
        data = {"ip_netmask": "127.0.0.1/32"}
        self.assertTrue(v.is_valid([data]))
        self.assertFalse(v.is_valid(data))
        self.assertFalse(v.is_valid([]))
        self.assertFalse(v.is_valid(None))

    def test_route(self):
        schema = validator.get_schema_for_defined_type("route")
        v = jsonschema.Draft4Validator(schema)
        data = {"next_hop": "172.19.0.1", "ip_netmask": "172.19.0.0/24",
                "default": True, "route_options": "metric 10"}
        self.assertTrue(v.is_valid(data))
        data["unkown_property"] = "value"
        self.assertFalse(v.is_valid(data))
        self.assertFalse(v.is_valid({}))
        self.assertFalse(v.is_valid([]))
        self.assertFalse(v.is_valid(None))


class TestDeviceTypes(base.TestCase):

    def test_interface(self):
        schema = validator.get_schema_for_defined_type("interface")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "interface",
            "name": "em1",
            "use_dhcp": False,
            "addresses": [{
                "ip_netmask": "192.0.2.1/24"
            }],
            "defroute": False,
            "dhclient_args": "--foobar",
            "dns_servers": ["1.2.3.4"],
            "mtu": 1501,
            "ethtool_opts": "speed 1000 duplex full",
            "hotplug": True,
            "routes": [{
                "next_hop": "192.0.2.1",
                "ip_netmask": "192.0.2.1/24",
                "route_options": "metric 10"
            }]
        }
        self.assertTrue(v.is_valid(data))

    def test_vlan(self):
        schema = validator.get_schema_for_defined_type("vlan")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "vlan",
            "vlan_id": 101,
            "addresses": [{
                "ip_netmask": "192.0.2.1/24"
            }]
        }
        self.assertTrue(v.is_valid(data))

    def test_ovs_bridge(self):
        schema = validator.get_schema_for_defined_type("ovs_bridge")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "ovs_bridge",
            "name": "br-ctlplane",
            "ovs_options": "lacp=active",
            "ovs_extra": [
                "br-set-external-id br-ctlplane bridge-id br-ctlplane",
                "set bridge {name} stp_enable=true"
            ],
            "ovs_fail_mode": "secure",
            "members": [
                {"type": "interface", "name": "em1"}
            ]
        }
        self.assertTrue(v.is_valid(data))

    def test_ovs_bond(self):
        schema = validator.get_schema_for_defined_type("ovs_bond")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "ovs_bond",
            "name": "bond1",
            "use_dhcp": "true",
            "members": [
                {"type": "interface", "name": "em1"},
                {"type": "interface", "name": "em2"}
            ]
        }
        self.assertTrue(v.is_valid(data))

    def test_ovs_user_bridge(self):
        schema = validator.get_schema_for_defined_type("ovs_user_bridge")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "ovs_user_bridge",
            "name": "br-link",
            "members": [{
                "type": "ovs_dpdk_bond",
                "name": "dpdkbond0",
                "mtu": 9000,
                "rx_queue": 4,
                "members": [{
                    "type": "ovs_dpdk_port",
                    "name": "dpdk0",
                    "members": [{
                        "type": "interface",
                        "name": "nic2"
                    }]
                }, {
                    "type": "ovs_dpdk_port",
                    "name": "dpdk1",
                    "members": [{
                        "type": "interface",
                        "name": "nic3"
                    }]
                }]
            }]
        }
        self.assertTrue(v.is_valid(data))

    def test_ovs_patch_port(self):
        schema = validator.get_schema_for_defined_type("ovs_patch_port")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "ovs_patch_port",
            "name": "br_pub-patch",
            "bridge_name": "br-ctlplane",
            "peer": "br-ctlplane-patch"
        }
        self.assertTrue(v.is_valid(data))

    def test_ovs_tunnel(self):
        schema = validator.get_schema_for_defined_type("ovs_tunnel")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "ovs_tunnel",
            "name": "tun0",
            "tunnel_type": "vxlan",
            "ovs_options": ["lacp=active"]
        }
        self.assertTrue(v.is_valid(data))

    def test_vpp_interface(self):
        schema = validator.get_schema_for_defined_type("vpp_interface")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "vpp_interface",
            "name": "nic2",
            "addresses": [
                {"ip_netmask": "192.0.2.1/24"}
            ],
            "uio_driver": "uio_pci_generic",
            "options": "vlan-strip-offload off"
        }
        self.assertTrue(v.is_valid(data))

    def test_linux_bridge(self):
        schema = validator.get_schema_for_defined_type("linux_bridge")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "linux_bridge",
            "name": "br-ctlplane",
            "use_dhcp": True,
            "members": [
                {"type": "interface", "name": "em1"}
            ]
        }
        self.assertTrue(v.is_valid(data))

    def test_linux_bond(self):
        schema = validator.get_schema_for_defined_type("linux_bond")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "linux_bond",
            "name": "bond1",
            "use_dhcp": True,
            "bonding_options": "mode=active-backup",
            "members": [
                {"type": "interface", "name": "em1"},
                {"type": "interface", "name": "em2"}
            ]
        }
        self.assertTrue(v.is_valid(data))

    def test_nfvswitch_bridge(self):
        schema = validator.get_schema_for_defined_type("nfvswitch_bridge")
        v = jsonschema.Draft4Validator(schema)
        data = {
            "type": "nfvswitch_bridge",
            "options": "-c 2,3,4,5",
            "members": [{
                "type": "nfvswitch_internal",
                "name": "api",
                "addresses": [
                    {"ip_netmask": "172.16.2.7/24"}
                ],
                "vlan_id": 201
            }, {
                "type": "nfvswitch_internal",
                "name": "storage",
                "addresses": [
                    {"ip_netmask": "172.16.1.6/24"}
                ],
                "vlan_id": 202
            }]
        }
        self.assertTrue(v.is_valid(data))


class TestSampleFiles(base.TestCase):

    def test_sample_files(self):
        sample_files = (glob.glob(os.path.join(SAMPLE_BASE, '*.json')) +
                        glob.glob(os.path.join(SAMPLE_BASE, '*.yaml')))
        for sample_file in sample_files:
            with open(sample_file, 'r') as f:
                try:
                    config = yaml.load(f.read()).get("network_config")
                except Exception:
                    continue
                if not config:
                    continue
                errors = validator.validate_config(config, sample_file)
                if os.path.basename(sample_file).startswith("invalid_"):
                    self.assertTrue(errors)
                else:
                    self.assertFalse(errors)
