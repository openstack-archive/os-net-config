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

import logging

import os_net_config
from os_net_config import objects
from os_net_config import utils


from os_net_config.openstack.common import processutils


logger = logging.getLogger(__name__)


def ifcfg_config_path(name):
    return "/etc/sysconfig/network-scripts/ifcfg-%s" % name


#NOTE(dprince): added here for testability
def bridge_config_path(name):
    return ifcfg_config_path(name)


def route_config_path(name):
    return "/etc/sysconfig/network-scripts/route-%s" % name


class IfcfgNetConfig(os_net_config.NetConfig):
    """Configure network interfaces using the ifcfg format."""

    def __init__(self):
        self.interfaces = {}
        self.routes = {}
        self.bridges = {}
        logger.info('Ifcfg net config provider created.')

    def _addCommon(self, base_opt):
        data = "DEVICE=%s\n" % base_opt.name
        data += "ONBOOT=yes\n"
        data += "HOTPLUG=no\n"
        if isinstance(base_opt, objects.Vlan):
            data += "VLAN=yes\n"
            data += "PHYSDEV=%s\n" % base_opt.device
        if base_opt.ovs_port:
            data += "DEVICETYPE=ovs\n"
            if base_opt.bridge_name:
                if isinstance(base_opt, objects.Vlan):
                    data += "TYPE=OVSIntPort\n"
                    data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
                    data += "OVS_OPTIONS=\"tag=%s\"\n" % base_opt.vlan_id
                else:
                    data += "TYPE=OVSPort\n"
                    data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
        if isinstance(base_opt, objects.OvsBridge):
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSBridge\n"
            if base_opt.use_dhcp:
                data += "OVSBOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                data += ("OVSDHCPINTERFACES=\"%s\"\n" % " ".join(members))
            if base_opt.ovs_options:
                data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
        elif isinstance(base_opt, objects.OvsBond):
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSBond\n"
            if base_opt.use_dhcp:
                data += "OVSBOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                data += ("BOND_IFACES=\"%s\"\n" % " ".join(members))
            if base_opt.ovs_options:
                data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
        else:
            if base_opt.use_dhcp:
                data += "BOOTPROTO=dhcp\n"
            elif not base_opt.addresses:
                data += "BOOTPROTO=none\n"
        if base_opt.mtu != 1500:
            data += "MTU=%i\n" % base_opt.mtu
        if base_opt.use_dhcpv6 or base_opt.v6_addresses():
            data += "IPV6INIT=yes\n"
            if base_opt.mtu != 1500:
                data += "IPV6_MTU=%i\n" % base_opt.mtu
        if base_opt.use_dhcpv6:
            data += "DHCPV6C=yes\n"
        elif base_opt.addresses:
            #TODO(dprince): Do we want to support multiple addresses?
            v4_addresses = base_opt.v4_addresses()
            if v4_addresses:
                first_v4 = v4_addresses[0]
                data += "BOOTPROTO=static\n"
                data += "IPADDR=%s\n" % first_v4.ip
                data += "NETMASK=%s\n" % first_v4.netmask

            v6_addresses = base_opt.v6_addresses()
            if v6_addresses:
                first_v6 = v6_addresses[0]
                data += "IPV6_AUTOCONF=no\n"
                data += "IPV6ADDR=%s\n" % first_v6.ip
        return data

    def _addRoutes(self, interface_name, routes=[]):
        logger.info('adding custom route for interface: %s' % interface_name)
        data = ""
        first_line = ""
        for route in routes:
            if route.default:
                first_line = "default via %s dev %s\n" % (route.next_hop,
                                                          interface_name)
            else:
                data += "%s via %s dev %s\n" % (route.ip_netmask,
                                                route.next_hop,
                                                interface_name)
        self.routes[interface_name] = first_line + data
        logger.debug('route data: %s' % self.routes[interface_name])

    def addInterface(self, interface):
        logger.info('adding interface: %s' % interface.name)
        data = self._addCommon(interface)
        logger.debug('interface data: %s' % data)
        self.interfaces[interface.name] = data
        if interface.routes:
            self._addRoutes(interface.name, interface.routes)

    def addVlan(self, vlan):
        logger.info('adding vlan: %s' % vlan.name)
        data = self._addCommon(vlan)
        logger.debug('vlan data: %s' % data)
        self.interfaces[vlan.name] = data
        if vlan.routes:
            self._addRoutes(vlan.name, vlan.routes)

    def addBridge(self, bridge):
        logger.info('adding bridge: %s' % bridge.name)
        data = self._addCommon(bridge)
        logger.debug('bridge data: %s' % data)
        self.bridges[bridge.name] = data
        if bridge.routes:
            self._addRoutes(bridge.name, bridge.routes)

    def addBond(self, bond):
        logger.info('adding bond: %s' % bond.name)
        data = self._addCommon(bond)
        logger.debug('bond data: %s' % data)
        self.interfaces[bond.name] = data
        if bond.routes:
            self._addRoutes(bond.name, bond.routes)

    def apply(self, mock=False):
        if not mock:
            logger.info('applying network configs...')
        restart_interfaces = []
        restart_bridges = []
        update_files = {}

        for interface_name, iface_data in self.interfaces.iteritems():
            route_data = self.routes.get(interface_name, '')
            if (utils.diff(ifcfg_config_path(interface_name), iface_data) or
                utils.diff(route_config_path(interface_name), route_data)):
                restart_interfaces.append(interface_name)
                update_files[ifcfg_config_path(interface_name)] = iface_data
                update_files[route_config_path(interface_name)] = route_data
            elif not mock:
                logger.info('No changes required for interface: %s' %
                            interface_name)

        for bridge_name, bridge_data in self.bridges.iteritems():
            route_data = self.routes.get(bridge_name, '')
            if (utils.diff(ifcfg_config_path(bridge_name), bridge_data) or
                utils.diff(route_config_path(bridge_name), route_data)):
                restart_bridges.append(bridge_name)
                update_files[bridge_config_path(bridge_name)] = bridge_data
                update_files[route_config_path(bridge_name)] = route_data
            elif not mock:
                logger.info('No changes required for bridge: %s' % bridge_name)

        if mock:
            mock_str = ""
            for location, data in update_files.iteritems():
                mock_str += "%s:\n%s" % (location, data)
            return mock_str

        for interface in restart_interfaces:
            logger.info('running ifdown on interface: %s' % interface)
            processutils.execute('/sbin/ifdown', interface,
                                 check_exit_code=False)

        for bridge in restart_bridges:
            logger.info('running ifdown on bridge: %s' % bridge)
            processutils.execute('/sbin/ifdown', bridge,
                                 check_exit_code=False)

        for location, data in update_files.iteritems():
            logger.info('writing config file: %s' % location)
            utils.write_config(location, data)

        for bridge in restart_bridges:
            logger.info('running ifup on bridge: %s' % bridge)
            processutils.execute('/sbin/ifup', bridge)

        for interface in restart_interfaces:
            logger.info('running ifup on interface: %s' % interface)
            processutils.execute('/sbin/ifup', interface)
