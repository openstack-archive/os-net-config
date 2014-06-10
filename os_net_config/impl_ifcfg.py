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

import os_net_config
from os_net_config import utils


from os_net_config.openstack.common import processutils


def ifcfg_config_path(name):
    return "/etc/sysconfig/network-scripts/ifcfg-%s" % name


def route_config_path(name):
    return "/etc/sysconfig/network-scripts/route-%s" % name


class IfcfgNetConfig(os_net_config.NetConfig):
    """Configure network interfaces using the ifcfg format."""

    def __init__(self):
        self.interfaces = {}
        self.routes = {}

    def addInterface(self, interface):
        data = "DEVICE=%s\n" % interface.name
        data += "ONBOOT=yes\n"
        data += "HOTPLUG=no\n"
        if interface.type == 'ovs':
            data += "DEVICETYPE=ovs\n"
            if interface.bridge:
                data += "TYPE=OVSPort\n"
                data += "OVS_BRIDGE=%s\n" % interface.bridge
                data += "BOOTPROTO=none\n"
        if interface.mtu != 1500:
            data += "MTU=%i\n" % interface.mtu
        if interface.use_dhcp:
            data += "BOOTPROTO=dhcp\n"
        if interface.use_dhcpv6 or interface.v6_addresses():
            data += "IPV6INIT=yes\n"
            if interface.mtu != 1500:
                data += "IPV6_MTU=%i\n" % interface.mtu
        if interface.use_dhcpv6:
            data += "DHCPV6C=yes\n"
        elif interface.addresses:
            #TODO(dprince): support multiple addresses for each type
            v4_addresses = interface.v4_addresses()
            if v4_addresses:
                first_v4 = v4_addresses[0]
                data += "BOOTPROTO=static\n"
                data += "IPADDR=%s\n" % first_v4.ip
                data += "NETMASK=%s\n" % first_v4.netmask

            v6_addresses = interface.v6_addresses()
            if v6_addresses:
                first_v6 = v6_addresses[0]
                data += "IPV6_AUTOCONF=no\n"
                data += "IPV6ADDR=%s\n" % first_v6.ip

        self.interfaces[interface.name] = data
        if interface.routes:
            self.addRoutes(interface.name, interface.routes)

    def addRoutes(self, interface_name, routes=[]):
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

    def apply(self):
        restart_interfaces = []
        update_files = {}
        for interface_name, iface_data in self.interfaces.iteritems():
            route_data = self.routes.get(interface_name)
            if (utils.diff(ifcfg_config_path(interface_name), iface_data) or
                utils.diff(route_config_path(interface_name), route_data)):
                restart_interfaces.append(interface_name)
                update_files[ifcfg_config_path(interface_name)] = iface_data
                update_files[route_config_path(interface_name)] = route_data

        for interface in restart_interfaces:
            processutils.execute('/sbin/ifdown', interface)

        for location, data in update_files.iteritems():
            utils.write_config(location, data)

        for interface in restart_interfaces:
            processutils.execute('/sbin/ifup', interface)
