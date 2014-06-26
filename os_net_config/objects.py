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

import netaddr


class NetworkObjectException(Exception):
    pass


class Route(object):
    """Base class for network routes."""

    def __init__(self, next_hop, ip_netmask="", default=False):
        self.next_hop = next_hop
        self.ip_netmask = ip_netmask
        self.default = default


class Address(object):
    """Base class for network addresses."""

    def __init__(self, ip_netmask, routes=[]):
        self.ip_netmask = ip_netmask
        ip_nw = netaddr.IPNetwork(self.ip_netmask)
        self.ip = str(ip_nw.ip)
        self.netmask = str(ip_nw.netmask)
        self.version = ip_nw.version
        self.routes = routes


class _BaseOpts(object):
    """Base abstraction for logical port options."""

    def __init__(self, name, use_dhcp=False, use_dhcpv6=False, addresses=[],
                 routes=[], mtu=1500):
        self.name = name
        self.mtu = mtu
        self.use_dhcp = use_dhcp
        self.use_dhcpv6 = use_dhcpv6
        self.addresses = addresses
        self.routes = routes
        self.bridge_name = None
        self.ovs_port = False

    def v4_addresses(self):
        v4_addresses = []
        for addr in self.addresses:
            if addr.version == 4:
                v4_addresses.append(addr)

        return v4_addresses

    def v6_addresses(self):
        v6_addresses = []
        for addr in self.addresses:
            if addr.version == 6:
                v6_addresses.append(addr)

        return v6_addresses


class Interface(_BaseOpts):
    """Base class for network interfaces."""

    def __init__(self, name, use_dhcp=False, use_dhcpv6=False, addresses=[],
                 routes=[], mtu=1500):
        super(Interface, self).__init__(name, use_dhcp, use_dhcpv6, addresses,
                                        routes, mtu)


class Vlan(_BaseOpts):
    """Base class for VLANs.

       NOTE: the name parameter must be formated w/ vlan#### where ####
       matches the vlan ID being used. Example: vlan5
    """

    def __init__(self, device, vlan_id, use_dhcp=False, use_dhcpv6=False,
                 addresses=[], routes=[], mtu=1500):
        name = 'vlan%i' % vlan_id
        super(Vlan, self).__init__(name, use_dhcp, use_dhcpv6, addresses,
                                   routes, mtu)
        self.vlan_id = int(vlan_id)
        self.device = device


class OvsBridge(_BaseOpts):
    """Base class for OVS bridges."""

    def __init__(self, name, use_dhcp=False, use_dhcpv6=False, addresses=[],
                 routes=[], members=[], mtu=1500):
        super(OvsBridge, self).__init__(name, use_dhcp, use_dhcpv6, addresses,
                                        routes, mtu)
        self.members = members
        for member in self.members:
            member.bridge_name = name
            member.ovs_port = True
