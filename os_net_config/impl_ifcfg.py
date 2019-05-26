# -*- coding: utf-8 -*-

# Copyright 2014-2015 Red Hat, Inc.
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
import itertools
import logging
import netaddr
import os
import re

import os_net_config
from os_net_config import objects
from os_net_config import utils


logger = logging.getLogger(__name__)

# Import the raw NetConfig object so we can call its methods
netconfig = os_net_config.NetConfig()

_ROUTE_TABLE_DEFAULT = """# reserved values
#
255\tlocal
254\tmain
253\tdefault
0\tunspec
#
# local
#
#1\tinr.ruhep\n"""


def ifcfg_config_path(name):
    return "/etc/sysconfig/network-scripts/ifcfg-%s" % name


def remove_ifcfg_config(ifname):
    if re.match('[\w-]+$', ifname):
        ifcfg_file = ifcfg_config_path(ifname)
        if os.path.exists(ifcfg_file):
            os.remove(ifcfg_file)


# NOTE(dprince): added here for testability
def bridge_config_path(name):
    return ifcfg_config_path(name)


def ivs_config_path():
    return "/etc/sysconfig/ivs"


def nfvswitch_config_path():
    return "/etc/sysconfig/nfvswitch"


def vpp_config_path():
    return "/etc/vpp/startup.conf"


def route_config_path(name):
    return "/etc/sysconfig/network-scripts/route-%s" % name


def route6_config_path(name):
    return "/etc/sysconfig/network-scripts/route6-%s" % name


def route_rule_config_path(name):
    return "/etc/sysconfig/network-scripts/rule-%s" % name


def route_table_config_path():
    return "/etc/iproute2/rt_tables"


def cleanup_pattern():
    return "/etc/sysconfig/network-scripts/ifcfg-*"


def dhclient_path():
    if os.path.exists("/usr/sbin/dhclient"):
        return "/usr/sbin/dhclient"
    elif os.path.exists("/sbin/dhclient"):
        return "/sbin/dhclient"
    else:
        raise RuntimeError("Could not find dhclient")


def stop_dhclient_process(interface):
    """Stop a DHCP process when no longer needed.

    This method exists so that it may be stubbed out for unit tests.
    :param interface: The interface on which to stop dhclient.
    """
    pid_file = '/var/run/dhclient-%s.pid' % (interface)
    try:
        dhclient = dhclient_path()
    except RuntimeError as err:
        logger.info('Exception when stopping dhclient: %s' % err)
        return

    if os.path.exists(pid_file):
        msg = 'Stopping %s on interface %s' % (dhclient, interface)
        netconfig.execute(msg, dhclient, '-r', '-pf',
                          pid_file, interface)
        try:
            os.unlink(pid_file)
        except OSError as err:
            logger.error('Could not remove dhclient pid file \'%s\': %s' %
                         (pid_file, err))


class IfcfgNetConfig(os_net_config.NetConfig):
    """Configure network interfaces using the ifcfg format."""

    def __init__(self, noop=False, root_dir=''):
        super(IfcfgNetConfig, self).__init__(noop, root_dir)
        self.interface_data = {}
        self.ivsinterface_data = {}
        self.nfvswitch_intiface_data = {}
        self.nfvswitch_options = None
        self.vlan_data = {}
        self.route_data = {}
        self.route6_data = {}
        self.route_table_data = {}
        self.rule_data = {}
        self.bridge_data = {}
        self.linuxbridge_data = {}
        self.linuxbond_data = {}
        self.ib_interface_data = {}
        self.linuxteam_data = {}
        self.vpp_interface_data = {}
        self.vpp_bond_data = {}
        self.member_names = {}
        self.renamed_interfaces = {}
        self.bond_primary_ifaces = {}
        logger.info('Ifcfg net config provider created.')

    def parse_ifcfg(self, ifcfg_data):
        """Break out the key/value pairs from ifcfg_data

           Return the keys and values without quotes.
           """
        ifcfg_values = {}
        for line in ifcfg_data.split("\n"):
            if not line.startswith("#") and line.find("=") > 0:
                k, v = line.split("=", 1)
                ifcfg_values[k] = v.strip("\"'")
        return ifcfg_values

    def parse_ifcfg_routes(self, ifcfg_data):
        """Break out the individual routes from an ifcfg route file."""
        routes = []
        for line in ifcfg_data.split("\n"):
            if not line.startswith("#"):
                routes.append(line)
        return routes

    def enumerate_ifcfg_changes(self, ifcfg_data_old, ifcfg_data_new):
        """Determine which values are added/modified/removed

        :param ifcfg_data_old: content of existing ifcfg file
        :param ifcfg_data_new: content of replacement ifcfg file
        :return: dict of changed values and states (added, removed, modified)
        """

        changed_values = {}
        for key in ifcfg_data_old:
            if key in ifcfg_data_new:
                if ifcfg_data_old[key].upper() != ifcfg_data_new[key].upper():
                    changed_values[key] = "modified"
            else:
                changed_values[key] = "removed"
        for key in ifcfg_data_new:
            if key not in ifcfg_data_old:
                changed_values[key] = "added"
        return changed_values

    def enumerate_ifcfg_route_changes(self, old_routes, new_routes):
        """Determine which routes are added or removed.

        :param file_values: contents of existing interface route file
        :param data_values: contents of replacement interface route file
        :return: list of tuples representing changes (route, state), where
                 state is one of added or removed
        """

        route_changes = []
        for route in old_routes:
            if route not in new_routes:
                route_changes.append((route, 'removed'))
        for route in new_routes:
            if route not in old_routes:
                route_changes.append((route, 'added'))
        return route_changes

    def ifcfg_requires_restart(self, filename, new_data):
        """Determine if changes to the ifcfg file require a restart to apply.

           Simple changes like IP, MTU, and routes can be directly applied
           without restarting the interface.

        :param filename: The ifcfg-<int> filename.
        :type filename: string
        :param new_data: The data for the new ifcfg-<int> file.
        :type new_data: string
        :returns: boolean value for whether a restart is required
        """

        file_data = utils.get_file_data(filename)
        logger.debug("Original ifcfg file:\n%s" % file_data)
        logger.debug("New ifcfg file:\n%s" % new_data)
        file_values = self.parse_ifcfg(file_data)
        new_values = self.parse_ifcfg(new_data)
        restart_required = False
        # Certain changes can be applied without restarting the interface
        permitted_changes = [
            "IPADDR",
            "NETMASK",
            "MTU",
            "ONBOOT"
        ]
        # Check whether any of the changes require restart
        for change in self.enumerate_ifcfg_changes(file_values, new_values):
            if change not in permitted_changes:
                # Moving to DHCP requires restarting interface
                if change in ["BOOTPROTO", "OVSBOOTPROTO"]:
                    if change in new_values:
                        if (new_values[change].upper() == "DHCP"):
                            restart_required = True
                            logger.debug(
                                "DHCP on %s requires restart" % change)
                else:
                    restart_required = True
        if not restart_required:
            logger.debug("Changes do not require restart")
        return restart_required

    def iproute2_apply_commands(self, device_name, filename, data):
        """Return list of commands needed to implement changes.

           Given ifcfg data for an interface, return commands required to
           apply the configuration using 'ip' commands.

        :param device_name: The name of the int, bridge, or bond
        :type device_name: string
        :param filename: The ifcfg-<int> filename.
        :type filename: string
        :param data: The data for the new ifcfg-<int> file.
        :type data: string
        :returns: commands (commands to be run)
        """

        previous_cfg = utils.get_file_data(filename)
        file_values = self.parse_ifcfg(previous_cfg)
        data_values = self.parse_ifcfg(data)
        logger.debug("File values:\n%s" % file_values)
        logger.debug("Data values:\n%s" % data_values)
        changes = self.enumerate_ifcfg_changes(file_values, data_values)
        commands = []
        new_cidr = 0
        old_cidr = 0
        # Convert dot notation netmask to CIDR length notation
        if "NETMASK" in file_values:
            netmask = file_values["NETMASK"]
            old_cidr = netaddr.IPAddress(netmask).netmask_bits()
        if "NETMASK" in data_values:
            netmask = data_values["NETMASK"]
            new_cidr = netaddr.IPAddress(netmask).netmask_bits()
        if "IPADDR" in changes:
            if changes["IPADDR"] == "removed" or changes[
                "IPADDR"] == "modified":
                if old_cidr:
                    commands.append("addr del %s/%s dev %s" %
                                    (file_values["IPADDR"], old_cidr,
                                     device_name))
                else:
                    # Cannot remove old IP specifically if netmask not known
                    commands.append("addr flush dev %s" % device_name)
            if changes["IPADDR"] == "added" or changes["IPADDR"] == "modified":
                commands.insert(0, "addr add %s/%s dev %s" %
                                (data_values["IPADDR"], new_cidr, device_name))
        if "MTU" in changes:
            if changes["MTU"] == "added" or changes["MTU"] == "modified":
                commands.append("link set dev %s mtu %s" %
                                (device_name, data_values["MTU"]))
            elif changes["MTU"] == "removed":
                commands.append("link set dev %s mtu 1500" % device_name)
        return commands

    def iproute2_route_commands(self, filename, data):
        """Return a list of commands for 'ip route' to modify routing table.

           The list of commands is generated by comparing the old and new
           configs, and calculating which routes need to be added and which
           need to be removed.

        :param filename: path to the original interface route file
        :param data: data that is to be written to new route file
        :return: list of commands to feed to 'ip' to reconfigure routes
        """

        file_values = self.parse_ifcfg_routes(utils.get_file_data(filename))
        data_values = self.parse_ifcfg_routes(data)
        route_changes = self.enumerate_ifcfg_route_changes(file_values,
                                                           data_values)
        commands = []

        for route in route_changes:
            if route[1] == 'removed':
                commands.append('route del ' + route[0])
            elif route[1] == 'added':
                commands.append('route add ' + route[0])
        return commands

    def child_members(self, name):
        children = set()
        try:
            for member in self.member_names[name]:
                children.add(member)
                children.update(self.child_members(member))
        except KeyError:
            pass
        return children

    def _add_common(self, base_opt):

        ovs_extra = []
        data = "# This file is autogenerated by os-net-config\n"
        data += "DEVICE=%s\n" % base_opt.name
        if base_opt.onboot:
            data += "ONBOOT=yes\n"
        else:
            data += "ONBOOT=no\n"
        if isinstance(base_opt, objects.Interface) and base_opt.hotplug:
            data += "HOTPLUG=yes\n"
        else:
            data += "HOTPLUG=no\n"
        if base_opt.nm_controlled:
            data += "NM_CONTROLLED=yes\n"
        else:
            data += "NM_CONTROLLED=no\n"
        if not base_opt.dns_servers and not base_opt.use_dhcp:
            data += "PEERDNS=no\n"
        if isinstance(base_opt, objects.Vlan):
            if not base_opt.ovs_port:
                # vlans on OVS bridges are internal ports (no device, etc)
                data += "VLAN=yes\n"
                if base_opt.device:
                    data += "PHYSDEV=%s\n" % base_opt.device
                elif base_opt.linux_bond_name:
                    data += "PHYSDEV=%s\n" % base_opt.linux_bond_name
            else:
                if base_opt.ovs_options:
                    data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
                ovs_extra.extend(base_opt.ovs_extra)
        elif isinstance(base_opt, objects.IvsInterface):
            data += "TYPE=IVSIntPort\n"
        elif isinstance(base_opt, objects.NfvswitchInternal):
            data += "TYPE=NFVSWITCHIntPort\n"
        elif isinstance(base_opt, objects.IbInterface):
            data += "TYPE=Infiniband\n"
        elif re.match('\w+\.\d+$', base_opt.name):
            data += "VLAN=yes\n"
        if base_opt.linux_bond_name:
            data += "MASTER=%s\n" % base_opt.linux_bond_name
            data += "SLAVE=yes\n"
        if base_opt.linux_team_name:
            data += "TEAM_MASTER=%s\n" % base_opt.linux_team_name
            if base_opt.primary:
                data += "TEAM_PORT_CONFIG='{\"prio\": 100}'\n"
        if base_opt.ivs_bridge_name:
            data += "DEVICETYPE=ivs\n"
            data += "IVS_BRIDGE=%s\n" % base_opt.ivs_bridge_name
        if base_opt.nfvswitch_bridge_name:
            data += "DEVICETYPE=nfvswitch\n"
            data += "NFVSWITCH_BRIDGE=%s\n" % base_opt.nfvswitch_bridge_name
        if base_opt.ovs_port:
            if not isinstance(base_opt, objects.LinuxTeam):
                data += "DEVICETYPE=ovs\n"
            if base_opt.bridge_name:
                if isinstance(base_opt, objects.Vlan):
                    data += "TYPE=OVSIntPort\n"
                    data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
                    data += "OVS_OPTIONS=\"tag=%s\"\n" % base_opt.vlan_id
                else:
                    data += "TYPE=OVSPort\n"
                    data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
        if base_opt.linux_bridge_name:
            data += "BRIDGE=%s\n" % base_opt.linux_bridge_name
        if isinstance(base_opt, objects.OvsBridge):
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSBridge\n"
            if base_opt.use_dhcp:
                data += "OVSBOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                self.member_names[base_opt.name] = members
                if base_opt.use_dhcp:
                    data += ("OVSDHCPINTERFACES=\"%s\"\n" % " ".join(members))
            if base_opt.primary_interface_name:
                mac = utils.interface_mac(base_opt.primary_interface_name)
                ovs_extra.append("set bridge %s other-config:hwaddr=%s" %
                                 (base_opt.name, mac))
            if base_opt.ovs_options:
                data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
            ovs_extra.extend(base_opt.ovs_extra)
        elif isinstance(base_opt, objects.OvsUserBridge):
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSUserBridge\n"
            if base_opt.use_dhcp:
                data += "OVSBOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                self.member_names[base_opt.name] = members
                if base_opt.use_dhcp:
                    data += ("OVSDHCPINTERFACES=\"%s\"\n" % " ".join(members))
            if base_opt.ovs_options:
                data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
            ovs_extra.extend(base_opt.ovs_extra)
        elif isinstance(base_opt, objects.OvsBond):
            if base_opt.primary_interface_name:
                primary_name = base_opt.primary_interface_name
                self.bond_primary_ifaces[base_opt.name] = primary_name
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSBond\n"
            if base_opt.use_dhcp:
                data += "OVSBOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                self.member_names[base_opt.name] = members
                data += ("BOND_IFACES=\"%s\"\n" % " ".join(members))
            if base_opt.ovs_options:
                data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
            ovs_extra.extend(base_opt.ovs_extra)
        elif isinstance(base_opt, objects.LinuxBridge):
            data += "TYPE=Bridge\n"
            data += "DELAY=0\n"
            if base_opt.use_dhcp:
                data += "BOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                self.member_names[base_opt.name] = members
            if base_opt.primary_interface_name:
                primary_name = base_opt.primary_interface_name
                primary_mac = utils.interface_mac(primary_name)
                data += "MACADDR=\"%s\"\n" % primary_mac
        elif isinstance(base_opt, objects.LinuxBond):
            if base_opt.primary_interface_name:
                primary_name = base_opt.primary_interface_name
                primary_mac = utils.interface_mac(primary_name)
                data += "MACADDR=\"%s\"\n" % primary_mac
            if base_opt.use_dhcp:
                data += "BOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                self.member_names[base_opt.name] = members
            if base_opt.bonding_options:
                data += "BONDING_OPTS=\"%s\"\n" % base_opt.bonding_options
        elif isinstance(base_opt, objects.LinuxTeam):
            if base_opt.primary_interface_name:
                primary_name = base_opt.primary_interface_name
                primary_mac = utils.interface_mac(primary_name)
                data += "MACADDR=\"%s\"\n" % primary_mac
            if base_opt.use_dhcp:
                data += "BOOTPROTO=dhcp\n"
            if base_opt.members:
                members = [member.name for member in base_opt.members]
                self.member_names[base_opt.name] = members
            data += "DEVICETYPE=Team\n"
            if base_opt.bonding_options:
                data += "TEAM_CONFIG='%s'\n" % base_opt.bonding_options
        elif isinstance(base_opt, objects.OvsTunnel):
            ovs_extra.extend(base_opt.ovs_extra)
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSTunnel\n"
            data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
            data += "OVS_TUNNEL_TYPE=%s\n" % base_opt.tunnel_type
            data += "OVS_TUNNEL_OPTIONS=\"%s\"\n" % \
                    ' '.join(base_opt.ovs_options)
        elif isinstance(base_opt, objects.OvsPatchPort):
            ovs_extra.extend(base_opt.ovs_extra)
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSPatchPort\n"
            data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
            data += "OVS_PATCH_PEER=%s\n" % base_opt.peer
        elif isinstance(base_opt, objects.OvsDpdkPort):
            ovs_extra.extend(base_opt.ovs_extra)
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSDPDKPort\n"
            data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
            # Validation of DPDK port having only one interface is done prior
            # to this. So accesing the interface name statically.
            # Also dpdk_devargs would be valid here, since
            # bind_dpdk_interfaces() is invoked before this.
            dpdk_devargs = utils.get_dpdk_devargs(
                base_opt.members[0].name, self.noop)

            ovs_extra.append("set Interface $DEVICE options:dpdk-devargs="
                             "%s" % dpdk_devargs)
            if base_opt.mtu:
                ovs_extra.append("set Interface $DEVICE mtu_request=$MTU")
            if base_opt.rx_queue:
                data += "RX_QUEUE=%i\n" % base_opt.rx_queue
                ovs_extra.append("set Interface $DEVICE " +
                                 "options:n_rxq=$RX_QUEUE")
        elif isinstance(base_opt, objects.OvsDpdkBond):
            ovs_extra.extend(base_opt.ovs_extra)
            # Referring to bug:1643026, the below commenting of the interfaces,
            # is to workaround the error, but is not the long term solution.
            # The long term solution is to run DPDK options before
            # os-net-config, which is being tracked at BUG:1654975
            # if base_opt.primary_interface_name:
            #    primary_name = base_opt.primary_interface_name
            #    self.bond_primary_ifaces[base_opt.name] = primary_name
            data += "DEVICETYPE=ovs\n"
            data += "TYPE=OVSDPDKBond\n"
            data += "OVS_BRIDGE=%s\n" % base_opt.bridge_name
            if base_opt.members:
                for bond_member in base_opt.members:
                    # Validation of DPDK port having only one interface is done
                    # prior to this. So accesing the interface name statically.
                    # Also dpdk_devargs would be valid here, since
                    # bind_dpdk_interfaces () is invoked before this.
                    dpdk_devargs = utils.get_dpdk_devargs(
                        bond_member.members[0].name, self.noop)
                    ovs_extra.append("set Interface %s options:"
                                     "dpdk-devargs=%s"
                                     % (bond_member.name, dpdk_devargs))
                members = [member.name for member in base_opt.members]
                data += ("BOND_IFACES=\"%s\"\n" % " ".join(members))
                # MTU configuration given for the OvsDpdkbond shall be applied
                # to each of the members of the OvsDpdkbond
                if base_opt.mtu:
                    for member in base_opt.members:
                        ovs_extra.append("set Interface %s mtu_request=$MTU" %
                                         member.name)
                if base_opt.rx_queue:
                    data += "RX_QUEUE=%i\n" % base_opt.rx_queue
                    for member in base_opt.members:
                        ovs_extra.append("set Interface %s options:n_rxq="
                                         "$RX_QUEUE" % member.name)
            if base_opt.ovs_options:
                data += "OVS_OPTIONS=\"%s\"\n" % base_opt.ovs_options
            ovs_extra.extend(base_opt.ovs_extra)
        else:
            if base_opt.use_dhcp:
                data += "BOOTPROTO=dhcp\n"
            elif not base_opt.addresses:
                data += "BOOTPROTO=none\n"
        if hasattr(base_opt, 'ethtool_opts') and base_opt.ethtool_opts:
            data += "ETHTOOL_OPTS=\"%s\"\n" % base_opt.ethtool_opts

        if base_opt.mtu:
            data += "MTU=%i\n" % base_opt.mtu
        if base_opt.use_dhcpv6 or base_opt.v6_addresses():
            data += "IPV6INIT=yes\n"
            if base_opt.mtu:
                data += "IPV6_MTU=%i\n" % base_opt.mtu
        if base_opt.use_dhcpv6:
            data += "DHCPV6C=yes\n"
        elif base_opt.addresses:
            v4_addresses = base_opt.v4_addresses()
            if v4_addresses:
                data += "BOOTPROTO=static\n"
                for i, address in enumerate(v4_addresses):
                    num = '%s' % i if i else ''
                    data += "IPADDR%s=%s\n" % (num, address.ip)
                    data += "NETMASK%s=%s\n" % (num, address.netmask)

            v6_addresses = base_opt.v6_addresses()
            if v6_addresses:
                first_v6 = v6_addresses[0]
                data += "IPV6_AUTOCONF=no\n"
                data += "IPV6ADDR=%s\n" % first_v6.ip_netmask
                if len(v6_addresses) > 1:
                    secondaries_v6 = " ".join(map(lambda a: a.ip_netmask,
                                                  v6_addresses[1:]))
                    data += "IPV6ADDR_SECONDARIES=\"%s\"\n" % secondaries_v6

        if base_opt.hwaddr:
            data += "HWADDR=%s\n" % base_opt.hwaddr
        if ovs_extra:
            data += "OVS_EXTRA=\"%s\"\n" % " -- ".join(ovs_extra)
        if not base_opt.defroute:
            data += "DEFROUTE=no\n"
        if base_opt.dhclient_args:
            data += "DHCLIENTARGS=%s\n" % base_opt.dhclient_args
        if base_opt.dns_servers:
            data += "DNS1=%s\n" % base_opt.dns_servers[0]
            if len(base_opt.dns_servers) >= 2:
                data += "DNS2=%s\n" % base_opt.dns_servers[1]
                if len(base_opt.dns_servers) > 2:
                    logger.warning('ifcfg format supports max 2 resolvers.')
        if base_opt.domain:
            if type(base_opt.domain) == list:
                data += "DOMAIN=\"%s\"\n" % ' '.join(base_opt.domain)
            else:
                data += "DOMAIN=%s\n" % base_opt.domain
        return data

    def _add_routes(self, interface_name, routes=[]):
        logger.info('adding custom route for interface: %s' % interface_name)
        data = ""
        first_line = ""
        data6 = ""
        first_line6 = ""
        for route in routes:
            options = ""
            table = ""
            if route.route_options:
                options = " %s" % route.route_options
            if route.route_table:
                if route.route_options.find('table ') == -1:
                    table = " table %s" % route.route_table
            if ":" not in route.next_hop:
                # Route is an IPv4 route
                if route.default:
                    first_line = "default via %s dev %s%s%s\n" % (
                                 route.next_hop, interface_name,
                                 table, options)
                else:
                    data += "%s via %s dev %s%s%s\n" % (
                            route.ip_netmask, route.next_hop,
                            interface_name, table, options)
            else:
                # Route is an IPv6 route
                if route.default:
                    first_line6 = "default via %s dev %s%s%s\n" % (
                                  route.next_hop, interface_name,
                                  table, options)
                else:
                    data6 += "%s via %s dev %s%s%s\n" % (
                             route.ip_netmask, route.next_hop,
                             interface_name, table, options)
        self.route_data[interface_name] = first_line + data
        self.route6_data[interface_name] = first_line6 + data6
        logger.debug('route data: %s' % self.route_data[interface_name])
        logger.debug('ipv6 route data: %s' % self.route6_data[interface_name])

    def _add_rules(self, interface, rules):
        """Add RouteRule objects to an interface.

        :param interface: the name of the interface to apply rules.
        :param rules: the list of rules to apply to the interface.
        """
        logger.info('adding route rules for interface: %s' % interface)
        data = ""
        first_line = "# This file is autogenerated by os-net-config\n"
        for rule in rules:
            if rule.comment:
                data += "# %s\n" % rule.comment
            data += "%s\n" % rule.rule
        self.rule_data[interface] = first_line + data
        logger.debug('rules for interface: %s' % self.rule_data[interface])

    def add_route_table(self, route_table):
        """Add a RouteTable object to the net config object.

        :param route_table: the RouteTable object to add.
        """
        logger.info('adding route table: %s %s' % (route_table.table_id,
                                                   route_table.name))
        self.route_table_data[int(route_table.table_id)] = route_table.name

    def add_interface(self, interface):
        """Add an Interface object to the net config object.

        :param interface: The Interface object to add.
        """
        logger.info('adding interface: %s' % interface.name)
        data = self._add_common(interface)
        logger.debug('interface data: %s' % data)
        self.interface_data[interface.name] = data
        if interface.routes:
            self._add_routes(interface.name, interface.routes)
        if interface.rules:
            self._add_rules(interface.name, interface.rules)

        if interface.renamed:
            logger.info("Interface %s being renamed to %s"
                        % (interface.hwname, interface.name))
            self.renamed_interfaces[interface.hwname] = interface.name

    def add_vlan(self, vlan):
        """Add a Vlan object to the net config object.

        :param vlan: The vlan object to add.
        """
        logger.info('adding vlan: %s' % vlan.name)
        data = self._add_common(vlan)
        logger.debug('vlan data: %s' % data)
        self.vlan_data[vlan.name] = data
        if vlan.routes:
            self._add_routes(vlan.name, vlan.routes)
        if vlan.rules:
            self._add_rules(vlan.name, vlan.rules)

    def add_ivs_interface(self, ivs_interface):
        """Add a ivs_interface object to the net config object.

        :param ivs_interface: The ivs_interface object to add.
        """
        logger.info('adding ivs_interface: %s' % ivs_interface.name)
        data = self._add_common(ivs_interface)
        logger.debug('ivs_interface data: %s' % data)
        self.ivsinterface_data[ivs_interface.name] = data
        if ivs_interface.routes:
            self._add_routes(ivs_interface.name, ivs_interface.routes)
        if ivs_interface.rules:
            self._add_rules(ivs_interface.name, ivs_interface.rules)

    def add_nfvswitch_internal(self, nfvswitch_internal):
        """Add a nfvswitch_internal interface object to the net config object.

        :param nfvswitch_internal: The nfvswitch_internal object to add.
        """
        iface_name = nfvswitch_internal.name
        logger.info('adding nfvswitch_internal interface: %s' % iface_name)
        data = self._add_common(nfvswitch_internal)
        logger.debug('nfvswitch_internal interface data: %s' % data)
        self.nfvswitch_intiface_data[iface_name] = data
        if nfvswitch_internal.routes:
            self._add_routes(iface_name, nfvswitch_internal.routes)
        if nfvswitch_internal.rules:
            self._add_rules(iface_name, nfvswitch_internal.rules)

    def add_bridge(self, bridge):
        """Add an OvsBridge object to the net config object.

        :param bridge: The OvsBridge object to add.
        """
        logger.info('adding bridge: %s' % bridge.name)
        data = self._add_common(bridge)
        logger.debug('bridge data: %s' % data)
        self.bridge_data[bridge.name] = data
        if bridge.routes:
            self._add_routes(bridge.name, bridge.routes)
        if bridge.rules:
            self._add_rules(bridge.name, bridge.rules)

    def add_ovs_user_bridge(self, bridge):
        """Add an OvsUserBridge object to the net config object.

        :param bridge: The OvsUserBridge object to add.
        """
        logger.info('adding ovs user bridge: %s' % bridge.name)
        data = self._add_common(bridge)
        logger.debug('ovs user bridge data: %s' % data)
        self.bridge_data[bridge.name] = data
        if bridge.routes:
            self._add_routes(bridge.name, bridge.routes)
        if bridge.rules:
            self._add_rules(bridge.name, bridge.rules)

    def add_linux_bridge(self, bridge):
        """Add a LinuxBridge object to the net config object.

        :param bridge: The LinuxBridge object to add.
        """
        logger.info('adding linux bridge: %s' % bridge.name)
        data = self._add_common(bridge)
        logger.debug('bridge data: %s' % data)
        self.linuxbridge_data[bridge.name] = data
        if bridge.routes:
            self._add_routes(bridge.name, bridge.routes)
        if bridge.rules:
            self._add_rules(bridge.name, bridge.rules)

    def add_ivs_bridge(self, bridge):
        """Add a IvsBridge object to the net config object.

        IVS can only support one virtual switch per node,
        using "ivs" as its name. As long as the ivs service
        is running, the ivs virtual switch will be there.
        It is impossible to add multiple ivs virtual switches
        per node.
        :param bridge: The IvsBridge object to add.
        """
        pass

    def add_nfvswitch_bridge(self, bridge):
        """Add a NFVSwitchBridge object to the net config object.

        NFVSwitch can only support one virtual switch per node,
        using "nfvswitch" as its name. As long as the nfvswitch service
        is running, the nfvswitch virtual switch will be available.
        :param bridge: The NfvswitchBridge object to add.
        """
        self.nfvswitch_options = bridge.options

    def add_bond(self, bond):
        """Add an OvsBond object to the net config object.

        :param bond: The OvsBond object to add.
        """
        logger.info('adding bond: %s' % bond.name)
        data = self._add_common(bond)
        logger.debug('bond data: %s' % data)
        self.interface_data[bond.name] = data
        if bond.routes:
            self._add_routes(bond.name, bond.routes)
        if bond.rules:
            self._add_rules(bond.name, bond.rules)

    def add_linux_bond(self, bond):
        """Add a LinuxBond object to the net config object.

        :param bond: The LinuxBond object to add.
        """
        logger.info('adding linux bond: %s' % bond.name)
        data = self._add_common(bond)
        logger.debug('bond data: %s' % data)
        self.linuxbond_data[bond.name] = data
        if bond.routes:
            self._add_routes(bond.name, bond.routes)
        if bond.rules:
            self._add_rules(bond.name, bond.rules)

    def add_linux_team(self, team):
        """Add a LinuxTeam object to the net config object.

        :param team: The LinuxTeam object to add.
        """
        logger.info('adding linux team: %s' % team.name)
        data = self._add_common(team)
        logger.debug('team data: %s' % data)
        self.linuxteam_data[team.name] = data
        if team.routes:
            self._add_routes(team.name, team.routes)
        if team.rules:
            self._add_rules(team.name, team.rules)

    def add_ovs_tunnel(self, tunnel):
        """Add a OvsTunnel object to the net config object.

        :param tunnel: The OvsTunnel object to add.
        """
        logger.info('adding ovs tunnel: %s' % tunnel.name)
        data = self._add_common(tunnel)
        logger.debug('ovs tunnel data: %s' % data)
        self.interface_data[tunnel.name] = data

    def add_ovs_patch_port(self, ovs_patch_port):
        """Add a OvsPatchPort object to the net config object.

        :param ovs_patch_port: The OvsPatchPort object to add.
        """
        logger.info('adding ovs patch port: %s' % ovs_patch_port.name)
        data = self._add_common(ovs_patch_port)
        logger.debug('ovs patch port data: %s' % data)
        self.interface_data[ovs_patch_port.name] = data

    def add_ib_interface(self, ib_interface):
        """Add an InfiniBand interface object to the net config object.

        :param ib_interface: The InfiniBand interface object to add.
        """
        logger.info('adding ib_interface: %s' % ib_interface.name)
        data = self._add_common(ib_interface)
        logger.debug('ib_interface data: %s' % data)
        self.ib_interface_data[ib_interface.name] = data
        if ib_interface.routes:
            self._add_routes(ib_interface.name, ib_interface.routes)
        if ib_interface.rules:
            self._add_rules(ib_interface.name, ib_interface.rules)

        if ib_interface.renamed:
            logger.info("InfiniBand interface %s being renamed to %s"
                        % (ib_interface.hwname, ib_interface.name))
            self.renamed_interfaces[ib_interface.hwname] = ib_interface.name

    def add_ovs_dpdk_port(self, ovs_dpdk_port):
        """Add a OvsDpdkPort object to the net config object.

        :param ovs_dpdk_port: The OvsDpdkPort object to add.
        """
        logger.info('adding ovs dpdk port: %s' % ovs_dpdk_port.name)

        # DPDK Port will have only one member of type Interface, validation
        # checks are added at the object creation stage.
        ifname = ovs_dpdk_port.members[0].name

        # Bind the dpdk interface
        utils.bind_dpdk_interfaces(ifname, ovs_dpdk_port.driver, self.noop)
        if not self.noop:
            remove_ifcfg_config(ifname)

        data = self._add_common(ovs_dpdk_port)
        logger.debug('ovs dpdk port data: %s' % data)
        self.interface_data[ovs_dpdk_port.name] = data

    def add_ovs_dpdk_bond(self, ovs_dpdk_bond):
        """Add an OvsDPDKBond object to the net config object.

        :param ovs_dpdk_bond: The OvsBond object to add.
        """
        logger.info('adding ovs dpdk bond: %s' % ovs_dpdk_bond.name)

        # Bind the dpdk interface
        for dpdk_port in ovs_dpdk_bond.members:
            # DPDK Port will have only one member of type Interface, validation
            # checks are added at the object creation stage.
            ifname = dpdk_port.members[0].name
            utils.bind_dpdk_interfaces(ifname, dpdk_port.driver, self.noop)
            if not self.noop:
                remove_ifcfg_config(ifname)

        data = self._add_common(ovs_dpdk_bond)
        logger.debug('ovs dpdk bond data: %s' % data)
        self.interface_data[ovs_dpdk_bond.name] = data
        if ovs_dpdk_bond.routes:
            self._add_routes(ovs_dpdk_bond.name, ovs_dpdk_bond.routes)
        if ovs_dpdk_bond.rules:
            self._add_rules(ovs_dpdk_bond.name, ovs_dpdk_bond.rules)

    def add_sriov_pf(self, sriov_pf):
        """Add a SriovPF object to the net config object

        :param sriov_pf: The SriovPF object to add
        """
        logger.info('adding sriov pf: %s' % sriov_pf.name)
        data = self._add_common(sriov_pf)
        logger.debug('sriov pf data: %s' % data)
        utils.update_sriov_pf_map(sriov_pf.name, sriov_pf.numvfs,
                                  self.noop, promisc=sriov_pf.promisc,
                                  link_mode=sriov_pf.link_mode)
        self.interface_data[sriov_pf.name] = data

    def add_sriov_vf(self, sriov_vf):
        """Add a SriovVF object to the net config object

        :param sriov_vf: The SriovVF object to add
        """
        logger.info('adding sriov vf: %s for pf: %s, vfid: %d'
                    % (sriov_vf.name, sriov_vf.device, sriov_vf.vfid))
        data = self._add_common(sriov_vf)
        logger.debug('sriov vf data: %s' % data)
        self.interface_data[sriov_vf.name] = data
        if sriov_vf.routes:
            self._add_routes(sriov_vf.name, sriov_vf.routes)
        if sriov_vf.rules:
            self._add_rules(sriov_vf.name, sriov_vf.rules)

    def add_vpp_interface(self, vpp_interface):
        """Add a VppInterface object to the net config object

        :param vpp_interface: The VppInterface object to add
        """
        vpp_interface.pci_dev = utils.get_pci_address(vpp_interface.name,
                                                      False)
        if not vpp_interface.pci_dev:
            vpp_interface.pci_dev = utils.get_stored_pci_address(
                vpp_interface.name, False)
        vpp_interface.hwaddr = utils.interface_mac(vpp_interface.name)
        if not self.noop:
            self.ifdown(vpp_interface.name)
            remove_ifcfg_config(vpp_interface.name)
        logger.info('adding vpp interface: %s %s'
                    % (vpp_interface.name, vpp_interface.pci_dev))
        self.vpp_interface_data[vpp_interface.name] = vpp_interface

    def add_vpp_bond(self, vpp_bond):
        """Add a VppInterface object to the net config object

        :param vpp_bond: The VPPBond object to add
        """
        logger.info('adding vpp bond: %s' % vpp_bond.name)
        self.vpp_bond_data[vpp_bond.name] = vpp_bond

    def add_contrail_vrouter(self, contrail_vrouter):
        """Add a ContraiVrouter object to the net config object

        :param contrail_vrouter:
           The ContrailVrouter object to add
        """
        logger.info('adding contrail_vrouter interface: %s'
                    % contrail_vrouter.name)
        # Contrail vrouter will have the only member (of type interface,
        # vlan or linux_bond)
        ifname = contrail_vrouter.members[0].name
        data = self._add_common(contrail_vrouter)
        data += "DEVICETYPE=vhost\n"
        data += "TYPE=kernel_mode\n"
        data += "BIND_INT=%s\n" % ifname
        logger.debug('contrail data: %s' % data)
        self.interface_data[contrail_vrouter.name] = data
        if contrail_vrouter.routes:
            self._add_routes(contrail_vrouter.name, contrail_vrouter.routes)
        if contrail_vrouter.rules:
            self._add_rules(contrail_vrouter.name, contrail_vrouter.rules)

    def add_contrail_vrouter_dpdk(self, contrail_vrouter_dpdk):
        """Add a ContraiVrouterDpdk object to the net config object

        :param contrail_vrouter_dpdk:
           The ContrailVrouterDpdk object to add
        """
        logger.info('adding contrail vrouter dpdk interface: %s'
                    % contrail_vrouter_dpdk.name)
        pci_string = ",".join(
            utils.translate_ifname_to_pci_address(bind_int.name, self.noop)
            for bind_int in contrail_vrouter_dpdk.members)
        data = self._add_common(contrail_vrouter_dpdk)
        data += "DEVICETYPE=vhost\n"
        data += "TYPE=dpdk\n"
        data += "BIND_INT=%s\n" % pci_string
        if len(contrail_vrouter_dpdk.members) > 1:
            data += "BOND_MODE=%s\n" % contrail_vrouter_dpdk.bond_mode
            data += "BOND_POLICY=%s\n" % contrail_vrouter_dpdk.bond_policy
        data += "DRIVER=%s\n" % contrail_vrouter_dpdk.driver
        data += "CPU_LIST=%s\n" % contrail_vrouter_dpdk.cpu_list
        if contrail_vrouter_dpdk.vlan_id:
            data += "VLAN_ID=%s\n" % contrail_vrouter_dpdk.vlan_id
        logger.debug('contrail dpdk data: %s' % data)
        self.interface_data[contrail_vrouter_dpdk.name] = data
        if contrail_vrouter_dpdk.routes:
            self._add_routes(contrail_vrouter_dpdk.name,
                             contrail_vrouter_dpdk.routes)
        if contrail_vrouter_dpdk.rules:
            self._add_rules(contrail_vrouter_dpdk.name,
                            contrail_vrouter_dpdk.rules)

    def generate_ivs_config(self, ivs_uplinks, ivs_interfaces):
        """Generate configuration content for ivs."""

        intfs = []
        for intf in ivs_uplinks:
            intfs.append(' -u ')
            intfs.append(intf)
        uplink_str = ''.join(intfs)

        intfs = []
        for intf in ivs_interfaces:
            intfs.append(' --internal-port=')
            intfs.append(intf)
        intf_str = ''.join(intfs)

        data = ("DAEMON_ARGS=\"--hitless --certificate /etc/ivs "
                "--inband-vlan 4092%s%s\""
                % (uplink_str, intf_str))
        return data

    def generate_nfvswitch_config(self, nfvswitch_ifaces,
                                  nfvswitch_internal_ifaces):
        """Generate configuration content for nfvswitch."""

        options_str = ""
        if self.nfvswitch_options:
            options_str = self.nfvswitch_options

        ifaces = []
        for iface in nfvswitch_ifaces:
            ifaces.append(' -u ')
            ifaces.append(iface)
        iface_str = ''.join(ifaces)

        ifaces = []
        for iface in nfvswitch_internal_ifaces:
            ifaces.append(' -m ')
            ifaces.append(iface)
        internal_str = ''.join(ifaces)

        data = "SETUP_ARGS=\"%s%s%s\"" % (options_str, iface_str, internal_str)
        return data

    def generate_route_table_config(self, route_tables):
        """Generate configuration content for routing tables.

        This method first extracts the existing route table definitions. If
        any non-default tables exist, they will be kept unless they conflict
        with new tables defined in the route_tables dict.

        :param route_tables: A dict of RouteTable objects
        """

        custom_tables = {}
        res_ids = ['0', '253', '254', '255']
        res_names = ['unspec', 'default', 'main', 'local']
        rt_config = utils.get_file_data(route_table_config_path()).split('\n')
        rt_defaults = _ROUTE_TABLE_DEFAULT.split("\n")
        data = _ROUTE_TABLE_DEFAULT
        for line in (line for line in rt_config if line not in rt_defaults):
            # Leave non-standard comments intact in file
            if line.startswith('#') and not line.strip() in rt_defaults:
                data += "%s\n" % line
            # Ignore old managed entries, will be added back if in new config.
            elif line.find("# os-net-config managed table") == -1:
                id_name = line.split()
                # Keep custom tables if there is no conflict with new tables.
                if id_name[0].isdigit() and len(id_name) > 1:
                    if not id_name[0] in res_ids:
                        if not id_name[1] in res_names:
                            if not int(id_name[0]) in route_tables:
                                if not id_name[1] in route_tables.values():
                                    # Replicate line with any comments appended
                                    custom_tables[id_name[0]] = id_name[1]
                                    data += "%s\n" % line
        if custom_tables:
            logger.debug("Existing route tables: %s" % custom_tables)
        for id in sorted(route_tables):
            if str(id) in res_ids:
                message = "Table %s(%s) conflicts with reserved table %s(%s)" \
                          % (route_tables[id], id,
                             res_names[res_ids.index(str(id))], id)
                raise os_net_config.ConfigurationError(message)
            elif route_tables[id] in res_names:
                message = "Table %s(%s) conflicts with reserved table %s(%s)" \
                          % (route_tables[id], id, route_tables[id],
                             res_ids[res_names.index(route_tables[id])])
                raise os_net_config.ConfigurationError(message)
            else:
                data += "%s\t%s    # os-net-config managed table\n" \
                        % (id, route_tables[id])
        return data

    def apply(self, cleanup=False, activate=True):
        """Apply the network configuration.

        :param cleanup: A boolean which indicates whether any undefined
            (existing but not present in the object model) interface
            should be disabled and deleted.
        :param activate: A boolean which indicates if the config should
            be activated by stopping/starting interfaces
            NOTE: if cleanup is specified we will deactivate interfaces even
            if activate is false
        :returns: a dict of the format: filename/data which contains info
            for each file that was changed (or would be changed if in --noop
            mode).
        Note the noop mode is set via the constructor noop boolean
        """
        logger.info('applying network configs...')
        restart_interfaces = []
        restart_vlans = []
        restart_bridges = []
        restart_linux_bonds = []
        restart_linux_teams = []
        restart_vpp = False
        apply_interfaces = []
        apply_bridges = []
        apply_routes = []
        update_files = {}
        all_file_names = []
        ivs_uplinks = []  # ivs physical uplinks
        ivs_interfaces = []  # ivs internal ports
        nfvswitch_interfaces = []       # nfvswitch physical interfaces
        nfvswitch_internal_ifaces = []  # nfvswitch internal/management ports
        stop_dhclient_interfaces = []
        ovs_needs_restart = False
        vpp_interfaces = self.vpp_interface_data.values()
        vpp_bonds = self.vpp_bond_data.values()
        ipcmd = utils.iproute2_path()

        for interface_name, iface_data in self.interface_data.items():
            route_data = self.route_data.get(interface_name, '')
            route6_data = self.route6_data.get(interface_name, '')
            rule_data = self.rule_data.get(interface_name, '')
            interface_path = self.root_dir + ifcfg_config_path(interface_name)
            route_path = self.root_dir + route_config_path(interface_name)
            route6_path = self.root_dir + route6_config_path(interface_name)
            rule_path = self.root_dir + route_rule_config_path(interface_name)
            all_file_names.append(interface_path)
            all_file_names.append(route_path)
            all_file_names.append(route6_path)
            if "IVS_BRIDGE" in iface_data:
                ivs_uplinks.append(interface_name)
            if "NFVSWITCH_BRIDGE" in iface_data:
                nfvswitch_interfaces.append(interface_name)
            if utils.diff(interface_path, iface_data):
                if self.ifcfg_requires_restart(interface_path, iface_data):
                    restart_interfaces.append(interface_name)
                    # Openvswitch needs to be restarted when OVSDPDKPort or
                    # OVSDPDKBond is added
                    if "OVSDPDK" in iface_data:
                        ovs_needs_restart = True
                else:
                    apply_interfaces.append(
                        (interface_name, interface_path, iface_data))
                update_files[interface_path] = iface_data
                if "BOOTPROTO=dhcp" not in iface_data:
                    stop_dhclient_interfaces.append(interface_name)

            else:
                logger.info('No changes required for interface: %s' %
                            interface_name)
            if utils.diff(route_path, route_data):
                update_files[route_path] = route_data
                if interface_name not in restart_interfaces:
                    apply_routes.append((interface_name, route_data))
            if utils.diff(route6_path, route6_data):
                update_files[route6_path] = route6_data
                if interface_name not in restart_interfaces:
                    apply_routes.append((interface_name, route6_data))
            if utils.diff(rule_path, rule_data):
                update_files[rule_path] = rule_data

        for interface_name, iface_data in self.ivsinterface_data.items():
            route_data = self.route_data.get(interface_name, '')
            route6_data = self.route6_data.get(interface_name, '')
            rule_data = self.rule_data.get(interface_name, '')
            interface_path = self.root_dir + ifcfg_config_path(interface_name)
            route_path = self.root_dir + route_config_path(interface_name)
            route6_path = self.root_dir + route6_config_path(interface_name)
            rule_path = self.root_dir + route_rule_config_path(interface_name)
            all_file_names.append(interface_path)
            all_file_names.append(route_path)
            all_file_names.append(route6_path)
            all_file_names.append(rule_path)
            ivs_interfaces.append(interface_name)
            if utils.diff(interface_path, iface_data):
                if self.ifcfg_requires_restart(interface_path, iface_data):
                    restart_interfaces.append(interface_name)
                else:
                    apply_interfaces.append(
                        (interface_name, interface_path, iface_data))
                update_files[interface_path] = iface_data
            else:
                logger.info('No changes required for ivs interface: %s' %
                            interface_name)
            if utils.diff(route_path, route_data):
                update_files[route_path] = route_data
                if interface_name not in restart_interfaces:
                    apply_routes.append((interface_name, route_data))
            if utils.diff(route6_path, route6_data):
                update_files[route6_path] = route6_data
                if interface_name not in restart_interfaces:
                    apply_routes.append((interface_name, route6_data))
            if utils.diff(rule_path, rule_data):
                update_files[rule_path] = rule_data

        for iface_name, iface_data in self.nfvswitch_intiface_data.items():
            route_data = self.route_data.get(iface_name, '')
            route6_data = self.route6_data.get(iface_name, '')
            rule_data = self.rule_data.get(iface_name, '')
            iface_path = self.root_dir + ifcfg_config_path(iface_name)
            route_path = self.root_dir + route_config_path(iface_name)
            route6_path = self.root_dir + route6_config_path(iface_name)
            rule_path = self.root_dir + route_rule_config_path(iface_name)
            all_file_names.append(iface_path)
            all_file_names.append(route_path)
            all_file_names.append(route6_path)
            all_file_names.append(rule_path)
            nfvswitch_internal_ifaces.append(iface_name)
            if utils.diff(iface_path, iface_data):
                if self.ifcfg_requires_restart(iface_path, iface_data):
                    restart_interfaces.append(iface_name)
                else:
                    apply_interfaces.append(
                        (iface_name, iface_path, iface_data))
                update_files[iface_path] = iface_data
            else:
                logger.info('No changes required for nfvswitch interface: %s' %
                            iface_name)
            if utils.diff(route_path, route_data):
                update_files[route_path] = route_data
                if iface_name not in restart_interfaces:
                    apply_routes.append((iface_name, route_data))
            if utils.diff(route6_path, route6_data):
                update_files[route6_path] = route6_data
                if iface_name not in restart_interfaces:
                    apply_routes.append((iface_name, route6_data))
            if utils.diff(rule_path, rule_data):
                update_files[rule_path] = rule_data

        for bridge_name, bridge_data in self.bridge_data.items():
            route_data = self.route_data.get(bridge_name, '')
            route6_data = self.route6_data.get(bridge_name, '')
            rule_data = self.rule_data.get(bridge_name, '')
            bridge_path = self.root_dir + bridge_config_path(bridge_name)
            br_route_path = self.root_dir + route_config_path(bridge_name)
            br_route6_path = self.root_dir + route6_config_path(bridge_name)
            br_rule_path = self.root_dir + route_rule_config_path(bridge_name)
            all_file_names.append(bridge_path)
            all_file_names.append(br_route_path)
            all_file_names.append(br_route6_path)
            all_file_names.append(br_rule_path)
            if utils.diff(bridge_path, bridge_data):
                if self.ifcfg_requires_restart(bridge_path, bridge_data):
                    restart_bridges.append(bridge_name)
                    # Avoid duplicate interface being added to the restart list
                    children = self.child_members(bridge_name)
                    for child in children:
                        if child not in restart_interfaces:
                            restart_interfaces.append(child)
                else:
                    apply_bridges.append((bridge_name, bridge_path,
                                          bridge_data))
                update_files[bridge_path] = bridge_data
            else:
                logger.info('No changes required for bridge: %s' % bridge_name)
            if utils.diff(br_route_path, route_data):
                update_files[br_route_path] = route_data
                if bridge_name not in restart_interfaces:
                    apply_routes.append((bridge_name, route_data))
            if utils.diff(br_route6_path, route6_data):
                update_files[br_route6_path] = route6_data
                if bridge_name not in restart_interfaces:
                    apply_routes.append((bridge_name, route6_data))
            if utils.diff(br_rule_path, rule_data):
                update_files[br_rule_path] = rule_data

        for bridge_name, bridge_data in self.linuxbridge_data.items():
            route_data = self.route_data.get(bridge_name, '')
            route6_data = self.route6_data.get(bridge_name, '')
            rule_data = self.rule_data.get(bridge_name, '')
            bridge_path = self.root_dir + bridge_config_path(bridge_name)
            br_route_path = self.root_dir + route_config_path(bridge_name)
            br_route6_path = self.root_dir + route6_config_path(bridge_name)
            br_rule_path = self.root_dir + route_rule_config_path(bridge_name)
            all_file_names.append(bridge_path)
            all_file_names.append(br_route_path)
            all_file_names.append(br_route6_path)
            all_file_names.append(br_rule_path)
            if utils.diff(bridge_path, bridge_data):
                if self.ifcfg_requires_restart(bridge_path, bridge_data):
                    restart_bridges.append(bridge_name)
                    # Avoid duplicate interface being added to the restart list
                    children = self.child_members(bridge_name)
                    for child in children:
                        if child not in restart_interfaces:
                            restart_interfaces.append(child)
                else:
                    apply_bridges.append((bridge_name, bridge_path,
                                          bridge_data))
                update_files[bridge_path] = bridge_data
            else:
                logger.info('No changes required for bridge: %s' % bridge_name)
            if utils.diff(br_route_path, route_data):
                update_files[br_route_path] = route_data
                if bridge_name not in restart_bridges:
                    apply_routes.append((bridge_name, route_data))
            if utils.diff(route6_path, route6_data):
                update_files[route6_path] = route6_data
                if bridge_name not in restart_bridges:
                    apply_routes.append((bridge_name, route6_data))
            if utils.diff(br_rule_path, rule_data):
                update_files[br_rule_path] = rule_data

        for team_name, team_data in self.linuxteam_data.items():
            route_data = self.route_data.get(team_name, '')
            route6_data = self.route6_data.get(team_name, '')
            rule_data = self.rule_data.get(team_name, '')
            team_path = self.root_dir + bridge_config_path(team_name)
            team_route_path = self.root_dir + route_config_path(team_name)
            team_route6_path = self.root_dir + route6_config_path(team_name)
            team_rule_path = self.root_dir + route_rule_config_path(team_name)
            all_file_names.append(team_path)
            all_file_names.append(team_route_path)
            all_file_names.append(team_route6_path)
            all_file_names.append(team_rule_path)
            if utils.diff(team_path, team_data):
                if self.ifcfg_requires_restart(team_path, team_data):
                    restart_linux_teams.append(team_name)
                    # Avoid duplicate interface being added to the restart list
                    children = self.child_members(team_name)
                    for child in children:
                        if child not in restart_interfaces:
                            restart_interfaces.append(child)
                else:
                    apply_interfaces.append(
                        (team_name, team_path, team_data))
                update_files[team_path] = team_data
            else:
                logger.info('No changes required for linux team: %s' %
                            team_name)
            if utils.diff(team_route_path, route_data):
                update_files[team_route_path] = route_data
                if team_name not in restart_linux_teams:
                    apply_routes.append((team_name, route_data))
            if utils.diff(team_route6_path, route6_data):
                update_files[team_route6_path] = route6_data
                if team_name not in restart_linux_teams:
                    apply_routes.append((team_name, route6_data))
            if utils.diff(team_rule_path, rule_data):
                update_files[team_rule_path] = rule_data

        for bond_name, bond_data in self.linuxbond_data.items():
            route_data = self.route_data.get(bond_name, '')
            route6_data = self.route6_data.get(bond_name, '')
            rule_data = self.rule_data.get(bond_name, '')
            bond_path = self.root_dir + bridge_config_path(bond_name)
            bond_route_path = self.root_dir + route_config_path(bond_name)
            bond_route6_path = self.root_dir + route6_config_path(bond_name)
            bond_rule_path = self.root_dir + route_rule_config_path(bond_name)
            all_file_names.append(bond_path)
            all_file_names.append(bond_route_path)
            all_file_names.append(bond_route6_path)
            all_file_names.append(bond_rule_path)
            if utils.diff(bond_path, bond_data):
                if self.ifcfg_requires_restart(bond_path, bond_data):
                    restart_linux_bonds.append(bond_name)
                    # Avoid duplicate interface being added to the restart list
                    children = self.child_members(bond_name)
                    for child in children:
                        if child not in restart_interfaces:
                            restart_interfaces.append(child)
                else:
                    apply_interfaces.append(
                        (bond_name, bond_path, bond_data))
                update_files[bond_path] = bond_data
            else:
                logger.info('No changes required for linux bond: %s' %
                            bond_name)
            if utils.diff(bond_route_path, route_data):
                update_files[bond_route_path] = route_data
                if bond_name not in restart_linux_bonds:
                    apply_routes.append((bond_name, route_data))
            if utils.diff(bond_route6_path, route6_data):
                update_files[bond_route6_path] = route6_data
                if bond_name not in restart_linux_bonds:
                    apply_routes.append((bond_name, route6_data))
            if utils.diff(bond_rule_path, rule_data):
                update_files[bond_rule_path] = rule_data

        # Infiniband interfaces are handled similarly to Ethernet interfaces
        for interface_name, iface_data in self.ib_interface_data.items():
            route_data = self.route_data.get(interface_name, '')
            route6_data = self.route6_data.get(interface_name, '')
            rule_data = self.rule_data.get(interface_name, '')
            interface_path = self.root_dir + ifcfg_config_path(interface_name)
            route_path = self.root_dir + route_config_path(interface_name)
            route6_path = self.root_dir + route6_config_path(interface_name)
            rule_path = self.root_dir + route_rule_config_path(interface_name)
            all_file_names.append(interface_path)
            all_file_names.append(route_path)
            all_file_names.append(route6_path)
            all_file_names.append(rule_path)
            # TODO(dsneddon) determine if InfiniBand can be used with IVS
            if "IVS_BRIDGE" in iface_data:
                ivs_uplinks.append(interface_name)
            if utils.diff(interface_path, iface_data):
                if self.ifcfg_requires_restart(interface_path, iface_data):
                    restart_interfaces.append(interface_name)
                else:
                    apply_interfaces.append(
                        (interface_name, interface_path, iface_data))
                update_files[interface_path] = iface_data
            else:
                logger.info('No changes required for InfiniBand iface: %s' %
                            interface_name)
            if utils.diff(route_path, route_data):
                update_files[route_path] = route_data
                if interface_name not in restart_interfaces:
                    apply_routes.append((interface_name, route_data))
            if utils.diff(route6_path, route6_data):
                update_files[route6_path] = route6_data
                if interface_name not in restart_interfaces:
                    apply_routes.append((interface_name, route6_data))
            if utils.diff(rule_path, rule_data):
                update_files[rule_path] = rule_data

        # NOTE(hjensas): Process the VLAN's last so that we know if the vlan's
        # parent interface is being restarted.
        for vlan_name, vlan_data in self.vlan_data.items():
            route_data = self.route_data.get(vlan_name, '')
            route6_data = self.route6_data.get(vlan_name, '')
            rule_data = self.rule_data.get(vlan_name, '')
            vlan_path = self.root_dir + ifcfg_config_path(vlan_name)
            vlan_route_path = self.root_dir + route_config_path(vlan_name)
            vlan_route6_path = self.root_dir + route6_config_path(vlan_name)
            vlan_rule_path = self.root_dir + route_rule_config_path(vlan_name)
            all_file_names.append(vlan_path)
            all_file_names.append(vlan_route_path)
            all_file_names.append(vlan_route6_path)
            all_file_names.append(vlan_rule_path)
            restarts_concatenated = itertools.chain(restart_interfaces,
                                                    restart_bridges,
                                                    restart_linux_bonds,
                                                    restart_linux_teams)
            if (self.parse_ifcfg(vlan_data).get('PHYSDEV') in
                    restarts_concatenated):
                if vlan_name not in restart_vlans:
                    restart_vlans.append(vlan_name)
                update_files[vlan_path] = vlan_data
            elif utils.diff(vlan_path, vlan_data):
                if self.ifcfg_requires_restart(vlan_path, vlan_data):
                    restart_vlans.append(vlan_name)
                else:
                    apply_interfaces.append(
                        (vlan_name, vlan_path, vlan_data))
                update_files[vlan_path] = vlan_data
            else:
                logger.info('No changes required for vlan interface: %s' %
                            vlan_name)
            if utils.diff(vlan_route_path, route_data):
                update_files[vlan_route_path] = route_data
                if vlan_name not in restart_vlans:
                    apply_routes.append((vlan_name, route_data))
            if utils.diff(vlan_route6_path, route6_data):
                update_files[vlan_route6_path] = route6_data
                if vlan_name not in restart_vlans:
                    apply_routes.append((vlan_name, route6_data))
            if utils.diff(vlan_rule_path, rule_data):
                update_files[vlan_rule_path] = rule_data

        if self.vpp_interface_data or self.vpp_bond_data:
            vpp_path = self.root_dir + vpp_config_path()
            vpp_config = utils.generate_vpp_config(vpp_path, vpp_interfaces,
                                                   vpp_bonds)
            if utils.diff(vpp_path, vpp_config):
                restart_vpp = True
                update_files[vpp_path] = vpp_config
            else:
                logger.info('No changes required for VPP')

        if cleanup:
            for ifcfg_file in glob.iglob(cleanup_pattern()):
                if ifcfg_file not in all_file_names:
                    interface_name = ifcfg_file[len(cleanup_pattern()) - 1:]
                    if interface_name != 'lo':
                        logger.info('cleaning up interface: %s'
                                    % interface_name)
                        self.ifdown(interface_name)
                        self.remove_config(ifcfg_file)

        if activate:
            for interface in apply_interfaces:
                logger.debug('Running ip commands on interface: %s' %
                             interface[0])
                commands = self.iproute2_apply_commands(interface[0],
                                                        interface[1],
                                                        interface[2])
                for command in commands:
                    try:
                        args = command.split()
                        self.execute('Running ip %s' % command, ipcmd, *args)
                    except Exception as e:
                        logger.warning("Error in 'ip %s', restarting %s:\n%s" %
                                       (command, interface[0], str(e)))
                        restart_interfaces.append(interface[0])
                        restart_interfaces.extend(
                            self.child_members(interface[0]))
                        break

            for bridge in apply_bridges:
                logger.debug('Running ip commands on bridge: %s' %
                             bridge[0])
                commands = self.iproute2_apply_commands(bridge[0],
                                                        bridge[1],
                                                        bridge[2])
                for command in commands:
                    try:
                        args = command.split()
                        self.execute('Running ip %s' % command, ipcmd, *args)
                    except Exception as e:
                        logger.warning("Error in 'ip %s', restarting %s:\n%s" %
                                       (command, bridge[0], str(e)))
                        restart_bridges.append(bridge[0])
                        restart_interfaces.extend(
                            self.child_members(bridge[0]))
                        break

            for interface in apply_routes:
                logger.debug('Applying routes for interface %s' % interface[0])
                filename = self.root_dir + route_config_path(interface[0])
                commands = self.iproute2_route_commands(filename, interface[1])
                for command in commands:
                    args = command.split()
                    try:
                        if len(args) > 0:
                            self.execute('Running ip %s' % command, ipcmd,
                                         *args)
                    except Exception as e:
                        logger.warning("Error in 'ip %s', restarting %s:\n%s" %
                                       (command, interface[0], str(e)))
                        restart_interfaces.append(interface[0])
                        restart_interfaces.extend(
                            self.child_members(interface[0]))
                        break

            for vlan in restart_vlans:
                self.ifdown(vlan)

            for interface in restart_interfaces:
                self.ifdown(interface)

            for linux_bond in restart_linux_bonds:
                self.ifdown(linux_bond)

            for linux_team in restart_linux_teams:
                self.ifdown(linux_team)

            for bridge in restart_bridges:
                self.ifdown(bridge, iftype='bridge')

            for vpp_interface in vpp_interfaces:
                self.ifdown(vpp_interface.name)

            for oldname, newname in self.renamed_interfaces.items():
                self.ifrename(oldname, newname)

            # DPDK initialization is done before running os-net-config, to make
            # the DPDK ports available when enabled. DPDK Hotplug support is
            # supported only in OvS 2.7 version. Until then, OvS needs to be
            # restarted after adding a DPDK port. This change will be removed
            # on migration to OvS 2.7 where DPDK Hotplug support is available.
            if ovs_needs_restart:
                msg = "Restart openvswitch"
                self.execute(msg, '/usr/bin/systemctl',
                             'restart', 'openvswitch')

        for location, data in update_files.items():
            self.write_config(location, data)

        if self.route_table_data:
            location = route_table_config_path()
            data = self.generate_route_table_config(self.route_table_data)
            self.write_config(location, data)

        if ivs_uplinks or ivs_interfaces:
            location = ivs_config_path()
            data = self.generate_ivs_config(ivs_uplinks, ivs_interfaces)
            if (utils.diff(location, data)):
                self.write_config(location, data)
                msg = "Restart ivs"
                self.execute(msg, '/usr/bin/systemctl',
                             'restart', 'ivs')

        if nfvswitch_interfaces or nfvswitch_internal_ifaces:
            location = nfvswitch_config_path()
            data = self.generate_nfvswitch_config(nfvswitch_interfaces,
                                                  nfvswitch_internal_ifaces)
            if (utils.diff(location, data)):
                self.write_config(location, data)
                msg = "Restart nfvswitch"
                self.execute(msg, '/usr/bin/systemctl',
                             'restart', 'nfvswitch')

        if activate:
            for linux_team in restart_linux_teams:
                self.ifup(linux_team)

            for bridge in restart_bridges:
                self.ifup(bridge, iftype='bridge')

            # If dhclient is running and dhcp not set, stop dhclient
            for interface in stop_dhclient_interfaces:
                logger.debug("Calling stop_dhclient_interfaces() for %s" %
                             interface)
                if not self.noop:
                    stop_dhclient_process(interface)

            for interface in restart_interfaces:
                self.ifup(interface)

            for linux_bond in restart_linux_bonds:
                self.ifup(linux_bond)

            for bond in self.bond_primary_ifaces:
                self.ovs_appctl('bond/set-active-slave', bond,
                                self.bond_primary_ifaces[bond])

            if ivs_uplinks or ivs_interfaces:
                logger.info("Attach to ivs with "
                            "uplinks: %s, "
                            "interfaces: %s" %
                            (ivs_uplinks, ivs_interfaces))
                for ivs_uplink in ivs_uplinks:
                    self.ifup(ivs_uplink)
                for ivs_interface in ivs_interfaces:
                    self.ifup(ivs_interface)

            if nfvswitch_interfaces or nfvswitch_internal_ifaces:
                logger.info("Attach to nfvswitch with "
                            "interfaces: %s, "
                            "internal interfaces: %s" %
                            (nfvswitch_interfaces, nfvswitch_internal_ifaces))
                for nfvswitch_interface in nfvswitch_interfaces:
                    self.ifup(nfvswitch_interface)
                for nfvswitch_internal in nfvswitch_internal_ifaces:
                    self.ifup(nfvswitch_internal)

            for vlan in restart_vlans:
                self.ifup(vlan)

            if not self.noop:
                if restart_vpp:
                    logger.info('Restarting VPP')
                    utils.restart_vpp(vpp_interfaces)

                if self.vpp_interface_data:
                    logger.info('Updating VPP mapping')
                    utils.update_vpp_mapping(vpp_interfaces, vpp_bonds)

            if self.errors:
                message = 'Failure(s) occurred when applying configuration'
                logger.error(message)
                for e in self.errors:
                    logger.error('stdout: %s, stderr: %s', e.stdout, e.stderr)
                raise os_net_config.ConfigurationError(message)

        return update_files
