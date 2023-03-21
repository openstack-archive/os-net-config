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

from libnmstate import netapplier
from libnmstate import netinfo
from libnmstate.schema import DNS
from libnmstate.schema import Ethernet
from libnmstate.schema import Ethtool
from libnmstate.schema import Interface
from libnmstate.schema import InterfaceIPv4
from libnmstate.schema import InterfaceIPv6
from libnmstate.schema import InterfaceState
from libnmstate.schema import InterfaceType
import logging
import netaddr
import re
import yaml

import os_net_config
from os_net_config import objects

logger = logging.getLogger(__name__)

# Import the raw NetConfig object so we can call its methods
netconfig = os_net_config.NetConfig()


IPV4_DEFAULT_GATEWAY_DESTINATION = "0.0.0.0/0"
IPV6_DEFAULT_GATEWAY_DESTINATION = "::/0"


def _get_type_value(str_val):
    if isinstance(str_val, str):
        if str_val.isdigit():
            return int(str_val)
        if str_val.lower() in ['true', 'yes', 'on']:
            return True
        if str_val.lower() in ['false', 'no', 'off']:
            return False
    return str_val


def is_dict_subset(superset, subset):
    """Check to see if one dict is a subset of another dict."""

    if superset == subset:
        return True
    if superset and subset:
        for key, value in subset.items():
            if key not in superset:
                return False
            if isinstance(value, dict):
                if not is_dict_subset(superset[key], value):
                    return False
            elif isinstance(value, int):
                if value != superset[key]:
                    return False
            elif isinstance(value, str):
                if value != superset[key]:
                    return False
            elif isinstance(value, list):
                try:
                    if not set(value) <= set(superset[key]):
                        return False
                except TypeError:
                    for item in value:
                        if item not in superset[key]:
                            return False
            elif isinstance(value, set):
                if not value <= superset[key]:
                    return False
            else:
                if not value == superset[key]:
                    return False
        return True
    return False


def _add_sub_tree(data, subtree):
    config = data
    if subtree:
        for cfg in subtree:
            if cfg not in config:
                config[cfg] = {}
            config = config[cfg]
    return config


class NmstateNetConfig(os_net_config.NetConfig):
    """Configure network interfaces using NetworkManager via nmstate API."""

    def __init__(self, noop=False, root_dir=''):
        super(NmstateNetConfig, self).__init__(noop, root_dir)
        self.interface_data = {}
        self.dns_data = {'server': [], 'domain': []}
        logger.info('nmstate net config provider created.')

    def __dump_config(self, config, msg="Applying config"):
        cfg_dump = yaml.dump(config, default_flow_style=False,
                             allow_unicode=True, encoding=None)
        logger.debug("----------------------------")
        logger.debug(f"{msg}\n{cfg_dump}")

    def iface_state(self, name=''):
        """Return the current interface state according to nmstate.

        Return the current state of all interfaces, or the named interface.
        :param name: name of the interface to return state, otherwise all.
        :returns: list state of all interfaces when name is not specified, or
                  the state of the specific interface when name is specified
        """
        ifaces = netinfo.show_running_config()[Interface.KEY]
        if name != '':
            for iface in ifaces:
                if iface[Interface.NAME] != name:
                    continue
                self.__dump_config(iface, msg=f"Running config for {name}")
                return iface
        else:
            self.__dump_config(ifaces,
                               msg=f"Running config for all interfaces")
            return ifaces

    def cleanup_all_ifaces(self, exclude_nics=[]):

        exclude_nics.extend(['lo'])
        ifaces = netinfo.show_running_config()[Interface.KEY]

        for iface in ifaces:
            if Interface.NAME in iface and \
               iface[Interface.NAME] not in exclude_nics:
                iface[Interface.STATE] = InterfaceState.DOWN
                state = {Interface.KEY: [iface]}
                self.__dump_config(state,
                                   msg=f"Cleaning up {iface[Interface.NAME]}")
                if not self.noop:
                    netapplier.apply(state, verify_change=True)

    def set_ifaces(self, iface_data, verify=True):
        """Apply the desired state using nmstate.

        :param iface_data: interface config json
        :param verify: boolean that determines if config will be verified
        """
        state = {Interface.KEY: iface_data}
        self.__dump_config(state, msg=f"Applying interface config")
        if not self.noop:
            netapplier.apply(state, verify_change=verify)

    def set_dns(self, verify=True):
        """Apply the desired DNS using nmstate.

        :param dns_data:  config json
        :param verify: boolean that determines if config will be verified
        """

        state = {DNS.KEY: {DNS.CONFIG: {DNS.SERVER: self.dns_data['server'],
                                        DNS.SEARCH: self.dns_data['domain']}}}
        self.__dump_config(state, msg=f"Applying DNS")
        if not self.noop:
            netapplier.apply(state, verify_change=verify)

    def add_ethtool_subtree(self, data, sub_config, command):
        config = _add_sub_tree(data, sub_config['sub-tree'])
        ethtool_map = sub_config['map']

        # skip first 2 entries as they are already validated
        for index in range(2, len(command) - 1, 2):
            value = _get_type_value(command[index + 1])
            if command[index] in ethtool_map.keys():
                config[ethtool_map[command[index]]] = value
            elif (sub_config['sub-options'] == 'copy'):
                config[command[index]] = value
            else:
                msg = f'Unhandled ethtool option {command[index]} for '\
                      f'command {command}.'
                raise os_net_config.ConfigurationError(msg)

    def add_ethtool_config(self, iface_name, data, ethtool_options):

        ethtool_generic_options = {'sub-tree': [Ethernet.CONFIG_SUBTREE],
                                   'sub-options': None,
                                   'map': {
                                   'speed': Ethernet.SPEED,
                                   'autoneg': Ethernet.AUTO_NEGOTIATION,
                                   'duplex': Ethernet.DUPLEX}
                                   }
        ethtool_set_ring = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                         Ethtool.Ring.CONFIG_SUBTREE],
                            'sub-options': None,
                            'map': {
                            'rx': Ethtool.Ring.RX,
                            'tx': Ethtool.Ring.TX,
                            'rx-jumbo': Ethtool.Ring.RX_JUMBO,
                            'rx-mini': Ethtool.Ring.RX_MINI}
                            }
        ethtool_set_pause = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                          Ethtool.Pause.CONFIG_SUBTREE],
                             'sub-options': None,
                             'map': {
                             'autoneg': Ethtool.Pause.AUTO_NEGOTIATION,
                             'tx': Ethtool.Pause.TX,
                             'rx': Ethtool.Pause.RX}
                             }
        coalesce_map = {'adaptive-rx': Ethtool.Coalesce.ADAPTIVE_RX,
                        'adaptive-tx': Ethtool.Coalesce.ADAPTIVE_TX,
                        'rx-usecs': Ethtool.Coalesce.RX_USECS,
                        'rx-frames': Ethtool.Coalesce.RX_FRAMES,
                        'rx-usecs-irq': Ethtool.Coalesce.RX_USECS_IRQ,
                        'rx-frames-irq': Ethtool.Coalesce.RX_FRAMES_IRQ,
                        'tx-usecs': Ethtool.Coalesce.TX_USECS,
                        'tx-frames': Ethtool.Coalesce.TX_FRAMES,
                        'tx-usecs-irq': Ethtool.Coalesce.TX_USECS_IRQ,
                        'tx-frames-irq': Ethtool.Coalesce.TX_FRAMES_IRQ,
                        'stats-block-usecs':
                            Ethtool.Coalesce.STATS_BLOCK_USECS,
                        'pkt-rate-low': Ethtool.Coalesce.PKT_RATE_LOW,
                        'rx-usecs-low': Ethtool.Coalesce.RX_USECS_LOW,
                        'rx-frames-low': Ethtool.Coalesce.RX_FRAMES_LOW,
                        'tx-usecs-low': Ethtool.Coalesce.TX_USECS_LOW,
                        'tx-frames-low': Ethtool.Coalesce.TX_FRAMES_LOW,
                        'pkt-rate-high': Ethtool.Coalesce.PKT_RATE_HIGH,
                        'rx-usecs-high': Ethtool.Coalesce.RX_USECS_HIGH,
                        'rx-frames-high': Ethtool.Coalesce.RX_FRAMES_HIGH,
                        'tx-usecs-high': Ethtool.Coalesce.TX_USECS_HIGH,
                        'tx-frames-high': Ethtool.Coalesce.TX_FRAMES_HIGH,
                        'sample-interval': Ethtool.Coalesce.SAMPLE_INTERVAL}
        ethtool_set_coalesce = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                             Ethtool.Coalesce.CONFIG_SUBTREE],
                                'sub-options': None,
                                'map': coalesce_map
                                }
        ethtool_set_features = {'sub-tree': [Ethtool.CONFIG_SUBTREE,
                                             Ethtool.Feature.CONFIG_SUBTREE],
                                'sub-options': 'copy',
                                'map': {}}
        ethtool_map = {'-G': ethtool_set_ring,
                       '--set-ring': ethtool_set_ring,
                       '-A': ethtool_set_pause,
                       '--pause': ethtool_set_pause,
                       '-C': ethtool_set_coalesce,
                       '--coalesce': ethtool_set_coalesce,
                       '-K': ethtool_set_features,
                       '--features': ethtool_set_features,
                       '--offload': ethtool_set_features,
                       '-s': ethtool_generic_options,
                       '--change': ethtool_generic_options}
        if Ethernet.CONFIG_SUBTREE not in data:
            data[Ethernet.CONFIG_SUBTREE] = {}
        if Ethtool.CONFIG_SUBTREE not in data:
            data[Ethtool.CONFIG_SUBTREE] = {}

        for ethtool_opts in ethtool_options.split(';'):
            ethtool_opts = ethtool_opts.strip()
            if re.match(r'^(-[\S-]+[ ]+[\S]+)([ ]+[\S-]+[ ]+[\S]+)+',
                        ethtool_opts):
                # The regex pattern is strict and hence a minimum of 4 items
                # are present in ethtool_opts.
                command = ethtool_opts.split()
                if len(command) < 4:
                    msg = f"Ethtool options {command} is incomplete"
                    raise os_net_config.ConfigurationError(msg)

                option = command[0]
                accepted_dev_names = ['${DEVICE}', '$DEVICE', iface_name]
                if command[1] not in accepted_dev_names:
                    msg = f'Skipping {ethtool_opts} due to incorrect device '\
                          f'name present for interface {iface_name}'
                    raise os_net_config.ConfigurationError(msg)
                if option in ethtool_map.keys():
                    self.add_ethtool_subtree(data, ethtool_map[option],
                                             command)
                else:
                    msg = f'Unhandled ethtool_opts {ethtool_opts} for device'\
                          f' {iface_name}. Option {option} is not supported.'
                    raise os_net_config.ConfigurationError(msg)
            else:
                command_str = '-s ${DEVICE} ' + ethtool_opts
                command = command_str.split()
                option = command[0]
                self.add_ethtool_subtree(data, ethtool_map[option], command)

    def _add_common(self, base_opt):

        data = {Interface.IPV4: {InterfaceIPv4.ENABLED: False},
                Interface.IPV6: {InterfaceIPv6.ENABLED: False},
                Interface.NAME: base_opt.name}
        if base_opt.use_dhcp:
            data[Interface.IPV4][InterfaceIPv4.ENABLED] = True
            data[Interface.IPV4][InterfaceIPv4.DHCP] = True
            data[Interface.IPV4][InterfaceIPv4.AUTO_DNS] = True
            data[Interface.IPV4][InterfaceIPv4.AUTO_ROUTES] = True
            data[Interface.IPV4][InterfaceIPv4.AUTO_GATEWAY] = True
        else:
            data[Interface.IPV4][InterfaceIPv4.DHCP] = False
            if base_opt.dns_servers:
                data[Interface.IPV4][InterfaceIPv4.AUTO_DNS] = False

        if base_opt.use_dhcpv6:
            data[Interface.IPV6][InterfaceIPv6.ENABLED] = True
            data[Interface.IPV6][InterfaceIPv6.DHCP] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_DNS] = True
            data[Interface.IPV6][InterfaceIPv6.AUTOCONF] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_DNS] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_ROUTES] = True
            data[Interface.IPV6][InterfaceIPv6.AUTO_GATEWAY] = True
        else:
            data[Interface.IPV6][InterfaceIPv6.DHCP] = False
            data[Interface.IPV6][InterfaceIPv6.AUTOCONF] = False
            if base_opt.dns_servers:
                data[Interface.IPV6][InterfaceIPv6.AUTO_DNS] = False

        if not base_opt.defroute:
            data[Interface.IPV4][InterfaceIPv4.AUTO_GATEWAY] = False
            data[Interface.IPV6][InterfaceIPv6.AUTO_GATEWAY] = False

        # NetworkManager always starts on boot, so set enabled state instead
        if base_opt.onboot:
            data[Interface.STATE] = InterfaceState.UP
        else:
            data[Interface.STATE] = InterfaceState.DOWN

        if isinstance(base_opt, objects.Interface):
            if not base_opt.hotplug:
                logger.info('Using NetworkManager, hotplug is always set to'
                            'true. Deprecating it from next release')
        elif isinstance(base_opt, objects.Vlan) or \
            re.match(r'\w+\.\d+$', base_opt.name):
            msg = 'Error: VLAN interfaces not yet supported by impl_nmstate'
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.IvsInterface):
            msg = 'Error: IVS interfaces not yet supported by impl_nmstate'
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.NfvswitchInternal):
            msg = 'Error: NFVSwitch not yet supported by impl_nmstate'
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.IbInterface):
            msg = 'Error: Infiniband not yet supported by impl_nmstate'
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.OvsBond):
            msg = "Error: Ovs Bonds are not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.LinuxBridge):
            msg = "Error: Linux bridges are not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.LinuxTeam):
            msg = "Error: Linux Teams are not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.OvsTunnel):
            msg = "Error: OVS tunnels not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.OvsPatchPort):
            msg = "Error: OVS tunnels not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        elif isinstance(base_opt, objects.OvsDpdkBond):
            msg = "Error: OVS DPDK Bonds not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        else:
            msg = "Error: Unsupported interface by impl_nmstate"
            raise os_net_config.NotImplemented(msg)

        if not base_opt.nm_controlled:
            logger.info('Using NetworkManager, nm_controlled is always true.'
                        'Deprecating it from next release')

        if base_opt.mtu:
            data[Interface.MTU] = base_opt.mtu
        if base_opt.addresses:
            v4_addresses = base_opt.v4_addresses()
            if v4_addresses:
                for address in v4_addresses:
                    netmask_ip = netaddr.IPAddress(address.netmask)
                    ip_netmask = {'ip': address.ip,
                                  'prefix-length': netmask_ip.netmask_bits()}
                    if InterfaceIPv4.ADDRESS not in data[Interface.IPV4]:
                        data[Interface.IPV4][InterfaceIPv4.ADDRESS] = []
                    data[Interface.IPV4][InterfaceIPv4.ENABLED] = True
                    data[Interface.IPV4][InterfaceIPv4.ADDRESS].append(
                        ip_netmask)

            v6_addresses = base_opt.v6_addresses()
            if v6_addresses:
                for v6_address in v6_addresses:
                    netmask_ip = netaddr.IPAddress(v6_address.netmask)
                    v6ip_netmask = {'ip': v6_address.ip,
                                    'prefix-length':
                                        netmask_ip.netmask_bits()}
                    if InterfaceIPv6.ADDRESS not in data[Interface.IPV6]:
                        data[Interface.IPV6][InterfaceIPv6.ADDRESS] = []
                    data[Interface.IPV6][InterfaceIPv6.ENABLED] = True
                    data[Interface.IPV6][InterfaceIPv6.ADDRESS].append(
                        v6ip_netmask)

        if base_opt.dhclient_args:
            msg = "DHCP Client args not supported in impl_nmstate, ignoring"
            logger.error(msg)
        if base_opt.dns_servers:
            self._add_dns_servers(base_opt.dns_servers)
        if base_opt.domain:
            self._add_dns_domain(base_opt.domain)
        if base_opt.routes:
            msg = "Error: Routes not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        if base_opt.rules:
            msg = "Error: IP Rules are not yet supported by impl_nmstate"
            raise os_net_config.NotImplemented(msg)
        return data

    def _add_dns_servers(self, dns_servers):
        for dns_server in dns_servers:
            if dns_server not in self.dns_data['server']:
                logger.debug(f"Adding DNS server {dns_server}")
                self.dns_data['server'].append(dns_server)

    def _add_dns_domain(self, dns_domain):
        if isinstance(dns_domain, str):
            logger.debug(f"Adding DNS domain {dns_domain}")
            self.dns_data['domain'].extend([dns_domain])
            return

        for domain in dns_domain:
            if domain not in self.dns_data['domain']:
                logger.debug(f"Adding DNS domain {domain}")
                self.dns_data['domain'].append(domain)

    def add_interface(self, interface):
        """Add an Interface object to the net config object.

        :param interface: The Interface object to add.
        """
        logger.info('adding interface: %s' % interface.name)
        data = self._add_common(interface)
        if isinstance(interface, objects.Interface):
            data[Interface.TYPE] = InterfaceType.ETHERNET
            data[Ethernet.CONFIG_SUBTREE] = {}

        if interface.ethtool_opts:
            self.add_ethtool_config(interface.name, data,
                                    interface.ethtool_opts)

        if interface.renamed:
            # TODO(Karthik S) Handle renamed interfaces
            pass
        if interface.hwaddr:
            data[Interface.MAC] = interface.hwaddr

        logger.debug('interface data: %s' % data)
        self.interface_data[interface.name] = data

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
        if cleanup:
            logger.info('Cleaning up all network configs...')
            self.cleanup_all_ifaces()

        updated_interfaces = {}
        logger.debug("----------------------------")
        for interface_name, iface_data in self.interface_data.items():
            iface_state = self.iface_state(interface_name)
            if not is_dict_subset(iface_state, iface_data):
                updated_interfaces[interface_name] = iface_data
            else:
                logger.info('No changes required for interface: %s' %
                            interface_name)

        if activate:
            if not self.noop:
                try:
                    self.set_ifaces(list(updated_interfaces.values()))
                except Exception as e:
                    msg = 'Error setting interfaces state: %s' % str(e)
                    raise os_net_config.ConfigurationError(msg)

                try:
                    self.set_dns()
                except Exception as e:
                    msg = 'Error setting dns servers: %s' % str(e)
                    raise os_net_config.ConfigurationError(msg)

            if self.errors:
                message = 'Failure(s) occurred when applying configuration'
                logger.error(message)
                for e in self.errors:
                    logger.error(str(e))
                raise os_net_config.ConfigurationError(message)

        self.interface_data = {}
        return updated_interfaces
