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

import logging
import os

from oslo_concurrency import processutils

from os_net_config import objects
from os_net_config import utils


logger = logging.getLogger(__name__)


class NotImplemented(Exception):
    pass


class NetConfig(object):
    """Common network config methods class."""

    def __init__(self, noop=False, root_dir=''):
        self.noop = noop
        self.log_prefix = "NOOP: " if noop else ""
        self.root_dir = root_dir

    def add_object(self, obj):
        """Convenience method to add any type of object to the network config.

           See objects.py.

        :param obj: The object to add.
        """
        if isinstance(obj, objects.Interface):
            self.add_interface(obj)
        elif isinstance(obj, objects.Vlan):
            self.add_vlan(obj)
        elif isinstance(obj, objects.IvsInterface):
            self.add_ivs_interface(obj)
        elif isinstance(obj, objects.NfvswitchInternal):
            self.add_nfvswitch_internal(obj)
        elif isinstance(obj, objects.OvsBridge):
            self.add_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.LinuxBridge):
            self.add_linux_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.IvsBridge):
            self.add_ivs_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.NfvswitchBridge):
            self.add_nfvswitch_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.OvsBond):
            self.add_bond(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.LinuxBond):
            self.add_linux_bond(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.LinuxTeam):
            self.add_linux_team(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.OvsTunnel):
            self.add_ovs_tunnel(obj)
        elif isinstance(obj, objects.OvsPatchPort):
            self.add_ovs_patch_port(obj)
        elif isinstance(obj, objects.IbInterface):
            self.add_ib_interface(obj)

    def add_interface(self, interface):
        """Add an Interface object to the net config object.

        :param interface: The Interface object to add.
        """
        raise NotImplemented("add_interface is not implemented.")

    def add_vlan(self, vlan):
        """Add a Vlan object to the net config object.

        :param vlan: The vlan object to add.
        """
        raise NotImplemented("add_vlan is not implemented.")

    def add_bridge(self, bridge):
        """Add an OvsBridge object to the net config object.

        :param bridge: The OvsBridge object to add.
        """
        raise NotImplemented("add_bridge is not implemented.")

    def add_linux_bridge(self, bridge):
        """Add a LinuxBridge object to the net config object.

        :param bridge: The LinuxBridge object to add.
        """
        raise NotImplemented("add_linux_bridge is not implemented.")

    def add_ivs_bridge(self, bridge):
        """Add a IvsBridge object to the net config object.

        :param bridge: The IvsBridge object to add.
        """
        raise NotImplemented("add_ivs_bridge is not implemented.")

    def add_nfvswitch_bridge(self, bridge):
        """Add a NfvswitchBridge object to the net config object.

        :param bridge: The NfvswitchBridge object to add.
        """
        raise NotImplemented("add_nfvswitch_bridge is not implemented.")

    def add_bond(self, bond):
        """Add an OvsBond object to the net config object.

        :param bond: The OvsBond object to add.
        """
        raise NotImplemented("add_bond is not implemented.")

    def add_linux_bond(self, bond):
        """Add a LinuxBond object to the net config object.

        :param bond: The LinuxBond object to add.
        """
        raise NotImplemented("add_linux_bond is not implemented.")

    def add_linux_team(self, team):
        """Add a LinuxTeam object to the net config object.

        :param team: The LinuxTeam object to add.
        """
        raise NotImplemented("add_linux_team is not implemented.")

    def add_ovs_tunnel(self, tunnel):
        """Add a OvsTunnel object to the net config object.

        :param tunnel: The OvsTunnel object to add.
        """
        raise NotImplemented("add_ovs_tunnel is not implemented.")

    def add_ovs_patch_port(self, ovs_patch_port):
        """Add a OvsPatchPort object to the net config object.

        :param ovs_patch_port: The OvsPatchPort object to add.
        """
        raise NotImplemented("add_ovs_patch_port is not implemented.")

    def add_ib_interface(self, ib_interface):
        """Add an InfiniBand Interface object to the net config object.

        :param interface: The InfiniBand Interface object to add.
        """
        raise NotImplemented("add_ib_interface is not implemented.")

    def apply(self, cleanup=False):
        """Apply the network configuration.

        :param cleanup: A boolean which indicates whether any undefined
            (existing but not present in the object model) interfaces
            should be disabled and deleted.
        :returns: a dict of the format: filename/data which contains info
            for each file that was changed (or would be changed if in --noop
            mode).
        """
        raise NotImplemented("apply is not implemented.")

    def execute(self, msg, cmd, *args, **kwargs):
        """Print a message and run a command.

        Print a message and run a command with processutils
        in noop mode, this just prints a message.
        """
        logger.info('%s%s' % (self.log_prefix, msg))
        if not self.noop:
            processutils.execute(cmd, *args, **kwargs)

    def write_config(self, filename, data, msg=None):
        msg = msg or "Writing config %s" % filename
        logger.info('%s%s' % (self.log_prefix, msg))
        if not self.noop:
            utils.write_config(filename, data)

    def remove_config(self, filename, msg=None):
        msg = msg or "Removing config %s" % filename
        logger.info('%s%s' % (self.log_prefix, msg))
        if not self.noop:
            os.remove(filename)

    def ifdown(self, interface, iftype='interface'):
        msg = 'running ifdown on %s: %s' % (iftype, interface)
        self.execute(msg, '/sbin/ifdown', interface, check_exit_code=False)

    def ifup(self, interface, iftype='interface'):
        msg = 'running ifup on %s: %s' % (iftype, interface)
        self.execute(msg, '/sbin/ifup', interface)

    def ifrename(self, oldname, newname):
        msg = 'renaming %s to %s: ' % (oldname, newname)
        # ifdown isn't enough when renaming, we need the link down
        for name in (oldname, newname):
            if utils._is_active_nic(name):
                self.execute(msg, '/sbin/ip',
                             'link', 'set', 'dev', name, 'down')
                self.execute(msg, '/sbin/ip',
                             'link', 'set', 'dev', name, 'link', 'down')
        self.execute(msg, '/sbin/ip',
                     'link', 'set', 'dev', oldname, 'name', newname)
        self.execute(msg, '/sbin/ip',
                     'link', 'set', 'dev', newname, 'up')

    def ovs_appctl(self, action, *parameters):
        msg = 'Running ovs-appctl %s %s' % (action, parameters)
        self.execute(msg, '/bin/ovs-appctl', action, *parameters)
