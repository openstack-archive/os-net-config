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

import pbr.version


from os_net_config import objects

__version__ = pbr.version.VersionInfo(
    'os_net_config').version_string()


class NotImplemented(Exception):
    pass


class NetConfig(object):
    """Configure network interfaces using the ifcfg format."""

    def add_object(self, obj):
        if isinstance(obj, objects.Interface):
            self.add_interface(obj)
        elif isinstance(obj, objects.Vlan):
            self.add_vlan(obj)
        elif isinstance(obj, objects.OvsBridge):
            self.add_bridge(obj)
            for member in obj.members:
                self.add_object(member)
        elif isinstance(obj, objects.OvsBond):
            self.add_bond(obj)
            for member in obj.members:
                self.add_object(member)

    def add_interface(self, interface):
        raise NotImplemented("add_interface is not implemented.")

    def add_vlan(self, vlan):
        raise NotImplemented("add_vlan is not implemented.")

    def add_bridge(self, bridge):
        raise NotImplemented("add_bridge is not implemented.")

    def add_bond(self, bond):
        raise NotImplemented("add_bond is not implemented.")

    def apply(self, noop=False):
        """Apply the network configuration.

        :param noop: A boolean which indicates whether this is a no-op.
        :returns: a dict of the format: filename/data which contains info
            for each file that was changed (or would be changed if in --noop
            mode).
        """
        raise NotImplemented("apply is not implemented.")
