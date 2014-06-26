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

import pbr.version


__version__ = pbr.version.VersionInfo(
    'os_net_config').version_string()


class NotImplemented(Exception):
    pass


class NetConfig(object):
    """Configure network interfaces using the ifcfg format."""

    def addInterface(self, interface):
        raise NotImplemented("addInterface is not implemented.")

    def addVlan(self, bridge):
        raise NotImplemented("addVlan is not implemented.")

    def addBridge(self, bridge):
        raise NotImplemented("addBridge is not implemented.")

    def addBond(self, bridge):
        raise NotImplemented("addBond is not implemented.")

    def apply(self):
        raise NotImplemented("apply is not implemented.")
