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

#
# The sriov_config.py module does the SR-IOV PF configuration.
# It'll be invoked by the sriov_config systemd service for the persistence of
# the SR-IOV configuration across reboots. And os-net-config:utils also invokes
# it for the first time configuration.
# An entry point os-net-config-sriov is added for invocation of this module.

import logging
import os
import sys
import time
import yaml

logger = logging.getLogger(__name__)

# File to contain the list of SR-IOV nics and the numvfs
# Format of the file shall be
#
# - name: eth1
#   numvfs: 5
_SRIOV_PF_CONFIG_FILE = '/var/lib/os-net-config/sriov_pf.yaml'
_SYS_CLASS_NET = '/sys/class/net'
# maximum retries for checking the creation of VFs
_MAX_SRIOV_VFS_CONFIG_RETRIES = 60


class SRIOVNumvfsException(ValueError):
    pass


def get_file_data(filename):
    if not os.path.exists(filename):
        return ''
    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError:
        logger.error("Error reading file: %s" % filename)
        return ''


def _get_sriov_pf_map():
    contents = get_file_data(_SRIOV_PF_CONFIG_FILE)
    sriov_pf_map = yaml.load(contents) if contents else []
    return sriov_pf_map


def _configure_sriov_pf():
    sriov_pf_map = _get_sriov_pf_map()
    for item in sriov_pf_map:
        try:
            sriov_numvfs_path = ("/sys/class/net/%s/device/sriov_numvfs"
                                 % item['name'])
            with open(sriov_numvfs_path, 'w') as f:
                f.write("%d" % item['numvfs'])
        except IOError as exc:
            msg = ("Unable to configure pf: %s with numvfs: %d\n%s"
                   % (item['name'], item['numvfs'], exc))
            raise SRIOVNumvfsException(msg)


def _wait_for_vf_creation():
    sriov_map = _get_sriov_pf_map()
    for item in sriov_map:
        count = 0
        while count < _MAX_SRIOV_VFS_CONFIG_RETRIES:
            pf = item['name']
            numvfs = item['numvfs']
            vf_path = os.path.join(_SYS_CLASS_NET, pf,
                                   "device/virtfn%d/net" % (numvfs - 1))
            if os.path.isdir(vf_path):
                vf_nic = os.listdir(vf_path)
                if len(vf_nic) == 1 and pf in vf_nic[0]:
                    logger.info("VFs created for PF: %s" % pf)
                    break
                else:
                    logger.debug("VF device name not present for PF %s" % pf)
            else:
                logger.info("Attempt#%d, VFs for PF %s is not yet created"
                            % (count + 1, pf))
            time.sleep(1)
            count += 1


def main(argv=None):
    # Configure the PF's
    _configure_sriov_pf()
    # Wait for the VF's to get created
    _wait_for_vf_creation()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
