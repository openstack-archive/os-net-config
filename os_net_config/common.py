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
# Common functions and variables meant to be shared across various modules
# As opposed to utils, this is meant to be imported from anywhere. We can't
# import anything from os_net_config here.
import logging
import logging.handlers
import os
from oslo_concurrency import processutils

_SYS_BUS_PCI_DEV = '/sys/bus/pci/devices'
MLNX_VENDOR_ID = "0x15b3"

logger = logging.getLogger(__name__)


class OvsDpdkBindException(ValueError):
    pass


def get_pci_dev_path(pci_address, path=None):
    if not path:
        path = ""
    elif path.startswith("_"):
        path = path[1:]
    return os.path.join(_SYS_BUS_PCI_DEV, pci_address, path)


def get_interface_driver_by_pci_address(pci_address):
    try:
        uevent = get_pci_dev_path(pci_address, 'uevent')
        with open(uevent, 'r') as f:
            out = f.read().strip()
            for line in out.split('\n'):
                if 'DRIVER' in line:
                    driver = line.split('=')
                    if len(driver) == 2:
                        return driver[1]
    except IOError:
        return


def is_vf(pci_address):

    # If DPDK drivers are bound on a VF, then the path common.SYS_CLASS_NET
    # wouldn't exist. Instead we look for the path
    # /sys/bus/pci/devices/<PCI addr>/physfn to understand if the device
    # is actually a VF. This path could be used by VFs not bound with
    # DPDK drivers as well

    vf_path_check = _SYS_BUS_PCI_DEV + '/%s/physfn' % pci_address
    is_sriov_vf = os.path.isdir(vf_path_check)
    return is_sriov_vf


def set_driverctl_override(pci_address, driver):
    if driver is None:
        logger.info(f"Driver override is not required for device"
                    "{pci_address}")
        return False
    iface_driver = get_interface_driver_by_pci_address(pci_address)
    if iface_driver == driver:
        logger.info(f"Driver {driver} is already bound to the device"
                    "{pci_address}")
        return False
    try:
        if is_vf(pci_address):
            out, err = processutils.execute('driverctl', '--nosave',
                                            'set-override', pci_address,
                                            driver)
        else:
            out, err = processutils.execute('driverctl', 'set-override',
                                            pci_address, driver)
        if err:
            msg = f"Failed to bind dpdk interface {pci_address} err - {err}"
            raise OvsDpdkBindException(msg)
    except processutils.ProcessExecutionError:
        msg = f"Failed to bind interface {pci_address} with dpdk"
        raise OvsDpdkBindException(msg)
    return err
