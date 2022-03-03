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
import sys
import yaml

# File to contain the DPDK mapped nics, as nic name will not be available after
# binding driver, which is required for correct nic numbering.
# Format of the file (list mapped nic's details):
#   -
#     name: eth1
#     pci_address: 0000:02:00.0
#     mac_address: 01:02:03:04:05:06
#     driver: vfio-pci
DPDK_MAPPING_FILE = '/var/lib/os-net-config/dpdk_mapping.yaml'

# File to contain the list of SR-IOV PF, VF and their configurations
# Format of the file shall be
# - device_type: pf
#   name: <pf name>
#   numvfs: <number of VFs>
#   promisc: "on"/"off"
# - device_type: vf
#   device:
#      name: <pf name>
#      vfid: <VF id>
#   name: <vf name>
#   vlan_id: <vlan>
#   qos: <qos>
#   spoofcheck: "on"/"off"
#   trust: "on"/"off"
#   state: "auto"/"enable"/"disable"
#   macaddr: <mac address>
#   promisc: "on"/"off"
SRIOV_CONFIG_FILE = '/var/lib/os-net-config/sriov_config.yaml'


_SYS_BUS_PCI_DEV = '/sys/bus/pci/devices'
SYS_CLASS_NET = '/sys/class/net'
_LOG_FILE = '/var/log/os-net-config.log'
MLNX_VENDOR_ID = "0x15b3"

logger = logging.getLogger(__name__)


class OvsDpdkBindException(ValueError):
    pass


def configure_logger(log_file=False, verbose=False, debug=False):
    LOG_FORMAT = ('%(asctime)s.%(msecs)03d %(levelname)s '
                  '%(name)s.%(funcName)s %(message)s')
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    logger = logging.getLogger("os_net_config")
    logger.handlers.clear()
    logger_level(logger, verbose, debug)
    logger.propagate = True
    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=10485760, backupCount=7
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def logger_level(logger, verbose=False, debug=False):
    log_level = logging.WARN
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    logger.setLevel(log_level)


def get_dev_path(ifname, path=None):
    if not path:
        path = ""
    elif path.startswith("_"):
        path = path[1:]
    else:
        path = f"device/{path}"
    return os.path.join(SYS_CLASS_NET, ifname, path)


def get_pci_dev_path(pci_address, path=None):
    if not path:
        path = ""
    elif path.startswith("_"):
        path = path[1:]
    return os.path.join(_SYS_BUS_PCI_DEV, pci_address, path)


def get_vendor_id(ifname):
    try:
        with open(get_dev_path(ifname, "vendor"), 'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_device_id(ifname):
    try:
        with open(get_dev_path(ifname, 'device'), 'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_file_data(filename):
    if not os.path.exists(filename):
        return ''
    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError:
        logger.error(f"Error reading file: {filename}")
        return ''


def get_sriov_map(pf_name=None):
    contents = get_file_data(SRIOV_CONFIG_FILE)
    sriov_map = yaml.safe_load(contents) if contents else []
    if len(sriov_map) and pf_name:
        return [pf for pf in sriov_map if pf['name'] == pf_name]
    return sriov_map


def get_dpdk_map():
    contents = get_file_data(DPDK_MAPPING_FILE)
    dpdk_map = yaml.safe_load(contents) if contents else []
    return dpdk_map


def _get_dpdk_mac_address(name):
    contents = get_file_data(DPDK_MAPPING_FILE)
    dpdk_map = yaml.safe_load(contents) if contents else []
    for item in dpdk_map:
        if item['name'] == name:
            return item['mac_address']


def interface_mac(name):
    try:  # If the iface is part of a Linux bond, the real MAC is only here.
        with open(get_dev_path(name, 'bonding_slave/perm_hwaddr'),
                  'r') as f:
            return f.read().rstrip()
    except IOError:
        pass  # Iface is not part of a bond, continue

    try:
        with open(get_dev_path(name, '_address'), 'r') as f:
            return f.read().rstrip()
    except IOError:
        # If the interface is bound to a DPDK driver, get the mac address from
        # the DPDK mapping file as /sys files will be removed after binding.
        dpdk_mac_address = _get_dpdk_mac_address(name)
        if dpdk_mac_address:
            return dpdk_mac_address

        logger.error("Unable to read mac address: %s" % name)
        raise


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


def is_mellanox_interface(ifname):
    vendor_id = get_vendor_id(ifname)
    return vendor_id == MLNX_VENDOR_ID


def is_vf(pci_address):

    # If DPDK drivers are bound on a VF, then the path common.SYS_CLASS_NET
    # wouldn't exist. Instead we look for the path
    # /sys/bus/pci/devices/<PCI addr>/physfn to understand if the device
    # is actually a VF. This path could be used by VFs not bound with
    # DPDK drivers as well

    vf_path_check = _SYS_BUS_PCI_DEV + '/%s/physfn' % pci_address
    is_sriov_vf = os.path.isdir(vf_path_check)
    return is_sriov_vf


def is_vf_by_name(interface_name, check_mapping_file=False):
    vf_path_check = get_dev_path(interface_name, 'physfn')
    is_sriov_vf = os.path.isdir(vf_path_check)
    if not is_sriov_vf and check_mapping_file:
        sriov_map = get_sriov_map()
        for item in sriov_map:
            if (item['name'] == interface_name and
                    item['device_type'] == 'vf'):
                is_sriov_vf = True
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


def list_kmods(mods: list) -> list:
    """Listing Kernel Modules

    Checks in currently loaded modules for a list
    of modules and returns the ones that are not loaded
    """
    try:
        stdout, stderr = processutils.execute('lsmod')
    except processutils.ProcessExecutionError as exc:
        logger.error(f"Failed to get lsmod: {exc}")
        raise
    modules = set([line.split()[0] for line in stdout.strip().split('\n')])
    return list(set(mods) - set(modules))


def load_kmods(mods: list):
    """Loading Kernel Modules

    Loads modules from list that are not already loaded
    """
    needed = list_kmods(mods)
    for mod in needed:
        try:
            stdout, stderr = processutils.execute('modprobe', mod)
        except processutils.ProcessExecutionError as exc:
            logger.error(f"Failed to modprobe {mod}: {exc}")
            raise


def restorecon(path: str):
    """Executes restorecon on a path"""
    logger.info(f"Restoring selinux context on {path}")
    try:
        stdout, stderr = processutils.execute('restorecon', '-R', '-F', '-v',
                                              path)
    except processutils.ProcessExecutionError as exc:
        logger.error(f"Failed to restorecon on {path}: {exc}")
        raise
    logger.debug(f"Restorecon completed: {stdout}")
