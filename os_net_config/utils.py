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

import glob
import logging
import os
import re
import yaml

from oslo_concurrency import processutils


logger = logging.getLogger(__name__)
_SYS_CLASS_NET = '/sys/class/net'
# File to contain the DPDK mapped nics, as nic name will not be available after
# binding driver, which is required for correct nic numbering.
# Format of the file (list mapped nic's details):
#   -
#     name: eth1
#     pci_address: 0000:02:00.0
#     mac_address: 01:02:03:04:05:06
#     driver: vfio-pci
_DPDK_MAPPING_FILE = '/var/lib/os-net-config/dpdk_mapping.yaml'


class OvsDpdkBindException(ValueError):
    pass


def write_config(filename, data):
    with open(filename, 'w') as f:
        f.write(str(data))


def write_yaml_config(filepath, data):
    ensure_directory_presence(filepath)
    with open(filepath, 'w') as f:
        yaml.dump(data, f, default_flow_style=False)


def ensure_directory_presence(filepath):
    dir_path = os.path.dirname(filepath)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def get_file_data(filename):
    if not os.path.exists(filename):
        return ''

    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError:
        logger.error("Error reading file: %s" % filename)
        return ''


def interface_mac(name):
    try:  # If the iface is part of a Linux bond, the real MAC is only here.
        with open('/sys/class/net/%s/bonding_slave/perm_hwaddr' % name,
                  'r') as f:
            return f.read().rstrip()
    except IOError:
        pass  # Iface is not part of a bond, continue

    try:
        with open('/sys/class/net/%s/address' % name, 'r') as f:
            return f.read().rstrip()
    except IOError:
        # If the interface is bound to a DPDK driver, get the mac address from
        # the dpdk mapping file as /sys files will be removed after binding.
        dpdk_mac_address = _get_dpdk_mac_address(name)
        if dpdk_mac_address:
            return dpdk_mac_address

        logger.error("Unable to read mac address: %s" % name)
        raise


def _is_active_nic(interface_name):
    return _is_available_nic(interface_name, True)


def _is_available_nic(interface_name, check_active=True):
    try:
        if interface_name == 'lo':
            return False

        device_dir = _SYS_CLASS_NET + '/%s/device' % interface_name
        has_device_dir = os.path.isdir(device_dir)
        if not has_device_dir:
            return False

        operstate = None
        with open(_SYS_CLASS_NET + '/%s/operstate' % interface_name, 'r') as f:
            operstate = f.read().rstrip().lower()
        if check_active and operstate != 'up':
            return False

        address = None
        with open(_SYS_CLASS_NET + '/%s/address' % interface_name, 'r') as f:
            address = f.read().rstrip()
        if not address:
            return False

        # If SR-IOV Virtual Functions (VF) are enabled in an interface, there
        # will be additional nics created for each VF. It has to be ignored in
        # the nic numbering. All the VFs will have a reference to the PF with
        # directory name as 'physfn', if this directory is present it should be
        # ignored.
        vf_path_check = _SYS_CLASS_NET + '/%s/device/physfn' % interface_name
        is_sriov_vf = os.path.isdir(vf_path_check)
        if is_sriov_vf:
            return False

        # nic is available
        return True

    except IOError:
        return False


def _natural_sort_key(s):
    nsre = re.compile('([0-9]+)')
    return [int(text) if text.isdigit() else text
            for text in re.split(nsre, s)]


def _is_embedded_nic(nic):
    if nic.startswith('em') or nic.startswith('eth') or nic.startswith('eno'):
        return True
    return False


def ordered_available_nics():
    return _ordered_nics(False)


def ordered_active_nics():
    return _ordered_nics(True)


def _ordered_nics(check_active):
    embedded_nics = []
    nics = []
    logger.debug("Finding active nics")
    for name in glob.iglob(_SYS_CLASS_NET + '/*'):
        nic = name[(len(_SYS_CLASS_NET) + 1):]
        if _is_available_nic(nic, check_active):
            if _is_embedded_nic(nic):
                logger.debug("%s is an embedded active nic" % nic)
                embedded_nics.append(nic)
            else:
                logger.debug("%s is an active nic" % nic)
                nics.append(nic)
        else:
            logger.debug("%s is not an active nic" % nic)

    # Adding nics which are bound to DPDK as it will not be found in '/sys'
    # after it is bound to DPDK driver.
    contents = get_file_data(_DPDK_MAPPING_FILE)
    if contents:
        dpdk_map = yaml.load(contents)
        for item in dpdk_map:
            nic = item['name']
            if _is_embedded_nic(nic):
                logger.debug("%s is an embedded DPDK bound nic" % nic)
                embedded_nics.append(nic)
            else:
                logger.debug("%s is an DPDK bound nic" % nic)
                nics.append(nic)
    else:
        logger.debug("No DPDK mapping available in path (%s)" %
                     _DPDK_MAPPING_FILE)

    # NOTE: we could just natural sort all active devices,
    # but this ensures em, eno, and eth are ordered first
    # (more backwards compatible)
    active_nics = (sorted(embedded_nics, key=_natural_sort_key) +
                   sorted(nics, key=_natural_sort_key))
    logger.debug("Active nics are %s" % active_nics)
    return active_nics


def diff(filename, data):
    file_data = get_file_data(filename)
    logger.debug("Diff file data:\n%s" % file_data)
    logger.debug("Diff data:\n%s" % data)
    # convert to string as JSON may have unicode in it
    return not file_data == data


def bind_dpdk_interfaces(ifname, driver, noop):
    pci_address = _get_pci_address(ifname, noop)
    if not noop:
        if pci_address:
            # modbprobe of the driver has to be done before binding.
            # for reboots, puppet will add the modprobe to /etc/rc.modules
            if 'vfio-pci' in driver:
                try:
                    processutils.execute('modprobe', 'vfio-pci')
                except processutils.ProcessExecutionError:
                    msg = "Failed to modprobe vfio-pci module"
                    raise OvsDpdkBindException(msg)

            mac_address = interface_mac(ifname)
            try:
                out, err = processutils.execute('driverctl', 'set-override',
                                                pci_address, driver)
                if err:
                    msg = "Failed to bind dpdk interface err - %s" % err
                    raise OvsDpdkBindException(msg)
                else:
                    _update_dpdk_map(ifname, pci_address, mac_address, driver)

            except processutils.ProcessExecutionError:
                msg = "Failed to bind interface %s with dpdk" % ifname
                raise OvsDpdkBindException(msg)
        else:
            # Check if the pci address is already fetched and stored.
            # If the pci address could not be fetched from dpdk_mapping.yaml
            # raise OvsDpdkBindException, since the interface is neither
            # available nor bound with dpdk.
            if not get_stored_pci_address(ifname, noop):
                msg = "Interface %s cannot be found" % ifname
                raise OvsDpdkBindException(msg)
    else:
        logger.info('Interface %(name)s bound to DPDK driver %(driver)s '
                    'using driverctl command' %
                    {'name': ifname, 'driver': driver})


def _get_pci_address(ifname, noop):
    # TODO(skramaja): Validate if the given interface supports dpdk
    if not noop:
        try:
            out, err = processutils.execute('ethtool', '-i', ifname)
            if not err:
                for item in out.split('\n'):
                    if 'bus-info' in item:
                        return item.split(' ')[1]
        except processutils.ProcessExecutionError:
            # If ifname is already bound, then ethtool will not be able to
            # list the device, in which case, binding is already done, proceed
            # with scripts generation.
            return

    else:
        logger.info('Fetch the PCI address of the interface %s using '
                    'ethtool' % ifname)


def get_stored_pci_address(ifname, noop):
    if not noop:
        dpdk_map = _get_dpdk_map()
        for dpdk_nic in dpdk_map:
            if dpdk_nic['name'] == ifname:
                return dpdk_nic['pci_address']
    else:
        logger.info('Fetch the PCI address of the interface %s using '
                    'ethtool' % ifname)


# Once the interface is bound to a DPDK driver, all the references to the
# interface including '/sys' and '/proc', will be removed. And there is no
# way to identify the nic name after it is bound. So, the DPDK bound nic info
# is stored persistently in a file and is used to for nic numbering on
# subsequent runs of os-net-config.
def _update_dpdk_map(ifname, pci_address, mac_address, driver):
    dpdk_map = _get_dpdk_map()
    for item in dpdk_map:
        if item['pci_address'] == pci_address:
            item['name'] = ifname
            item['mac_address'] = mac_address
            item['driver'] = driver
            break
    else:
        new_item = {}
        new_item['pci_address'] = pci_address
        new_item['name'] = ifname
        new_item['mac_address'] = mac_address
        new_item['driver'] = driver
        dpdk_map.append(new_item)

    write_yaml_config(_DPDK_MAPPING_FILE, dpdk_map)


def _get_dpdk_map():
    contents = get_file_data(_DPDK_MAPPING_FILE)
    dpdk_map = yaml.load(contents) if contents else []
    return dpdk_map


def _get_dpdk_mac_address(name):
    contents = get_file_data(_DPDK_MAPPING_FILE)
    dpdk_map = yaml.load(contents) if contents else []
    for item in dpdk_map:
        if item['name'] == name:
            return item['mac_address']
