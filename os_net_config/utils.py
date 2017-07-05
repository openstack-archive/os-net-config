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

# VPP startup operational configuration file. The content of this file will
# be executed when VPP starts as if typed from CLI.
_VPP_EXEC_FILE = '/etc/vpp/vpp-exec'


class OvsDpdkBindException(ValueError):
    pass


class VppException(ValueError):
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
        # the DPDK mapping file as /sys files will be removed after binding.
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
    pci_address = get_pci_address(ifname, noop)
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


def get_pci_address(ifname, noop):
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
# is stored persistently in _DPDK_MAPPING_FILE and is used to for nic numbering
# on subsequent runs of os-net-config.
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


def restart_vpp(vpp_interfaces):
    for vpp_int in vpp_interfaces:
        if 'vfio-pci' in vpp_int.uio_driver:
            processutils.execute('modprobe', 'vfio-pci')
    logger.info('Restarting VPP')
    processutils.execute('systemctl', 'restart', 'vpp')


def _get_vpp_interface_name(pci_addr):
    """Get VPP interface name from a given PCI address

    From a running VPP instance, attempt to find the interface name from
    a given PCI address of a NIC.

    VppException will be raised if pci_addr is not formatted correctly.
    ProcessExecutionError will be raised if VPP interface mapped to pci_addr
    is not found.

    :param pci_addr: PCI address to lookup, in the form of DDDD:BB:SS.F, where
                     - DDDD = Domain
                     - BB = Bus Number
                     - SS = Slot number
                     - F = Function
    :return: VPP interface name. None if an interface is not found.
    """
    if not pci_addr:
        return None

    try:
        processutils.execute('systemctl', 'is-active', 'vpp')
        out, err = processutils.execute('vppctl', 'show', 'interfaces')
        m = re.search(r':([0-9a-fA-F]{2}):([0-9a-fA-F]{2}).([0-9a-fA-F])',
                      pci_addr)
        if m:
            formatted_pci = "%x/%x/%x" % (int(m.group(1), 16),
                                          int(m.group(2), 16),
                                          int(m.group(3), 16))
        else:
            raise VppException('Invalid PCI address format: %s' % pci_addr)

        m = re.search(r'^(\w+%s)\s+' % formatted_pci, out, re.MULTILINE)
        if m:
            logger.debug('VPP interface found: %s' % m.group(1))
            return m.group(1)
        else:
            logger.debug('Interface with pci address %s not bound to VPP'
                         % pci_addr)
            return None
    except processutils.ProcessExecutionError:
        logger.debug('Interface with pci address %s not bound to vpp' %
                     pci_addr)


def generate_vpp_config(vpp_config_path, vpp_interfaces):
    """Generate configuration content for VPP

    Generate interface related configuration content for VPP. Current
    configuration will be preserved, with interface related configurations
    updated or inserted. The config only affects 'dpdk' section of VPP config
    file, and only those lines affecting interfaces, specifically, lines
    containing the following:
    dpdk {
      ...
      dev <pci_dev> {<options>}
      uio-driver <uio_driver_name>
      ...
    }

    :param vpp_config_path: VPP Configuration file path
    :param vpp_interfaces: List of VPP interface objects
    :return: updated VPP config content.
    """

    data = get_file_data(vpp_config_path)

    # Add interface config to 'dpdk' section
    for vpp_interface in vpp_interfaces:
        if vpp_interface.pci_dev:
            logger.info('vpp interface %s pci dev: %s'
                        % (vpp_interface.name, vpp_interface.pci_dev))

            if vpp_interface.options:
                int_cfg = '%s {%s}' % (vpp_interface.pci_dev,
                                       vpp_interface.options)
            else:
                int_cfg = vpp_interface.pci_dev

            # Make sure 'dpdk' section exists in the config
            if not re.search(r'^\s*dpdk\s*\{', data, re.MULTILINE):
                data += "\ndpdk {\n}\n"

            # Find existing config line for the device we are trying to
            # configure, the line should look like 'dev <pci_dev>  ...'
            # If such config line is found, we will replace the line with
            # appropriate configuration, otherwise, add a new config line
            # in 'dpdk' section of the config.
            m = re.search(r'^\s*dev\s+%s\s*(\{[^}]*\})?\s*'
                          % vpp_interface.pci_dev, data,
                          re.IGNORECASE | re.MULTILINE)
            if m:
                data = re.sub(m.group(0), '  dev %s\n' % int_cfg, data)
            else:
                data = re.sub(r'(^\s*dpdk\s*\{)',
                              r'\1\n  dev %s\n' % int_cfg,
                              data,
                              flags=re.MULTILINE)

            if vpp_interface.uio_driver:
                # Check if there is existing uio-driver configuration, if
                # found, the line will be replaced with the appropriate
                # configuration, otherwise, add a new line in 'dpdk' section.
                m = re.search(r'^\s*uio-driver.*$', data, re.MULTILINE)
                if m:
                    data = re.sub(m.group(0), r'  uio-driver %s'
                                  % vpp_interface.uio_driver, data)
                else:
                    data = re.sub(r'(dpdk\s*\{)',
                                  r'\1\n  uio-driver %s'
                                  % vpp_interface.uio_driver,
                                  data)
        else:
            logger.debug('pci address not found for interface %s, may have'
                         'already been bound to vpp' % vpp_interface.name)

    # Add start up script for VPP to config. This script will be executed by
    # VPP on service start.
    if not re.search(r'^\s*unix\s*\{', data, re.MULTILINE):
        data += "\nunix {\n}\n"

    m = re.search(r'^\s*(exec|startup-config).*$',
                  data,
                  re.IGNORECASE | re.MULTILINE)
    if m:
        data = re.sub(m.group(0), '  exec %s' % _VPP_EXEC_FILE, data)
    else:
        data = re.sub(r'(^\s*unix\s*\{)',
                      r'\1\n  exec %s' % _VPP_EXEC_FILE,
                      data,
                      flags=re.MULTILINE)
    # Make sure startup script exists to avoid VPP startup failure.
    open(_VPP_EXEC_FILE, 'a').close()

    return data


def update_vpp_mapping(vpp_interfaces):
    """Verify VPP interface binding and update mapping file

    VppException will be raised if interfaces are not properly bound.

    :param vpp_interfaces: List of VPP interface objects
    """
    vpp_start_cli = ""

    for vpp_int in vpp_interfaces:
        if not vpp_int.pci_dev:
            dpdk_map = _get_dpdk_map()
            for dpdk_int in dpdk_map:
                if dpdk_int['name'] == vpp_int.name:
                    vpp_int.pci_dev = dpdk_int['pci_address']
                    break
            else:
                raise VppException('Interface %s has no PCI address and is not'
                                   ' found in mapping file' % vpp_int.name)

        # Try to get VPP interface name. In case VPP service is down
        # for some reason, we will restart VPP and try again. Currently
        # only trying one more time, can turn into a retry_counter if needed
        # in the future.
        for i in range(2):
            vpp_name = _get_vpp_interface_name(vpp_int.pci_dev)
            if not vpp_name:
                restart_vpp(vpp_interfaces)
            else:
                break
        else:
            raise VppException('Interface %s with pci address %s not '
                               'bound to vpp'
                               % (vpp_int.name, vpp_int.pci_dev))

        # Generate content of startup script for VPP
        for address in vpp_int.addresses:
            vpp_start_cli += 'set interface state %s up\n' % vpp_name
            vpp_start_cli += 'set interface ip address %s %s/%s\n' \
                             % (vpp_name, address.ip, address.prefixlen)

        logger.info('Updating mapping for vpp interface %s:'
                    'pci_dev: %s mac address: %s uio driver: %s'
                    % (vpp_int.name, vpp_int.pci_dev, vpp_int.hwaddr,
                       vpp_int.uio_driver))
        _update_dpdk_map(vpp_int.name, vpp_int.pci_dev, vpp_int.hwaddr,
                         vpp_int.uio_driver)
        # Enable VPP service to make the VPP interface configuration
        # persistent.
        processutils.execute('systemctl', 'enable', 'vpp')
    if diff(_VPP_EXEC_FILE, vpp_start_cli):
        write_config(_VPP_EXEC_FILE, vpp_start_cli)
        restart_vpp(vpp_interfaces)
