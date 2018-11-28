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
import six
import time
import yaml

from os_net_config import sriov_config
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
# sriov_config service shall be created and enabled so that the various
# SR-IOV PF and VF configurations shall be done during reboot as well using
# sriov_config.py installed in path /usr/bin/os-net-config-sriov
_SRIOV_CONFIG_SERVICE_FILE = "/etc/systemd/system/sriov_config.service"
_SRIOV_CONFIG_DEVICE_CONTENT = """[Unit]
Description=SR-IOV numvfs configuration
After=systemd-udev-settle.service
Before=ovs-vswitchd.service

[Service]
Type=oneshot
ExecStart=/usr/bin/os-net-config-sriov

[Install]
WantedBy=multi-user.target
"""

# VPP startup operational configuration file. The content of this file will
# be executed when VPP starts as if typed from CLI.
_VPP_EXEC_FILE = '/etc/vpp/vpp-exec'


class OvsDpdkBindException(ValueError):
    pass


class VppException(ValueError):
    pass


class ContrailVrouterException(ValueError):
    pass


class SriovVfNotFoundException(ValueError):
    pass


def write_config(filename, data):
    with open(filename, 'w') as f:
        f.write(str(data))


def write_yaml_config(filepath, data):
    ensure_directory_presence(filepath)
    with open(filepath, 'w') as f:
        yaml.safe_dump(data, f, default_flow_style=False)


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


def is_active_nic(interface_name):
    return _is_available_nic(interface_name, True)


def is_real_nic(interface_name):
    if interface_name == 'lo':
        return True

    device_dir = _SYS_CLASS_NET + '/%s/device' % interface_name
    has_device_dir = os.path.isdir(device_dir)

    address = None
    try:
        with open(_SYS_CLASS_NET + '/%s/address' % interface_name, 'r') as f:
            address = f.read().rstrip()
    except IOError:
        return False

    if has_device_dir and address:
        return True
    else:
        return False


def _is_available_nic(interface_name, check_active=True):
    try:
        if interface_name == 'lo':
            return False

        if not is_real_nic(interface_name):
            return False

        operstate = None
        with open(_SYS_CLASS_NET + '/%s/operstate' % interface_name, 'r') as f:
            operstate = f.read().rstrip().lower()
        if check_active and operstate != 'up':
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
    logger.info("Finding active nics")
    for name in glob.iglob(_SYS_CLASS_NET + '/*'):
        nic = name[(len(_SYS_CLASS_NET) + 1):]
        if _is_available_nic(nic, check_active):
            if _is_embedded_nic(nic):
                logger.info("%s is an embedded active nic" % nic)
                embedded_nics.append(nic)
            else:
                logger.info("%s is an active nic" % nic)
                nics.append(nic)
        else:
            logger.info("%s is not an active nic" % nic)

    # Adding nics which are bound to DPDK as it will not be found in '/sys'
    # after it is bound to DPDK driver.
    contents = get_file_data(_DPDK_MAPPING_FILE)
    if contents:
        dpdk_map = yaml.safe_load(contents)
        for item in dpdk_map:
            nic = item['name']
            if _is_embedded_nic(nic):
                logger.info("%s is an embedded DPDK bound nic" % nic)
                embedded_nics.append(nic)
            else:
                logger.info("%s is an DPDK bound nic" % nic)
                nics.append(nic)
    else:
        logger.info("No DPDK mapping available in path (%s)" %
                    _DPDK_MAPPING_FILE)

    # NOTE: we could just natural sort all active devices,
    # but this ensures em, eno, and eth are ordered first
    # (more backwards compatible)
    active_nics = (sorted(embedded_nics, key=_natural_sort_key) +
                   sorted(nics, key=_natural_sort_key))
    logger.info("Active nics are %s" % active_nics)
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
            vendor_id = get_vendor_id(ifname)
            try:
                out, err = processutils.execute('driverctl', 'set-override',
                                                pci_address, driver)
                if err:
                    msg = "Failed to bind dpdk interface err - %s" % err
                    raise OvsDpdkBindException(msg)
                else:
                    _update_dpdk_map(ifname, pci_address, mac_address, driver)
                    # Not like other nics, beacause mellanox nics keep the
                    # interface after binding it to dpdk, so we are adding
                    # ethtool command with 10 attempts after binding the driver
                    # just to make sure that the interface is initialized
                    # successfully in order not to fail in each of this cases:
                    # - get_dpdk_devargs() in case of OvsDpdkPort and
                    #   OvsDpdkBond.
                    # - bind_dpdk_interface() in case of OvsDpdkBond.
                    if vendor_id == "0x15b3":
                        processutils.execute('ethtool', '-i', ifname,
                                             attempts=10)

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


def translate_ifname_to_pci_address(ifname, noop):
    pci_address = get_stored_pci_address(ifname, noop)
    if pci_address is None and not noop:
        pci_address = get_pci_address(ifname, noop=False)
        mac_address = interface_mac(ifname)
        _update_dpdk_map(ifname, pci_address, mac_address, driver=None)
    return pci_address


def get_vendor_id(ifname):
    try:
        with open('%s/%s/device/vendor' % (_SYS_CLASS_NET, ifname),
                  'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_device_id(ifname):
    try:
        with open('%s/%s/device/device' % (_SYS_CLASS_NET, ifname),
                  'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_dpdk_devargs(ifname, noop):
    if not noop:
        vendor_id = get_vendor_id(ifname)
        device_id = get_device_id(ifname)
        if vendor_id == "0x15b3" and device_id == "0x1007":
            # Some NICs (i.e. Mellanox ConnectX-3) have only one PCI address
            # associated with multiple ports. Using a PCI device won’t work.
            # Instead, we should use "class=eth,mac=<MAC>"
            dpdk_devargs = "class=eth,mac=%s" % interface_mac(ifname)
        else:
            dpdk_devargs = get_stored_pci_address(ifname, noop)
        return dpdk_devargs


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
    dpdk_map = yaml.safe_load(contents) if contents else []
    return dpdk_map


def _get_dpdk_mac_address(name):
    contents = get_file_data(_DPDK_MAPPING_FILE)
    dpdk_map = yaml.safe_load(contents) if contents else []
    for item in dpdk_map:
        if item['name'] == name:
            return item['mac_address']


def update_sriov_pf_map(ifname, numvfs, noop, promisc=None,
                        link_mode='legacy'):
    if not noop:
        sriov_map = _get_sriov_map()
        for item in sriov_map:
            if item['device_type'] == 'pf' and item['name'] == ifname:
                item['numvfs'] = numvfs
                if promisc is not None:
                    item['promisc'] = promisc
                item['link_mode'] = link_mode
                break
        else:
            new_item = {}
            new_item['device_type'] = 'pf'
            new_item['name'] = ifname
            new_item['numvfs'] = numvfs
            if promisc is not None:
                new_item['promisc'] = promisc
            new_item['link_mode'] = link_mode
            sriov_map.append(new_item)

        write_yaml_config(sriov_config._SRIOV_CONFIG_FILE, sriov_map)


def _get_sriov_map():
    contents = get_file_data(sriov_config._SRIOV_CONFIG_FILE)
    sriov_map = yaml.safe_load(contents) if contents else []
    return sriov_map


def _set_vf_fields(vf_name, vlan_id, qos, spoofcheck, trust, state, macaddr,
                   promisc, pci_address):
    vf_configs = {}
    vf_configs['name'] = vf_name
    if vlan_id != 0:
        vf_configs['vlan_id'] = vlan_id
    else:
        vf_configs['vlan_id'] = None
    if qos != 0:
        vf_configs['qos'] = qos
    else:
        vf_configs['qos'] = None
    vf_configs['spoofcheck'] = spoofcheck
    vf_configs['trust'] = trust
    vf_configs['state'] = state
    vf_configs['macaddr'] = macaddr
    vf_configs['promisc'] = promisc
    vf_configs['pci_address'] = pci_address
    return vf_configs


def _clear_empty_values(vf_config):
    for (key, val) in list(six.iteritems(vf_config)):
        if val is None:
            del vf_config[key]


def update_sriov_vf_map(pf_name, vfid, vf_name, vlan_id=0, qos=0,
                        spoofcheck=None, trust=None, state=None, macaddr=None,
                        promisc=None, pci_address=None):
    sriov_map = _get_sriov_map()
    for item in sriov_map:
        if (item['device_type'] == 'vf' and
           item['device'].get('name') == pf_name and
           item['device'].get('vfid') == vfid):
            item.update(_set_vf_fields(vf_name, vlan_id, qos, spoofcheck,
                                       trust, state, macaddr, promisc,
                                       pci_address))
            _clear_empty_values(item)
            break
    else:
        new_item = {}
        new_item['device_type'] = 'vf'
        new_item['device'] = {"name": pf_name, "vfid": vfid}
        new_item.update(_set_vf_fields(vf_name, vlan_id, qos, spoofcheck,
                                       trust, state, macaddr, promisc,
                                       pci_address))
        _clear_empty_values(new_item)
        sriov_map.append(new_item)

    write_yaml_config(sriov_config._SRIOV_CONFIG_FILE, sriov_map)


def _get_vf_name_from_map(pf_name, vfid):
    sriov_map = _get_sriov_map()
    for item in sriov_map:
        if (item['device_type'] == 'vf' and
           item['device'].get('name') == pf_name and
           item['device'].get('vfid') == vfid):
            return item['name']


def _configure_sriov_config_service():
    """Generate the sriov_config.service

     sriov_config service shall configure the numvfs for the SriovPF nics
     during reboot of the nodes.
    """
    with open(_SRIOV_CONFIG_SERVICE_FILE, 'w') as f:
        f.write(_SRIOV_CONFIG_DEVICE_CONTENT)
    processutils.execute('systemctl', 'enable', 'sriov_config')


def configure_sriov_pfs():
    logger.info("Configuring PFs now")
    sriov_config.configure_sriov_pf()
    _configure_sriov_config_service()


def configure_sriov_vfs():
    logger.info("Configuring VFs now")
    sriov_config.configure_sriov_vf()


def get_vf_devname(pf_name, vfid):
    vf_path = os.path.join(_SYS_CLASS_NET, pf_name, "device/virtfn%d/net"
                           % vfid)
    if os.path.isdir(vf_path):
        vf_nic = os.listdir(vf_path)
    else:
        # if VF devices are bound with other drivers (DPDK) then the path
        # doesn't exist. In such cases let us retrieve the vf name stored in
        # the map
        vf_name = _get_vf_name_from_map(pf_name, vfid)
        if vf_name is not None:
            return vf_name
        else:
            msg = "NIC %s with VF id: %d could not be found" % (pf_name, vfid)
            raise SriovVfNotFoundException(msg)
    if len(vf_nic) != 1:
        msg = "VF name could not be identified in %s" % vf_path
        raise SriovVfNotFoundException(msg)
    # The VF's actual device name shall be the only directory seen in the path
    # /sys/class/net/<pf_name>/device/virtfn<vfid>/net
    return vf_nic[0]


def restart_vpp(vpp_interfaces):
    for vpp_int in vpp_interfaces:
        if 'vfio-pci' in vpp_int.uio_driver:
            processutils.execute('modprobe', 'vfio-pci')
    logger.info('Restarting VPP')
    processutils.execute('systemctl', 'restart', 'vpp')


def _get_vpp_interface(pci_addr, tries=1, timeout=5):
    """Get VPP interface information from a given PCI address

    From a running VPP instance, attempt to find the interface name and index
    from a given PCI address of a NIC. The index is used to identify VPP bond
    interface associated with the VPP interface.

    :param pci_addr: PCI address to lookup, in the form of DDDD:BB:SS.F, where
                     - DDDD = Domain
                     - BB = Bus Number
                     - SS = Slot number
                     - F = Function
    :param tries: Number of tries for getting vppctl output. Defaults to 1.
    :param timeout: Timeout in seconds between tries. Defaults to 5.
    :return: VPP interface name. None if an interface is not found.
    """
    if not pci_addr:
        return None

    for _ in range(tries):
        try:
            timestamp = time.time()
            processutils.execute('systemctl', 'is-active', 'vpp')
            out, err = processutils.execute('vppctl', 'show', 'interface',
                                            check_exit_code=False)
            logger.debug("vppctl show interface\n%s\n%s\n" % (out, err))
            m = re.search(r':([0-9a-fA-F]{2}):([0-9a-fA-F]{2}).([0-9a-fA-F])',
                          pci_addr)
            if m:
                formatted_pci = "%x/%x/%x" % (int(m.group(1), 16),
                                              int(m.group(2), 16),
                                              int(m.group(3), 16))
            else:
                raise VppException('Invalid PCI address format: %s' % pci_addr)

            m = re.search(r'^(\w+%s)\s+(\d+)' % formatted_pci, out,
                          re.MULTILINE)
            if m:
                logger.info('VPP interface found: %s, index: %s' %
                            (m.group(1), m.group(2)))
                return {'name': m.group(1), 'index': m.group(2)}
        except processutils.ProcessExecutionError:
            pass

        time.sleep(max(0, (timestamp + timeout) - time.time()))
    else:
        logger.info('Interface with pci address %s not bound to vpp' %
                    pci_addr)
        return None


def _get_vpp_bond(member_ids):
    """Get VPP bond information from a given list of VPP interface indices

    :param member_ids: list of VPP interfaces indices for the bond
    :return: VPP bond name and index. None if an interface is not found.
    """
    if not member_ids:
        return None

    member_ids.sort()
    member_ids_str = ' '.join(member_ids)

    out, err = processutils.execute('vppctl', 'show',
                                    'hardware-interfaces', 'bond', 'brief',
                                    check_exit_code=False)
    logger.debug('vppctl show hardware-interfaces bond brief\n%s' % out)
    m = re.search(r'^\s*(BondEthernet\d+)\s+(\d+)\s+.+Slave-Idx:\s+%s\s*$' %
                  member_ids_str,
                  out,
                  re.MULTILINE)
    if m:
        logger.info('Bond found: %s, index: %s' % (m.group(1), m.group(2)))
        return {'name': m.group(1), 'index': m.group(2)}
    else:
        logger.info('Bond with member indices "%s" not found in VPP'
                    % member_ids_str)
        return None


def generate_vpp_config(vpp_config_path, vpp_interfaces, vpp_bonds):
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
    :param vpp_bonds: List of VPP bond objects
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
            m = re.search(r'^\s*dev\s+%s\s*(\{[^}]*\})?\s*$'
                          % vpp_interface.pci_dev, data,
                          re.IGNORECASE | re.MULTILINE)
            if m:
                data = re.sub(m.group(0), '  dev %s\n' % int_cfg, data,
                              flags=re.MULTILINE)
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
                    data = re.sub(r'^\s*uio-driver.*$', '  uio-driver %s'
                                  % vpp_interface.uio_driver, data,
                                  flags=re.MULTILINE)
                else:
                    data = re.sub(r'(^\s*dpdk\s*\{)',
                                  r'\1\n  uio-driver %s'
                                  % vpp_interface.uio_driver,
                                  data,
                                  flags=re.MULTILINE)
        else:
            raise VppException('Interface %s has no PCI address and is not'
                               ' found in mapping file' % vpp_interface.name)

    # Add bond config to 'dpdk' section
    for vpp_bond in vpp_bonds:
        slave_str = ''
        for member in vpp_bond.members:
            slave_str += ",slave=%s" % member.pci_dev
        if vpp_bond.bonding_options:
            options_str = ',' + vpp_bond.bonding_options.strip(' ,')
        else:
            options_str = ''

        if slave_str:
            m = re.search(r'^\s*vdev\s+%s.*$' % vpp_bond.name,
                          data, re.MULTILINE)
            if m:
                data = re.sub(m.group(0), r'  vdev %s%s%s'
                              % (vpp_bond.name, slave_str, options_str),
                              data)
            else:
                data = re.sub(r'(^\s*dpdk\s*\{)',
                              r'\1\n  vdev %s%s%s'
                              % (vpp_bond.name, slave_str, options_str),
                              data,
                              flags=re.MULTILINE)

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


def update_vpp_mapping(vpp_interfaces, vpp_bonds):
    """Verify VPP interface binding and update mapping file

    VppException will be raised if interfaces are not properly bound.

    :param vpp_interfaces: List of VPP interface objects
    :param vpp_bonds: List of VPP bond objects
    """
    cli_list = []

    for vpp_int in vpp_interfaces:
        # Try to get VPP interface name. In case VPP service is down
        # for some reason, we will restart VPP and try again. Currently
        # only trying one more time, can turn into a retry_counter if needed
        # in the future.
        for i in range(2):
            int_info = _get_vpp_interface(vpp_int.pci_dev,
                                          tries=12, timeout=5)
            if not int_info:
                restart_vpp(vpp_interfaces)
            else:
                vpp_int.vpp_name = int_info['name']
                vpp_int.vpp_idx = int_info['index']
                break
        else:
            raise VppException('Interface %s with pci address %s not '
                               'bound to vpp'
                               % (vpp_int.name, vpp_int.pci_dev))

        # Generate content of startup script for VPP
        if not vpp_bonds:
            cli_list.append('set interface state %s up'
                            % int_info['name'])
            for address in vpp_int.addresses:
                cli_list.append('set interface ip address %s %s/%s\n'
                                % (int_info['name'], address.ip,
                                   address.prefixlen))

        logger.info('Updating mapping for vpp interface %s:'
                    'pci_dev: %s mac address: %s uio driver: %s'
                    % (vpp_int.name, vpp_int.pci_dev, vpp_int.hwaddr,
                       vpp_int.uio_driver))
        _update_dpdk_map(vpp_int.name, vpp_int.pci_dev, vpp_int.hwaddr,
                         vpp_int.uio_driver)

    for vpp_bond in vpp_bonds:
        bond_ids = [member.vpp_idx for member in vpp_bond.members]
        bond_info = _get_vpp_bond(bond_ids)
        if bond_info:
            cli_list.append('set interface state %s up'
                            % bond_info['name'])
            for address in vpp_bond.addresses:
                cli_list.append('set interface ip address %s %s/%s'
                                % (bond_info['name'], address.ip,
                                   address.prefixlen))
        else:
            raise VppException('Bond %s not found in VPP.' % vpp_bond.name)

    vpp_start_cli = get_file_data(_VPP_EXEC_FILE)
    for cli_line in cli_list:
        if not re.search(r'^\s*%s\s*$' % cli_line,
                         vpp_start_cli, re.MULTILINE):
            vpp_start_cli += cli_line + '\n'

    if diff(_VPP_EXEC_FILE, vpp_start_cli):
        write_config(_VPP_EXEC_FILE, vpp_start_cli)
        restart_vpp(vpp_interfaces)

    # Enable VPP service to make the VPP interface configuration
    # persistent.
    processutils.execute('systemctl', 'enable', 'vpp')


def is_ovs_installed():
    """Check if OpenVswitch is installed

    Verify that OpenVswitch is installed by checking if
    ovs-appctl is on the system.  If OVS is not installed
    it will limit os-net-config's ability to set up ovs-bonds,
    ovs-bridges etc.
    """
    return os.path.exists("/usr/bin/ovs-appctl")


def iproute2_path():
    """Find 'ip' executable."""
    if os.access('/sbin/ip', os.X_OK):
        ipcmd = '/sbin/ip'
    elif os.access('/usr/sbin/ip', os.X_OK):
        ipcmd = '/usr/sbin/ip'
    else:
        logger.warning("Could not execute /sbin/ip or /usr/sbin/ip")
        return False
    return ipcmd
