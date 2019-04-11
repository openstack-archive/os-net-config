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

import argparse
import logging
import os
import pyudev
import re
from six.moves import queue as Queue
import sys
import yaml

from oslo_concurrency import processutils

logger = logging.getLogger(__name__)
_SYS_CLASS_NET = '/sys/class/net'
_UDEV_RULE_FILE = '/etc/udev/rules.d/70-persistent-net.rules'

# In order to keep VF representor name consistent specially after the upgrade
# proccess, we should have a udev rule to handle that.
# The udev rule will rename the VF representor as "<sriov_pf_name>_<vf_num>"
_REP_LINK_NAME_FILE = "/etc/udev/rep-link-name.sh"
_REP_LINK_NAME_DATA = '''#!/bin/bash
SWID="$1"
PORT="$2"
parent_phys_port_name=${PORT%vf*}
parent_phys_port_name=${parent_phys_port_name//f}
for i in `ls -1 /sys/class/net/*/phys_port_name`
do
    nic=`echo $i | cut -d/ -f 5`
    sw_id=`cat /sys/class/net/$nic/phys_switch_id 2>/dev/null`
    phys_port_name=`cat /sys/class/net/$nic/phys_port_name 2>/dev/null`
    if [ "$parent_phys_port_name" = "$phys_port_name" ] &&
       [ "$sw_id" = "$SWID" ]
    then
        echo "NAME=${nic}_${PORT##pf*vf}"
        break
        exit
    fi
done'''

# Create a queue for passing the udev network events
vf_queue = Queue.Queue()


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
_SRIOV_CONFIG_FILE = '/var/lib/os-net-config/sriov_config.yaml'


class SRIOVNumvfsException(ValueError):
    pass


def udev_event_handler(action, device):
    event = {"action": action, "device": device.sys_path}
    logger.info("Received udev event %s for %s"
                % (event["action"], event["device"]))
    vf_queue.put(event)


def get_file_data(filename):
    if not os.path.exists(filename):
        return ''
    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError:
        logger.error("Error reading file: %s" % filename)
        return ''


def _get_sriov_map():
    contents = get_file_data(_SRIOV_CONFIG_FILE)
    sriov_map = yaml.safe_load(contents) if contents else []
    return sriov_map


def configure_sriov_pf():
    # Create a context for pyudev and observe udev events for network
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by('net')
    observer = pyudev.MonitorObserver(monitor, udev_event_handler)
    observer.start()

    sriov_map = _get_sriov_map()
    MLNX_UNBIND_FILE_PATH = "/sys/bus/pci/drivers/mlx5_core/unbind"
    MLNX_VENDOR_ID = "0x15b3"
    for item in sriov_map:
        if item['device_type'] == 'pf':
            _pf_interface_up(item)
            try:
                sriov_numvfs_path = ("/sys/class/net/%s/device/sriov_numvfs"
                                     % item['name'])
                with open(sriov_numvfs_path, 'w') as f:
                    f.write("%d" % item['numvfs'])
            except IOError as exc:
                msg = ("Unable to configure pf: %s with numvfs: %d\n%s"
                       % (item['name'], item['numvfs'], exc))
                raise SRIOVNumvfsException(msg)
            # Wait for the creation of VFs for each PF
            _wait_for_vf_creation(item['name'], item['numvfs'])
            # Configure switchdev mode
            vendor_id = get_vendor_id(item['name'])
            if (item.get('link_mode') == "switchdev" and
                    vendor_id == MLNX_VENDOR_ID):
                vf_pcis_list = get_vf_pcis_list(item['name'])
                for vf_pci in vf_pcis_list:
                    vf_pci_path = "/sys/bus/pci/devices/%s/driver" % vf_pci
                    if os.path.exists(vf_pci_path):
                        with open(MLNX_UNBIND_FILE_PATH, 'w') as f:
                            f.write("%s" % vf_pci)
                # Adding a udev rule to save the sriov_pf name
                add_udev_rule_for_sriov_pf(item['name'])
                add_udev_rule_for_vf_representors()
                configure_switchdev(item['name'])
                if_up_interface(item['name'])

    observer.stop()


def _wait_for_vf_creation(pf_name, numvfs):
    vf_count = 0
    vf_list = []
    while vf_count < numvfs:
        try:
            # wait for 5 seconds after every udev event
            event = vf_queue.get(True, 5)
            vf_name = os.path.basename(event["device"])
            pf_path = os.path.normpath(os.path.join(event["device"],
                                                    "../../physfn/net"))
            if os.path.isdir(pf_path):
                pf_nic = os.listdir(pf_path)
                if len(pf_nic) == 1 and pf_name == pf_nic[0]:
                    if vf_name not in vf_list:
                        vf_list.append(vf_name)
                        logger.info("VF: %s created for PF: %s"
                                    % (vf_name, pf_name))
                        vf_count = vf_count + 1
                else:
                    logger.error("Unable to parse event %s" % event["device"])
            else:
                logger.error("%s is not a directory" % pf_path)
        except Queue.Empty:
            logger.info("Timeout in the creation of VFs for PF %s" % pf_name)
            return
    logger.info("Required VFs are created for PF %s" % pf_name)


def create_rep_link_name_script():
    with open(_REP_LINK_NAME_FILE, "w") as f:
        f.write(_REP_LINK_NAME_DATA)
    # Make the _REP_LINK_NAME_FILE executable
    os.chmod(_REP_LINK_NAME_FILE, 0o755)


def add_udev_rule_for_sriov_pf(pf_name):
    pf_pci = get_pf_pci(pf_name)
    udev_data_line = 'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", '\
                     'KERNELS=="%s", NAME="%s"' % (pf_pci, pf_name)
    add_udev_rule(udev_data_line, _UDEV_RULE_FILE)


def add_udev_rule_for_vf_representors():
    udev_data_line = 'SUBSYSTEM=="net", ACTION=="add", ATTR{phys_switch_id}'\
                     '!="", ATTR{phys_port_name}=="pf*vf*", '\
                     'IMPORT{program}="%s '\
                     '$attr{phys_switch_id} $attr{phys_port_name}" '\
                     'NAME="$env{NAME}"' % _REP_LINK_NAME_FILE
    create_rep_link_name_script()
    add_udev_rule(udev_data_line, _UDEV_RULE_FILE)


def add_udev_rule(udev_data, udev_file):
    udev_data = udev_data.strip()
    if not os.path.exists(udev_file):
        with open(udev_file, "w") as f:
            f.write(udev_data + "\n")
        reload_udev_rules()
    else:
        file_data = get_file_data(udev_file)
        udev_lines = file_data.split("\n")
        if udev_data not in udev_lines:
            with open(udev_file, "a") as f:
                f.write(udev_data + "\n")
            reload_udev_rules()


def reload_udev_rules():
    try:
        processutils.execute('/usr/sbin/udevadm', 'control', '--reload-rules')
    except processutils.ProcessExecutionError:
        logger.error("Failed to reload udev rules")
        raise


def configure_switchdev(pf_name):
    pf_pci = get_pf_pci(pf_name)
    pf_device_id = get_pf_device_id(pf_name)
    if pf_device_id == "0x1013" or pf_device_id == "0x1015":
        try:
            processutils.execute('/usr/sbin/devlink', 'dev', 'eswitch', 'set',
                                 'pci/%s' % pf_pci, 'inline-mode', 'transport')
        except processutils.ProcessExecutionError:
            logger.error("Failed to set inline-mode to transport")
            raise
    try:
        processutils.execute('/usr/sbin/devlink', 'dev', 'eswitch', 'set',
                             'pci/%s' % pf_pci, 'mode', 'switchdev')
    except processutils.ProcessExecutionError:
        logger.error("Failed to set mode to switchdev")
        raise
    try:
        processutils.execute('/usr/sbin/ethtool', '-K', pf_name,
                             'hw-tc-offload', 'on')
    except processutils.ProcessExecutionError:
        logger.error("Failed to enable hw-tc-offload")
        raise


def run_ip_config_cmd(*cmd, **kwargs):
    logger.info("Running %s" % ' '.join(cmd))
    try:
        processutils.execute(*cmd, **kwargs)
    except processutils.ProcessExecutionError:
        logger.error("Failed to execute %s" % ' '.join(cmd))
        raise


def _pf_interface_up(pf_device):
    if 'promisc' in pf_device:
        run_ip_config_cmd('ip', 'link', 'set', 'dev', pf_device['name'],
                          'promisc', pf_device['promisc'])
    logger.info("Bringing up PF: %s" % pf_device['name'])
    run_ip_config_cmd('ip', 'link', 'set', 'dev', pf_device['name'], 'up')


def get_vendor_id(ifname):
    try:
        with open(os.path.join(_SYS_CLASS_NET, ifname, "device/vendor"),
                  'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_pf_pci(pf_name):
    pf_pci_path = os.path.join(_SYS_CLASS_NET, pf_name, "device/uevent")
    pf_info = get_file_data(pf_pci_path)
    pf_pci = re.search(r'PCI_SLOT_NAME=(.*)', pf_info, re.MULTILINE).group(1)
    return pf_pci


def get_pf_device_id(pf_name):
    pf_device_path = os.path.join(_SYS_CLASS_NET, pf_name, "device/device")
    pf_device_id = get_file_data(pf_device_path).strip()
    return pf_device_id


def get_vf_pcis_list(pf_name):
    vf_pcis_list = []
    listOfPfFiles = os.listdir(os.path.join(_SYS_CLASS_NET, pf_name,
                                            "device"))
    for pf_file in listOfPfFiles:
        if pf_file.startswith("virtfn"):
            vf_info = get_file_data(os.path.join(_SYS_CLASS_NET, pf_name,
                                    "device", pf_file, "uevent"))
            vf_pcis_list.append(re.search(r'PCI_SLOT_NAME=(.*)',
                                          vf_info, re.MULTILINE).group(1))
    return vf_pcis_list


def if_up_interface(device):
    logger.info("Running /sbin/ifup %s" % device)
    try:
        processutils.execute('/sbin/ifup', device)
    except processutils.ProcessExecutionError:
        logger.error("Failed to ifup  %s" % device)
        raise


def configure_sriov_vf():
    sriov_map = _get_sriov_map()
    for item in sriov_map:
        if item['device_type'] == 'vf':
            pf_name = item['device']['name']
            vfid = item['device']['vfid']
            base_cmd = ('ip', 'link', 'set', 'dev', pf_name, 'vf', str(vfid))
            logger.info("Configuring settings for PF: %s VF :%d VF name : %s"
                        % (pf_name, vfid, item['name']))
            if 'macaddr' in item:
                cmd = base_cmd + ('mac', item['macaddr'])
                run_ip_config_cmd(*cmd)
            if 'vlan_id' in item:
                vlan_cmd = base_cmd + ('vlan', str(item['vlan_id']))
                if 'qos' in item:
                    vlan_cmd = vlan_cmd + ('qos', str(item['qos']))
                run_ip_config_cmd(*vlan_cmd)
            if 'spoofcheck' in item:
                cmd = base_cmd + ('spoofchk', item['spoofcheck'])
                run_ip_config_cmd(*cmd)
            if 'state' in item:
                cmd = base_cmd + ('state', item['state'])
                run_ip_config_cmd(*cmd)
            if 'trust' in item:
                cmd = base_cmd + ('trust', item['trust'])
                run_ip_config_cmd(*cmd)
            if 'promisc' in item:
                run_ip_config_cmd('ip', 'link', 'set', 'dev', item['name'],
                                  'promisc', item['promisc'])


def parse_opts(argv):

    parser = argparse.ArgumentParser(
        description='Configure SR-IOV PF and VF interfaces using a YAML'
        ' config file format.')

    parser.add_argument(
        '-d', '--debug',
        dest="debug",
        action='store_true',
        help="Print debugging output.",
        required=False)

    parser.add_argument(
        '-v', '--verbose',
        dest="verbose",
        action='store_true',
        help="Print verbose output.",
        required=False)

    opts = parser.parse_args(argv[1:])

    return opts


def configure_logger(verbose=False, debug=False):
    LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
    DATE_FORMAT = '%Y/%m/%d %I:%M:%S %p'
    log_level = logging.WARN

    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO

    logging.basicConfig(format=LOG_FORMAT, datefmt=DATE_FORMAT,
                        level=log_level)


def main(argv=sys.argv):
    opts = parse_opts(argv)
    configure_logger(opts.verbose, opts.debug)
    # Configure the PF's
    configure_sriov_pf()
    # Configure the VFs
    configure_sriov_vf()


if __name__ == '__main__':
    sys.exit(main(sys.argv))
