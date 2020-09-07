# Copyright 2020 Red Hat, Inc.
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


import logging
import os
import yaml


from oslo_concurrency import processutils


logger = logging.getLogger(__name__)
_PCI_DRIVER_BIND_FILE_PATH = "/sys/bus/pci/drivers/%(driver)s/bind"
_PCI_DRIVER_FILE_PATH = "/sys/bus/pci/devices/%(pci)s/driver"
_SRIOV_BIND_CONFIG_FILE = "/var/lib/os-net-config/sriov_bind_config.yaml"
_SRIOV_BIND_SERVICE_FILE = "/etc/systemd/system/sriov_bind.service"
_SRIOV_BIND_SERVICE_CONTENT = """[Unit]
Description=SR-IOV vfs binding
After=network.service sriov_config.service

[Service]
Type=oneshot
ExecStart=/usr/bin/os-net-config-sriov-bind

[Install]
WantedBy=multi-user.target
"""

# File to contain the map of drivers and it's VFs list that should be bound
# Format of the file shall be
# <driver1>:
# - '<VF1_PCI>'
# - '<VF2_PCI>'
# - '<VF3_PCI>'
# - '<VF4_PCI>'
# <driver2>:
# - '<VF5_PCI>'
# - '<VF6_PCI>'
# - '<VF7_PCI>'
# - '<VF8_PCI>'


def get_file_data(filename):
    if not os.path.exists(filename):
        logger.error("Error file is not exist: %s" % filename)
        raise FileNotFoundError(filename)
    try:
        with open(filename, 'r') as f:
            return f.read()
    except IOError:
        logger.error("Error reading file: %s" % filename)
        raise


def ensure_directory_presence(filepath):
    dir_path = os.path.dirname(filepath)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def write_yaml_config(filepath, data):
    ensure_directory_presence(filepath)
    with open(filepath, 'w') as f:
        yaml.safe_dump(data, f, default_flow_style=False)


def update_sriov_bind_pcis_map(sriov_bind_pcis_map):
    sriov_bind_config_data = {}
    try:
        sriov_bind_config_data = _get_sriov_bind_pcis_map()
    except Exception:
        pass
    # Compare two levels of the dictionary to conditionally write
    # sriov_bind_pcis_map if it differs from existning sriov_bind_config_data
    if (sriov_bind_config_data == {} or
            set(sriov_bind_config_data.keys()) !=
            set(sriov_bind_pcis_map.keys()) or not
            all([set(sriov_bind_config_data[key]) ==
                 set(sriov_bind_pcis_map[key]) for key in
                 sriov_bind_config_data])):
        write_yaml_config(_SRIOV_BIND_CONFIG_FILE, sriov_bind_pcis_map)


def _get_sriov_bind_pcis_map():
    contents = get_file_data(_SRIOV_BIND_CONFIG_FILE)
    sriov_bind_pcis_map = yaml.safe_load(contents) if contents else {}
    return sriov_bind_pcis_map


def configure_sriov_bind_service():
    """Generate the sriov_bind.service

       sriov_bind service shall bind all the vfs of switchdev-mode mlnx SriovPF
       nics during reboot of the nodes.
    """
    with open(_SRIOV_BIND_SERVICE_FILE, 'w') as f:
        f.write(_SRIOV_BIND_SERVICE_CONTENT)
    processutils.execute('systemctl', 'enable', 'sriov_bind')


def bind_vfs(sriov_bind_pcis_map=None):
    if not sriov_bind_pcis_map:
        sriov_bind_pcis_map = _get_sriov_bind_pcis_map()
    for driver, pcis_list in sriov_bind_pcis_map.items():
        for vf_pci in pcis_list:
            vf_pci_driver_path = _PCI_DRIVER_FILE_PATH % {"pci": vf_pci}
            if not os.path.exists(vf_pci_driver_path):
                pci_driver_bind_file_path = _PCI_DRIVER_BIND_FILE_PATH %\
                    {"driver": driver}
                try:
                    with open(pci_driver_bind_file_path, 'w') as f:
                        f.write("%s" % vf_pci)
                    logger.info("Vf %s has been bound" % vf_pci)
                except IOError:
                    logger.error("Failed to bind vf %s" % vf_pci)


def main():
    bind_vfs()


if __name__ == "__main__":
    main()
