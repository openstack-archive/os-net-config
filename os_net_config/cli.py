# -*- coding: utf-8 -*-

# Copyright 2014-2015 Red Hat, Inc.
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


import argparse
import logging
import os
import sys
import yaml

from os_net_config import impl_eni
from os_net_config import impl_ifcfg
from os_net_config import impl_iproute
from os_net_config import objects
from os_net_config import utils
from os_net_config import validator
from os_net_config import version

logger = logging.getLogger(__name__)


def parse_opts(argv):
    parser = argparse.ArgumentParser(
        description='Configure host network interfaces using a JSON'
        ' config file format.')
    parser.add_argument('-c', '--config-file', metavar='CONFIG_FILE',
                        help="""path to the configuration file.""",
                        default='/etc/os-net-config/config.yaml')
    parser.add_argument('-m', '--mapping-file', metavar='MAPPING_FILE',
                        help="""path to the interface mapping file.""",
                        default='/etc/os-net-config/mapping.yaml')
    parser.add_argument('-i', '--interfaces', metavar='INTERFACES',
                        help="""Identify the real interface for a nic name. """
                        """If a real name is given, it is returned if live. """
                        """If no value is given, display full NIC mapping. """
                        """Exit after printing, ignoring other parameters. """,
                        nargs='*', default=None)
    parser.add_argument('-p', '--provider', metavar='PROVIDER',
                        help="""The provider to use. """
                        """One of: ifcfg, eni, iproute.""",
                        default=None)
    parser.add_argument('-r', '--root-dir', metavar='ROOT_DIR',
                        help="""The root directory of the filesystem.""",
                        default='')
    parser.add_argument('--detailed-exit-codes',
                        action='store_true',
                        help="""Enable detailed exit codes. """
                        """If enabled an exit code of '2' means """
                        """that files were modified. """
                        """Disabled by default.""",
                        default=False)

    parser.add_argument(
        '--exit-on-validation-errors',
        action='store_true',
        help="Exit with an error if configuration file validation fails. "
             "Without this option, just log a warning and continue.",
        default=False)

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

    parser.add_argument('--version', action='version',
                        version=version.version_info.version_string())
    parser.add_argument(
        '--noop',
        dest="noop",
        action='store_true',
        help="Return the configuration commands, without applying them.",
        required=False)

    parser.add_argument(
        '--no-activate',
        dest="no_activate",
        action='store_true',
        help="Install the configuration but don't start/stop interfaces.",
        required=False)

    parser.add_argument(
        '--cleanup',
        dest="cleanup",
        action='store_true',
        help="Cleanup unconfigured interfaces.",
        required=False)

    parser.add_argument(
        '--persist-mapping',
        dest="persist_mapping",
        action='store_true',
        help="Make aliases defined in the mapping file permanent "
             "(WARNING, permanently renames nics).",
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


def check_configure_sriov(obj):
    configure_sriov = False
    for member in obj.members:
        if isinstance(member, objects.SriovPF):
            configure_sriov = True
        elif hasattr(member, "members") and member.members is not None:
            configure_sriov = check_configure_sriov(member)
    return configure_sriov


def main(argv=sys.argv):
    opts = parse_opts(argv)
    configure_logger(opts.verbose, opts.debug)
    logger.info('Using config file at: %s' % opts.config_file)
    iface_array = []
    configure_sriov = False

    provider = None
    if opts.provider:
        if opts.provider == 'ifcfg':
            provider = impl_ifcfg.IfcfgNetConfig(noop=opts.noop,
                                                 root_dir=opts.root_dir)
        elif opts.provider == 'eni':
            provider = impl_eni.ENINetConfig(noop=opts.noop,
                                             root_dir=opts.root_dir)
        elif opts.provider == 'iproute':
            provider = impl_iproute.IPRouteNetConfig(noop=opts.noop,
                                                     root_dir=opts.root_dir)
        else:
            logger.error('Invalid provider specified.')
            return 1
    else:
        if os.path.exists('%s/etc/sysconfig/network-scripts/' % opts.root_dir):
            provider = impl_ifcfg.IfcfgNetConfig(noop=opts.noop,
                                                 root_dir=opts.root_dir)
        elif os.path.exists('%s/etc/network/' % opts.root_dir):
            provider = impl_eni.ENINetConfig(noop=opts.noop,
                                             root_dir=opts.root_dir)
        else:
            logger.error('Unable to set provider for this operating system.')
            return 1

    # Read the interface mapping file, if it exists
    # This allows you to override the default network naming abstraction
    # mappings by specifying a specific nicN->name or nicN->MAC mapping
    if os.path.exists(opts.mapping_file):
        logger.info('Using mapping file at: %s' % opts.mapping_file)
        with open(opts.mapping_file) as cf:
            iface_map = yaml.safe_load(cf.read())
            iface_mapping = iface_map.get("interface_mapping")
            logger.debug('interface_mapping JSON: %s' % str(iface_mapping))
            persist_mapping = opts.persist_mapping
            logger.debug('persist_mapping: %s' % persist_mapping)
    else:
        logger.info('Not using any mapping file.')
        iface_mapping = None
        persist_mapping = False

    # If --interfaces is specified, either return the real name of the
    # interfaces specified, or return the map of all nic abstractions/names.
    if opts.interfaces is not None:
        reported_nics = {}
        mapped_nics = objects.mapped_nics(iface_mapping)
        retval = 0
        if len(opts.interfaces) > 0:
            for requested_nic in opts.interfaces:
                found = False
                # Check to see if requested iface is a mapped NIC name.
                if requested_nic in mapped_nics:
                    reported_nics[requested_nic] = mapped_nics[requested_nic]
                    found = True
                # Check to see if the requested iface is a real NIC name
                if requested_nic in mapped_nics.values():
                    if found is True:  # Name matches alias and real NIC
                        # (return the mapped NIC, but warn of overlap).
                        logger.warning('"%s" overlaps with real NIC name.'
                                       % (requested_nic))
                    else:
                        reported_nics[requested_nic] = requested_nic
                        found = True
                if not found:
                    retval = 1
            if reported_nics:
                logger.debug("Interface mapping requested for interface: "
                             "%s" % reported_nics.keys())
        else:
            logger.debug("Interface mapping requested for all interfaces")
            reported_nics = mapped_nics
        # Return the report on the mapped NICs. If all NICs were found, exit
        # cleanly, otherwise exit with status 1.
        logger.debug("Interface report requested, exiting after report.")
        print(reported_nics)
        return retval

    # Read config file containing network configs to apply
    if os.path.exists(opts.config_file):
        try:
            with open(opts.config_file) as cf:
                iface_array = yaml.safe_load(cf.read()).get("network_config")
                logger.debug('network_config JSON: %s' % str(iface_array))
        except IOError:
            logger.error("Error reading file: %s" % opts.config_file)
            return 1
    else:
        logger.error('No config file exists at: %s' % opts.config_file)
        return 1

    if not isinstance(iface_array, list):
        logger.error('No interfaces defined in config: %s' % opts.config_file)
        return 1

    for iface_json in iface_array:
        if iface_json.get('type') != 'route_table':
            iface_json.update({'nic_mapping': iface_mapping})
            iface_json.update({'persist_mapping': persist_mapping})

    validation_errors = validator.validate_config(iface_array)
    if validation_errors:
        if opts.exit_on_validation_errors:
            logger.error('\n'.join(validation_errors))
            return 1
        else:
            logger.warning('\n'.join(validation_errors))

    # Look for the presence of SriovPF types in the first parse of the json
    # if SriovPFs exists then PF devices needs to be configured so that the VF
    # devices are created.
    # The VFs will not be available now and an exception
    # SriovVfNotFoundException will be raised while fetching the device name.
    # After the first parse the SR-IOV PF devices would be configured and the
    # VF devices would be created.
    # In the second parse, all other objects shall be added
    for iface_json in iface_array:
        try:
            obj = objects.object_from_json(iface_json)
        except utils.SriovVfNotFoundException:
            continue
        if isinstance(obj, objects.SriovPF):
            configure_sriov = True
            provider.add_object(obj)
        elif hasattr(obj, 'members') and obj.members is not None:
            if check_configure_sriov(obj):
                configure_sriov = True
                provider.add_object(obj)

    if configure_sriov:
        # Apply the ifcfgs for PFs now, so that NM_CONTROLLED=no is applied
        # for each of the PFs before configuring the numvfs for the PF device.
        # This step allows the network manager to unmanage the created VFs.
        # In the second parse, when these ifcfgs for PFs are encountered,
        # os-net-config skips the ifup <ifcfg-pfs>, since the ifcfgs for PFs
        # wouldn't have changed.
        pf_files_changed = provider.apply(cleanup=opts.cleanup,
                                          activate=not opts.no_activate)
        if not opts.noop:
            utils.configure_sriov_pfs()

    for iface_json in iface_array:
        # All objects other than the sriov_pf will be added here.
        # The VFs are expected to be available now and an exception
        # SriovVfNotFoundException shall be raised if not available.
        try:
            obj = objects.object_from_json(iface_json)
        except utils.SriovVfNotFoundException:
            if not opts.noop:
                raise
        if not isinstance(obj, objects.SriovPF):
            provider.add_object(obj)

    if configure_sriov and not opts.noop:
        utils.configure_sriov_vfs()

    files_changed = provider.apply(cleanup=opts.cleanup,
                                   activate=not opts.no_activate)
    if opts.noop:
        if configure_sriov:
            files_changed.update(pf_files_changed)
        for location, data in files_changed.items():
            print("File: %s\n" % location)
            print(data)
            print("----")

    if opts.detailed_exit_codes and len(files_changed) > 0:
        return 2

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
