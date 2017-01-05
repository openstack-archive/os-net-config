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
    parser.add_argument('-p', '--provider', metavar='PROVIDER',
                        help="""The provider to use."""
                        """One of: ifcfg, eni, iproute.""",
                        default=None)
    parser.add_argument('-r', '--root-dir', metavar='ROOT_DIR',
                        help="""The root directory of the filesystem.""",
                        default='')
    parser.add_argument('--detailed-exit-codes',
                        action='store_true',
                        help="""Enable detailed exit codes. """
                        """If enabled an exit code of '2' means """
                        """that files were modified."""
                        """Disabled by default.""",
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


def main(argv=sys.argv):
    opts = parse_opts(argv)
    configure_logger(opts.verbose, opts.debug)
    logger.info('Using config file at: %s' % opts.config_file)
    if opts.mapping_file:
        logger.info('Using mapping file at: %s' % opts.mapping_file)
    iface_array = []

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

    # Read config file containing network configs to apply
    if os.path.exists(opts.config_file):
        with open(opts.config_file) as cf:
            iface_array = yaml.load(cf.read()).get("network_config")
            logger.debug('network_config JSON: %s' % str(iface_array))
    else:
        logger.error('No config file exists at: %s' % opts.config_file)
        return 1

    if not isinstance(iface_array, list):
        logger.error('No interfaces defined in config: %s' % opts.config_file)
        return 1

    # Read the interface mapping file, if it exists
    # This allows you to override the default network naming abstraction
    # mappings by specifying a specific nicN->name or nicN->MAC mapping
    if os.path.exists(opts.mapping_file):
        with open(opts.mapping_file) as cf:
            iface_map = yaml.load(cf.read())
            iface_mapping = iface_map.get("interface_mapping")
            logger.debug('interface_mapping JSON: %s' % str(iface_mapping))
            persist_mapping = opts.persist_mapping
            logger.debug('persist_mapping: %s' % persist_mapping)
    else:
        iface_mapping = None
        persist_mapping = False

    for iface_json in iface_array:
        iface_json.update({'nic_mapping': iface_mapping})
        iface_json.update({'persist_mapping': persist_mapping})
        obj = objects.object_from_json(iface_json)
        provider.add_object(obj)
    files_changed = provider.apply(cleanup=opts.cleanup,
                                   activate=not opts.no_activate)
    if opts.noop:
        for location, data in files_changed.items():
            print("File: %s\n" % location)
            print(data)
            print("----")

    if opts.detailed_exit_codes and len(files_changed) > 0:
        return 2

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
