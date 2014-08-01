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


import argparse
import json
import logging
import os
import sys

import os_net_config
from os_net_config import impl_eni
from os_net_config import impl_ifcfg
from os_net_config import impl_iproute
from os_net_config import objects


logger = logging.getLogger(__name__)


def parse_opts(argv):
    parser = argparse.ArgumentParser(
        description='Configure host network interfaces using a JSON'
        ' config file format.')
    parser.add_argument('-c', '--config-file', metavar='CONFIG_FILE',
                        help="""path to the configuration file.""",
                        default='/etc/os-net-config/config.json')
    parser.add_argument('-p', '--provider', metavar='PROVIDER',
                        help="""The provider to use."""
                        """One of: ifcfg, eni, iproute.""",
                        default=None)
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
                        version=os_net_config.__version__)
    parser.add_argument(
        '-m', '--mock',
        dest="mock",
        action='store_true',
        help="Return the configuration commands, without applying them.",
        required=False)

    opts = parser.parse_args(argv[1:])

    return opts


def configure_logger(verbose=False, debug=False):
    LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
    DATE_FORMAT = '%Y/%m/%d %I:%M:%S %p'
    log_level = logging.WARN

    if verbose:
        log_level = logging.DEBUG
    elif debug:
        log_level = logging.INFO

    logging.basicConfig(format=LOG_FORMAT, datefmt=DATE_FORMAT,
                        level=log_level)


def main(argv=sys.argv):
    opts = parse_opts(argv)
    configure_logger(opts.verbose, opts.debug)
    logger.info('Using config file at: %s' % opts.config_file)
    iface_array = []

    provider = None
    if opts.provider:
        if opts.provider == 'ifcfg':
            provider = impl_ifcfg.IfcfgNetConfig()
        elif opts.provider == 'eni':
            provider = impl_eni.ENINetConfig()
        elif opts.provider == 'iproute':
            provider = impl_iproute.IPRouteNetConfig()
        else:
            logger.error('Invalid provider specified.')
            return 1
    else:
        if os.path.exists('/etc/sysconfig/network-scripts/'):
            provider = impl_ifcfg.IfcfgNetConfig()
        elif os.path.exists('/etc/network/'):
            provider = impl_eni.ENINetConfig()
        else:
            logger.error('Unable to set provider for this operating system.')
            return 1

    if os.path.exists(opts.config_file):
        with open(opts.config_file) as cf:
            iface_array = json.loads(cf.read()).get("network_config")
            logger.debug('network_config JSON: %s' % str(iface_array))
    else:
        logger.error('No config file exists at: %s' % opts.config_file)
        return 1
    if not isinstance(iface_array, list):
        logger.error('No interfaces defined in config: %s' % opts.config_file)
        return 1
    for iface_json in iface_array:
        obj = objects.object_from_json(iface_json)
        provider.addObject(obj)
    if opts.mock:
        res = provider.apply(mock=True)
        print res
    else:
        provider.apply()
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
