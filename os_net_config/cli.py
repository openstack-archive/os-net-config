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
    parser.add_argument('--version', action='version',
                        version=os_net_config.__version__)
    opts = parser.parse_args(argv[1:])

    return opts


def main(argv=sys.argv):
    opts = parse_opts(argv)
    logger.info('Using config file at: %s' % opts.config_file)
    iface_array = []

    provider = None
    if opts.provider:
        if opts.provider == 'ifcfg':
            provider = impl_ifcfg.IfcfgNetConfig()
        elif opts.provider == 'eni':
            provider = impl_eni.ENINetConfig()
        elif opts.provider == 'iproute':
            provider = impl_iproute.IprouteNetConfig()
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
    provider.apply()
    return 0


LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
DATE_FORMAT = '%Y/%m/%d %I:%M:%S %p'


def add_handler(logger, handler):
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(handler)
logger = logging.getLogger('os-net-config')
logger.setLevel(logging.INFO)
add_handler(logger, logging.StreamHandler())
if os.geteuid() == 0:
    add_handler(logger, logging.FileHandler('/var/log/os-net-config.log'))

if __name__ == '__main__':
    sys.exit(main(sys.argv))
