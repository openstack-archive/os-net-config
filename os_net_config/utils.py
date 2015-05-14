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


logger = logging.getLogger(__name__)
_SYS_CLASS_NET = '/sys/class/net'


def write_config(filename, data):
    with open(filename, 'w') as f:
        f.write(str(data))


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
    try:
        with open('/sys/class/net/%s/address' % name, 'r') as f:
            return f.read().rstrip()
    except IOError:
        logger.error("Unable to read mac address: %s" % name)
        raise


def _is_active_nic(interface_name):
    try:
        if interface_name == 'lo':
            return False

        addr_assign_type = None
        with open(_SYS_CLASS_NET + '/%s/addr_assign_type' % interface_name,
                  'r') as f:
            addr_assign_type = int(f.read().rstrip())

        carrier = None
        with open(_SYS_CLASS_NET + '/%s/carrier' % interface_name, 'r') as f:
            carrier = int(f.read().rstrip())

        address = None
        with open(_SYS_CLASS_NET + '/%s/address' % interface_name, 'r') as f:
            address = f.read().rstrip()

        if addr_assign_type == 0 and carrier == 1 and address:
            return True
        else:
            return False
    except IOError:
        return False


def ordered_active_nics():
    embedded_nics = []
    nics = []
    for name in glob.iglob(_SYS_CLASS_NET + '/*'):
        nic = name[(len(_SYS_CLASS_NET) + 1):]
        if _is_active_nic(nic):
            if nic.startswith('em') or nic.startswith('eth') or \
                    nic.startswith('eno'):
                embedded_nics.append(nic)
            else:
                nics.append(nic)
    return sorted(embedded_nics) + sorted(nics)


def diff(filename, data):
    file_data = get_file_data(filename)
    logger.debug("Diff file data:\n%s" % file_data)
    logger.debug("Diff data:\n%s" % data)
    # convert to string as JSON may have unicode in it
    return not file_data == data
