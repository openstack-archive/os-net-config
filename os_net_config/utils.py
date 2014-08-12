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

import logging


logger = logging.getLogger(__name__)


def write_config(filename, data):
    with open(filename, "w") as f:
        f.write(str(data))


def get_file_data(filename):
    try:
        with open(filename, "r") as f:
            return f.read()
    except IOError:
        logger.error("Error reading file: %s" % filename)
        return ""


def interface_mac(name):
    try:
        with open('/sys/class/net/%s/address' % name, "r") as f:
            return f.read().rstrip()
    except IOError:
        logger.error("Unable to read file: %s" % name)
        raise


def diff(filename, data):
    file_data = get_file_data(filename)
    logger.debug("Diff file data:\n%s" % file_data)
    logger.debug("Diff data:\n%s" % data)
    # convert to string as JSON may have unicode in it
    return not file_data == data
