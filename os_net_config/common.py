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
# Common functions and variables meant to be shared across various modules
# As opposed to utils, this is meant to be imported from anywhere. We can't
# import anything from os_net_config here.

import logging
import logging.handlers
import os
import sys

SYS_CLASS_NET = '/sys/class/net'
_LOG_FILE = '/var/log/os-net-config.log'


def configure_logger(log_file=False, verbose=False, debug=False):
    LOG_FORMAT = ('%(asctime)s.%(msecs)03d %(levelname)s '
                  '%(name)s.%(funcName)s %(message)s')
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    logger = logging.getLogger("os_net_config")
    logger.handlers.clear()
    logger_level(logger, verbose, debug)
    logger.propagate = True
    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=10485760, backupCount=7
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def logger_level(logger, verbose=False, debug=False):
    log_level = logging.WARN
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    logger.setLevel(log_level)


def get_dev_path(ifname, path=None):
    if not path:
        path = ""
    elif path.startswith("_"):
        path = path[1:]
    else:
        path = f"device/{path}"
    return os.path.join(SYS_CLASS_NET, ifname, path)


def get_vendor_id(ifname):
    try:
        with open(get_dev_path(ifname, "vendor"), 'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return


def get_device_id(ifname):
    try:
        with open(get_dev_path(ifname, 'device'), 'r') as f:
            out = f.read().strip()
        return out
    except IOError:
        return
