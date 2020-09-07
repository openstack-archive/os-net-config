# -*- coding: utf-8 -*-

# Copyright 2019 Red Hat, Inc.
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

import os
import os.path
import random


from os_net_config import sriov_bind_config
from os_net_config.tests import base
from os_net_config import utils


class TestSriovBindConfig(base.TestCase):
    """Unit tests for methods defined in sriov_bind_config.py"""

    def setUp(self):
        super(TestSriovBindConfig, self).setUp()
        rand = str(int(random.random() * 100000))

        sriov_bind_config._SRIOV_BIND_CONFIG_FILE = '/tmp/' + rand +\
            'sriov_bind_config.yaml'
        sriov_bind_config._PCI_DRIVER_BIND_FILE_PATH = '/tmp/' + rand +\
            '%(driver)s/bind'

    def tearDown(self):
        super(TestSriovBindConfig, self).tearDown()
        if os.path.isfile(sriov_bind_config._SRIOV_BIND_CONFIG_FILE):
            os.remove(sriov_bind_config._SRIOV_BIND_CONFIG_FILE)

    def test_bind_vfs(self):
        """Test SR-IOV VFs binding"""
        vfs_driver = "mlx5_core"
        sriov_bind_pcis_map = {vfs_driver: ['0000:03:00.2', '0000:03:00.3']}
        os.makedirs(sriov_bind_config._PCI_DRIVER_BIND_FILE_PATH %
                    {"driver": vfs_driver})

        utils.write_yaml_config(sriov_bind_config._SRIOV_BIND_CONFIG_FILE,
                                sriov_bind_pcis_map)
        sriov_bind_config.bind_vfs()
