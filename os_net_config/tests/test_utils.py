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

import os.path
import shutil
import tempfile

from os_net_config.tests import base
from os_net_config import utils


class TestUtils(base.TestCase):

    def test_ordered_active_nics(self):

        tmpdir = tempfile.mkdtemp()
        self.stubs.Set(utils, '_SYS_CLASS_NET', tmpdir)

        def test_is_active_nic(interface_name):
            return True
        self.stubs.Set(utils, '_is_active_nic', test_is_active_nic)

        for nic in ['a1', 'em1', 'em2', 'eth2', 'z1',
                    'enp8s0', 'enp10s0', 'enp1s0f0']:
            with open(os.path.join(tmpdir, nic), 'w') as f:
                f.write(nic)

        nics = utils.ordered_active_nics()
        self.assertEqual('em1', nics[0])
        self.assertEqual('em2', nics[1])
        self.assertEqual('eth2', nics[2])
        self.assertEqual('a1', nics[3])
        self.assertEqual('enp1s0f0', nics[4])
        self.assertEqual('enp8s0', nics[5])
        self.assertEqual('enp10s0', nics[6])
        self.assertEqual('z1', nics[7])

        shutil.rmtree(tmpdir)
