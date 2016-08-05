# -*- coding: utf-8 -*-

# Copyright 2010-2011 OpenStack Foundation
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
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

import fixtures
import stubout
import testtools

from os_net_config import objects

_TRUE_VALUES = ('True', 'true', '1', 'yes')


class TestCase(testtools.TestCase):

    """Test case base class for all unit tests."""
    stub_mapped_nics = True

    def setUp(self):
        """Run before each test method to initialize test environment."""

        super(TestCase, self).setUp()
        self.stubs = stubout.StubOutForTesting()
        self.stubbed_mapped_nics = {}

        def dummy_mapped_nics(nic_mapping=None):
            return self.stubbed_mapped_nics
        if self.stub_mapped_nics:
            self.stubs.Set(objects, '_mapped_nics', dummy_mapped_nics)

        test_timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            test_timeout = int(test_timeout)
        except ValueError:
            # If timeout value is invalid do not set a timeout.
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))

        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())

        if os.environ.get('OS_STDOUT_CAPTURE') in _TRUE_VALUES:
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if os.environ.get('OS_STDERR_CAPTURE') in _TRUE_VALUES:
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))

        self.log_fixture = self.useFixture(fixtures.FakeLogger())

    def tearDown(self):
        self.stubs.UnsetAll()
        self.stubs.SmartUnsetAll()
        super(TestCase, self).tearDown()
