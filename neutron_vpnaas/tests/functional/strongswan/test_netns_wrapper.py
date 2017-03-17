# Copyright (c) 2015 Canonical, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re

from neutron.agent.linux import utils
from neutron.conf.agent import common as config
from neutron.tests.common import net_helpers
from neutron.tests.functional import base

WRAPPER_SCRIPT = 'neutron-vpn-netns-wrapper'
STATUS_PATTERN = re.compile('Command:.*ip.*addr.*show.*Exit code: 0')


class TestNetnsWrapper(base.BaseSudoTestCase):

    def setUp(self):
        super(TestNetnsWrapper, self).setUp()
        config.setup_logging()
        self.fake_ns = 'func-8f1b728c-6eca-4042-9b6b-6ef66ab9352a'
        self.mount_paths = ('--mount_paths=/etc:/var/lib/neutron'
                            '/vpnaas/%(ns)s/etc,/var/run:/var/lib'
                            '/neutron/vpnaas/%(ns)s/var/run')
        self.fake_pth = self.mount_paths % {'ns': self.fake_ns}

    def test_netns_wrap_success(self):
        client_ns = self.useFixture(net_helpers.NamespaceFixture()).ip_wrapper
        ns = client_ns.namespace
        pth = self.mount_paths % {'ns': ns}
        cmd = WRAPPER_SCRIPT, pth, '--cmd=ip,addr,show'
        output = client_ns.netns.execute(cmd)
        self.assertTrue(STATUS_PATTERN.search(output))

    def test_netns_wrap_fail_without_netns(self):
        cmd = [WRAPPER_SCRIPT, self.fake_pth,
               '--cmd=ip,addr,show']
        self.assertRaises(RuntimeError, utils.execute, cmd=cmd,
                          run_as_root=True)

    def test_netns_wrap_unauthorized_command(self):
        cmd = [WRAPPER_SCRIPT, self.fake_pth,
               '--cmd=nofiltercommand']
        self.assertRaises(RuntimeError, utils.execute, cmd=cmd,
                          run_as_root=True)
