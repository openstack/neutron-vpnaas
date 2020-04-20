# Copyright (c) 2015 OpenStack Foundation.
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

from unittest import mock

from neutron.tests import base
from neutron_vpnaas.services.vpn.common import netns_wrapper as nswrap


class TestNetnsWrapper(base.BaseTestCase):

    def setUp(self):
        super(TestNetnsWrapper, self).setUp()
        patch_methods = ['filter_command',
                         'execute',
                         'setup_conf']
        for method in patch_methods:
            self.patch_obj(nswrap, method)
        patch_classes = ['neutron.common.config.setup_logging',
                         'os.path.isdir',
                         'os.path.samefile',
                         'sys.exit']
        for cls in patch_classes:
            self.patch_cls(cls)

        self.filter_command.return_value = False
        self.execute.return_value = 0
        self.conf = mock.Mock()
        self.conf.cmd = 'ls,-al'
        self.conf.mount_paths = {'/foo': '/dir/foo',
                                 '/var': '/dir/var'}
        self.setup_conf.return_value = self.conf
        self.conf.rootwrap_config = 'conf'
        self.isdir.return_value = True
        self.samefile.return_value = False

    def patch_obj(self, obj, method):
        _m = mock.patch.object(obj, method)
        _mock = _m.start()
        setattr(self, method, _mock)

    def patch_cls(self, patch_class):
        _m = mock.patch(patch_class)
        mock_name = patch_class.split('.')[-1]
        _mock = _m.start()
        setattr(self, mock_name, _mock)

    def test_netns_wrap_fail_without_netns(self):
        self.samefile.return_value = True
        return_val = nswrap.execute_with_mount()
        self.assertTrue(return_val)

    def test_netns_wrap(self):
        self.conf.cmd = 'ls,-al'
        return_val = nswrap.execute_with_mount()
        exp_calls = [mock.call(['mount', '--bind', '/dir/foo', '/foo']),
                     mock.call(['mount', '--bind', '/dir/var', '/var']),
                     mock.call('ls,-al')]
        self.execute.assert_has_calls(exp_calls, any_order=True)
        self.assertFalse(return_val)

    def test_netns_wrap_fail_without_cmd(self):
        self.conf.cmd = None
        return_val = nswrap.execute_with_mount()
        self.assertFalse(self.execute.called)
        self.assertTrue(return_val)

    def test_netns_wrap_fail_without_mount_paths(self):
        self.conf.mount_paths = None
        return_val = nswrap.execute_with_mount()
        self.assertFalse(self.execute.called)
        self.assertTrue(return_val)
