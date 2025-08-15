# Copyright (c) Ericsson Software Technology 2025  Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_policy import policy as base_policy

from neutron import policy
from neutron.tests.unit.conf.policies import test_base as base


class VpnServiceAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        self.target = {
            'project_id': self.project_id,
            'tenant_id': self.project_id}
        self.alt_target = {
            'project_id': self.alt_project_id,
            'tenant_id': self.alt_project_id}


class SystemAdminTests(VpnServiceAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.system_admin_ctx

    def test_create_vpnservice(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_vpnservice',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'create_vpnservice',
            self.alt_target)

    def test_update_vpnservice(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_vpnservice',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'update_vpnservice',
            self.alt_target)

    def test_delete_vpnservice(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_vpnservice',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'delete_vpnservice',
            self.alt_target)

    def test_get_vpnservice(self):
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_vpnservice',
            self.target)
        self.assertRaises(
            base_policy.InvalidScope,
            policy.enforce, self.context, 'get_vpnservice',
            self.alt_target)


class SystemMemberTests(SystemAdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_member_ctx


class SystemReaderTests(SystemMemberTests):

    def setUp(self):
        super().setUp()
        self.context = self.system_reader_ctx


class AdminTests(VpnServiceAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.project_admin_ctx

    def test_create_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_vpnservice', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'create_vpnservice', self.alt_target))

    def test_update_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_vpnservice', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'update_vpnservice', self.alt_target))

    def test_delete_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_vpnservice', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_vpnservice', self.alt_target))

    def test_get_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_vpnservice', self.target))
        self.assertTrue(
            policy.enforce(
                self.context, 'get_vpnservice', self.alt_target))


class ProjectManagerTests(AdminTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_manager_ctx

    def test_create_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'create_vpnservice', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_vpnservice',
            self.alt_target)

    def test_update_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'update_vpnservice', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_vpnservice',
            self.alt_target)

    def test_delete_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'delete_vpnservice', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_vpnservice',
            self.alt_target)

    def test_get_vpnservice(self):
        self.assertTrue(
            policy.enforce(
                self.context, 'get_vpnservice', self.target))
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_vpnservice',
            self.alt_target)


class ProjectMemberTests(ProjectManagerTests):

    def setUp(self):
        super().setUp()
        self.context = self.project_member_ctx


class ServiceRoleTests(VpnServiceAPITestCase):

    def setUp(self):
        super().setUp()
        self.context = self.service_ctx

    def test_create_vpnservice(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'create_vpnservice', self.target)

    def test_update_vpnservice(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'update_vpnservice', self.target)

    def test_delete_vpnservice(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'delete_vpnservice', self.target)

    def test_get_vpnservice(self):
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce, self.context, 'get_vpnservice', self.target)
