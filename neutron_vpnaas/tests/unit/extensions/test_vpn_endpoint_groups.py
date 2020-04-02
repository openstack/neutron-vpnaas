#    (c) Copyright 2015 NEC Corporation, All Rights Reserved.
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

import copy
from unittest import mock

from oslo_utils import uuidutils
from webob import exc

from neutron.tests.unit.api.v2 import test_base as test_api_v2
from neutron_lib.plugins import constants as nconstants

from neutron_vpnaas.extensions import vpn_endpoint_groups
from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.services.vpn.common import constants
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class VpnEndpointGroupsTestPlugin(
        vpnaas.VPNPluginBase,
        vpn_endpoint_groups.VPNEndpointGroupsPluginBase):
    pass


class VpnEndpointGroupsTestCase(base.ExtensionTestCase):

    fmt = 'json'

    def setUp(self):
        super(VpnEndpointGroupsTestCase, self).setUp()
        plural_mappings = {'endpoint_group': 'endpoint-groups'}
        self.setup_extension(
            'neutron_vpnaas.tests.unit.extensions.test_vpn_endpoint_groups.'
            'VpnEndpointGroupsTestPlugin',
            nconstants.VPN,
            vpn_endpoint_groups.Vpn_endpoint_groups,
            'vpn', plural_mappings=plural_mappings,
            use_quota=True)

    def helper_test_endpoint_group_create(self, data):
        """Check that the endpoint_group_create works.

        Uses passed in endpoint group information, which specifies an
        endpoint type and values.
        """
        data['endpoint_group'].update({'tenant_id': _uuid(),
                                       'name': 'my endpoint group',
                                       'description': 'my description'})
        return_value = copy.copy(data['endpoint_group'])
        return_value.update({'id': _uuid()})

        instance = self.plugin.return_value
        instance.create_endpoint_group.return_value = return_value
        res = self.api.post(_get_path('vpn/endpoint-groups', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.assertEqual(1, instance.create_endpoint_group.call_count)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertDictSupersetOf(return_value, res['endpoint_group'])

    def test_create_cidr_endpoint_group_create(self):
        """Test creation of CIDR type endpoint group."""
        data = {'endpoint_group':
                {'type': constants.CIDR_ENDPOINT,
                 'endpoints': ['10.10.10.0/24', '20.20.20.0/24']}}
        self.helper_test_endpoint_group_create(data)

    def test_create_subnet_endpoint_group_create(self):
        """Test creation of subnet type endpoint group."""
        data = {'endpoint_group':
                {'type': constants.SUBNET_ENDPOINT,
                 'endpoints': [_uuid(), _uuid()]}}
        self.helper_test_endpoint_group_create(data)

    def test_create_vlan_endpoint_group_create(self):
        """Test creation of VLAN type endpoint group."""
        data = {'endpoint_group':
                {'type': constants.VLAN_ENDPOINT,
                 'endpoints': ['100', '200', '300', '400']}}
        self.helper_test_endpoint_group_create(data)

    def test_get_endpoint_group(self):
        """Test show for endpoint group."""
        endpoint_group_id = _uuid()
        return_value = {'id': endpoint_group_id,
                        'tenant_id': _uuid(),
                        'name': 'my-endpoint-group',
                        'description': 'my endpoint group',
                        'type': constants.CIDR_ENDPOINT,
                        'endpoints': ['10.10.10.0/24']}

        instance = self.plugin.return_value
        instance.get_endpoint_group.return_value = return_value

        res = self.api.get(_get_path('vpn/endpoint-groups',
                                     id=endpoint_group_id,
                                     fmt=self.fmt))

        instance.get_endpoint_group.assert_called_with(mock.ANY,
                                                       endpoint_group_id,
                                                       fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(res['endpoint_group'], return_value)

    def test_endpoint_group_list(self):
        """Test listing all endpoint groups."""
        return_value = [{'id': _uuid(),
                         'tenant_id': _uuid(),
                         'name': 'my-endpoint-group',
                         'description': 'my endpoint group',
                         'type': constants.CIDR_ENDPOINT,
                         'endpoints': ['10.10.10.0/24']},
                        {'id': _uuid(),
                         'tenant_id': _uuid(),
                         'name': 'another-endpoint-group',
                         'description': 'second endpoint group',
                         'type': constants.VLAN_ENDPOINT,
                         'endpoints': ['100', '200', '300']}]

        instance = self.plugin.return_value
        instance.get_endpoint_groups.return_value = return_value

        res = self.api.get(_get_path('vpn/endpoint-groups', fmt=self.fmt))

        instance.get_endpoint_groups.assert_called_with(mock.ANY,
                                                        fields=mock.ANY,
                                                        filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_endpoint_group_delete(self):
        """Test deleting an endpoint group."""
        self._test_entity_delete('endpoint_group')

    def test_endpoint_group_update(self):
        """Test updating endpoint_group."""
        endpoint_group_id = _uuid()
        update_data = {'endpoint_group': {'description': 'new description'}}
        return_value = {'id': endpoint_group_id,
                        'tenant_id': _uuid(),
                        'name': 'my-endpoint-group',
                        'description': 'new_description',
                        'type': constants.CIDR_ENDPOINT,
                        'endpoints': ['10.10.10.0/24']}

        instance = self.plugin.return_value
        instance.update_endpoint_group.return_value = return_value

        res = self.api.put(_get_path('vpn/endpoint-groups',
                                     id=endpoint_group_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_endpoint_group.assert_called_with(
            mock.ANY, endpoint_group_id, endpoint_group=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(res['endpoint_group'], return_value)

    def test_fail_updating_endpoints_in_endpoint_group(self):
        """Test fails to update the endpoints in an endpoint group.

        This documents that we are not allowing endpoints to be updated
        (currently), as doing so, implies that the connection using the
        enclosing endpoint group would also need to be updated. For now,
        a new endpoint group can be created, and the connection can be
        updated to point to the new endpoint group.
        """
        endpoint_group_id = _uuid()
        update_data = {'endpoint_group': {'endpoints': ['10.10.10.0/24']}}
        res = self.api.put(_get_path('vpn/endpoint-groups',
                                     id=endpoint_group_id,
                                     fmt=self.fmt),
                           params=self.serialize(update_data),
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
