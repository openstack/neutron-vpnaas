# Copyright 2015 Brocade Communications System, Inc.
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
#

import sys

import mock
from neutron.agent.l3 import legacy_router
from oslo_utils import uuidutils

from neutron_vpnaas.tests import base

with mock.patch.dict(sys.modules, {
    'networking_brocade': mock.Mock(),
    'networking_brocade.vyatta': mock.Mock(),
    'networking_brocade.vyatta.common': mock.Mock(),
    'networking_brocade.vyatta.vrouter': mock.Mock(),
    'networking_brocade.vyatta.vpn': mock.Mock(),
}):
    from networking_brocade.vyatta.common import vrouter_config
    from networking_brocade.vyatta.vpn import config as vyatta_vpn_config
    from neutron_vpnaas.services.vpn.device_drivers import vyatta_ipsec


_uuid = uuidutils.generate_uuid

FAKE_HOST = 'fake_host'


class TestNeutronServerAPI(base.BaseTestCase):

    def setUp(self):
        super(TestNeutronServerAPI, self).setUp()

        get_client_mock = mock.patch(
            'neutron.common.rpc.get_client').start()
        self.client = get_client_mock.return_value

        self.api = vyatta_ipsec.NeutronServerAPI('fake-topic')

    def test_get_vpn_services_on_host(self):
        fake_context = mock.Mock()

        svc_connections = [
            self._make_svc_connection(),
            self._make_svc_connection()
        ]

        vpn_services_on_host = [{
            vyatta_ipsec._KEY_CONNECTIONS: svc_connections
        }]

        cctxt = self.client.prepare.return_value
        cctxt.call.return_value = vpn_services_on_host

        vpn_services = self.api.get_vpn_services_on_host(
            fake_context, FAKE_HOST)

        cctxt.call.assert_called_with(
            fake_context, 'get_vpn_services_on_host', host=FAKE_HOST)

        validate_func = vyatta_vpn_config.validate_svc_connection
        for connection in svc_connections:
            validate_func.assert_any_call(connection)

        self.assertEqual(len(vpn_services_on_host), len(vpn_services))

    def test_update_status(self):
        context = mock.Mock()
        fake_status = 'fake-status'

        cctxt = self.client.prepare.return_value

        self.api.update_status(context, 'fake-status')
        cctxt.cast.assert_called_once_with(
            context, 'update_status', status=fake_status)

    @staticmethod
    def _make_svc_connection():
        return {
            vyatta_ipsec._KEY_IKEPOLICY: {
                'encryption_algorithm': 'aes-256',
                'lifetime_units': 'seconds',
            },
            vyatta_ipsec._KEY_ESPPOLICY: {
                'encryption_algorithm': 'aes-256',
                'lifetime_units': 'seconds',
                'transform_protocol': 'esp',
                'pfs': 'dh-group2',
                'encapsulation_mode': 'tunnel'
            },
            'dpd_action': 'hold',
        }


class TestVyattaDeviceDriver(base.BaseTestCase):

    def setUp(self):
        super(TestVyattaDeviceDriver, self).setUp()

        mock.patch('oslo_service.loopingcall.DynamicLoopingCall').start()
        self.server_api = mock.patch(
            'neutron_vpnaas.services.vpn.device_drivers'
            '.vyatta_ipsec.NeutronServerAPI').start()

        self.agent = mock.Mock()

        self.driver = vyatta_ipsec.VyattaIPSecDriver(self.agent, FAKE_HOST)

    def test_create_router(self):
        router_id = _uuid()
        router = mock.Mock(legacy_router.LegacyRouter)
        router.router_id = router_id

        vrouter_svc_list = [self._make_vrouter_svc()]

        parse_vrouter_config = mock.Mock()
        parse_vrouter_config.return_value = vrouter_svc_list

        with mock.patch.object(vrouter_config, 'parse_config'), \
                mock.patch.object(vyatta_vpn_config, 'parse_vrouter_config',
                                  parse_vrouter_config), \
                mock.patch.object(self.driver, 'get_router_resources',
                                  mock.MagicMock()):
            self.driver.create_router(router)

        svc_cache = self.driver._svc_cache
        self.assertEqual(1, len(svc_cache))
        self.assertEqual(router_id, svc_cache[0]['router_id'])
        ipsec_connections = svc_cache[0]['ipsec_site_connections']
        self.assertEqual(
            '172.24.4.234',
            ipsec_connections[0]['peer_address'])

    def test_destroy_router(self):
        router_id = _uuid()

        get_router_resources = mock.Mock()

        vrouter_svc = self._make_vrouter_svc()
        vrouter_svc['router_id'] = router_id
        svc_cache = [vrouter_svc]

        svc_delete = mock.Mock()

        with mock.patch.object(self.driver, 'get_router_resources',
                               get_router_resources), \
                mock.patch.object(self.driver, '_svc_delete', svc_delete), \
                mock.patch.object(self.driver, '_svc_cache', svc_cache):
            self.driver.destroy_router(router_id)

        self.assertNotIn(vrouter_svc, svc_cache)

        svc_delete.assert_called_with(vrouter_svc, mock.ANY)

    def test_sync(self):
        router_id = _uuid()
        self.agent.router_info = {
            router_id: mock.Mock()
        }

        to_del = [self._make_svc()]
        to_change = [
            (self._make_svc(), self._make_svc()),
        ]
        to_add = [self._make_svc()]

        svc_diff = mock.Mock()
        svc_diff.return_value = (
            to_del,
            to_change,
            to_add,
        )

        svc_delete = mock.Mock()
        svc_add = mock.Mock()

        with mock.patch.object(self.driver, '_svc_diff', svc_diff), \
                mock.patch.object(self.driver, '_svc_delete', svc_delete), \
                mock.patch.object(self.driver, '_svc_add', svc_add):
            self.driver.sync(mock.Mock(), None)

        for svc in to_add:
            svc_add.assert_any_call(svc, mock.ANY)

        for svc in to_del:
            svc_delete.assert_any_call(svc, mock.ANY)

        for old, new in to_change:
            svc_delete.assert_any_call(old, mock.ANY)
            svc_add.assert_any_call(new, mock.ANY)

    @staticmethod
    def _make_vrouter_svc():
        return {
            'id': _uuid(),
            vyatta_ipsec._KEY_CONNECTIONS: [{
                'peer_address': '172.24.4.234',
            }]
        }

    @staticmethod
    def _make_svc():
        return {
            'router_id': _uuid()
        }
