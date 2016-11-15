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

import mock
from neutron import context as n_ctx
from neutron_lib import constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn.service_drivers import vyatta_ipsec
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid

FAKE_HOST = 'fake_host'
FAKE_SERVICE_ID = _uuid()
FAKE_VPN_CONNECTION = {
    'vpnservice_id': FAKE_SERVICE_ID
}
FAKE_ROUTER_ID = _uuid()
FAKE_VPN_SERVICE = {
    'router_id': FAKE_ROUTER_ID
}


class TestVyattaDriver(base.BaseTestCase):

    def setUp(self):
        super(TestVyattaDriver, self).setUp()
        mock.patch('neutron.common.rpc.create_connection').start()

        l3_agent = mock.Mock()
        l3_agent.host = FAKE_HOST
        plugin = mock.Mock()
        plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        directory.add_plugin(constants.CORE, plugin)
        directory.add_plugin(constants.L3, plugin)
        service_plugin = mock.Mock()
        service_plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        self._fake_vpn_router_id = _uuid()
        service_plugin._get_vpnservice.return_value = {
            'router_id': self._fake_vpn_router_id
        }
        self.driver = vyatta_ipsec.VyattaIPsecDriver(service_plugin)

    def _test_update(self, func, args, additional_info=None):
        ctxt = n_ctx.Context('', 'somebody')
        with mock.patch.object(self.driver.agent_rpc.client, 'cast'
                               ) as rpc_mock, \
                mock.patch.object(self.driver.agent_rpc.client, 'prepare'
                                  ) as prepare_mock:
            prepare_mock.return_value = self.driver.agent_rpc.client
            func(ctxt, *args)

        prepare_args = {'server': 'fake_host', 'version': '1.0'}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(ctxt, 'vpnservice_updated',
                                         **additional_info)

    def test_create_ipsec_site_connection(self):
        self._test_update(self.driver.create_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION],
                          {'router': {'id': self._fake_vpn_router_id}})

    def test_update_ipsec_site_connection(self):
        self._test_update(self.driver.update_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION, FAKE_VPN_CONNECTION],
                          {'router': {'id': self._fake_vpn_router_id}})

    def test_delete_ipsec_site_connection(self):
        self._test_update(self.driver.delete_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION],
                          {'router': {'id': self._fake_vpn_router_id}})

    def test_update_vpnservice(self):
        self._test_update(self.driver.update_vpnservice,
                          [FAKE_VPN_SERVICE, FAKE_VPN_SERVICE],
                          {'router': {'id': FAKE_VPN_SERVICE['router_id']}})

    def test_delete_vpnservice(self):
        self._test_update(self.driver.delete_vpnservice,
                          [FAKE_VPN_SERVICE],
                          {'router': {'id': FAKE_VPN_SERVICE['router_id']}})
