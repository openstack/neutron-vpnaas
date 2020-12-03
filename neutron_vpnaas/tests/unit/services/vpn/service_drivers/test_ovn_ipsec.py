# Copyright 2020, SysEleven GbmH
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

from neutron_lib import context as n_ctx
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn.service_drivers import ipsec_validator
from neutron_vpnaas.services.vpn.service_drivers \
    import ovn_ipsec as ipsec_driver
from neutron_vpnaas.tests import base


_uuid = uuidutils.generate_uuid

FAKE_HOST = 'fake_host'
FAKE_TENANT_ID = 'tenant1'
FAKE_ROUTER_ID = _uuid()
FAKE_TRANSIT_IP_ADDRESS = '169.254.0.2'

FAKE_VPNSERVICE_1 = {
    'id': _uuid(),
    'router_id': FAKE_ROUTER_ID,
    'tenant_id': FAKE_TENANT_ID
}

FAKE_VPNSERVICE_2 = {
    'id': _uuid(),
    'router_id': FAKE_ROUTER_ID,
    'tenant_id': FAKE_TENANT_ID
}

FAKE_VPN_CONNECTION_1 = {
    'vpnservice_id': FAKE_VPNSERVICE_1['id']
}


class FakeSqlQueryObject(dict):
    """To fake SqlAlchemy query object and access keys as attributes."""

    def __init__(self, **entries):
        self.__dict__.update(entries)
        super(FakeSqlQueryObject, self).__init__(**entries)


class FakeGatewayDB(object):
    def __init__(self):
        self.gateways_by_router = {}
        self.gateways_by_id = {}

    def create_gateway(self, context, gateway):
        info = gateway['gateway']
        fake_gw = {
            'id': _uuid(),
            'status': 'PENDING_CREATE',
            'external_fixed_ips': [{'subnet_id': '1',
                                    'ip_address': '10.2.3.4'}],
            **info
        }
        self.gateways_by_router[info['router_id']] = fake_gw
        self.gateways_by_id[fake_gw['id']] = fake_gw
        return fake_gw

    def update_gateway(self, context, gateway_id, gateway):
        self.gateways_by_id[gateway_id].update(**gateway['gateway'])

    def delete_gateway(self, context, gateway_id):
        fake_gw = self.gateways_by_id.pop(gateway_id, None)
        if fake_gw:
            self.gateways_by_router.pop(fake_gw['router_id'])
        return 1 if fake_gw else 0

    def get_vpn_gw_dict_by_router_id(self, context, router_id, refresh=False):
        return self.gateways_by_router.get(router_id)


class TestOvnIPsecDriver(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        mock.patch('neutron_lib.rpc.Connection').start()
        self.create_port = \
            mock.patch('neutron_lib.plugins.utils.create_port').start()
        self.create_network = \
            mock.patch('neutron_lib.plugins.utils.create_network').start()
        self.create_subnet = \
            mock.patch('neutron_lib.plugins.utils.create_subnet').start()

        self.create_port.side_effect = lambda pl, c, p: {
            'id': _uuid(),
            'fixed_ips': [{'subnet_id': '1', 'ip_address': '10.1.1.2'}]}
        self.create_network.side_effect = lambda pl, c, n: {'id': _uuid()}
        self.create_subnet.side_effect = lambda pl, c, s: {'id': _uuid()}

        vpn_agent = {'host': FAKE_HOST}

        self.core_plugin = mock.Mock()
        self.core_plugin.get_vpn_agents_hosting_routers.return_value = \
            [vpn_agent]

        directory.add_plugin(constants.CORE, self.core_plugin)

        self._fake_router = FakeSqlQueryObject(
            id=FAKE_ROUTER_ID,
            gw_port=FakeSqlQueryObject(network_id=_uuid())
        )

        self.l3_plugin = mock.Mock()
        self.l3_plugin.get_router.return_value = self._fake_router
        directory.add_plugin(constants.L3, self.l3_plugin)

        self.svc_plugin = mock.Mock()
        self.svc_plugin.get_vpn_agents_hosting_routers.return_value = \
            [vpn_agent]
        self.svc_plugin.schedule_router.return_value = vpn_agent
        self.svc_plugin._get_vpnservice.return_value = FakeSqlQueryObject(
            router_id=FAKE_ROUTER_ID,
            router=self._fake_router
        )
        self.svc_plugin.get_vpnservice.return_value = FAKE_VPNSERVICE_1
        self.svc_plugin.get_vpnservice_router_id.return_value = FAKE_ROUTER_ID
        self.driver = ipsec_driver.IPsecOvnVPNDriver(self.svc_plugin)
        self.validator = ipsec_validator.IpsecVpnValidator(self.driver)
        self.context = n_ctx.get_admin_context()

    def test_create_vpnservice(self):
        mock.patch.object(self.driver.agent_rpc.client, 'cast')
        mock.patch.object(self.driver.agent_rpc.client, 'prepare')
        fake_gw_db = FakeGatewayDB()

        self.svc_plugin.get_vpn_gw_dict_by_router_id.side_effect = \
            fake_gw_db.get_vpn_gw_dict_by_router_id
        self.svc_plugin.create_gateway.side_effect = fake_gw_db.create_gateway
        self.svc_plugin.update_gateway.side_effect = fake_gw_db.update_gateway

        self.driver.create_vpnservice(self.context, FAKE_VPNSERVICE_1)
        self.svc_plugin.create_gateway.assert_called_once()

        # check that the plugin utils create functions were called
        self.create_port.assert_called()
        self.create_network.assert_called_once()
        self.create_subnet.assert_called_once()

        # check that the core plugin create functions were not called directly
        self.core_plugin.create_port.assert_not_called()
        self.core_plugin.create_network.assert_not_called()
        self.core_plugin.create_subnet.assert_not_called()

        self.svc_plugin.reset_mock()

        self.driver.create_vpnservice(self.context, FAKE_VPNSERVICE_2)
        self.svc_plugin.create_gateway.assert_not_called()

    def test_delete_vpnservice(self):
        mock.patch.object(self.driver.agent_rpc.client, 'cast')
        mock.patch.object(self.driver.agent_rpc.client, 'prepare')
        fake_gw_db = FakeGatewayDB()
        self.svc_plugin.get_vpn_gw_dict_by_router_id.side_effect = \
            fake_gw_db.get_vpn_gw_dict_by_router_id
        self.svc_plugin.create_gateway.side_effect = fake_gw_db.create_gateway
        self.svc_plugin.update_gateway.side_effect = fake_gw_db.update_gateway
        self.svc_plugin.delete_gateway.side_effect = fake_gw_db.delete_gateway

        # create 2 VPN services on same router
        self.driver.create_vpnservice(self.context, FAKE_VPNSERVICE_1)
        self.driver.create_vpnservice(self.context, FAKE_VPNSERVICE_2)
        self.svc_plugin.reset_mock()

        # deleting one VPN service must not delete the VPN gateway
        self.svc_plugin.get_vpnservices.return_value = [FAKE_VPNSERVICE_2]
        self.driver.delete_vpnservice(self.context, FAKE_VPNSERVICE_1)
        self.core_plugin.delete_port.assert_not_called()
        self.core_plugin.delete_network.assert_not_called()
        self.core_plugin.delete_subnet.assert_not_called()
        self.svc_plugin.create_gateway.assert_not_called()
        self.svc_plugin.delete_gateway.assert_not_called()

        # deleting last VPN service shall delete the VPN gateway
        self.svc_plugin.get_vpnservices.return_value = []
        self.driver.delete_vpnservice(self.context, FAKE_VPNSERVICE_1)
        self.core_plugin.delete_port.assert_called()
        self.core_plugin.delete_network.assert_called_once()
        self.core_plugin.delete_subnet.assert_called_once()
        self.svc_plugin.create_gateway.assert_not_called()
        self.svc_plugin.delete_gateway.assert_called_once()

    def _test_ipsec_site_connection(self, old_peers, new_peers,
                                    func, args,
                                    expected_add, expected_remove):
        self._fake_router['routes'] = [
            {'destination': peer, 'nexthop': FAKE_TRANSIT_IP_ADDRESS}
            for peer in old_peers
        ]
        transit_port = FakeSqlQueryObject(
            id=_uuid(),
            fixed_ips=[
                {'subnet_id': _uuid(), 'ip_address': FAKE_TRANSIT_IP_ADDRESS}
            ]
        )
        self.svc_plugin.get_vpn_gw_by_router_id.return_value = \
            FakeSqlQueryObject(id=_uuid(),
                               router_id=FAKE_ROUTER_ID,
                               transit_port_id=transit_port.id,
                               transit_port=transit_port)

        self.svc_plugin.get_peer_cidrs_for_router.return_value = new_peers

        # create/update/delete_ipsec_site_connection
        with mock.patch.object(self.driver.agent_rpc.client, 'cast'
                               ) as rpc_mock, \
                mock.patch.object(self.driver.agent_rpc.client, 'prepare'
                                  ) as prepare_mock:
            prepare_mock.return_value = self.driver.agent_rpc.client
            func(self.context, *args)

        prepare_args = {'server': 'fake_host', 'version': '1.0'}
        prepare_mock.assert_called_once_with(**prepare_args)

        # check that agent RPC vpnservice_updated is called
        rpc_mock.assert_called_once_with(self.context, 'vpnservice_updated',
                                         router={'id': FAKE_ROUTER_ID})

        # check that routes were updated
        if expected_add:
            expected_router = {'router': {'routes': [
                {'destination': peer,
                 'nexthop': FAKE_TRANSIT_IP_ADDRESS}
                for peer in expected_add
            ]}}
            self.l3_plugin.add_extraroutes.assert_called_once_with(
                self.context, FAKE_ROUTER_ID, expected_router)
        else:
            self.l3_plugin.add_extraroutes.assert_not_called()

        if expected_remove:
            expected_router = {'router': {'routes': [
                {'destination': peer,
                 'nexthop': FAKE_TRANSIT_IP_ADDRESS}
                for peer in expected_remove
            ]}}
            self.l3_plugin.remove_extraroutes.assert_called_once_with(
                self.context, FAKE_ROUTER_ID, expected_router)
        else:
            self.l3_plugin.remove_extraroutes.assert_not_called()

    def test_create_ipsec_site_connection_1(self):
        old_peers = []
        new_peers = ['192.168.1.0/24']
        expected_add = new_peers
        expected_remove = []
        self._test_ipsec_site_connection(
            old_peers, new_peers,
            self.driver.create_ipsec_site_connection,
            [FAKE_VPN_CONNECTION_1],
            expected_add, expected_remove
        )

    def test_create_ipsec_site_connection_2(self):
        """Test creating a 2nd site connection."""
        old_peers = ['192.168.1.0/24']
        new_peers = ['192.168.1.0/24', '192.168.2.0/24']
        expected_add = ['192.168.2.0/24']
        expected_remove = []
        self._test_ipsec_site_connection(
            old_peers, new_peers,
            self.driver.create_ipsec_site_connection,
            [FAKE_VPN_CONNECTION_1],
            expected_add, expected_remove
        )

    def test_update_ipsec_site_connection(self):
        old_peers = ['192.168.1.0/24']
        new_peers = ['192.168.2.0/24']
        expected_add = new_peers
        expected_remove = old_peers
        self._test_ipsec_site_connection(
            old_peers, new_peers,
            self.driver.update_ipsec_site_connection,
            [FAKE_VPN_CONNECTION_1, FAKE_VPN_CONNECTION_1],
            expected_add, expected_remove
        )

    def test_delete_ipsec_site_connection(self):
        old_peers = ['192.168.1.0/24', '192.168.2.0/24']
        new_peers = ['192.168.2.0/24']
        expected_add = []
        expected_remove = ['192.168.1.0/24']
        self._test_ipsec_site_connection(
            old_peers, new_peers,
            self.driver.delete_ipsec_site_connection,
            [FAKE_VPN_CONNECTION_1],
            expected_add, expected_remove
        )
