# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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

from neutron.db import servicetype_db as st_db
from neutron_lib import context as n_ctx
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn import plugin as vpn_plugin
from neutron_vpnaas.services.vpn.service_drivers import ipsec as ipsec_driver
from neutron_vpnaas.services.vpn.service_drivers import ipsec_validator
from neutron_vpnaas.tests import base


_uuid = uuidutils.generate_uuid

FAKE_SERVICE_ID = _uuid()
FAKE_VPN_CONNECTION = {
    'vpnservice_id': FAKE_SERVICE_ID
}
FAKE_ROUTER_ID = _uuid()
FAKE_VPN_SERVICE = {
    'router_id': FAKE_ROUTER_ID
}
FAKE_HOST = 'fake_host'
FAKE_CONN_ID = _uuid()

IPSEC_SERVICE_DRIVER = ('neutron_vpnaas.services.vpn.service_drivers.'
                        'ipsec.IPsecVPNDriver')


class FakeSqlQueryObject(dict):
    """To fake SqlAlchemy query object and access keys as attributes."""

    def __init__(self, **entries):
        self.__dict__.update(entries)
        super(FakeSqlQueryObject, self).__init__(**entries)


class TestValidatorSelection(base.BaseTestCase):

    def setUp(self):
        super(TestValidatorSelection, self).setUp()
        vpnaas_provider = [{
            'service_type': constants.VPN,
            'name': 'vpnaas',
            'driver': IPSEC_SERVICE_DRIVER,
            'default': True
        }]
        # override the default service provider
        self.service_providers = (
            mock.patch.object(st_db.ServiceTypeManager,
                              'get_service_providers').start())
        self.service_providers.return_value = vpnaas_provider
        mock.patch('neutron_lib.rpc.Connection').start()
        stm = st_db.ServiceTypeManager()
        stm.get_provider_names_by_resource_ids = mock.Mock(
            return_value={})
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=stm).start()
        mock.patch('neutron_vpnaas.db.vpn.vpn_db.VPNPluginDb.get_vpnservices',
                   return_value=[]).start()
        self.vpn_plugin = vpn_plugin.VPNDriverPlugin()

    def test_reference_driver_used(self):
        default_provider = self.vpn_plugin.default_provider
        default_driver = self.vpn_plugin.drivers[default_provider]
        self.assertIsInstance(default_driver.validator,
                              ipsec_validator.IpsecVpnValidator)


class TestIPsecDriver(base.BaseTestCase):
    def setUp(self):
        super(TestIPsecDriver, self).setUp()
        mock.patch('neutron_lib.rpc.Connection').start()

        l3_agent = mock.Mock()
        l3_agent.host = FAKE_HOST
        plugin = mock.Mock()
        plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        directory.add_plugin(constants.CORE, plugin)
        directory.add_plugin(constants.L3, plugin)
        self.svc_plugin = mock.Mock()
        self.svc_plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        self._fake_vpn_router_id = _uuid()
        self.svc_plugin.get_vpnservice_router_id.return_value = \
            self._fake_vpn_router_id
        self.driver = ipsec_driver.IPsecVPNDriver(self.svc_plugin)
        self.validator = ipsec_validator.IpsecVpnValidator(self.driver)
        self.context = n_ctx.get_admin_context()

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

    def prepare_dummy_query_objects(self, info):
        """Create fake query objects to test dict creation for sync oper."""
        external_ip = '10.0.0.99'
        peer_address = '10.0.0.2'
        peer_endpoints = info.get('peer_endpoints', [])
        local_endpoints = info.get('local_endpoints', [])
        peer_cidrs = info.get('peer_cidrs', ['40.4.0.0/24', '50.5.0.0/24'])
        peer_id = info.get('peer_id', '30.30.0.0')
        local_id = info.get('local_id', '')

        fake_ikepolicy = FakeSqlQueryObject(id='foo-ike', name='ike-name')
        fake_ipsecpolicy = FakeSqlQueryObject(id='foo-ipsec')

        fake_peer_cidrs_list = [
            FakeSqlQueryObject(cidr=cidr, ipsec_site_connection_id='conn-id')
            for cidr in peer_cidrs]

        peer_epg_id = 'peer-epg-id' if peer_endpoints else None
        local_epg_id = 'local-epg-id' if local_endpoints else None

        fake_ipsec_conn = FakeSqlQueryObject(id='conn-id',
                                             peer_id=peer_id,
                                             peer_address=peer_address,
                                             local_id=local_id,
                                             ikepolicy=fake_ikepolicy,
                                             ipsecpolicy=fake_ipsecpolicy,
                                             peer_ep_group_id=peer_epg_id,
                                             local_ep_group_id=local_epg_id,
                                             peer_cidrs=fake_peer_cidrs_list)

        if peer_endpoints:
            fake_peer_ep_group = FakeSqlQueryObject(id=peer_epg_id)
            fake_peer_ep_group.endpoints = [
                FakeSqlQueryObject(endpoint=ep,
                                   endpoint_group_id=peer_epg_id)
                for ep in peer_endpoints]
            fake_ipsec_conn.peer_ep_group = fake_peer_ep_group

        if local_endpoints:
            fake_local_ep_group = FakeSqlQueryObject(id=local_epg_id)
            fake_local_ep_group.endpoints = [
                FakeSqlQueryObject(endpoint=ep,
                                   endpoint_group_id=local_epg_id)
                for ep in local_endpoints]
            fake_ipsec_conn.local_ep_group = fake_local_ep_group
            subnet_id = None
        else:
            subnet_id = 'foo-subnet-id'

        fake_gw_port = {'fixed_ips': [{'ip_address': external_ip}]}
        fake_router = FakeSqlQueryObject(gw_port=fake_gw_port)
        fake_vpnservice = FakeSqlQueryObject(id='foo-vpn-id', name='foo-vpn',
                                             description='foo-vpn-service',
                                             admin_state_up=True,
                                             status='active',
                                             external_v4_ip=external_ip,
                                             external_v6_ip=None,
                                             subnet_id=subnet_id,
                                             router_id='foo-router-id',
                                             project_id='foo-project-id')
        if local_endpoints:
            fake_vpnservice.subnet = None
        else:
            fake_subnet = FakeSqlQueryObject(id=subnet_id,
                                             name='foo-subnet',
                                             cidr='9.0.0.0/16',
                                             network_id='foo-net-id')
            fake_vpnservice.subnet = fake_subnet
        fake_vpnservice.router = fake_router
        fake_vpnservice.ipsec_site_connections = [fake_ipsec_conn]
        return fake_vpnservice

    def build_expected_dict(self, info):
        """Create the expected dict used in sync operations.

        The default is to use non-endpoint groups, where the peer CIDRs come
        from the peer_cidrs arguments, the local CIDRs come from the (sole)
        subnet CIDR, and there is subnet info. Tests will customize the peer
        ID and peer CIDRs.
        """

        external_ip = '10.0.0.99'
        peer_id = info.get('peer_id', '30.30.0.0')
        peer_cidrs = info.get('peer_cidrs', ['40.4.0.0/24', '50.5.0.0/24'])
        local_id = info.get('local_id', '')

        return {'name': 'foo-vpn',
                'id': 'foo-vpn-id',
                'description': 'foo-vpn-service',
                'admin_state_up': True,
                'status': 'active',
                'external_v4_ip': external_ip,
                'external_v6_ip': None,
                'router_id': 'foo-router-id',
                'subnet': {'cidr': '9.0.0.0/16',
                           'id': 'foo-subnet-id',
                           'name': 'foo-subnet',
                           'network_id': 'foo-net-id'},
                'subnet_id': 'foo-subnet-id',
                'external_ip': external_ip,
                'project_id': 'foo-project-id',
                'tenant_id': 'foo-project-id',
                'ipsec_site_connections': [
                    {'id': 'conn-id',
                     'peer_id': peer_id,
                     'external_ip': external_ip,
                     'peer_address': '10.0.0.2',
                     'local_id': local_id,
                     'ikepolicy': {'id': 'foo-ike',
                                   'name': 'ike-name'},
                     'ipsecpolicy': {'id': 'foo-ipsec'},
                     'peer_ep_group_id': None,
                     'local_ep_group_id': None,
                     'peer_cidrs': peer_cidrs,
                     'local_cidrs': ['9.0.0.0/16'],
                     'local_ip_vers': 4}
                ]}

    def build_expected_dict_for_endpoints(self, info):
        """Create the expected dict used in sync operations for endpoints.

        The local and peer CIDRs come from the endpoint groups (with the
        local CIDR translated from the corresponding subnets specified).
        Tests will customize CIDRs, and the subnet, which is needed for
        backward compatibility with agents, during rolling upgrades.
        """

        external_ip = '10.0.0.99'
        peer_id = '30.30.0.0'
        local_id = info.get('local_id', '')
        return {'name': 'foo-vpn',
                'id': 'foo-vpn-id',
                'description': 'foo-vpn-service',
                'admin_state_up': True,
                'status': 'active',
                'external_v4_ip': external_ip,
                'external_v6_ip': None,
                'router_id': 'foo-router-id',
                'subnet': None,
                'subnet_id': None,
                'external_ip': external_ip,
                'project_id': 'foo-project-id',
                'tenant_id': 'foo-project-id',
                'ipsec_site_connections': [
                    {'id': 'conn-id',
                     'peer_id': peer_id,
                     'external_ip': external_ip,
                     'peer_address': '10.0.0.2',
                     'local_id': local_id,
                     'ikepolicy': {'id': 'foo-ike',
                                   'name': 'ike-name'},
                     'ipsecpolicy': {'id': 'foo-ipsec'},
                     'peer_ep_group_id': 'peer-epg-id',
                     'local_ep_group_id': 'local-epg-id',
                     'peer_cidrs': info['peers'],
                     'local_cidrs': info['locals'],
                     'local_ip_vers': info['vers']}
                ]}

    def test_make_vpnservice_dict_peer_id_is_ipaddr(self):
        """Peer ID as IP should be copied as-is, when creating dict."""
        subnet_cidr_map = {}
        peer_id_as_ip = {'peer_id': '10.0.0.2'}
        fake_service = self.prepare_dummy_query_objects(peer_id_as_ip)
        expected_dict = self.build_expected_dict(peer_id_as_ip)
        actual_dict = self.driver.make_vpnservice_dict(fake_service,
                                                       subnet_cidr_map)
        self.assertEqual(expected_dict, actual_dict)

        # make sure that ipsec_site_conn peer_id is not updated by
        # _make_vpnservice_dict (bug #1423244)
        self.assertEqual(peer_id_as_ip['peer_id'],
                         fake_service.ipsec_site_connections[0].peer_id)

    def test_make_vpnservice_dict_peer_id_is_string(self):
        """Peer ID as string should have '@' prepended, when creating dict."""
        subnet_cidr_map = {}
        peer_id_as_name = {'peer_id': 'foo.peer.id'}
        fake_service = self.prepare_dummy_query_objects(peer_id_as_name)
        expected_peer_id = {'peer_id': '@foo.peer.id'}
        expected_dict = self.build_expected_dict(expected_peer_id)
        actual_dict = self.driver.make_vpnservice_dict(fake_service,
                                                       subnet_cidr_map)
        self.assertEqual(expected_dict, actual_dict)

        # make sure that ipsec_site_conn peer_id is not updated by
        # _make_vpnservice_dict (bug #1423244)
        self.assertEqual(peer_id_as_name['peer_id'],
                         fake_service.ipsec_site_connections[0].peer_id)

    def test_make_vpnservice_dict_peer_cidrs_from_peer_cidr_table(self):
        """Peer CIDRs list populated from peer_cidr table.

        User provides peer CIDRs as parameters to IPSec site-to-site
        connection API, and they are stored in the peercidrs table.
        """
        subnet_cidr_map = {}
        peer_cidrs = {'peer_cidrs': ['80.0.0.0/24', '90.0.0.0/24']}
        fake_service = self.prepare_dummy_query_objects(peer_cidrs)
        expected_dict = self.build_expected_dict(peer_cidrs)
        actual_dict = self.driver.make_vpnservice_dict(fake_service,
                                                       subnet_cidr_map)
        self.assertEqual(expected_dict, actual_dict)

    def test_make_vpnservice_dict_cidrs_from_endpoints(self):
        """CIDRs list populated from local and peer endpoints.

        User provides peer and local endpoint group IDs in the IPSec
        site-to-site connection API. The endpoint groups contains peer
        CIDRs and local subnets (which will be mapped to CIDRs).
        """
        # Cannot have peer CIDRs specified, when using endpoint group
        subnet_cidr_map = {'local-sn1': '5.0.0.0/16',
                           'local-sn2': '5.1.0.0/16'}
        endpoint_groups = {'peer_cidrs': [],
                           'peer_endpoints': ['80.0.0.0/24', '90.0.0.0/24'],
                           'local_endpoints': ['local-sn1', 'local-sn2']}

        expected_cidrs = {'peers': ['80.0.0.0/24', '90.0.0.0/24'],
                          'locals': ['5.0.0.0/16', '5.1.0.0/16'],
                          'vers': 4}
        fake_service = self.prepare_dummy_query_objects(endpoint_groups)
        expected_dict = self.build_expected_dict_for_endpoints(expected_cidrs)
        expected_dict['subnet'] = {'cidr': '5.0.0.0/16'}
        actual_dict = self.driver.make_vpnservice_dict(fake_service,
                                                       subnet_cidr_map)
        self.assertEqual(expected_dict, actual_dict)

    def test_make_vpnservice_dict_v6_cidrs_from_endpoints(self):
        """IPv6 CIDRs list populated from local and peer endpoints."""
        # Cannot have peer CIDRs specified, when using endpoint group
        subnet_cidr_map = {'local-sn1': '2002:0a00:0000::/48',
                           'local-sn2': '2002:1400:0000::/48'}
        endpoint_groups = {'peer_cidrs': [],
                           'peer_endpoints': ['2002:5000:0000::/48',
                                              '2002:5a00:0000::/48'],
                           'local_endpoints': ['local-sn1', 'local-sn2']}

        expected_cidrs = {'peers': ['2002:5000:0000::/48',
                                   '2002:5a00:0000::/48'],
                          'locals': ['2002:0a00:0000::/48',
                                    '2002:1400:0000::/48'],
                          'vers': 6}
        fake_service = self.prepare_dummy_query_objects(endpoint_groups)
        expected_dict = self.build_expected_dict_for_endpoints(expected_cidrs)
        expected_dict['subnet'] = {'cidr': '2002:0a00:0000::/48'}
        actual_dict = self.driver.make_vpnservice_dict(fake_service,
                                                       subnet_cidr_map)
        self.assertEqual(expected_dict, actual_dict)

    def test_get_external_ip_based_on_ipv4_peer(self):
        vpnservice = mock.Mock()
        vpnservice.external_v4_ip = '10.0.0.99'
        vpnservice.external_v6_ip = '2001::1'
        ipsec_sitecon = {'id': FAKE_CONN_ID, 'peer_address': '10.0.0.9'}
        ip_to_use = self.driver.get_external_ip_based_on_peer(vpnservice,
                                                              ipsec_sitecon)
        self.assertEqual('10.0.0.99', ip_to_use)

    def test_get_external_ip_based_on_ipv6_peer(self):
        vpnservice = mock.Mock()
        vpnservice.external_v4_ip = '10.0.0.99'
        vpnservice.external_v6_ip = '2001::1'
        ipsec_sitecon = {'id': FAKE_CONN_ID, 'peer_address': '2001::5'}
        ip_to_use = self.driver.get_external_ip_based_on_peer(vpnservice,
                                                              ipsec_sitecon)
        self.assertEqual('2001::1', ip_to_use)

    def test_get_ipv4_gw_ip(self):
        vpnservice = mock.Mock()
        vpnservice.router.gw_port = {'fixed_ips':
                                     [{'ip_address': '10.0.0.99'}]}
        v4_ip, v6_ip = self.driver._get_gateway_ips(vpnservice.router)
        self.assertEqual('10.0.0.99', v4_ip)
        self.assertIsNone(v6_ip)

    def test_get_ipv6_gw_ip(self):
        vpnservice = mock.Mock()
        vpnservice.router.gw_port = {'fixed_ips': [{'ip_address': '2001::1'}]}
        v4_ip, v6_ip = self.driver._get_gateway_ips(vpnservice.router)
        self.assertIsNone(v4_ip)
        self.assertEqual('2001::1', v6_ip)

    def test_get_both_gw_ips(self):
        vpnservice = mock.Mock()
        vpnservice.router.gw_port = {'fixed_ips': [{'ip_address': '10.0.0.99'},
                                                   {'ip_address': '2001::1'}]}
        v4_ip, v6_ip = self.driver._get_gateway_ips(vpnservice.router)
        self.assertEqual('10.0.0.99', v4_ip)
        self.assertEqual('2001::1', v6_ip)

    def test_use_first_gw_ips_when_multiples(self):
        vpnservice = mock.Mock()
        vpnservice.router.gw_port = {'fixed_ips': [{'ip_address': '10.0.0.99'},
                                                   {'ip_address': '20.0.0.99'},
                                                   {'ip_address': '2001::1'},
                                                   {'ip_address': 'fd00::4'}]}
        v4_ip, v6_ip = self.driver._get_gateway_ips(vpnservice.router)
        self.assertEqual('10.0.0.99', v4_ip)
        self.assertEqual('2001::1', v6_ip)

    def test_store_gw_ips_on_service_create(self):
        vpnservice = mock.Mock()
        self.svc_plugin._get_vpnservice.return_value = vpnservice
        vpnservice.router.gw_port = {'fixed_ips': [{'ip_address': '10.0.0.99'},
                                                   {'ip_address': '2001::1'}]}
        ctxt = n_ctx.Context('', 'somebody')
        vpnservice_dict = {'id': FAKE_SERVICE_ID,
                           'router_id': FAKE_ROUTER_ID}
        self.driver.create_vpnservice(ctxt, vpnservice_dict)
        self.svc_plugin.set_external_tunnel_ips.assert_called_once_with(
            ctxt, FAKE_SERVICE_ID, v4_ip='10.0.0.99', v6_ip='2001::1')

    def test_validate_ipsec_policy(self):
        # Validate IPsec Policy transform_protocol
        ipsec_policy = {'transform_protocol': 'ah-esp'}
        self.assertRaises(ipsec_validator.IpsecValidationFailure,
                          self.validator.validate_ipsec_policy,
                          self.context, ipsec_policy)
