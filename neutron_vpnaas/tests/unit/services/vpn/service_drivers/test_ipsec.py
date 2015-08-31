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

import mock
import socket

from neutron import context as n_ctx
from neutron.db import l3_db
from neutron.db import servicetype_db as st_db
from neutron.plugins.common import constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.services.vpn import plugin as vpn_plugin
from neutron_vpnaas.services.vpn.service_drivers import ipsec as ipsec_driver
from neutron_vpnaas.services.vpn.service_drivers \
    import ipsec_validator as vpn_validator
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
FAKE_ROUTER = {l3_db.EXTERNAL_GW_INFO: FAKE_ROUTER_ID}
FAKE_SUBNET_ID = _uuid()
IPV4 = 4
IPV6 = 6
FAKE_CONN_ID = _uuid()

IPSEC_SERVICE_DRIVER = ('neutron_vpnaas.services.vpn.service_drivers.'
                        'ipsec.IPsecVPNDriver')


class TestValidatorSelection(base.BaseTestCase):

    def setUp(self):
        super(TestValidatorSelection, self).setUp()
        # TODO(armax): remove this if branch as soon as the ServiceTypeManager
        # API for adding provider configurations becomes available
        if not hasattr(st_db.ServiceTypeManager, 'add_provider_configuration'):
            vpnaas_provider = (constants.VPN + ':vpnaas:' +
                               IPSEC_SERVICE_DRIVER + ':default')
            cfg.CONF.set_override(
                'service_provider', [vpnaas_provider], 'service_providers')
        else:
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
        mock.patch('neutron.common.rpc.create_connection').start()
        stm = st_db.ServiceTypeManager()
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=stm).start()
        self.vpn_plugin = vpn_plugin.VPNDriverPlugin()

    def test_reference_driver_used(self):
        self.assertIsInstance(self.vpn_plugin._get_validator(),
                              vpn_validator.IpsecVpnValidator)


class TestIPsecDriverValidation(base.BaseTestCase):

    def setUp(self):
        super(TestIPsecDriverValidation, self).setUp()
        self.l3_plugin = mock.Mock()
        mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins',
            return_value={constants.L3_ROUTER_NAT: self.l3_plugin}).start()
        self.core_plugin = mock.Mock()
        mock.patch('neutron.manager.NeutronManager.get_plugin',
                   return_value=self.core_plugin).start()
        self.context = n_ctx.Context('some_user', 'some_tenant')
        self.service_plugin = mock.Mock()
        self.validator = vpn_validator.IpsecVpnValidator(self.service_plugin)
        self.router = mock.Mock()
        self.router.gw_port = {'fixed_ips': [{'ip_address': '10.0.0.99'}]}

    def test_non_public_router_for_vpn_service(self):
        """Failure test of service validate, when router missing ext. I/F."""
        self.l3_plugin.get_router.return_value = {}  # No external gateway
        vpnservice = {'router_id': 123, 'subnet_id': 456}
        self.assertRaises(vpnaas.RouterIsNotExternal,
                          self.validator.validate_vpnservice,
                          self.context, vpnservice)

    def test_subnet_not_connected_for_vpn_service(self):
        """Failure test of service validate, when subnet not on router."""
        self.l3_plugin.get_router.return_value = FAKE_ROUTER
        self.core_plugin.get_ports.return_value = None
        vpnservice = {'router_id': FAKE_ROUTER_ID, 'subnet_id': FAKE_SUBNET_ID}
        self.assertRaises(vpnaas.SubnetIsNotConnectedToRouter,
                          self.validator.validate_vpnservice,
                          self.context, vpnservice)

    def test_defaults_for_ipsec_site_connections_on_create(self):
        """Check that defaults are applied correctly.

        MTU has a default and will always be present on create.
        However, the DPD settings do not have a default, so
        database create method will assign default values for any
        missing. In addition, the DPD dict will be flattened
        for storage into the database, so we'll do it as part of
        assigning defaults.
        """
        ipsec_sitecon = {}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        expected = {
            'dpd_action': 'hold',
            'dpd_timeout': 120,
            'dpd_interval': 30
        }
        self.assertEqual(expected, ipsec_sitecon)

        ipsec_sitecon = {'dpd': {'interval': 50}}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        expected = {
            'dpd': {'interval': 50},
            'dpd_action': 'hold',
            'dpd_timeout': 120,
            'dpd_interval': 50
        }
        self.assertEqual(expected, ipsec_sitecon)

    def test_resolve_peer_address_with_ipaddress(self):
        ipsec_sitecon = {'peer_address': '10.0.0.9'}
        self.validator.validate_peer_address = mock.Mock()
        self.validator.resolve_peer_address(ipsec_sitecon, self.router)
        self.assertEqual('10.0.0.9', ipsec_sitecon['peer_address'])
        self.validator.validate_peer_address.assert_called_once_with(
            IPV4, self.router)

    def test_resolve_peer_address_with_fqdn(self):
        with mock.patch.object(socket, 'getaddrinfo') as mock_getaddr_info:
            mock_getaddr_info.return_value = [(2, 1, 6, '',
                                              ('10.0.0.9', 0))]
            ipsec_sitecon = {'peer_address': 'fqdn.peer.addr'}
            self.validator.validate_peer_address = mock.Mock()
            self.validator.resolve_peer_address(ipsec_sitecon, self.router)
            self.assertEqual('10.0.0.9', ipsec_sitecon['peer_address'])
            self.validator.validate_peer_address.assert_called_once_with(
                IPV4, self.router)

    def test_resolve_peer_address_with_invalid_fqdn(self):
        with mock.patch.object(socket, 'getaddrinfo') as mock_getaddr_info:
            def getaddr_info_failer(*args, **kwargs):
                raise socket.gaierror()
            mock_getaddr_info.side_effect = getaddr_info_failer
            ipsec_sitecon = {'peer_address': 'fqdn.invalid'}
            self.assertRaises(vpnaas.VPNPeerAddressNotResolved,
                              self.validator.resolve_peer_address,
                              ipsec_sitecon, self.router)

    def _validate_peer_address(self, fixed_ips, ip_version,
                               expected_exception=False):
        self.router.id = FAKE_ROUTER_ID
        self.router.gw_port = {'fixed_ips': fixed_ips}
        try:
            self.validator.validate_peer_address(ip_version, self.router)
            if expected_exception:
                self.fail("No exception raised for invalid peer address")
        except vpnaas.ExternalNetworkHasNoSubnet:
            if not expected_exception:
                self.fail("exception for valid peer address raised")

    def test_validate_peer_address(self):
        # validate ipv4 peer_address with ipv4 gateway
        fixed_ips = [{'ip_address': '10.0.0.99'}]
        self._validate_peer_address(fixed_ips, IPV4)

        # validate ipv6 peer_address with ipv6 gateway
        fixed_ips = [{'ip_address': '2001::1'}]
        self._validate_peer_address(fixed_ips, IPV6)

        # validate ipv6 peer_address with both ipv4 and ipv6 gateways
        fixed_ips = [{'ip_address': '2001::1'}, {'ip_address': '10.0.0.99'}]
        self._validate_peer_address(fixed_ips, IPV6)

        # validate ipv4 peer_address with both ipv4 and ipv6 gateways
        fixed_ips = [{'ip_address': '2001::1'}, {'ip_address': '10.0.0.99'}]
        self._validate_peer_address(fixed_ips, IPV4)

        # validate ipv4 peer_address with ipv6 gateway
        fixed_ips = [{'ip_address': '2001::1'}]
        self._validate_peer_address(fixed_ips, IPV4, expected_exception=True)

        # validate ipv6 peer_address with ipv4 gateway
        fixed_ips = [{'ip_address': '10.0.0.99'}]
        self._validate_peer_address(fixed_ips, IPV6, expected_exception=True)

    def test_validate_ipsec_policy(self):
        ipsec_policy = {'transform_protocol': 'ah-esp'}
        self.assertRaises(vpn_validator.IpsecValidationFailure,
                          self.validator.validate_ipsec_policy,
                          self.context, ipsec_policy)

    def test_defaults_for_ipsec_site_connections_on_update(self):
        """Check that defaults are used for any values not specified."""
        ipsec_sitecon = {}
        prev_connection = {'dpd_action': 'clear',
                           'dpd_timeout': 500,
                           'dpd_interval': 250}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        expected = {
            'dpd_action': 'clear',
            'dpd_timeout': 500,
            'dpd_interval': 250
        }
        self.assertEqual(expected, ipsec_sitecon)

        ipsec_sitecon = {'dpd': {'timeout': 200}}
        prev_connection = {'dpd_action': 'clear',
                           'dpd_timeout': 500,
                           'dpd_interval': 100}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        expected = {
            'dpd': {'timeout': 200},
            'dpd_action': 'clear',
            'dpd_timeout': 200,
            'dpd_interval': 100
        }
        self.assertEqual(expected, ipsec_sitecon)

    def test_bad_dpd_settings_on_create(self):
        """Failure tests of DPD settings for IPSec conn during create."""
        ipsec_sitecon = {'mtu': 1500, 'dpd_action': 'hold',
                         'dpd_interval': 100, 'dpd_timeout': 100}
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)
        ipsec_sitecon = {'mtu': 1500, 'dpd_action': 'hold',
                         'dpd_interval': 100, 'dpd_timeout': 99}
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)

    def test_bad_dpd_settings_on_update(self):
        """Failure tests of DPD settings for IPSec conn. during update.

        Note: On an update, the user may specify only some of the DPD settings.
        Previous values will be assigned for any missing items, so by the
        time the validation occurs, all items will be available for checking.
        The MTU may not be provided, during validation and will be ignored,
        if that is the case.
        """
        prev_connection = {'mtu': 2000,
                           'dpd_action': 'hold',
                           'dpd_interval': 100,
                           'dpd_timeout': 120}
        ipsec_sitecon = {'dpd': {'interval': 120}}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)

        prev_connection = {'mtu': 2000,
                           'dpd_action': 'hold',
                           'dpd_interval': 100,
                           'dpd_timeout': 120}
        ipsec_sitecon = {'dpd': {'timeout': 99}}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)

    def test_bad_mtu_for_ipsec_connection(self):
        """Failure test of invalid MTU values for IPSec conn create/update."""
        ip_version_limits = vpn_validator.IpsecVpnValidator.IP_MIN_MTU
        for version, limit in ip_version_limits.items():
            ipsec_sitecon = {'mtu': limit - 1,
                             'dpd_action': 'hold',
                             'dpd_interval': 100,
                             'dpd_timeout': 120}
            self.assertRaises(
                vpnaas.IPsecSiteConnectionMtuError,
                self.validator.validate_ipsec_site_connection,
                self.context, ipsec_sitecon, version)


class FakeSqlQueryObject(dict):
    """To fake SqlAlchemy query object and access keys as attributes."""

    def __init__(self, **entries):
        self.__dict__.update(entries)
        super(FakeSqlQueryObject, self).__init__(**entries)


class TestIPsecDriver(base.BaseTestCase):
    def setUp(self):
        super(TestIPsecDriver, self).setUp()
        mock.patch('neutron.common.rpc.create_connection').start()

        l3_agent = mock.Mock()
        l3_agent.host = FAKE_HOST
        plugin = mock.Mock()
        plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        plugin_p = mock.patch('neutron.manager.NeutronManager.get_plugin')
        get_plugin = plugin_p.start()
        get_plugin.return_value = plugin
        service_plugin_p = mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins')
        get_service_plugin = service_plugin_p.start()
        get_service_plugin.return_value = {constants.L3_ROUTER_NAT: plugin}
        self.svc_plugin = mock.Mock()
        self.svc_plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        self._fake_vpn_router_id = _uuid()
        self.svc_plugin._get_vpnservice.return_value = {
            'router_id': self._fake_vpn_router_id
        }
        self.driver = ipsec_driver.IPsecVPNDriver(self.svc_plugin)

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

    def _test_make_vpnservice_dict_helper(self, peer_id, expected_peer_id):
        fake_subnet = FakeSqlQueryObject(id='foo-subnet-id',
                                         name='foo-subnet',
                                         network_id='foo-net-id')

        fake_ikepolicy = FakeSqlQueryObject(id='foo-ike', name='ike-name')
        fake_ipsecpolicy = FakeSqlQueryObject(id='foo-ipsec')
        fake_peer_address = '10.0.0.2'

        fake_ipsec_conn = FakeSqlQueryObject(peer_id=peer_id,
                                             peer_address=fake_peer_address,
                                             ikepolicy=fake_ikepolicy,
                                             ipsecpolicy=fake_ipsecpolicy,
                                             peer_cidrs=[])
        fake_external_ip = '10.0.0.99'
        fake_gw_port = {'fixed_ips': [{'ip_address': fake_external_ip}]}
        fake_router = FakeSqlQueryObject(gw_port=fake_gw_port)
        fake_vpnservice = FakeSqlQueryObject(id='foo-vpn-id', name='foo-vpn',
                                             description='foo-vpn-service',
                                             admin_state_up=True,
                                             status='active',
                                             external_v4_ip=fake_external_ip,
                                             external_v6_ip=None,
                                             subnet_id='foo-subnet-id',
                                             router_id='foo-router-id')
        fake_vpnservice.subnet = fake_subnet
        fake_vpnservice.router = fake_router
        fake_vpnservice.ipsec_site_connections = [fake_ipsec_conn]

        expected_vpnservice_dict = {'name': 'foo-vpn',
                                    'id': 'foo-vpn-id',
                                    'description': 'foo-vpn-service',
                                    'admin_state_up': True,
                                    'status': 'active',
                                    'external_v4_ip': fake_external_ip,
                                    'external_v6_ip': None,
                                    'subnet_id': 'foo-subnet-id',
                                    'router_id': 'foo-router-id',
                                    'subnet': {'id': 'foo-subnet-id',
                                               'name': 'foo-subnet',
                                               'network_id': 'foo-net-id'},
                                    'external_ip': fake_external_ip,
                                    'ipsec_site_connections': [
                                        {'peer_id': expected_peer_id,
                                         'external_ip': fake_external_ip,
                                         'peer_address': fake_peer_address,
                                         'ikepolicy': {'id': 'foo-ike',
                                                       'name': 'ike-name'},
                                         'ipsecpolicy': {'id': 'foo-ipsec'},
                                         'peer_cidrs': []}]}

        actual_vpnservice_dict = self.driver.make_vpnservice_dict(
            fake_vpnservice)

        self.assertEqual(expected_vpnservice_dict, actual_vpnservice_dict)

        # make sure that ipsec_site_conn peer_id is not updated by
        # _make_vpnservice_dict (bug #1423244)
        self.assertEqual(peer_id,
                         fake_vpnservice.ipsec_site_connections[0].peer_id)

    def test_make_vpnservice_dict_peer_id_is_ipaddr(self):
        self._test_make_vpnservice_dict_helper('10.0.0.2', '10.0.0.2')

    def test_make_vpnservice_dict_peer_id_is_string(self):
        self._test_make_vpnservice_dict_helper('foo.peer.id', '@foo.peer.id')

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
