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
import contextlib
from unittest import mock

from neutron.db import servicetype_db as st_db
from neutron.services.flavors import flavors_plugin
from neutron.tests.unit.db import test_agentschedulers_db
from neutron.tests.unit.extensions import test_agent as test_agent_ext_plugin

from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import flavors as flav_exc
from neutron_lib.plugins import constants as p_constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from neutron_vpnaas.extensions import vpn_flavors
from neutron_vpnaas.services.vpn import plugin as vpn_plugin
from neutron_vpnaas.services.vpn.service_drivers import driver_validator
from neutron_vpnaas.services.vpn.service_drivers import ipsec as ipsec_driver
from neutron_vpnaas.tests import base
from neutron_vpnaas.tests.unit.db.vpn import test_vpn_db as test_db_vpnaas

FAKE_HOST = test_agent_ext_plugin.L3_HOSTA
VPN_DRIVER_CLASS = 'neutron_vpnaas.services.vpn.plugin.VPNDriverPlugin'

IPSEC_SERVICE_DRIVER = ('neutron_vpnaas.services.vpn.service_drivers.'
                        'ipsec.IPsecVPNDriver')
DUMMY_IPSEC_SERVICE_DRIVER = ('neutron_vpnaas.tests.unit.dummy_ipsec.'
                              'DummyIPsecVPNDriver')

_uuid = uuidutils.generate_uuid


class TestVPNDriverPlugin(test_db_vpnaas.TestVpnaas,
                          test_agentschedulers_db.AgentSchedulerTestMixIn,
                          test_agent_ext_plugin.AgentDBTestMixIn):

    def setUp(self):
        driver_cls_p = mock.patch(
            'neutron_vpnaas.services.vpn.'
            'service_drivers.ipsec.IPsecVPNDriver')
        driver_cls = driver_cls_p.start()
        self.driver = mock.Mock()
        self.driver.service_type = ipsec_driver.IPSEC
        self.driver.validator = driver_validator.VpnDriverValidator(
            self.driver)
        driver_cls.return_value = self.driver
        super(TestVPNDriverPlugin, self).setUp(
            vpnaas_plugin=VPN_DRIVER_CLASS)
        # Note: Context must be created after BaseTestCase.setUp() so that
        # config for policy is set.
        self.adminContext = context.get_admin_context()

    def test_create_ipsec_site_connection(self, **extras):
        super(TestVPNDriverPlugin, self).test_create_ipsec_site_connection()
        self.driver.create_ipsec_site_connection.assert_called_once_with(
            mock.ANY, mock.ANY)
        self.driver.delete_ipsec_site_connection.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_create_vpnservice(self):
        mock.patch('neutron_vpnaas.services.vpn.plugin.'
                   'VPNDriverPlugin._get_driver_for_vpnservice',
                   return_value=self.driver).start()
        stm = directory.get_plugin(p_constants.VPN).service_type_manager
        stm.add_resource_association = mock.Mock()
        super(TestVPNDriverPlugin, self).test_create_vpnservice()
        self.driver.create_vpnservice.assert_called_once_with(
            mock.ANY, mock.ANY)
        stm.add_resource_association.assert_called_once_with(
            mock.ANY, p_constants.VPN, 'vpnaas', mock.ANY)

    def test_delete_vpnservice(self, **extras):
        stm = directory.get_plugin(p_constants.VPN).service_type_manager
        stm.del_resource_associations = mock.Mock()
        super(TestVPNDriverPlugin, self).test_delete_vpnservice()
        self.driver.delete_vpnservice.assert_called_once_with(
            mock.ANY, mock.ANY)
        stm.del_resource_associations.assert_called_once_with(
            mock.ANY, [mock.ANY])

    def test_update_vpnservice(self, **extras):
        super(TestVPNDriverPlugin, self).test_update_vpnservice()
        self.driver.update_vpnservice.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY)

    @contextlib.contextmanager
    def vpnservice_set(self):
        """Test case to create a ipsec_site_connection."""
        vpnservice_name = "vpn1"
        ipsec_site_connection_name = "ipsec_site_connection"
        ikename = "ikepolicy1"
        ipsecname = "ipsecpolicy1"
        description = "my-vpn-connection"
        keys = {'name': vpnservice_name,
                'description': "my-vpn-connection",
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'dpd_action': 'hold',
                'dpd_interval': 40,
                'dpd_timeout': 120,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
        with self.ikepolicy(name=ikename) as ikepolicy:
            with self.ipsecpolicy(name=ipsecname) as ipsecpolicy:
                with self.subnet() as subnet:
                    with self.router() as router:
                        plugin = directory.get_plugin()
                        agent = {'host': FAKE_HOST,
                                 'agent_type': lib_constants.AGENT_TYPE_L3,
                                 'binary': 'fake-binary',
                                 'topic': 'fake-topic'}
                        plugin.create_or_update_agent(self.adminContext, agent)
                        plugin.schedule_router(
                            self.adminContext, router['router']['id'])
                        with self.vpnservice(name=vpnservice_name,
                                             subnet=subnet,
                                             router=router) as vpnservice1:
                            keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                            keys['ipsecpolicy_id'] = (
                                ipsecpolicy['ipsecpolicy']['id']
                            )
                            keys['vpnservice_id'] = (
                                vpnservice1['vpnservice']['id']
                            )
                            with self.ipsec_site_connection(
                                self.fmt,
                                ipsec_site_connection_name,
                                keys['peer_address'],
                                keys['peer_id'],
                                keys['peer_cidrs'],
                                keys['mtu'],
                                keys['psk'],
                                keys['initiator'],
                                keys['dpd_action'],
                                keys['dpd_interval'],
                                keys['dpd_timeout'],
                                vpnservice1,
                                ikepolicy,
                                ipsecpolicy,
                                keys['admin_state_up'],
                                description=description,
                            ):
                                yield vpnservice1['vpnservice']

    def test_update_status(self):
        with self.vpnservice_set() as vpnservice:
            self._register_agent_states()
            service_plugin = directory.get_plugin(p_constants.VPN)
            service_plugin.update_status_by_agent(
                self.adminContext,
                [{'status': 'ACTIVE',
                  'ipsec_site_connections': {},
                  'updated_pending_status': True,
                  'id': vpnservice['id']}])
            vpnservice = service_plugin.get_vpnservice(
                self.adminContext, vpnservice['id'])
            self.assertEqual(lib_constants.ACTIVE, vpnservice['status'])


class TestVPNDriverPluginMultipleDrivers(base.BaseTestCase):

    def setUp(self):
        super(TestVPNDriverPluginMultipleDrivers, self).setUp()
        vpnaas_providers = [
            {'service_type': p_constants.VPN,
             'name': 'ipsec',
             'driver': IPSEC_SERVICE_DRIVER,
             'default': True},
            {'service_type': p_constants.VPN,
             'name': 'dummy',
             'driver': DUMMY_IPSEC_SERVICE_DRIVER,
             'default': False}]
        self.service_providers = (
            mock.patch.object(st_db.ServiceTypeManager,
                              'get_service_providers').start())
        self.service_providers.return_value = vpnaas_providers
        self.adminContext = context.get_admin_context()

    @contextlib.contextmanager
    def vpnservices_providers_set(self, vpnservices=None, provider_names=None):
        if not vpnservices:
            vpnservices = []
        if not provider_names:
            provider_names = {}
        stm = st_db.ServiceTypeManager()
        stm.get_provider_names_by_resource_ids = mock.Mock(
            return_value=provider_names)
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=stm).start()
        mock.patch('neutron_vpnaas.db.vpn.vpn_db.VPNPluginDb.get_vpnservices',
                   return_value=vpnservices).start()
        yield stm

    def test_multiple_drivers_loaded(self):
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertEqual(2, len(driver_plugin.drivers))
            self.assertEqual('ipsec', driver_plugin.default_provider)
            self.assertIn('ipsec', driver_plugin.drivers)
            self.assertEqual('ipsec', driver_plugin.drivers['ipsec'].name)
            self.assertIn('dummy', driver_plugin.drivers)
            self.assertEqual('dummy', driver_plugin.drivers['dummy'].name)

    def test_provider_lost(self):
        LOST_SERVICE_ID = _uuid()
        LOST_PROVIDER_SERVICE = {'id': LOST_SERVICE_ID}
        with self.vpnservices_providers_set(
                vpnservices=[LOST_PROVIDER_SERVICE],
                provider_names={LOST_SERVICE_ID: 'LOST_PROVIDER'}
        ):
            self.assertRaises(SystemExit, vpn_plugin.VPNDriverPlugin)

    def test_unasso_vpnservices(self):
        UNASSO_SERVICE_ID = _uuid()
        with self.vpnservices_providers_set(
                vpnservices=[{'id': UNASSO_SERVICE_ID}]
        ) as stm:
            stm.add_resource_association = mock.Mock()
            vpn_plugin.VPNDriverPlugin()
            stm.add_resource_association.assert_called_once_with(
                mock.ANY, p_constants.VPN, 'ipsec', UNASSO_SERVICE_ID)

    def test_get_driver_for_vpnservice(self):
        DUMMY_VPNSERVICE_ID = _uuid()
        DUMMY_VPNSERVICE = {'id': DUMMY_VPNSERVICE_ID}
        provider_names = {DUMMY_VPNSERVICE_ID: 'dummy'}
        with self.vpnservices_providers_set(provider_names=provider_names):
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertEqual(
                driver_plugin.drivers['dummy'],
                driver_plugin._get_driver_for_vpnservice(
                    self.adminContext, DUMMY_VPNSERVICE))

    def test_get_driver_for_ipsec_site_connection(self):
        IPSEC_VPNSERVICE_ID = _uuid()
        IPSEC_SITE_CONNECTION = {'vpnservice_id': IPSEC_VPNSERVICE_ID}
        provider_names = {IPSEC_VPNSERVICE_ID: 'ipsec'}
        with self.vpnservices_providers_set(provider_names=provider_names):
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertEqual(
                driver_plugin.drivers['ipsec'],
                driver_plugin._get_driver_for_ipsec_site_connection(
                    self.adminContext, IPSEC_SITE_CONNECTION))

    def test_get_provider_for_none_flavor_id(self):
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            provider = driver_plugin._get_provider_for_flavor(
                self.adminContext, None)
            self.assertEqual(
                driver_plugin.default_provider, provider)

    def test_get_provider_for_flavor_id_plugin_not_loaded(self):
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertRaises(
                vpn_flavors.FlavorsPluginNotLoaded,
                driver_plugin._get_provider_for_flavor,
                self.adminContext,
                _uuid())

    def test_get_provider_for_flavor_id_invalid_type(self):
        FAKE_FLAVOR = {'service_type': 'NOT_VPN'}
        directory.add_plugin(p_constants.FLAVORS,
                             flavors_plugin.FlavorsPlugin())
        mock.patch(
            'neutron.services.flavors.flavors_plugin.FlavorsPlugin.get_flavor',
            return_value=FAKE_FLAVOR).start()
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertRaises(
                lib_exc.InvalidServiceType,
                driver_plugin._get_provider_for_flavor,
                self.adminContext,
                _uuid())

    def test_get_provider_for_flavor_id_flavor_disabled(self):
        FAKE_FLAVOR = {'service_type': p_constants.VPN,
                       'enabled': False}
        directory.add_plugin(p_constants.FLAVORS,
                             flavors_plugin.FlavorsPlugin())
        mock.patch(
            'neutron.services.flavors.flavors_plugin.FlavorsPlugin.get_flavor',
            return_value=FAKE_FLAVOR).start()
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertRaises(
                flav_exc.FlavorDisabled,
                driver_plugin._get_provider_for_flavor,
                self.adminContext,
                _uuid())

    def test_get_provider_for_flavor_id_provider_not_found(self):
        FLAVOR_ID = _uuid()
        FAKE_FLAVOR = {'id': FLAVOR_ID,
                       'service_type': p_constants.VPN,
                       'enabled': True}
        PROVIDERS = [{'provider': 'SOME_PROVIDER'}]
        directory.add_plugin(p_constants.FLAVORS,
                             flavors_plugin.FlavorsPlugin())
        mock.patch(
            'neutron.services.flavors.flavors_plugin.FlavorsPlugin.get_flavor',
            return_value=FAKE_FLAVOR).start()
        mock.patch(
            'neutron.services.flavors.flavors_plugin.'
            'FlavorsPlugin.get_flavor_next_provider',
            return_value=PROVIDERS).start()
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertRaises(
                vpn_flavors.NoProviderFoundForFlavor,
                driver_plugin._get_provider_for_flavor,
                self.adminContext,
                FLAVOR_ID)

    def test_get_provider_for_flavor_id(self):
        FLAVOR_ID = _uuid()
        FAKE_FLAVOR = {'id': FLAVOR_ID,
                       'service_type': p_constants.VPN,
                       'enabled': True}
        PROVIDERS = [{'provider': 'dummy'}]
        directory.add_plugin(p_constants.FLAVORS,
                             flavors_plugin.FlavorsPlugin())
        mock.patch(
            'neutron.services.flavors.flavors_plugin.FlavorsPlugin.get_flavor',
            return_value=FAKE_FLAVOR).start()
        mock.patch(
            'neutron.services.flavors.flavors_plugin.'
            'FlavorsPlugin.get_flavor_next_provider',
            return_value=PROVIDERS).start()
        with self.vpnservices_providers_set():
            driver_plugin = vpn_plugin.VPNDriverPlugin()
            self.assertEqual(
                'dummy',
                driver_plugin._get_provider_for_flavor(
                    self.adminContext, FLAVOR_ID))
