# Copyright 2023 SysEleven GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron.api import extensions
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions as cb_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib.plugins import constants as nconstants
from neutron_lib.plugins import directory
from neutron_vpnaas.db.vpn.vpn_ext_gw_db import VPNExtGWPlugin_db
from neutron_vpnaas.services.vpn.common import constants as v_constants
from neutron_vpnaas.tests import base
from neutron_vpnaas.tests.unit.db.vpn import test_vpn_db


OVN_VPN_PLUGIN_KLASS = "neutron_vpnaas.services.vpn.ovn_plugin.VPNOVNPlugin"


class VPNOVNPluginDbTestCase(test_l3_plugin.L3NatTestCaseMixin,
                             base.NeutronDbPluginV2TestCase):
    def setUp(self, core_plugin=None, vpnaas_plugin=OVN_VPN_PLUGIN_KLASS,
              vpnaas_provider=None):

        service_plugins = {'vpnaas_plugin': vpnaas_plugin}
        plugin_str = 'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin'
        super().setUp(plugin_str, service_plugins=service_plugins)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.core_plugin = directory.get_plugin()
        self.tenant_id = 'tenant1'


class TestVPNExtGw(VPNOVNPluginDbTestCase):
    def _pre_port_delete(self, admin_context, port_id):
        registry.publish(
            resources.PORT, events.BEFORE_DELETE, self,
            payload=events.DBEventPayload(
                admin_context,
                metadata={'port_check': True},
                resource_id=port_id))

    def _pre_subnet_delete(self, admin_context, subnet_id):
        registry.publish(resources.SUBNET, events.BEFORE_DELETE, self,
                         payload=events.DBEventPayload(admin_context,
                                                       resource_id=subnet_id))

    def _pre_network_delete(self, admin_context, network_id):
        registry.publish(resources.NETWORK, events.BEFORE_DELETE, self,
                         payload=events.DBEventPayload(admin_context,
                                                       resource_id=network_id))

    def _test_prevent_vpn_port_deletion(self, device_owner, gw_key):
        plugin = directory.get_plugin(nconstants.VPN)
        with self.router() as router, \
                self.port(device_owner=device_owner) as port:
            gateway = {'gateway': {
                'router_id': router['router']['id'],
                gw_key: port['port']['id'],
                'tenant_id': self.tenant_id
            }}
            admin_context = context.get_admin_context()
            plugin.create_gateway(admin_context, gateway)
            self.assertRaises(
                cb_exc.CallbackFailure,
                self._pre_port_delete, admin_context, port['port']['id'])

    def test_prevent_vpn_port_deletion_gw_port(self):
        self._test_prevent_vpn_port_deletion(
            v_constants.DEVICE_OWNER_VPN_ROUTER_GW, 'gw_port_id')

    def test_prevent_vpn_port_deletion_transit_port(self):
        self._test_prevent_vpn_port_deletion(
            v_constants.DEVICE_OWNER_TRANSIT_NETWORK, 'transit_port_id')

    def test_prevent_vpn_port_deletion_other_device_owner(self):
        plugin = directory.get_plugin(nconstants.VPN)
        device_owner = v_constants.DEVICE_OWNER_TRANSIT_NETWORK
        with self.router() as router, \
                self.port(device_owner=device_owner) as transit_port, \
                self.port(device_owner='other-device-owner') as other_port:
            gateway = {'gateway': {
                'router_id': router['router']['id'],
                'transit_port_id': transit_port['port']['id'],
                'tenant_id': self.tenant_id
            }}
            admin_context = context.get_admin_context()
            plugin.create_gateway(admin_context, gateway)
            # BEFORE_DELETE event for other_port should not raise an exception
            self._pre_port_delete(admin_context, other_port['port']['id'])

    def test_prevent_vpn_subnet_deletion(self):
        plugin = directory.get_plugin(nconstants.VPN)
        with self.router() as router, self.subnet() as subnet:
            gateway = {'gateway': {
                'router_id': router['router']['id'],
                'transit_subnet_id': subnet['subnet']['id'],
                'tenant_id': self.tenant_id
            }}
            admin_context = context.get_admin_context()
            plugin.create_gateway(admin_context, gateway)
            self.assertRaises(
                cb_exc.CallbackFailure,
                self._pre_subnet_delete, admin_context, subnet['subnet']['id'])
            # should not raise an exception for other subnet id
            self._pre_subnet_delete(admin_context, "other-id")

    def test_prevent_vpn_network_deletion(self):
        plugin = directory.get_plugin(nconstants.VPN)
        with self.router() as router, self.network() as network:
            gateway = {'gateway': {
                'router_id': router['router']['id'],
                'transit_network_id': network['network']['id'],
                'tenant_id': self.tenant_id
            }}
            admin_context = context.get_admin_context()
            plugin.create_gateway(admin_context, gateway)
            self.assertRaises(
                cb_exc.CallbackFailure,
                self._pre_network_delete, admin_context,
                network['network']['id'])
            # should not raise an exception for other network id
            self._pre_network_delete(admin_context, "other-id")


class TestVPNExtGwDB(base.NeutronDbPluginV2TestCase,
                     test_vpn_db.NeutronResourcesMixin):
    def setUp(self):
        plugin_str = 'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin'
        super().setUp(plugin_str)

        self.core_plugin = directory.get_plugin()
        self.l3_plugin = directory.get_plugin(nconstants.L3)
        self.tenant_id = 'tenant1'
        self.context = context.get_admin_context()

    def _create_gw_port(self, router):
        port = {'port': {
            'tenant_id': self.tenant_id,
            'network_id': router['external_gateway_info']['network_id'],
            'fixed_ips': lib_constants.ATTR_NOT_SPECIFIED,
            'mac_address': lib_constants.ATTR_NOT_SPECIFIED,
            'admin_state_up': True,
            'device_id': router['id'],
            'device_owner': v_constants.DEVICE_OWNER_VPN_ROUTER_GW,
            'name': ''
        }}
        return self.core_plugin.create_port(self.context, port)

    def test_create_gateway(self):
        private_subnet, router = self.create_basic_topology()
        gateway = {'gateway': {
            'router_id': router['id'],
            'tenant_id': self.tenant_id
        }}
        gwdb = VPNExtGWPlugin_db()
        new_gateway = gwdb.create_gateway(self.context, gateway)
        expected = {**gateway['gateway'],
                    'status': lib_constants.PENDING_CREATE}
        self.assertDictSupersetOf(expected, new_gateway)

    def test_update_gateway_with_external_port(self):
        private_subnet, router = self.create_basic_topology()
        gwdb = VPNExtGWPlugin_db()
        # create gateway
        gateway = {'gateway': {
            'router_id': router['id'],
            'tenant_id': self.tenant_id
        }}
        new_gateway = gwdb.create_gateway(self.context, gateway)

        # create external port and update gateway with the port id
        gw_port = self._create_gw_port(router)
        gateway_update = {'gateway': {
            'gw_port_id': gw_port['id']
        }}
        gwdb.update_gateway(self.context, new_gateway['id'], gateway_update)

        # check that get_vpn_gw_dict_by_router_id includes external_fixed_ips
        found_gateway = gwdb.get_vpn_gw_dict_by_router_id(self.context,
                                                          router['id'])
        self.assertIn('external_fixed_ips', found_gateway)
        expected = sorted(gw_port['fixed_ips'])
        returned = sorted(found_gateway['external_fixed_ips'])
        self.assertEqual(returned, expected)

    def test_delete_gateway(self):
        private_subnet, router = self.create_basic_topology()
        gwdb = VPNExtGWPlugin_db()
        # create gateway
        gateway = {'gateway': {
            'router_id': router['id'],
            'tenant_id': self.tenant_id
        }}
        new_gateway = gwdb.create_gateway(self.context, gateway)
        self.assertIsNotNone(new_gateway)
        deleted = gwdb.delete_gateway(self.context, new_gateway['id'])
        self.assertEqual(deleted, 1)
        deleted = gwdb.delete_gateway(self.context, new_gateway['id'])
        self.assertEqual(deleted, 0)
        found_gateway = gwdb.get_vpn_gw_dict_by_router_id(self.context,
                                                          router['id'])
        self.assertIsNone(found_gateway)
