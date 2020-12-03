# Copyright 2023 SysEleven GmbH.
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

from unittest import mock

from neutron.agent.linux import ip_lib
from neutron.conf.agent import common as agent_config
from neutron.conf import common as common_config
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn.device_drivers import ovn_ipsec
from neutron_vpnaas.tests import base
from neutron_vpnaas.tests.unit.services.vpn.device_drivers import test_ipsec

_uuid = uuidutils.generate_uuid


FAKE_PROCESS_ID = "c5b52e50-e678-491e-98dd-34e2676a6f81"
FAKE_NAMESPACE_NAME = "qvpn-c5b52e50-e678-491e-98dd-34e2676a6f81"

FAKE_GW_PORT_ID = "e95d89fb-1723-4865-876f-a1c8efed4b55"
FAKE_GW_PORT_INTERFACE_NAME = "vge95d89fb-172"
FAKE_GW_PORT_IP_ADDRESS = "20.20.20.20"
FAKE_GW_PORT_MAC_ADDRESS = "11:22:33:44:55:66"
FAKE_GW_PORT_SUBNET_ID = _uuid()
FAKE_GW_PORT_SUBNET_INFO = {
    'id': FAKE_GW_PORT_SUBNET_ID,
    'cidr': '20.20.20.0/24',
    'ip_version': 4
}
FAKE_GW_PORT = {
    'id': FAKE_GW_PORT_ID,
    'mac_address': FAKE_GW_PORT_MAC_ADDRESS,
    'fixed_ips': [{
        'ip_address': FAKE_GW_PORT_IP_ADDRESS,
        'subnet_id': FAKE_GW_PORT_SUBNET_ID
    }]
}
FAKE_TRANSIT_PORT_ID = "0eb4bdb3-fe2e-4724-bb04-f84b6a5974f8"
FAKE_TRANSIT_PORT_INTERFACE_NAME = "vr0eb4bdb3-fe2"
FAKE_TRANSIT_PORT_MAC_ADDRESS = "22:33:44:55:66:77"
FAKE_TRANSIT_PORT_IP_ADDRESS = "169.254.0.2"
FAKE_TRANSIT_PORT_SUBNET_ID = _uuid()
FAKE_TRANSIT_PORT = {
    'id': FAKE_TRANSIT_PORT_ID,
    'mac_address': FAKE_TRANSIT_PORT_MAC_ADDRESS,
    'fixed_ips': [{
        'ip_address': FAKE_TRANSIT_PORT_IP_ADDRESS,
        'subnet_id': FAKE_TRANSIT_PORT_SUBNET_ID
    }]
}


def fake_interface_driver(*args, **kwargs):
    driver = mock.Mock()
    driver.DEV_NAME_LEN = 14
    return driver


class TestDeviceManager(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.conf = cfg.CONF
        self.conf.register_opts(common_config.core_opts)
        self.conf.register_opts(agent_config.INTERFACE_DRIVER_OPTS)
        self.conf.set_override('interface_driver',
            'neutron_vpnaas.tests.unit.services.vpn.device_drivers'
            '.test_ovn_ipsec.fake_interface_driver')
        self.host = "some-hostname"
        self.plugin = mock.Mock()
        self.plugin.get_subnet_info.return_value = FAKE_GW_PORT_SUBNET_INFO
        self.context = mock.Mock()

    def test_names(self):
        mgr = ovn_ipsec.DeviceManager(self.conf, self.host,
                        self.plugin, self.context)
        port = {'id': "0df5beb8-4794-4217-acde-e6ce4875a59f"}
        name = mgr.get_interface_name(port, "internal")
        self.assertEqual(name, "vr0df5beb8-479")

        name = mgr.get_interface_name(port, "external")
        self.assertEqual(name, "vg0df5beb8-479")

        name = mgr.get_namespace_name("0df5beb8-4794-4217-acde-e6ce4875a59f")
        self.assertEqual(name, "qvpn-0df5beb8-4794-4217-acde-e6ce4875a59f")

    def test_setup_external(self):
        ext_net_id = _uuid()
        network_details = {
            'gw_port': FAKE_GW_PORT,
            'external_network': {
                'id': ext_net_id
            }
        }

        mgr = ovn_ipsec.DeviceManager(self.conf, self.host,
                        self.plugin, self.context)

        with mock.patch.object(ip_lib, 'ensure_device_is_ready') as dev_ready:
            with mock.patch.object(mgr, 'set_default_route') as set_def_route:
                dev_ready.return_value = False

                mgr.setup_external(FAKE_PROCESS_ID, network_details)

                dev_ready.assert_called_once()
                self.plugin.get_subnet_info.assert_called_once_with(
                    FAKE_GW_PORT_SUBNET_ID
                )
                set_def_route.assert_called_once_with(
                    FAKE_NAMESPACE_NAME,
                    FAKE_GW_PORT_SUBNET_INFO,
                    FAKE_GW_PORT_INTERFACE_NAME
                )
                mgr.driver.init_l3.assert_called_once()
                mgr.driver.plug.assert_called_once()

    def test_setup_internal(self):
        network_details = {'transit_port': FAKE_TRANSIT_PORT}

        mgr = ovn_ipsec.DeviceManager(self.conf, self.host,
                        self.plugin, self.context)

        with mock.patch.object(ip_lib, 'ensure_device_is_ready') as dev_ready:
            dev_ready.return_value = False

            mgr.setup_internal(FAKE_PROCESS_ID, network_details)

            dev_ready.assert_called_once()
            mgr.driver.init_l3.assert_called_once()
            mgr.driver.plug.assert_called_once()

    def test_list_routes(self):
        mgr = ovn_ipsec.DeviceManager(self.conf, self.host,
                self.plugin, self.context)
        mock_ipdev = mock.Mock()
        routes = [
            {'cidr': '192.168.111.0/24', 'via': FAKE_TRANSIT_PORT_IP_ADDRESS}
        ]
        with mock.patch.object(ip_lib, 'IPDevice') as ipdev:
            ipdev.return_value = mock_ipdev
            mock_ipdev.route.list_routes.return_value = routes
            returned = mgr.list_routes(FAKE_NAMESPACE_NAME)
            self.assertEqual(returned, routes)

    def test_del_static_routes(self):
        mgr = ovn_ipsec.DeviceManager(self.conf, self.host, self.plugin,
                                      self.context)
        mock_ipdev = mock.Mock()
        routes = [
            {'cidr': '192.168.111.0/24', 'via': FAKE_TRANSIT_PORT_IP_ADDRESS},
            {'cidr': '192.168.112.0/24', 'via': FAKE_TRANSIT_PORT_IP_ADDRESS}
        ]
        with mock.patch.object(ip_lib, 'IPDevice') as ipdev:
            ipdev.return_value = mock_ipdev
            mock_ipdev.route.list_routes.return_value = routes

            mgr.del_static_routes(FAKE_NAMESPACE_NAME)

            mock_ipdev.route.delete_route.assert_has_calls([
                mock.call(routes[0]['cidr'], via=FAKE_TRANSIT_PORT_IP_ADDRESS),
                mock.call(routes[1]['cidr'], via=FAKE_TRANSIT_PORT_IP_ADDRESS),
            ], any_order=True)


class TestOvnStrongSwanDriver(test_ipsec.IPSecDeviceLegacy):

    def setUp(self, driver=ovn_ipsec.OvnStrongSwanDriver,
              ipsec_process=ovn_ipsec.OvnStrongSwanProcess):
        conf = cfg.CONF
        conf.register_opts(common_config.core_opts)
        conf.register_opts(agent_config.INTERFACE_DRIVER_OPTS)
        conf.set_override('interface_driver',
            'neutron_vpnaas.tests.unit.services.vpn.device_drivers'
            '.test_ovn_ipsec.fake_interface_driver')

        super().setUp(driver, ipsec_process)
        self.driver.nsmgr = mock.Mock()
        self.driver.nsmgr.exists.return_value = False
        self.driver.devmgr = mock.Mock()
        self.driver.devmgr.get_namespace_name.return_value = \
            FAKE_NAMESPACE_NAME
        self.driver.devmgr.list_routes.return_value = []
        self.driver.devmgr.get_existing_process_ids.return_value = []
        self.driver.agent_rpc.get_vpn_transit_network_details.return_value = {
            'transit_gateway_ip': '192.168.1.1',
        }

    def test_iptables_apply(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_get_namespace_for_router(self):
        """Different for OvnIPsecDriver"""
        namespace = self.driver.get_namespace(FAKE_PROCESS_ID)
        self.assertEqual(FAKE_NAMESPACE_NAME, namespace)

    def test_fail_getting_namespace_for_unknown_router(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_create_router(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_destroy_router(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_remove_rule(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_add_nat_rules_with_multiple_local_subnets(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def _test_add_nat_rule(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_add_nat_rule(self):
        """Not applicable for OvnIPsecDriver"""
        pass

    def test_stale_cleanup(self):
        process = self.fake_ensure_process(FAKE_PROCESS_ID)

        self.driver.devmgr.get_existing_process_ids.return_value = [
            FAKE_PROCESS_ID]

        self.driver.agent_rpc.get_vpn_services_on_host.return_value = []
        context = mock.Mock()
        with mock.patch.object(self.driver, 'ensure_process') as ensure:
            ensure.return_value = process
            self.driver.sync(context, [])
            process.disable.assert_called()


class TestOvnOpenSwanDriver(TestOvnStrongSwanDriver):
    def setUp(self):
        super().setUp(driver=ovn_ipsec.OvnOpenSwanDriver,
                      ipsec_process=ovn_ipsec.OvnOpenSwanProcess)


class TestOvnLibreSwanDriver(TestOvnStrongSwanDriver):
    def setUp(self):
        super().setUp(driver=ovn_ipsec.OvnLibreSwanDriver,
                      ipsec_process=ovn_ipsec.OvnLibreSwanProcess)
