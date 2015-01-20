# Copyright 2014 OpenStack Foundation.
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
from oslo.config import cfg

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import router_info
from neutron.agent.linux import iptables_manager
from neutron.extensions import vpnaas
from neutron.openstack.common import uuidutils
from neutron_vpnaas.services.vpn import agent as vpn_agent
from neutron_vpnaas.services.vpn import device_drivers
from neutron_vpnaas.services.vpn import vpn_service
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid

VPNAAS_NOP_DEVICE = ('neutron_vpnaas.tests.unit.services.'
                     'vpn.test_vpn_service.NoopDeviceDriver')
VPNAAS_DEFAULT_DEVICE = ('neutron_vpnaas.services.vpn.'
                         'device_drivers.ipsec.OpenSwanDriver')
FAKE_ROUTER_ID = _uuid()


class NoopDeviceDriver(device_drivers.DeviceDriver):

    def sync(self, context, processes):
        pass

    def create_router(self, process_id):
        pass

    def destroy_router(self, process_id):
        pass


class TestVirtualPrivateNetworkDeviceDriverLoading(base.BaseTestCase):

    def setUp(self):
        super(TestVirtualPrivateNetworkDeviceDriverLoading, self).setUp()
        cfg.CONF.register_opts(vpn_agent.vpn_agent_opts, 'vpnagent')
        self.agent = mock.Mock()
        self.service = vpn_service.VPNService.instance(self.agent)

    def test_loading_vpn_device_drivers(self):
        """Get two device drivers (in a list) for VPNaaS."""
        cfg.CONF.set_override('vpn_device_driver',
                              [VPNAAS_NOP_DEVICE, VPNAAS_NOP_DEVICE],
                              'vpnagent')

        drivers = self.service.load_device_drivers('host')
        self.assertEqual(2, len(drivers))
        self.assertIn(drivers[0].__class__.__name__, VPNAAS_NOP_DEVICE)
        self.assertIn(drivers[1].__class__.__name__, VPNAAS_NOP_DEVICE)

    def test_use_default_for_vpn_device_driver(self):
        """When no VPNaaS device drivers specified, we get the default."""
        drivers = self.service.load_device_drivers('host')
        self.assertEqual(1, len(drivers))
        self.assertIn(drivers[0].__class__.__name__, VPNAAS_DEFAULT_DEVICE)

    def test_fail_no_such_vpn_device_driver(self):
        """Failure test of import error for VPNaaS device driver."""
        cfg.CONF.set_override('vpn_device_driver',
                              ['no.such.class'],
                              'vpnagent')
        self.assertRaises(vpnaas.DeviceDriverImportError,
                          self.service.load_device_drivers, 'host')


class TestVPNDeviceDriverCallsToService(base.BaseTestCase):

    def setUp(self):
        super(TestVPNDeviceDriverCallsToService, self).setUp()
        self.conf = cfg.CONF
        agent_config.register_root_helper(self.conf)
        self.service = vpn_service.VPNService.instance(mock.Mock())
        self.iptables = mock.Mock()
        self.apply_mock = mock.Mock()

    def _make_router_info_for_test(self, ns_name=None, iptables=None):
        ri = router_info.RouterInfo(FAKE_ROUTER_ID, self.conf.root_helper,
                                    {}, ns_name=ns_name)
        ri.router['distributed'] = False
        if iptables:
            ri.iptables_manager.ipv4['nat'] = iptables
            ri.iptables_manager.apply = self.apply_mock
        self.service.l3_agent.router_info = {FAKE_ROUTER_ID: ri}

    def _make_dvr_router_info_for_test(self, ns_name=None, iptables=None):
        ri = router_info.RouterInfo(FAKE_ROUTER_ID, self.conf.root_helper,
                                    {}, ns_name=ns_name)
        ri.router['distributed'] = True
        if iptables:
            ri.snat_iptables_manager = iptables_manager.IptablesManager(
                root_helper=mock.ANY,
                namespace='snat-' + FAKE_ROUTER_ID,
                use_ipv6=mock.ANY)
            ri.snat_iptables_manager.ipv4['nat'] = iptables
            ri.snat_iptables_manager.apply = self.apply_mock
        self.service.l3_agent.router_info = {FAKE_ROUTER_ID: ri}

    def test_get_namespace_for_router(self):
        ns = "ns-" + FAKE_ROUTER_ID
        self._make_router_info_for_test(ns_name=ns)
        namespace = self.service.get_namespace(FAKE_ROUTER_ID)
        self.assertTrue(namespace.endswith(FAKE_ROUTER_ID))

    def test_get_namespace_for_dvr_router(self):
        ns = "ns-" + FAKE_ROUTER_ID
        self._make_dvr_router_info_for_test(ns_name=ns)
        namespace = self.service.get_namespace(FAKE_ROUTER_ID)
        self.assertTrue(namespace.startswith('snat'))
        self.assertTrue(namespace.endswith(FAKE_ROUTER_ID))

    def test_fail_getting_namespace_for_unknown_router(self):
        self._make_router_info_for_test()
        self.assertFalse(self.service.get_namespace('bogus_id'))

    def test_add_nat_rule(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.add_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                  'fake_rule', True)
        self.iptables.add_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_add_nat_rule_with_dvr_router(self):
        self._make_dvr_router_info_for_test(iptables=self.iptables)
        self.service.add_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                  'fake_rule', True)
        self.iptables.add_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_add_nat_rule_with_no_router(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.add_nat_rule(
            'bogus_router_id',
            'fake_chain',
            'fake_rule',
            True)
        self.assertFalse(self.iptables.add_rule.called)

    def test_remove_rule(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.remove_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                     'fake_rule', True)
        self.iptables.remove_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_remove_rule_with_dvr_router(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.remove_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                     'fake_rule', True)
        self.iptables.remove_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_remove_rule_with_no_router(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.remove_nat_rule(
            'bogus_router_id',
            'fake_chain',
            'fake_rule')
        self.assertFalse(self.iptables.remove_rule.called)

    def test_iptables_apply(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.iptables_apply(FAKE_ROUTER_ID)
        self.apply_mock.assert_called_once_with()

    def test_iptables_apply_with_dvr_router(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.iptables_apply(FAKE_ROUTER_ID)
        self.apply_mock.assert_called_once_with()

    def test_iptables_apply_with_no_router(self):
        self._make_router_info_for_test(iptables=self.iptables)
        self.service.iptables_apply('bogus_router_id')
        self.assertFalse(self.apply_mock.called)


class TestVPNServiceEventHandlers(base.BaseTestCase):

    def setUp(self):
        super(TestVPNServiceEventHandlers, self).setUp()
        self.conf = cfg.CONF
        agent_config.register_root_helper(self.conf)
        self.service = vpn_service.VPNService.instance(mock.Mock())
        self.device = mock.Mock()
        self.service.devices = [self.device]

    def test_actions_after_router_added(self):
        ri = router_info.RouterInfo(
            FAKE_ROUTER_ID, self.conf.root_helper, {})
        self.service.after_router_added(ri)
        self.device.create_router.assert_called_once_with(FAKE_ROUTER_ID)
        self.device.sync.assert_called_once_with(self.service.context,
                                                 [ri.router])

    def test_actions_after_router_removed(self):
        ri = router_info.RouterInfo(
            FAKE_ROUTER_ID, self.conf.root_helper, {},
            ns_name="qrouter-%s" % FAKE_ROUTER_ID)
        self.service.after_router_removed(ri)
        self.device.destroy_router.assert_called_once_with(FAKE_ROUTER_ID)

    def test_actions_after_router_updated(self):
        ri = router_info.RouterInfo(
            FAKE_ROUTER_ID, self.conf.root_helper, {})
        self.service.after_router_updated(ri)
        self.device.sync.assert_called_once_with(self.service.context,
                                                 [ri.router])
