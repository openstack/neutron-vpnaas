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
from neutron.agent.l3 import legacy_router
from neutron.openstack.common import uuidutils
from oslo_config import cfg

from neutron_vpnaas.extensions import vpnaas
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

    def create_router(self, router_info):
        pass

    def destroy_router(self, process_id):
        pass


class VPNBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(VPNBaseTestCase, self).setUp()
        self.conf = cfg.CONF
        self.ri_kwargs = {'router': {'id': FAKE_ROUTER_ID},
                          'agent_conf': self.conf,
                          'interface_driver': mock.sentinel.interface_driver}


class TestVirtualPrivateNetworkDeviceDriverLoading(VPNBaseTestCase):

    def setUp(self):
        super(TestVirtualPrivateNetworkDeviceDriverLoading, self).setUp()
        cfg.CONF.register_opts(vpn_agent.vpn_agent_opts, 'vpnagent')
        self.agent = mock.Mock()
        self.service = vpn_service.VPNService(self.agent)

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


class TestVPNServiceEventHandlers(VPNBaseTestCase):

    def setUp(self):
        super(TestVPNServiceEventHandlers, self).setUp()
        self.service = vpn_service.VPNService(mock.Mock())
        self.device = mock.Mock()
        self.service.devices = [self.device]

    def test_actions_after_router_added(self):
        ri = legacy_router.LegacyRouter(FAKE_ROUTER_ID, **self.ri_kwargs)
        self.service.after_router_added(ri)
        self.device.create_router.assert_called_once_with(ri)
        self.device.sync.assert_called_once_with(self.service.context,
                                                 [ri.router])

    def test_actions_after_router_removed(self):
        ri = legacy_router.LegacyRouter(FAKE_ROUTER_ID, **self.ri_kwargs)
        self.service.after_router_removed(ri)
        self.device.destroy_router.assert_called_once_with(FAKE_ROUTER_ID)

    def test_actions_after_router_updated(self):
        ri = legacy_router.LegacyRouter(FAKE_ROUTER_ID, **self.ri_kwargs)
        self.service.after_router_updated(ri)
        self.device.sync.assert_called_once_with(self.service.context,
                                                 [ri.router])
