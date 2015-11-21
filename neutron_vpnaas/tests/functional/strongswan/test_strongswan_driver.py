# Copyright (c) 2015 Canonical, Inc.
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
import os

from neutron.agent.l3 import config as l3_config
from neutron.agent.l3 import legacy_router
from neutron.plugins.common import constants
from neutron.tests.functional import base
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec

_uuid = uuidutils.generate_uuid
FAKE_ROUTER_ID = _uuid()
FAKE_IPSEC_SITE_CONNECTION1_ID = _uuid()
FAKE_IPSEC_SITE_CONNECTION2_ID = _uuid()
FAKE_IKE_POLICY = {
    'ike_version': 'v1',
    'encryption_algorithm': 'aes-128',
    'auth_algorithm': 'sha1',
    'pfs': 'group5'
}

FAKE_IPSEC_POLICY = {
    'encryption_algorithm': 'aes-128',
    'auth_algorithm': 'sha1',
    'pfs': 'group5'
}

FAKE_VPN_SERVICE = {
    'id': _uuid(),
    'router_id': FAKE_ROUTER_ID,
    'name': 'myvpn',
    'admin_state_up': True,
    'status': constants.PENDING_CREATE,
    'external_ip': '50.0.0.4',
    'subnet': {'cidr': '10.0.0.0/24'},
    'ipsec_site_connections': [
        {'peer_cidrs': ['20.0.0.0/24',
                        '30.0.0.0/24'],
         'id': FAKE_IPSEC_SITE_CONNECTION1_ID,
         'external_ip': '50.0.0.4',
         'peer_address': '30.0.0.5',
         'peer_id': '30.0.0.5',
         'psk': 'password',
         'initiator': 'bi-directional',
         'ikepolicy': FAKE_IKE_POLICY,
         'ipsecpolicy': FAKE_IPSEC_POLICY,
         'status': constants.PENDING_CREATE},
        {'peer_cidrs': ['40.0.0.0/24',
                        '50.0.0.0/24'],
         'external_ip': '50.0.0.4',
         'peer_address': '50.0.0.5',
         'peer_id': '50.0.0.5',
         'psk': 'password',
         'id': FAKE_IPSEC_SITE_CONNECTION2_ID,
         'initiator': 'bi-directional',
         'ikepolicy': FAKE_IKE_POLICY,
         'ipsecpolicy': FAKE_IPSEC_POLICY,
         'status': constants.PENDING_CREATE}]
}

DESIRED_CONN_STATUS = {FAKE_IPSEC_SITE_CONNECTION1_ID:
                       {'status': 'DOWN',
                        'updated_pending_status': False},
                       FAKE_IPSEC_SITE_CONNECTION2_ID:
                       {'status': 'DOWN',
                        'updated_pending_status': False}}


class TestStrongSwanDeviceDriver(base.BaseSudoTestCase):

    """Test the StrongSwan reference implementation of the device driver."""

    def setUp(self):
        super(TestStrongSwanDeviceDriver, self).setUp()
        self.conf = cfg.CONF
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(ipsec.ipsec_opts, 'ipsec')
        self.conf.register_opts(strongswan_ipsec.strongswan_opts,
                                'strongswan')
        self.conf.set_override('state_path', '/tmp')

        ri_kwargs = {'router': {'id': FAKE_ROUTER_ID},
                     'agent_conf': self.conf,
                     'interface_driver': mock.sentinel.interface_driver}
        self.router = legacy_router.LegacyRouter(FAKE_ROUTER_ID, **ri_kwargs)
        self.router.router['distributed'] = False
        self.router_id = FAKE_VPN_SERVICE['router_id']

        looping_call_p = mock.patch(
            'oslo_service.loopingcall.FixedIntervalLoopingCall')
        looping_call_p.start()

        vpn_service = mock.Mock()
        vpn_service.conf = self.conf
        self.driver = strongswan_ipsec.StrongSwanDriver(
            vpn_service, host=mock.sentinel.host)
        self.driver.routers[FAKE_ROUTER_ID] = self.router
        self.driver.agent_rpc = mock.Mock()
        self.driver._update_nat = mock.Mock()
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            FAKE_VPN_SERVICE]
        self.addCleanup(self.driver.destroy_router, self.router_id)

        self.router.router_namespace.create()
        self.addCleanup(self.router.router_namespace.delete)

    def test_process_lifecycle(self):
        """
        Lifecycle test that validates that the strongswan process could be
        launched, that a connection could be successfully initiated through
        it, and then that it could be terminated and clean up after itself.
        """
        process = self.driver.ensure_process(self.router_id,
                                             FAKE_VPN_SERVICE)
        process.enable()
        self.assertTrue(process.active)
        self.assertIn(self.router_id, self.driver.processes)
        self.assertEqual(DESIRED_CONN_STATUS, process.connection_status)
        self.assertIsNotNone(process.namespace)

        conf_dir = os.path.join(self.conf.ipsec.config_base_dir,
                                self.router_id)
        self.assertTrue(os.path.exists(conf_dir))
        process.disable()
        self.assertFalse(process.active)
        self.assertFalse(process.connection_status)
        self.assertFalse(os.path.exists(conf_dir))
