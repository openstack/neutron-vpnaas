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

import os
from unittest import mock

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3 import legacy_router
from neutron.conf.agent.l3 import config as l3_config
from neutron.tests.functional import base
from neutron_lib import constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn import agent as vpn_agent
from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.tests.functional.common import test_scenario

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

FAKE_IKE_POLICY2 = {
    'ike_version': 'v1',
    'encryption_algorithm': 'aes-256',
    'auth_algorithm': 'sha1',
    'pfs': 'group2',
    'lifetime_value': 1800
}

FAKE_IPSEC_POLICY2 = {
    'encryption_algorithm': 'aes-256',
    'auth_algorithm': 'sha1',
    'pfs': 'group2',
    'transform_protocol': 'esp',
    'lifetime_value': 1800,
    'encapsulation_mode': 'tunnel'
}


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
        self.router = legacy_router.LegacyRouter(router_id=FAKE_ROUTER_ID,
                                                 agent=mock.Mock(),
                                                 **ri_kwargs)
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


class TestStrongSwanScenario(test_scenario.TestIPSecBase):

    def setUp(self):
        super(TestStrongSwanScenario, self).setUp()
        self.conf.register_opts(strongswan_ipsec.strongswan_opts,
                                'strongswan')
        VPNAAS_STRONGSWAN_DEVICE = ('neutron_vpnaas.services.vpn.'
                                    'device_drivers.strongswan_ipsec.'
                                    'StrongSwanDriver')
        cfg.CONF.set_override('vpn_device_driver',
                              [VPNAAS_STRONGSWAN_DEVICE],
                              'vpnagent')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport('agent1',
                                                                self.conf)
        self.vpn_agent = vpn_agent.L3WithVPNaaS(self.conf)
        vpn_service = mock.Mock()
        vpn_service.conf = self.conf
        self.driver = strongswan_ipsec.StrongSwanDriver(
            vpn_service, host=mock.sentinel.host)

    def _override_ikepolicy_for_site(self, site, ikepolicy):
        ipsec_connection = site.vpn_service['ipsec_site_connections'][0]
        ipsec_connection['ikepolicy'] = ikepolicy

    def _override_ipsecpolicy_for_site(self, site, ipsecpolicy):
        ipsec_connection = site.vpn_service['ipsec_site_connections'][0]
        ipsec_connection['ipsecpolicy'] = ipsecpolicy

    def _override_dpd_for_site(self, site, dpdaction, dpddelay, dpdtimeout):
        ipsec_connection = site.vpn_service['ipsec_site_connections'][0]
        ipsec_connection['dpd_action'] = dpdaction
        ipsec_connection['dpd_interval'] = dpddelay
        ipsec_connection['dpd_timeout'] = dpdtimeout

    def _override_auth_algorithm_for_site(self, site, auth):
        ipsec_connection = site.vpn_service['ipsec_site_connections'][0]
        ipsec_connection['ipsecpolicy']['auth_algorithm'] = auth
        ipsec_connection['ikepolicy']['auth_algorithm'] = auth

    def test_strongswan_connection_with_non_default_value(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._override_ikepolicy_for_site(site1, FAKE_IKE_POLICY2)
        self._override_ikepolicy_for_site(site2, FAKE_IKE_POLICY2)
        self._override_ipsecpolicy_for_site(site1, FAKE_IPSEC_POLICY2)
        self._override_ipsecpolicy_for_site(site2, FAKE_IPSEC_POLICY2)
        self._override_dpd_for_site(site1, 'hold', 60, 240)
        self._override_dpd_for_site(site2, 'hold', 60, 240)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    def _test_strongswan_connection_with_auth_algo(self, auth_algo):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._override_auth_algorithm_for_site(site1, auth_algo)
        self._override_auth_algorithm_for_site(site2, auth_algo)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    def test_strongswan_connection_with_sha256(self):
        self._test_strongswan_connection_with_auth_algo('sha256')

    def test_strongswan_connection_with_sha384(self):
        self._test_strongswan_connection_with_auth_algo('sha384')

    def test_strongswan_connection_with_sha512(self):
        self._test_strongswan_connection_with_auth_algo('sha512')

    def test_strongswan_connection_with_non_ascii_vpnservice_name(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                                 [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                                 [self.private_nets[2]])
        site1.vpn_service.update(
            {'name': test_scenario.NON_ASCII_VPNSERVICE_NAME})

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    def test_strongswan_connection_with_non_ascii_psk(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._update_ipsec_connection(site1, psk=test_scenario.NON_ASCII_PSK)
        self._update_ipsec_connection(site2, psk=test_scenario.NON_ASCII_PSK)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    def test_strongswan_connection_with_wrong_non_ascii_psk(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._update_ipsec_connection(site1, psk=test_scenario.NON_ASCII_PSK)
        self._update_ipsec_connection(site2,
                                      psk=test_scenario.NON_ASCII_PSK[:-1])
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)
