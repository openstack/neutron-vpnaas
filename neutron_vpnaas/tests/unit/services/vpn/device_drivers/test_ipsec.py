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
import copy
import difflib
import io
import mock
import os
import socket

from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import legacy_router
from neutron.agent.linux import iptables_manager
from neutron.plugins.common import constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.services.vpn.device_drivers import fedora_strongswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import ipsec as openswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import libreswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid
FAKE_HOST = 'fake_host'
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
         'admin_state_up': True,
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
         'admin_state_up': True,
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


AUTH_ESP = '''esp
    # [encryption_algorithm]-[auth_algorithm]-[pfs]
    phase2alg=aes128-sha1;modp1536'''

AUTH_AH = '''ah
    # AH protocol does not support encryption
    # [auth_algorithm]-[pfs]
    phase2alg=sha1;modp1536'''

OPENSWAN_CONNECTION_DETAILS = '''# rightsubnet=networkA/netmaskA, networkB/netmaskB (IKEv2 only)
    # [mtu]
    # Note It looks like not supported in the strongswan driver
    # ignore it now
    # [dpd_action]
    dpdaction=
    # [dpd_interval]
    dpddelay=
    # [dpd_timeout]
    dpdtimeout=
    # [auth_mode]
    authby=secret
    ######################
    # IKEPolicy params
    ######################
    #ike version
    ikev2=never
    # [encryption_algorithm]-[auth_algorithm]-[pfs]
    ike=aes128-sha1;modp1536
    # [lifetime_value]
    ikelifetime=s
    # NOTE: it looks lifetime_units=kilobytes can't be enforced \
(could be seconds,  hours,  days...)
    ##########################
    # IPsecPolicys params
    ##########################
    # [transform_protocol]
    auth=%(auth_mode)s
    # [encapsulation_mode]
    type=
    # [lifetime_value]
    lifetime=s
    # lifebytes=100000 if lifetime_units=kilobytes (IKEv2 only)
'''


EXPECTED_OPENSWAN_CONF = """
# Configuration for myvpn
config setup
    nat_traversal=yes
conn %(default_id)s
    ikelifetime=480m
    keylife=60m
    keyingtries=%%forever
conn %(conn1_id)s
    # NOTE: a default route is required for %%defaultroute to work...
    leftnexthop=%%defaultroute
    rightnexthop=%%defaultroute
    left=50.0.0.4
    leftid=50.0.0.4
    auto=start
    # NOTE:REQUIRED
    # [subnet]
    leftsubnet=10.0.0.0/24
    # leftsubnet=networkA/netmaskA, networkB/netmaskB (IKEv2 only)
    ######################
    # ipsec_site_connections
    ######################
    # [peer_address]
    right=30.0.0.5
    # [peer_id]
    rightid=30.0.0.5
    # [peer_cidrs]
    rightsubnets={ 20.0.0.0/24 30.0.0.0/24 }
    %(conn_details)sconn %(conn2_id)s
    # NOTE: a default route is required for %%defaultroute to work...
    leftnexthop=%%defaultroute
    rightnexthop=%%defaultroute
    left=50.0.0.4
    leftid=50.0.0.4
    auto=start
    # NOTE:REQUIRED
    # [subnet]
    leftsubnet=10.0.0.0/24
    # leftsubnet=networkA/netmaskA, networkB/netmaskB (IKEv2 only)
    ######################
    # ipsec_site_connections
    ######################
    # [peer_address]
    right=50.0.0.5
    # [peer_id]
    rightid=50.0.0.5
    # [peer_cidrs]
    rightsubnets={ 40.0.0.0/24 50.0.0.0/24 }
    %(conn_details)s
"""

EXPECTED_IPSEC_OPENSWAN_SECRET_CONF = '''
# Configuration for myvpn
50.0.0.4 30.0.0.5 : PSK "password"
50.0.0.4 50.0.0.5 : PSK "password"'''

EXPECTED_IPSEC_STRONGSWAN_CONF = '''
# Configuration for myvpn
config setup

conn %(default_id)s
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        authby=psk
        mobike=no

conn %(conn1_id)s
    keyexchange=ikev1
    left=50.0.0.4
    leftsubnet=10.0.0.0/24
    leftid=50.0.0.4
    leftfirewall=yes
    right=30.0.0.5
    rightsubnet=20.0.0.0/24,30.0.0.0/24
    rightid=30.0.0.5
    auto=route

conn %(conn2_id)s
    keyexchange=ikev1
    left=50.0.0.4
    leftsubnet=10.0.0.0/24
    leftid=50.0.0.4
    leftfirewall=yes
    right=50.0.0.5
    rightsubnet=40.0.0.0/24,50.0.0.0/24
    rightid=50.0.0.5
    auto=route
''' % {'default_id': '%default',
       'conn1_id': FAKE_IPSEC_SITE_CONNECTION1_ID,
       'conn2_id': FAKE_IPSEC_SITE_CONNECTION2_ID}

EXPECTED_STRONGSWAN_DEFAULT_CONF = '''
charon {
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
}

include strongswan.d/*.conf
'''

EXPECTED_IPSEC_STRONGSWAN_SECRET_CONF = '''
# Configuration for myvpn
50.0.0.4 30.0.0.5 : PSK "password"

50.0.0.4 50.0.0.5 : PSK "password"
'''

ACTIVE_STATUS = "%(conn_id)s{1}:  INSTALLED, TUNNEL" % {'conn_id':
    FAKE_IPSEC_SITE_CONNECTION2_ID}
DOWN_STATUS = "%(conn_id)s{1}:  ROUTED, TUNNEL" % {'conn_id':
    FAKE_IPSEC_SITE_CONNECTION2_ID}
NOT_RUNNING_STATUS = "Command: ['ipsec', 'status'] Exit code: 3 Stdout:"


class BaseIPsecDeviceDriver(base.BaseTestCase):
    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(BaseIPsecDeviceDriver, self).setUp()
        for klass in [
            'neutron.common.rpc.create_connection',
            'oslo_service.loopingcall.FixedIntervalLoopingCall'
        ]:
            mock.patch(klass).start()
        self._execute = mock.patch.object(ipsec_process, '_execute').start()
        self.agent = mock.Mock()
        self.conf = cfg.CONF
        self.agent.conf = self.conf
        self.driver = driver(
            self.agent,
            FAKE_HOST)
        self.conf.use_namespaces = True
        self.driver.agent_rpc = mock.Mock()
        self.ri_kwargs = {'router': {'id': FAKE_ROUTER_ID, 'ha': False},
                          'agent_conf': self.conf,
                          'interface_driver': mock.sentinel.interface_driver}
        self.iptables = mock.Mock()
        self.apply_mock = mock.Mock()
        self.vpnservice = copy.deepcopy(FAKE_VPN_SERVICE)

    @staticmethod
    def generate_diff(a, b):
        """Generates unified diff of a and b."""
        by_lines = lambda x: x.splitlines(True)
        a, b = list(by_lines(a)), list(by_lines(b))
        diff = difflib.unified_diff(a, b, fromfile="expected",
                                    tofile="actual")
        return diff


class IPSecDeviceLegacy(BaseIPsecDeviceDriver):

    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(IPSecDeviceLegacy, self).setUp(driver, ipsec_process)
        self._make_router_info_for_test()

    def _make_router_info_for_test(self):
        self.router = legacy_router.LegacyRouter(FAKE_ROUTER_ID,
                                                 **self.ri_kwargs)
        self.router.router['distributed'] = False
        self.router.iptables_manager.ipv4['nat'] = self.iptables
        self.router.iptables_manager.apply = self.apply_mock
        self.driver.routers[FAKE_ROUTER_ID] = self.router

    def _test_vpnservice_updated(self, expected_param, **kwargs):
        with mock.patch.object(self.driver, 'sync') as sync:
            context = mock.Mock()
            self.driver.vpnservice_updated(context, **kwargs)
            sync.assert_called_once_with(context, expected_param)

    def test_vpnservice_updated(self):
        self._test_vpnservice_updated([])

    def test_vpnservice_updated_with_router_info(self):
        router_info = {'id': FAKE_ROUTER_ID, 'ha': False}
        kwargs = {'router': router_info}
        self._test_vpnservice_updated([router_info], **kwargs)

    def test_create_router(self):
        process = mock.Mock(openswan_ipsec.OpenSwanProcess)
        process.vpnservice = self.vpnservice
        self.driver.processes = {
            FAKE_ROUTER_ID: process}
        self.driver.create_router(self.router)
        self._test_add_nat_rule_helper()
        process.enable.assert_called_once_with()

    def test_destroy_router(self):
        process_id = _uuid()
        process = mock.Mock()
        process.vpnservice = self.vpnservice
        self.driver.processes = {
            process_id: process}
        self.driver.destroy_router(process_id)
        process.disable.assert_called_once_with()
        self.assertNotIn(process_id, self.driver.processes)

    def _test_add_nat_rule_helper(self):
        self.router.iptables_manager.ipv4['nat'].assert_has_calls([
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 20.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 30.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 50.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True)
        ])
        self.router.iptables_manager.apply.assert_called_once_with()

    def test_sync(self):
        fake_vpn_service = FAKE_VPN_SERVICE
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            fake_vpn_service]
        context = mock.Mock()
        self.driver._sync_vpn_processes = mock.Mock()
        self.driver._delete_vpn_processes = mock.Mock()
        self.driver._cleanup_stale_vpn_processes = mock.Mock()
        sync_routers = [{'id': fake_vpn_service['router_id']}]
        sync_router_ids = [fake_vpn_service['router_id']]
        self.driver.sync(context, sync_routers)
        self.driver._sync_vpn_processes.assert_called_once_with(
            [fake_vpn_service], sync_router_ids)
        self.driver._delete_vpn_processes.assert_called_once_with(
            sync_router_ids, sync_router_ids)
        self.driver._cleanup_stale_vpn_processes.assert_called_once_with(
            sync_router_ids)

    def test__sync_vpn_processes_new_vpn_service(self):
        new_vpnservice = self.vpnservice
        router_id = new_vpnservice['router_id']
        self.driver.processes = {}
        with mock.patch.object(self.driver, 'ensure_process') as ensure_p:
            ensure_p.side_effect = self.fake_ensure_process
            self.driver._sync_vpn_processes([new_vpnservice], router_id)
            self._test_add_nat_rule_helper()
            self.driver.processes[router_id].update.assert_called_once_with()

    def test__sync_vpn_processes_router_with_no_vpn(self):
        """Test _sync_vpn_processes with a router not hosting vpnservice.

        This test case tests that when a router which doesn't host
        vpn services is updated, sync_vpn_processes doesn't restart/update
        the existing vpnservice processes.
        """
        process = mock.Mock()
        process.vpnservice = self.vpnservice
        process.connection_status = {}
        self.driver.processes = {
            self.vpnservice['router_id']: process}
        router_id_no_vpn = _uuid()
        with mock.patch.object(self.driver, 'ensure_process') as ensure_p:
            self.driver._sync_vpn_processes([self.vpnservice],
                                            [router_id_no_vpn])
            self.assertEqual(ensure_p.call_count, 0)

    def test__sync_vpn_processes_router_with_no_vpn_and_no_vpn_services(self):
        """No vpn services running and router not hosting vpn svc."""
        router_id_no_vpn = _uuid()
        self.driver.process_status_cache = {}
        self.driver.processes = {}
        with mock.patch.object(self.driver, 'ensure_process') as ensure_p:
            ensure_p.side_effect = self.fake_ensure_process
            self.driver._sync_vpn_processes([], [router_id_no_vpn])
            self.assertEqual(ensure_p.call_count, 0)

    def test__sync_vpn_processes_router_with_no_vpn_agent_restarted(self):
        """Test for the router not hosting vpnservice and agent restarted.

        This test case tests that when a non vpnservice hosted router
        is updated, _sync_vpn_processes restart/update the existing vpnservices
        which are not yet stored in driver.processes.
        """
        router_id = FAKE_ROUTER_ID
        self.driver.process_status_cache = {}
        self.driver.processes = {}
        with mock.patch.object(self.driver, 'ensure_process') as ensure_p:
            ensure_p.side_effect = self.fake_ensure_process
            self.driver._sync_vpn_processes([self.vpnservice], [router_id])
            self._test_add_nat_rule_helper()
            self.driver.processes[router_id].update.assert_called_once_with()

    def test_delete_vpn_processes(self):
        router_id_no_vpn = _uuid()
        vpn_service_router_id = _uuid()
        with mock.patch.object(self.driver,
            'destroy_process') as (fake_destroy_process):
            self.driver._delete_vpn_processes([router_id_no_vpn],
                                              [vpn_service_router_id])
            fake_destroy_process.assert_has_calls(
                [mock.call(router_id_no_vpn)])

        # test that _delete_vpn_processes doesn't delete the
        # the valid vpn processes
        with mock.patch.object(self.driver,
            'destroy_process') as fake_destroy_process:
            self.driver._delete_vpn_processes([vpn_service_router_id],
                                              [vpn_service_router_id])
            self.assertFalse(fake_destroy_process.called)

    def test_cleanup_stale_vpn_processes(self):
        stale_vpn_service = {'router_id': _uuid()}
        active_vpn_service = {'router_id': _uuid()}
        self.driver.processes = {
            stale_vpn_service['router_id']: stale_vpn_service,
            active_vpn_service['router_id']: active_vpn_service}
        with mock.patch.object(self.driver, 'destroy_process') as destroy_p:
            self.driver._cleanup_stale_vpn_processes(
                [active_vpn_service['router_id']])
            destroy_p.assert_has_calls(
                [mock.call(stale_vpn_service['router_id'])])

    def fake_ensure_process(self, process_id, vpnservice=None):
        process = self.driver.processes.get(process_id)
        if not process:
            process = mock.Mock()
            process.vpnservice = self.vpnservice
            process.connection_status = {}
            process.status = constants.ACTIVE
            process.updated_pending_status = True
            self.driver.processes[process_id] = process
        elif vpnservice:
            process.vpnservice = vpnservice
            process.update_vpnservice(vpnservice)
        return process

    def fake_destroy_router(self, process_id):
        process = self.driver.processes.get(process_id)
        if process:
            del self.driver.processes[process_id]

    def test_sync_update_vpnservice(self):
        with mock.patch.object(self.driver,
                               'ensure_process') as ensure_process:
            ensure_process.side_effect = self.fake_ensure_process
            new_vpn_service = FAKE_VPN_SERVICE
            updated_vpn_service = copy.deepcopy(new_vpn_service)
            updated_vpn_service['ipsec_site_connections'].append(
                {'peer_cidrs': ['60.0.0.0/24',
                                '70.0.0.0/24']})
            context = mock.Mock()
            self.driver.process_status_cache = {}
            self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
                new_vpn_service]
            self.driver.sync(context, [{'id': FAKE_ROUTER_ID}])
            process = self.driver.processes[FAKE_ROUTER_ID]
            self.assertEqual(process.vpnservice, new_vpn_service)
            self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
                updated_vpn_service]
            self.driver.sync(context, [{'id': FAKE_ROUTER_ID}])
            process = self.driver.processes[FAKE_ROUTER_ID]
            process.update_vpnservice.assert_called_once_with(
                updated_vpn_service)
            self.assertEqual(process.vpnservice, updated_vpn_service)

    def test_sync_removed(self):
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = []
        context = mock.Mock()
        process_id = _uuid()
        process = mock.Mock()
        process.vpnservice = self.vpnservice
        self.driver.processes = {
            process_id: process}
        self.driver.sync(context, [])
        process.disable.assert_called_once_with()
        self.assertNotIn(process_id, self.driver.processes)

    def test_sync_removed_router(self):
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = []
        context = mock.Mock()
        process_id = _uuid()
        self.driver.sync(context, [{'id': process_id}])
        self.assertNotIn(process_id, self.driver.processes)

    def test_status_updated_on_connection_admin_down(self):
        self.driver.process_status_cache = {
            '1': {
                'status': constants.ACTIVE,
                'id': 123,
                'updated_pending_status': False,
                'ipsec_site_connections': {
                    '10': {
                        'status': constants.ACTIVE,
                        'updated_pending_status': False,
                    },
                    '20': {
                        'status': constants.ACTIVE,
                        'updated_pending_status': False,
                    }
                }
            }
        }
        # Simulate that there is no longer status for connection '20'
        # e.g. connection admin down
        new_status = {
            'ipsec_site_connections': {
                '10': {
                    'status': constants.ACTIVE,
                    'updated_pending_status': False
                }
            }
        }
        self.driver.update_downed_connections('1', new_status)
        existing_conn = new_status['ipsec_site_connections'].get('10')
        self.assertIsNotNone(existing_conn)
        self.assertEqual(constants.ACTIVE, existing_conn['status'])
        missing_conn = new_status['ipsec_site_connections'].get('20')
        self.assertIsNotNone(missing_conn)
        self.assertEqual(constants.DOWN, missing_conn['status'])

    def test_status_updated_on_service_admin_down(self):
        self.driver.process_status_cache = {
            '1': {
                'status': constants.ACTIVE,
                'id': 123,
                'updated_pending_status': False,
                'ipsec_site_connections': {
                    '10': {
                        'status': constants.ACTIVE,
                        'updated_pending_status': False,
                    },
                    '20': {
                        'status': constants.ACTIVE,
                        'updated_pending_status': False,
                    }
                }
            }
        }
        # Simulate that there are no connections now
        new_status = {
            'ipsec_site_connections': {}
        }
        self.driver.update_downed_connections('1', new_status)
        missing_conn = new_status['ipsec_site_connections'].get('10')
        self.assertIsNotNone(missing_conn)
        self.assertEqual(constants.DOWN, missing_conn['status'])
        missing_conn = new_status['ipsec_site_connections'].get('20')
        self.assertIsNotNone(missing_conn)
        self.assertEqual(constants.DOWN, missing_conn['status'])

    def test_get_namespace_for_router(self):
        namespace = self.driver.get_namespace(FAKE_ROUTER_ID)
        self.assertEqual('qrouter-' + FAKE_ROUTER_ID, namespace)

    def test_fail_getting_namespace_for_unknown_router(self):
        self.assertFalse(self.driver.get_namespace('bogus_id'))

    def test_add_nat_rule(self):
        self.driver.add_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                 'fake_rule', True)
        self.iptables.add_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_add_nat_rule_with_no_router(self):
        self.driver.add_nat_rule(
            'bogus_router_id',
            'fake_chain',
            'fake_rule',
            True)
        self.assertFalse(self.iptables.add_rule.called)

    def test_remove_rule(self):
        self.driver.remove_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                    'fake_rule', True)
        self.iptables.remove_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_remove_rule_with_no_router(self):
        self.driver.remove_nat_rule(
            'bogus_router_id',
            'fake_chain',
            'fake_rule')
        self.assertFalse(self.iptables.remove_rule.called)

    def test_iptables_apply(self):
        self.driver.iptables_apply(FAKE_ROUTER_ID)
        self.apply_mock.assert_called_once_with()

    def test_iptables_apply_with_no_router(self):
        self.driver.iptables_apply('bogus_router_id')
        self.assertFalse(self.apply_mock.called)


class IPSecDeviceDVR(BaseIPsecDeviceDriver):

    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(IPSecDeviceDVR, self).setUp(driver, ipsec_process)
        mock.patch.object(dvr_snat_ns.SnatNamespace, 'create').start()
        self._make_dvr_edge_router_info_for_test()

    def _make_dvr_edge_router_info_for_test(self):
        router = dvr_edge_router.DvrEdgeRouter(mock.sentinel.agent,
                                               mock.sentinel.myhost,
                                               FAKE_ROUTER_ID,
                                               **self.ri_kwargs)
        router.router['distributed'] = True
        router.snat_namespace = dvr_snat_ns.SnatNamespace(router.router['id'],
                                                          mock.sentinel.agent,
                                                          self.driver,
                                                          mock.ANY)
        router.snat_namespace.create()
        router.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace='snat-' + FAKE_ROUTER_ID, use_ipv6=mock.ANY)
        router.snat_iptables_manager.ipv4['nat'] = self.iptables
        router.snat_iptables_manager.apply = self.apply_mock
        self.driver.routers[FAKE_ROUTER_ID] = router

    def test_get_namespace_for_dvr_edge_router(self):
        namespace = self.driver.get_namespace(FAKE_ROUTER_ID)
        self.assertEqual('snat-' + FAKE_ROUTER_ID, namespace)

    def test_add_nat_rule_with_dvr_edge_router(self):
        self.driver.add_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                 'fake_rule', True)
        self.iptables.add_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_iptables_apply_with_dvr_edge_router(self):
        self.driver.iptables_apply(FAKE_ROUTER_ID)
        self.apply_mock.assert_called_once_with()

    def test_remove_rule_with_dvr_edge_router(self):
        self.driver.remove_nat_rule(FAKE_ROUTER_ID, 'fake_chain',
                                    'fake_rule', True)
        self.iptables.remove_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)


class TestOpenSwanProcess(BaseIPsecDeviceDriver):
    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(TestOpenSwanProcess, self).setUp(driver, ipsec_process)
        self.conf.register_opts(openswan_ipsec.openswan_opts,
                                'openswan')
        self.conf.set_override('state_path', '/tmp')

        self.process = openswan_ipsec.OpenSwanProcess(self.conf,
                                                      'foo-process-id',
                                                      self.vpnservice,
                                                      mock.ANY)

    def _test_config_files_on_create(self, proto, auth_mode):
        """Verify that the content of config files are correct on create."""
        auth_proto = {'transform_protocol': proto}
        for conn in self.vpnservice['ipsec_site_connections']:
            conn['ipsecpolicy'].update(auth_proto)
        content = self.process._gen_config_content(
            self.conf.openswan.ipsec_config_template,
            self.vpnservice)
        conn_details = OPENSWAN_CONNECTION_DETAILS % {'auth_mode': auth_mode}
        expected_openswan_conf = EXPECTED_OPENSWAN_CONF % {
            'default_id': '%default',
            'conn1_id': FAKE_IPSEC_SITE_CONNECTION1_ID,
            'conn2_id': FAKE_IPSEC_SITE_CONNECTION2_ID,
            'conn_details': conn_details}

        res_diff = self.generate_diff(expected_openswan_conf.strip(),
                                      content.strip())

        self.assertEqual(expected_openswan_conf.strip(),
                         str(content.strip()), message=''.join(res_diff))
        content = self.process._gen_config_content(
            self.conf.openswan.ipsec_secret_template,
            self.vpnservice)
        res_diff = self.generate_diff(
            EXPECTED_IPSEC_OPENSWAN_SECRET_CONF.strip(),
            content.strip())
        self.assertEqual(EXPECTED_IPSEC_OPENSWAN_SECRET_CONF.strip(),
                         str(content.strip()), message=''.join(res_diff))

    def test_config_files_on_create_esp_transform_protocol(self):
        self._test_config_files_on_create('esp', AUTH_ESP)

    def test_config_files_on_create_ah_transform_protocol(self):
        self._test_config_files_on_create('ah', AUTH_AH)

    def test__resolve_fqdn(self):
        with mock.patch.object(socket, 'getaddrinfo') as mock_getaddr_info:
            mock_getaddr_info.return_value = [(2, 1, 6, '',
                                              ('172.168.1.2', 0))]
            resolved_ip_addr = self.process._resolve_fqdn('fqdn.foo.addr')
            self.assertEqual('172.168.1.2', resolved_ip_addr)

    def _test_get_nexthop_helper(self, address, _resolve_fqdn_side_effect,
                                 expected_ip_cmd, expected_nexthop):
        with mock.patch.object(self.process,
                               '_resolve_fqdn') as fake_resolve_fqdn:
            fake_resolve_fqdn.side_effect = _resolve_fqdn_side_effect

            returned_next_hop = self.process._get_nexthop(address,
                                                          'fake-conn-id')
            _resolve_fqdn_expected_call_count = (
                1 if _resolve_fqdn_side_effect else 0)

            self.assertEqual(_resolve_fqdn_expected_call_count,
                             fake_resolve_fqdn.call_count)
            self._execute.assert_called_once_with(expected_ip_cmd)
            self.assertEqual(expected_nexthop, returned_next_hop)

    def test__get_nexthop_peer_addr_is_ipaddr(self):
        gw_addr = '10.0.0.1'
        self._execute.return_value = '172.168.1.2 via %s' % gw_addr
        peer_address = '172.168.1.2'
        expected_ip_cmd = ['ip', 'route', 'get', peer_address]
        self._test_get_nexthop_helper(peer_address, None,
                                      expected_ip_cmd, gw_addr)

    def test__get_nexthop_peer_addr_is_valid_fqdn(self):
        peer_address = 'foo.peer.addr'
        expected_ip_cmd = ['ip', 'route', 'get', '172.168.1.2']
        gw_addr = '10.0.0.1'
        self._execute.return_value = '172.168.1.2 via %s' % gw_addr

        def _fake_resolve_fqdn(address):
            return '172.168.1.2'

        self._test_get_nexthop_helper(peer_address, _fake_resolve_fqdn,
                                      expected_ip_cmd, gw_addr)

    def test__get_nexthop_gw_not_present(self):
        peer_address = '172.168.1.2'
        expected_ip_cmd = ['ip', 'route', 'get', '172.168.1.2']
        self._execute.return_value = ' '

        self._test_get_nexthop_helper(peer_address, None,
                                      expected_ip_cmd, peer_address)

    def test__get_nexthop_fqdn_peer_addr_is_not_resolved(self):
        self.process.connection_status = {}
        expected_connection_status_dict = (
            {'fake-conn-id': {'status': constants.ERROR,
                              'updated_pending_status': True}})

        self.assertRaises(vpnaas.VPNPeerAddressNotResolved,
                          self.process._get_nexthop, 'foo.peer.addr',
                          'fake-conn-id')
        self.assertEqual(expected_connection_status_dict,
                         self.process.connection_status)

        self.process.connection_status = (
            {'fake-conn-id': {'status': constants.PENDING_CREATE,
                              'updated_pending_status': False}})

        self.assertRaises(vpnaas.VPNPeerAddressNotResolved,
                          self.process._get_nexthop, 'foo.peer.addr',
                          'fake-conn-id')
        self.assertEqual(expected_connection_status_dict,
                         self.process.connection_status)


class TestLibreSwanProcess(base.BaseTestCase):

    _test_timeout = 1
    _test_backoff = 2
    _test_retries = 5

    def setUp(self):
        super(TestLibreSwanProcess, self).setUp()
        # Insulate tests against changes to configuration defaults.
        cfg.CONF.register_opts(libreswan_ipsec.libreswan_opts,
                               'libreswan')
        cfg.CONF.set_override('shutdown_check_timeout', self._test_timeout,
                              group='libreswan')
        cfg.CONF.set_override('shutdown_check_back_off', self._test_backoff,
                              group='libreswan')
        cfg.CONF.set_override('shutdown_check_retries', self._test_retries,
                              group='libreswan')
        self.addCleanup(cfg.CONF.reset)
        self.vpnservice = copy.deepcopy(FAKE_VPN_SERVICE)
        self.parent_start = mock.patch('neutron_vpnaas.services.'
                                       'vpn.device_drivers.ipsec.'
                                       'OpenSwanProcess.start').start()
        self.parent_stop = mock.patch('neutron_vpnaas.services.'
                                      'vpn.device_drivers.ipsec.'
                                      'OpenSwanProcess.stop').start()
        self.os_remove = mock.patch('os.remove').start()

        self.ipsec_process = libreswan_ipsec.LibreSwanProcess(cfg.CONF,
                                                       'foo-process-id',
                                                       self.vpnservice,
                                                       mock.ANY)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._cleanup_control_files')
    def test_no_cleanups(self, cleanup_mock):
        # Not an "awesome test" but more of a check box item. Basically,
        # what happens if we didn't need to clean up any files.
        with mock.patch.object(self.ipsec_process,
                               '_process_running',
                               return_value=True) as query_mock:
            self.ipsec_process.start()
            self.assertEqual(1, self.parent_start.call_count)
            self.assertEqual(1, query_mock.call_count)

            # This is really what is being tested here. If process is
            # running, we shouldn't attempt a cleanup.
            self.assertFalse(cleanup_mock.called)

    @mock.patch('os.path.exists', return_value=True)
    def test_cleanup_files(self, exists_mock):
        # Tests the 'bones' of things really and kind of check-box-item-bogus
        # test - this really needs exercising through a higher level test.
        with mock.patch.object(self.ipsec_process,
                               '_process_running',
                               return_value=False) as query_mock:
            fake_path = '/fake/path/run'
            self.ipsec_process.pid_path = fake_path
            self.ipsec_process.pid_file = '%s.pid' % fake_path
            self.ipsec_process.start()
            self.assertEqual(1, self.parent_start.call_count)
            self.assertEqual(1, query_mock.call_count)
            self.assertEqual(2, self.os_remove.call_count)
            self.os_remove.assert_has_calls([mock.call('%s.pid' % fake_path),
                                             mock.call('%s.ctl' % fake_path)])

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._process_running',
               return_value=False)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._cleanup_control_files')
    @mock.patch('eventlet.sleep')
    def test_restart_process_not_running(self, sleep_mock, cleanup_mock,
                                         query_mock):
        self.ipsec_process.restart()
        # Lame checks that are really for sanity
        self.assertTrue(self.parent_stop.called)
        self.assertTrue(self.parent_start.called)

        # Really what is being tested - retry configuration exists and that
        # we do the right things when process check is false.
        self.assertTrue(query_mock.called)
        self.assertTrue(cleanup_mock.called)
        self.assertFalse(sleep_mock.called)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._process_running',
               return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._cleanup_control_files')
    @mock.patch('eventlet.sleep')
    def test_restart_process_doesnt_stop(self, sleep_mock, cleanup_mock,
                                         query_mock):
        self.ipsec_process.restart()
        # Lame checks that are really for sanity
        self.assertTrue(self.parent_stop.called)
        self.assertTrue(self.parent_start.called)

        # Really what is being tested - retry configuration exists and that
        # we do the right things when process check is True.
        self.assertEqual(5, query_mock.call_count)
        self.assertFalse(cleanup_mock.called)
        self.assertEqual(5, sleep_mock.call_count)
        calls = [mock.call(1), mock.call(2), mock.call(4),
                 mock.call(8), mock.call(16)]
        sleep_mock.assert_has_calls(calls)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._process_running',
               side_effect=[True, True, False])
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.LibreSwanProcess._cleanup_control_files')
    @mock.patch('eventlet.sleep')
    def test_restart_process_retry_until_stop(self, sleep_mock, cleanup_mock,
                                              query_mock):
        self.ipsec_process.restart()
        # Lame checks that are really for sanity
        self.assertTrue(self.parent_start.called)
        self.assertTrue(self.parent_stop.called)

        # Really what is being tested - retry configuration exists and that
        # we do the right things when process check is True a few times and
        # then returns False.
        self.assertEqual(3, query_mock.call_count)
        self.assertTrue(cleanup_mock.called)
        self.assertEqual(2, sleep_mock.call_count)

    def test_process_running_no_pid(self):
        with mock.patch('os.path.exists', return_value=False):
            self.assertFalse(
                self.ipsec_process._process_running())

    # open() is used elsewhere, so we need to inject a mocked open into the
    # module to be tested.
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.open',
                create=True,
                side_effect=IOError)
    def test_process_running_open_failure(self, mock_open, mock_exists):
        self.assertFalse(self.ipsec_process._process_running())
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_open.called)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'invalid'),
                             IOError])
    def test_process_running_bogus_pid(self, mock_open, mock_exists):
        with mock.patch.object(libreswan_ipsec.LOG, 'error'):
            self.assertFalse(self.ipsec_process._process_running())
            self.assertTrue(mock_exists.called)
            self.assertEqual(2, mock_open.call_count)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'134'), io.StringIO(u'')])
    def test_process_running_no_cmdline(self, mock_open, mock_exists):
        with mock.patch.object(libreswan_ipsec.LOG, 'error') as log_mock:
            self.assertFalse(self.ipsec_process._process_running())
            self.assertFalse(log_mock.called)
            self.assertEqual(2, mock_open.call_count)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'134'), io.StringIO(u'ps ax')])
    def test_process_running_cmdline_mismatch(self, mock_open, mock_exists):
        with mock.patch.object(libreswan_ipsec.LOG, 'error') as log_mock:
            self.assertFalse(self.ipsec_process._process_running())
            self.assertFalse(log_mock.called)
            self.assertEqual(2, mock_open.call_count)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'libreswan_ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'134'),
                             io.StringIO(u'/usr/libexec/ipsec/pluto -ctlbase'
                                         '/some/foo/path')])
    def test_process_running_cmdline_match(self, mock_open, mock_exists):
        self.ipsec_process.pid_path = '/some/foo/path'
        with mock.patch.object(libreswan_ipsec.LOG, 'error') as log_mock:
            self.assertTrue(self.ipsec_process._process_running())
            self.assertTrue(log_mock.called)

    def test_ensure_configs(self):
        openswan_ipsec.OpenSwanProcess.ensure_configs = mock.Mock()
        with mock.patch.object(self.ipsec_process, '_execute') as fake_execute:
            self.ipsec_process.ensure_configs()
            expected = [mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root',
                                   self.ipsec_process._get_config_filename(
                                       'ipsec.secrets')]),
                        mock.call(['ipsec', '_stackmanager', 'start']),
                        mock.call(['ipsec', 'checknss',
                                   self.ipsec_process.etc_dir])]
            fake_execute.assert_has_calls(expected)
            self.assertEqual(3, fake_execute.call_count)

        with mock.patch.object(self.ipsec_process, '_execute') as fake_execute:
            fake_execute.side_effect = [None, None, RuntimeError, None]
            self.ipsec_process.ensure_configs()
            expected = [mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root',
                                   self.ipsec_process._get_config_filename(
                                       'ipsec.secrets')]),
                        mock.call(['ipsec', '_stackmanager', 'start']),
                        mock.call(['ipsec', 'checknss',
                                   self.ipsec_process.etc_dir]),
                        mock.call(['ipsec', 'initnss',
                                   self.ipsec_process.etc_dir])]
            fake_execute.assert_has_calls(expected)
            self.assertEqual(4, fake_execute.call_count)


class IPsecStrongswanDeviceDriverLegacy(IPSecDeviceLegacy):

    def setUp(self, driver=strongswan_ipsec.StrongSwanDriver,
              ipsec_process=strongswan_ipsec.StrongSwanProcess):
        super(IPsecStrongswanDeviceDriverLegacy, self).setUp(driver,
                                                       ipsec_process)
        self.conf.register_opts(strongswan_ipsec.strongswan_opts,
            'strongswan')
        self.conf.set_override('state_path', '/tmp')
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            self.vpnservice]

    def test_config_files_on_create(self):
        """Verify that the content of config files are correct on create."""
        process = self.driver.ensure_process(self.router.router_id,
                                             self.vpnservice)
        content = process._gen_config_content(
            self.conf.strongswan.ipsec_config_template,
            self.vpnservice)
        self.assertEqual(EXPECTED_IPSEC_STRONGSWAN_CONF.strip(),
                         str(content.strip()))
        content = process._gen_config_content(
            self.conf.strongswan.strongswan_config_template,
            self.vpnservice)
        self.assertEqual(EXPECTED_STRONGSWAN_DEFAULT_CONF.strip(),
                         str(content.strip()))
        content = process._gen_config_content(
            self.conf.strongswan.ipsec_secret_template,
            self.vpnservice)
        self.assertEqual(EXPECTED_IPSEC_STRONGSWAN_SECRET_CONF.strip(),
                         str(content.strip()))

    def test_status_handling_for_downed_connection(self):
        """Test status handling for downed connection."""
        router_id = self.router.router_id
        connection_id = FAKE_IPSEC_SITE_CONNECTION2_ID
        self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = DOWN_STATUS
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.ACTIVE, process_status['status'])
        self.assertEqual(constants.DOWN,
                         ipsec_site_conn[connection_id]['status'])

    def test_status_handling_for_active_connection(self):
        """Test status handling for actived connection."""
        router_id = self.router.router_id
        connection_id = FAKE_IPSEC_SITE_CONNECTION2_ID
        self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = ACTIVE_STATUS
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[
            router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.ACTIVE, process_status['status'])
        self.assertEqual(constants.ACTIVE,
                         ipsec_site_conn[connection_id]['status'])

    def test_status_handling_for_deleted_connection(self):
        """Test status handling for deleted connection."""
        router_id = self.router.router_id
        self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = NOT_RUNNING_STATUS
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.DOWN, process_status['status'])
        self.assertFalse(ipsec_site_conn)

    def test_update_connection_status(self):
        """Test the status of ipsec-site-connection parsed correctly."""
        router_id = self.router.router_id
        process = self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = NOT_RUNNING_STATUS
        self.assertFalse(process.active)
        # An empty return value to simulate that the StrongSwan process
        # does not have any status to report.
        self._execute.return_value = ''
        self.assertFalse(process.active)
        self._execute.return_value = ACTIVE_STATUS
        self.assertTrue(process.active)
        self._execute.return_value = DOWN_STATUS
        self.assertTrue(process.active)


class IPsecStrongswanDeviceDriverDVR(IPSecDeviceDVR):
    def setUp(self, driver=strongswan_ipsec.StrongSwanDriver,
              ipsec_process=strongswan_ipsec.StrongSwanProcess):
        super(IPsecStrongswanDeviceDriverDVR, self).setUp(driver,
                                                          ipsec_process)


class IPsecFedoraStrongswanDeviceDriverLegacy(
    IPsecStrongswanDeviceDriverLegacy):

    def setUp(self, driver=fedora_strongswan_ipsec.FedoraStrongSwanDriver,
              ipsec_process=fedora_strongswan_ipsec.FedoraStrongSwanProcess):
        super(IPsecFedoraStrongswanDeviceDriverLegacy,
              self).setUp(driver, ipsec_process)


class IPsecFedoraStrongswanDeviceDriverDVR(IPSecDeviceDVR):

    def setUp(self, driver=fedora_strongswan_ipsec.FedoraStrongSwanDriver,
              ipsec_process=fedora_strongswan_ipsec.FedoraStrongSwanProcess):
        super(IPsecFedoraStrongswanDeviceDriverDVR, self).setUp(driver,
                                                                ipsec_process)
