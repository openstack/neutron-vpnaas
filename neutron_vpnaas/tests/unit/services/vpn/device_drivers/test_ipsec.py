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
import os
import socket
from unittest import mock

import netaddr
from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import legacy_router
from neutron.agent.linux import iptables_manager
from neutron.conf.agent.l3 import config as l3_config
from neutron_lib import constants
from neutron_lib.exceptions import vpn as vpn_exception
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn.device_drivers import ipsec as openswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import libreswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid
FAKE_HOST = 'fake_host'
FAKE_ROUTER_ID = _uuid()
FAKE_IPSEC_SITE_CONNECTION1_ID = _uuid()
FAKE_IPSEC_SITE_CONNECTION2_ID = _uuid()
FAKE_VPNSERVICE_ID = _uuid()
FAKE_IKE_POLICY = {
    'ike_version': 'v1',
    'encryption_algorithm': 'aes-128',
    'auth_algorithm': 'sha1',
    'pfs': 'group5',
    'lifetime_value': 3600
}

FAKE_IPSEC_POLICY = {
    'encryption_algorithm': 'aes-128',
    'auth_algorithm': 'sha1',
    'pfs': 'group5',
    'transform_protocol': 'esp',
    'lifetime_value': 3600,
    'encapsulation_mode': 'tunnel'
}

FAKE_VPN_SERVICE = {
    'id': FAKE_VPNSERVICE_ID,
    'router_id': FAKE_ROUTER_ID,
    'name': 'myvpn',
    'admin_state_up': True,
    'status': constants.PENDING_CREATE,
    'external_ip': '60.0.0.4',
    'ipsec_site_connections': [
        {'peer_cidrs': ['20.0.0.0/24',
                        '30.0.0.0/24'],
         'local_cidrs': ['10.0.0.0/24'],
         'local_ip_vers': 4,
         'admin_state_up': True,
         'id': FAKE_IPSEC_SITE_CONNECTION1_ID,
         'external_ip': '60.0.0.4',
         'local_id': '60.0.0.4',
         'peer_address': '60.0.0.5',
         'mtu': 1500,
         'peer_id': '60.0.0.5',
         'psk': 'password',
         'initiator': 'bi-directional',
         'ikepolicy': FAKE_IKE_POLICY,
         'ipsecpolicy': FAKE_IPSEC_POLICY,
         'dpd_action': 'hold',
         'dpd_interval': 30,
         'dpd_timeout': 120,
         'status': constants.PENDING_CREATE},
        {'peer_cidrs': ['40.0.0.0/24',
                        '50.0.0.0/24'],
         'local_cidrs': ['11.0.0.0/24'],
         'local_ip_vers': 4,
         'admin_state_up': True,
         'external_ip': '60.0.0.4',
         'local_id': '60.0.0.4',
         'peer_address': '60.0.0.6',
         'peer_id': '60.0.0.6',
         'mtu': 1500,
         'psk': 'password',
         'id': FAKE_IPSEC_SITE_CONNECTION2_ID,
         'initiator': 'bi-directional',
         'ikepolicy': FAKE_IKE_POLICY,
         'ipsecpolicy': FAKE_IPSEC_POLICY,
         'dpd_action': 'hold',
         'dpd_interval': 30,
         'dpd_timeout': 120,
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
    mtu=1500
    # [dpd_action]
    dpdaction=%(dpd_action)s
    # [dpd_interval]
    dpddelay=%(dpd_delay)s
    # [dpd_timeout]
    dpdtimeout=%(dpd_timeout)s
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
    ikelifetime=%(ike_lifetime)ss
    # NOTE: it looks lifetime_units=kilobytes can't be enforced \
(could be seconds,  hours,  days...)
    ##########################
    # IPsecPolicys params
    ##########################
    # [transform_protocol]
    phase2=%(auth_mode)s
    # [encapsulation_mode]
    type=%(encapsulation_mode)s
    # [lifetime_value]
    lifetime=%(life_time)ss
    # lifebytes=100000 if lifetime_units=kilobytes (IKEv2 only)
'''

IPV4_NEXT_HOP = '''# NOTE: a default route is required for %defaultroute to work...
    leftnexthop=%defaultroute
    rightnexthop=%defaultroute'''

IPV6_NEXT_HOP = '''# To recognize the given IP addresses in this config
    # as IPv6 addresses by pluto whack. Default is ipv4
    connaddrfamily=ipv6
    # openswan can't process defaultroute for ipv6.
    # Assign gateway address as leftnexthop
    leftnexthop=%s
    # rightnexthop is not mandatory for ipsec, so no need in ipv6.'''

EXPECTED_OPENSWAN_CONF = """
# Configuration for %(vpnservice_id)s
config setup
    nat_traversal=yes
    virtual_private=%(virtual_privates)s
conn %%default
    keylife=60m
    keyingtries=%%forever
conn %(conn1_id)s
    %(next_hop)s
    left=%(left)s
    leftid=%(leftid)s
    auto=start
    # NOTE:REQUIRED
    # [subnet]
    leftsubnet%(local_cidrs1)s
    # [updown]
    # What "updown" script to run to adjust routing and/or firewalling when
    # the status of the connection changes (default "ipsec _updown").
    # "--route yes" allows to specify such routing options as mtu and metric.
    leftupdown="ipsec _updown --route yes"
    ######################
    # ipsec_site_connections
    ######################
    # [peer_address]
    right=%(right1)s
    # [peer_id]
    rightid=%(right1)s
    # [peer_cidrs]
    rightsubnets={ %(peer_cidrs1)s }
    %(conn_details)sconn %(conn2_id)s
    %(next_hop)s
    left=%(left)s
    leftid=%(leftid)s
    auto=start
    # NOTE:REQUIRED
    # [subnet]
    leftsubnet%(local_cidrs2)s
    # [updown]
    # What "updown" script to run to adjust routing and/or firewalling when
    # the status of the connection changes (default "ipsec _updown").
    # "--route yes" allows to specify such routing options as mtu and metric.
    leftupdown="ipsec _updown --route yes"
    ######################
    # ipsec_site_connections
    ######################
    # [peer_address]
    right=%(right2)s
    # [peer_id]
    rightid=%(right2)s
    # [peer_cidrs]
    rightsubnets={ %(peer_cidrs2)s }
    %(conn_details)s
"""

STRONGSWAN_AUTH_ESP = 'esp=aes128-sha1-modp1536'

STRONGSWAN_AUTH_AH = 'ah=sha1-modp1536'

EXPECTED_IPSEC_OPENSWAN_SECRET_CONF = '''
# Configuration for %s
60.0.0.4 60.0.0.5 : PSK 0scGFzc3dvcmQ=
60.0.0.4 60.0.0.6 : PSK 0scGFzc3dvcmQ=''' % FAKE_VPNSERVICE_ID

EXPECTED_IPSEC_STRONGSWAN_CONF = '''
# Configuration for %(vpnservice_id)s
config setup

conn %%default
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        authby=psk
        mobike=no

conn %(conn1_id)s
    keyexchange=ikev1
    left=%(left)s
    leftsubnet=%(local_cidrs1)s
    leftid=%(leftid)s
    leftfirewall=yes
    right=%(right1)s
    rightsubnet=%(peer_cidrs1)s
    rightid=%(right1)s
    auto=route
    dpdaction=%(dpd_action)s
    dpddelay=%(dpd_delay)ss
    dpdtimeout=%(dpd_timeout)ss
    ike=%(ike_encryption_algorithm)s-%(ike_auth_algorithm)s-%(ike_pfs)s
    ikelifetime=%(ike_lifetime)ss
    %(auth_mode)s
    lifetime=%(life_time)ss
    type=%(encapsulation_mode)s

conn %(conn2_id)s
    keyexchange=ikev1
    left=%(left)s
    leftsubnet=%(local_cidrs2)s
    leftid=%(leftid)s
    leftfirewall=yes
    right=%(right2)s
    rightsubnet=%(peer_cidrs2)s
    rightid=%(right2)s
    auto=route
    dpdaction=%(dpd_action)s
    dpddelay=%(dpd_delay)ss
    dpdtimeout=%(dpd_timeout)ss
    ike=%(ike_encryption_algorithm)s-%(ike_auth_algorithm)s-%(ike_pfs)s
    ikelifetime=%(ike_lifetime)ss
    %(auth_mode)s
    lifetime=%(life_time)ss
    type=%(encapsulation_mode)s
'''

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
# Configuration for %s
60.0.0.4 60.0.0.5 : PSK 0scGFzc3dvcmQ=

60.0.0.4 60.0.0.6 : PSK 0scGFzc3dvcmQ=
''' % FAKE_VPNSERVICE_ID

PLUTO_ACTIVE_STATUS = """000 "%(conn_id)s/0x1": erouted;\n
000 #4: "%(conn_id)s/0x1":500 STATE_QUICK_R2 (IPsec SA established); \
newest IPSEC;""" % {
    'conn_id': FAKE_IPSEC_SITE_CONNECTION2_ID}
PLUTO_ACTIVE_STATUS_IKEV2 = """000 "%(conn_id)s/0x1": erouted;\n
000 #4: "%(conn_id)s/0x1":500 STATE_PARENT_R2 (PARENT SA established); \
newest IPSEC;""" % {
    'conn_id': FAKE_IPSEC_SITE_CONNECTION2_ID}
PLUTO_MULTIPLE_SUBNETS_ESTABLISHED_STATUS = """000 "%(conn_id1)s/1x1": erouted;\n
000 #4: "%(conn_id1)s/1x1":500 STATE_QUICK_R2 (IPsec SA established); \
newest IPSEC;\n
000 "%(conn_id2)s/2x1": erouted;\n
000 #4: "%(conn_id2)s/2x1":500 STATE_QUICK_R2 (IPsec SA established); \
newest IPSEC;\n""" % {
    'conn_id1': FAKE_IPSEC_SITE_CONNECTION1_ID,
    'conn_id2': FAKE_IPSEC_SITE_CONNECTION2_ID}
PLUTO_ACTIVE_NO_IPSEC_SA_STATUS = """000 "%(conn_id)s/0x1": erouted;\n
000 #258: "%(conn_id)s/0x1":500 STATE_MAIN_R2 (sent MR2, expecting MI3);""" % {
    'conn_id': FAKE_IPSEC_SITE_CONNECTION2_ID}
PLUTO_DOWN_STATUS = "000 \"%(conn_id)s/0x1\": unrouted;" % {'conn_id':
                    FAKE_IPSEC_SITE_CONNECTION2_ID}

CHARON_ACTIVE_STATUS = "%(conn_id)s{1}:  INSTALLED, TUNNEL" % {'conn_id':
                       FAKE_IPSEC_SITE_CONNECTION2_ID}
CHARON_DOWN_STATUS = "%(conn_id)s{1}:  ROUTED, TUNNEL" % {'conn_id':
                     FAKE_IPSEC_SITE_CONNECTION2_ID}

NOT_RUNNING_STATUS = "Command: ['ipsec', 'status'] Exit code: 3 Stdout:"


class BaseIPsecDeviceDriver(base.BaseTestCase):
    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess,
              vpnservice=FAKE_VPN_SERVICE):
        super(BaseIPsecDeviceDriver, self).setUp()
        for klass in [
            'neutron_lib.rpc.Connection',
            'oslo_service.loopingcall.FixedIntervalLoopingCall'
        ]:
            mock.patch(klass).start()
        self._execute = mock.patch.object(ipsec_process, '_execute').start()
        self.agent = mock.Mock()
        self.conf = cfg.CONF
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, self.conf)
        self.agent.conf = self.conf
        self.driver = driver(
            self.agent,
            FAKE_HOST)
        self.driver.agent_rpc = mock.Mock()
        self.ri_kwargs = {'router': {'id': FAKE_ROUTER_ID, 'ha': False},
                          'agent_conf': self.conf,
                          'interface_driver': mock.sentinel.interface_driver}
        self.iptables = mock.Mock()
        self.apply_mock = mock.Mock()
        self.vpnservice = copy.deepcopy(vpnservice)
        ipsec_process._get_strongswan_piddir = mock.Mock(
            return_value="/var/run")

    @staticmethod
    def generate_diff(a, b):
        """Generates unified diff of a and b."""
        a, b = list(a.splitlines(True)), list(b.splitlines(True))
        diff = difflib.unified_diff(a, b, fromfile="expected",
                                    tofile="actual")
        return diff

    def modify_config_for_test(self, overrides):
        """Revise service/connection settings to test variations.

        Must update service, so that dialect mappings occur for any changes
        that are made.
        """
        ipsec_auth_protocol = overrides.get('ipsec_auth')
        if ipsec_auth_protocol:
            auth_proto = {'transform_protocol': ipsec_auth_protocol}
            for conn in self.vpnservice['ipsec_site_connections']:
                conn['ipsecpolicy'].update(auth_proto)

        local_cidrs = overrides.get('local_cidrs')
        if local_cidrs:
            for i, conn in enumerate(
                    self.vpnservice['ipsec_site_connections']):
                conn['local_cidrs'] = local_cidrs[i]

        local_ip_version = overrides.get('local_ip_vers', 4)
        for conn in self.vpnservice['ipsec_site_connections']:
            conn['local_ip_vers'] = local_ip_version

        peer_cidrs = overrides.get('peer_cidrs')
        if peer_cidrs:
            for i, conn in enumerate(
                    self.vpnservice['ipsec_site_connections']):
                conn['peer_cidrs'] = peer_cidrs[i]

        peers = overrides.get('peers')
        if peers:
            for i, conn in enumerate(
                    self.vpnservice['ipsec_site_connections']):
                conn['peer_id'] = peers[i]
                conn['peer_address'] = peers[i]

        local_ip = overrides.get('local')
        local_id = overrides.get('local_id')
        if local_ip:
            for conn in self.vpnservice['ipsec_site_connections']:
                conn['external_ip'] = local_ip
                conn['local_id'] = local_ip
                if local_id:
                    conn['local_id'] = local_id

    def check_config_file(self, expected, actual):
        expected = expected.strip()
        actual = actual.strip()
        res_diff = self.generate_diff(expected, actual)
        self.assertEqual(expected, actual, message=''.join(res_diff))

    def _test_ipsec_connection_config(self, info):
        """Check config file string for service/connection.

        Calls test specific method to create (and override as needed) the
        expected config file string, generates the config using the test's
        IPSec template, and then compares the results.
        """

        expected = self.build_ipsec_expected_config_for_test(info)
        actual = self.process._gen_config_content(self.ipsec_template,
                                                  self.vpnservice)
        self.check_config_file(expected, actual)


class IPSecDeviceLegacy(BaseIPsecDeviceDriver):

    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(IPSecDeviceLegacy, self).setUp(driver, ipsec_process)
        self._make_router_info_for_test()

    def _make_router_info_for_test(self):
        self.router = legacy_router.LegacyRouter(router_id=FAKE_ROUTER_ID,
                                                 agent=self.agent,
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
        self._test_add_nat_rule()
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

    def _test_add_nat_rule(self):
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
                '-s 11.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 11.0.0.0/24 -d 50.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True)
        ])
        self.router.iptables_manager.apply.assert_called_once_with()

    def _test_add_nat_rule_with_multiple_locals(self):
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
                '-s 11.0.0.0/24 -d 20.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 11.0.0.0/24 -d 30.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 12.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 12.0.0.0/24 -d 50.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 13.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 13.0.0.0/24 -d 50.0.0.0/24 -m policy '
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
            self._test_add_nat_rule()
            self.driver.processes[router_id].update.assert_called_once_with()

    def test_add_nat_rules_with_multiple_local_subnets(self):
        """Ensure that add nat rule combinations are correct."""
        overrides = {'local_cidrs': [['10.0.0.0/24', '11.0.0.0/24'],
                                     ['12.0.0.0/24', '13.0.0.0/24']]}
        self.modify_config_for_test(overrides)
        self.driver._update_nat(self.vpnservice, self.driver.add_nat_rule)
        self._test_add_nat_rule_with_multiple_locals()

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
            self.assertEqual(0, ensure_p.call_count)

    def test__sync_vpn_processes_router_with_no_vpn_and_no_vpn_services(self):
        """No vpn services running and router not hosting vpn svc."""
        router_id_no_vpn = _uuid()
        self.driver.process_status_cache = {}
        self.driver.processes = {}
        with mock.patch.object(self.driver, 'ensure_process') as ensure_p:
            ensure_p.side_effect = self.fake_ensure_process
            self.driver._sync_vpn_processes([], [router_id_no_vpn])
            self.assertEqual(0, ensure_p.call_count)

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
            self._test_add_nat_rule()
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
            new_vpn_service = self.vpnservice
            updated_vpn_service = copy.deepcopy(new_vpn_service)
            updated_vpn_service['ipsec_site_connections'][1].update(
                {'peer_cidrs': ['60.0.0.0/24', '70.0.0.0/24']})
            context = mock.Mock()
            self.driver.process_status_cache = {}
            self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
                new_vpn_service]
            self.driver.sync(context, [{'id': FAKE_ROUTER_ID}])
            process = self.driver.processes[FAKE_ROUTER_ID]
            self.assertEqual(new_vpn_service, process.vpnservice)
            self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
                updated_vpn_service]
            self.driver.sync(context, [{'id': FAKE_ROUTER_ID}])
            process = self.driver.processes[FAKE_ROUTER_ID]
            process.update_vpnservice.assert_called_once_with(
                updated_vpn_service)
            self.assertEqual(updated_vpn_service, process.vpnservice)

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

    def _test_status_handling_for_downed_connection(self, down_status):
        """Test status handling for downed connection."""
        router_id = self.router.router_id
        connection_id = FAKE_IPSEC_SITE_CONNECTION2_ID
        self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = down_status
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.ACTIVE, process_status['status'])
        self.assertEqual(constants.DOWN,
                         ipsec_site_conn[connection_id]['status'])

    def _test_status_handling_for_active_connection(self, active_status):
        """Test status handling for active connection."""
        router_id = self.router.router_id
        connection_id = FAKE_IPSEC_SITE_CONNECTION2_ID
        self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = active_status
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[
            router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.ACTIVE, process_status['status'])
        self.assertEqual(constants.ACTIVE,
                         ipsec_site_conn[connection_id]['status'])

    def _test_status_handling_for_ike_v2_active_connection(self,
            active_status):
        """Test status handling for active connection."""
        router_id = self.router.router_id
        connection_id = FAKE_IPSEC_SITE_CONNECTION2_ID
        ike_policy = {'ike_version': 'v2',
                      'encryption_algorithm': 'aes-128',
                      'auth_algorithm': 'sha1',
                      'pfs': 'group5',
                      'lifetime_value': 3600}
        vpn_service = FAKE_VPN_SERVICE
        for isc in vpn_service["ipsec_site_connections"]:
            isc['ikepolicy'] = ike_policy
        self.driver.ensure_process(router_id, vpn_service)
        self._execute.return_value = active_status
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[
            router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.ACTIVE, process_status['status'])
        self.assertEqual(constants.ACTIVE,
                         ipsec_site_conn[connection_id]['status'])

    def _test_connection_names_handling_for_multiple_subnets(self,
                                                             active_status):
        """Test connection names handling for multiple subnets."""
        router_id = self.router.router_id
        process = self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = active_status
        names = process.get_established_connections()
        self.assertEqual(2, len(names))

    def _test_status_handling_for_deleted_connection(self,
                                                     not_running_status):
        """Test status handling for deleted connection."""
        router_id = self.router.router_id
        self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = not_running_status
        self.driver.report_status(mock.Mock())
        process_status = self.driver.process_status_cache[router_id]
        ipsec_site_conn = process_status['ipsec_site_connections']
        self.assertEqual(constants.DOWN, process_status['status'])
        self.assertFalse(ipsec_site_conn)

    def _test_parse_connection_status(self, not_running_status,
                                      active_status, down_status):
        """Test the status of ipsec-site-connection is parsed correctly."""
        router_id = self.router.router_id
        process = self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = not_running_status
        self.assertFalse(process.active)
        # An empty return value to simulate that the process
        # does not have any status to report.
        self._execute.return_value = ''
        self.assertFalse(process.active)
        self._execute.return_value = active_status
        self.assertTrue(process.active)
        self._execute.return_value = down_status
        self.assertTrue(process.active)

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

    def test_sync_dvr(self):
        fake_vpn_service = FAKE_VPN_SERVICE
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            fake_vpn_service]
        context = mock.Mock()
        self.driver._sync_vpn_processes = mock.Mock()
        self.driver._delete_vpn_processes = mock.Mock()
        self.driver._cleanup_stale_vpn_processes = mock.Mock()
        sync_routers = [{'id': fake_vpn_service['router_id']}]
        sync_router_ids = [fake_vpn_service['router_id']]
        with mock.patch.object(self.driver,
                'get_process_status_cache') as process_status:
            self.driver.sync(context, sync_routers)
            self.driver._sync_vpn_processes.assert_called_once_with(
                [fake_vpn_service], sync_router_ids)
            self.driver._delete_vpn_processes.assert_called_once_with(
                sync_router_ids, sync_router_ids)
            self.driver._cleanup_stale_vpn_processes.assert_called_once_with(
                sync_router_ids)
            self.assertEqual(0, process_status.call_count)

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


class TestOpenSwanConfigGeneration(BaseIPsecDeviceDriver):

    """Verify that configuration files are generated correctly.

    Besides the normal translation of some settings, when creating the config
    file, the generated file can also vary based on the following
    special conditions:

        - IPv6 versus IPv4
        - Multiple left subnets versus a single left subnet
        - IPSec policy using AH transform

    The tests will focus on these variations.
    """

    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(TestOpenSwanConfigGeneration, self).setUp(
            driver, ipsec_process, vpnservice=FAKE_VPN_SERVICE)
        self.conf.register_opts(openswan_ipsec.openswan_opts, 'openswan')
        self.conf.set_override('state_path', '/tmp')
        self.ipsec_template = self.conf.openswan.ipsec_config_template
        self.process = openswan_ipsec.OpenSwanProcess(self.conf,
                                                      'foo-process-id',
                                                      self.vpnservice,
                                                      mock.ANY)

    def build_ipsec_expected_config_for_test(self, info):
        """Modify OpenSwan ipsec expected config files for test variations."""
        auth_mode = info.get('ipsec_auth', AUTH_ESP)
        conn_details = OPENSWAN_CONNECTION_DETAILS % {'auth_mode': auth_mode,
                'dpd_action': 'hold',
                'dpd_delay': 30,
                'dpd_timeout': 120,
                'ike_lifetime': 3600,
                'life_time': 3600,
                'encapsulation_mode': 'tunnel'}
        virtual_privates = []
        # Convert local CIDRs into assignment strings. IF more than one,
        # pluralize the attribute name and enclose in brackets.
        cidrs = info.get('local_cidrs', [['10.0.0.0/24'], ['11.0.0.0/24']])
        local_cidrs = []
        for cidr in cidrs:
            if len(cidr) == 2:
                local_cidrs.append("s={ %s }" % ' '.join(cidr))
            else:
                local_cidrs.append("=%s" % cidr[0])
            for net in cidr:
                version = netaddr.IPNetwork(net).version
                virtual_privates.append('%%v%s:%s' % (version, net))
        # Convert peer CIDRs into space separated strings
        cidrs = info.get('peer_cidrs', [['20.0.0.0/24', '30.0.0.0/24'],
                                        ['40.0.0.0/24', '50.0.0.0/24']])
        for cidr in cidrs:
            for net in cidr:
                version = netaddr.IPNetwork(net).version
                virtual_privates.append('%%v%s:%s' % (version, net))
        peer_cidrs = [' '.join(cidr) for cidr in cidrs]
        local_ip = info.get('local', '60.0.0.4')
        local_id = info.get('local_id')
        leftid = local_ip
        if local_id:
            leftid = local_id
        version = info.get('local_ip_vers', 4)
        next_hop = IPV4_NEXT_HOP if version == 4 else IPV6_NEXT_HOP % local_ip
        peer_ips = info.get('peers', ['60.0.0.5', '60.0.0.6'])
        virtual_privates.sort()
        return EXPECTED_OPENSWAN_CONF % {
            'vpnservice_id': FAKE_VPNSERVICE_ID,
            'virtual_privates': ','.join(virtual_privates),
            'next_hop': next_hop,
            'local_cidrs1': local_cidrs[0], 'local_cidrs2': local_cidrs[1],
            'local_ver': version,
            'peer_cidrs1': peer_cidrs[0], 'peer_cidrs2': peer_cidrs[1],
            'left': local_ip,
            'leftid': leftid,
            'right1': peer_ips[0], 'right2': peer_ips[1],
            'conn1_id': FAKE_IPSEC_SITE_CONNECTION1_ID,
            'conn2_id': FAKE_IPSEC_SITE_CONNECTION2_ID,
            'conn_details': conn_details}

    def test_connections_with_esp_transform_protocol(self):
        """Test config file with IPSec policy using ESP."""
        self._test_ipsec_connection_config({})

    def test_connections_with_ah_transform_protocol(self):
        """Test config file with IPSec policy using ESP."""
        overrides = {'ipsec_auth': 'ah'}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        info = {'ipsec_auth': AUTH_AH}
        self._test_ipsec_connection_config(info)

    def test_connections_with_multiple_left_subnets(self):
        """Test multiple local subnets.

        The configure uses the 'leftsubnets' attribute, instead of the
        'leftsubnet' attribute.
        """

        overrides = {'local_cidrs': [['10.0.0.0/24', '11.0.0.0/24'],
                                     ['12.0.0.0/24', '13.0.0.0/24']]}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        self._test_ipsec_connection_config(overrides)

    def test_config_files_with_ipv6_addresses(self):
        """Test creating config files using IPv6 addressing."""
        overrides = {'local_cidrs': [['2002:0a00::/48'], ['2002:0b00::/48']],
                     'local_ip_vers': 6,
                     'peer_cidrs': [['2002:1400::/48', '2002:1e00::/48'],
                                    ['2002:2800::/48', '2002:3200::/48']],
                     'local': '2002:3c00:0004::',
                     'peers': ['2002:3c00:0005::', '2002:3c00:0006::'],
                     'local_id': '2002:3c00:0004::'}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        self._test_ipsec_connection_config(overrides)

    def test_config_files_with_ipv6_addresses_without_local_id(self):
        """Test creating config files using IPv6 addressing."""
        overrides = {'local_cidrs': [['2002:0a00::/48'], ['2002:0b00::/48']],
                     'local_ip_vers': 6,
                     'peer_cidrs': [['2002:1400::/48', '2002:1e00::/48'],
                                    ['2002:2800::/48', '2002:3200::/48']],
                     'local': '2002:3c00:0004::',
                     'peers': ['2002:3c00:0005::', '2002:3c00:0006::']}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        self._test_ipsec_connection_config(overrides)

    def test_secrets_config_file(self):
        expected = EXPECTED_IPSEC_OPENSWAN_SECRET_CONF
        actual = self.process._gen_config_content(
            self.conf.openswan.ipsec_secret_template, self.vpnservice)
        self.check_config_file(expected, actual)


class IPsecStrongswanConfigGeneration(BaseIPsecDeviceDriver):

    def setUp(self, driver=strongswan_ipsec.StrongSwanDriver,
              ipsec_process=strongswan_ipsec.StrongSwanProcess):
        super(IPsecStrongswanConfigGeneration, self).setUp(
            driver, ipsec_process, vpnservice=FAKE_VPN_SERVICE)
        self.conf.register_opts(strongswan_ipsec.strongswan_opts,
            'strongswan')
        self.conf.set_override('state_path', '/tmp')
        self.ipsec_template = self.conf.strongswan.ipsec_config_template
        self.process = strongswan_ipsec.StrongSwanProcess(self.conf,
                                                          'foo-process-id',
                                                          self.vpnservice,
                                                          mock.ANY)

    def build_ipsec_expected_config_for_test(self, info):
        cidrs = info.get('local_cidrs', [['10.0.0.0/24'], ['11.0.0.0/24']])
        local_cidrs = [','.join(cidr) for cidr in cidrs]
        cidrs = info.get('peer_cidrs', [['20.0.0.0/24', '30.0.0.0/24'],
                                        ['40.0.0.0/24', '50.0.0.0/24']])
        peer_cidrs = [','.join(cidr) for cidr in cidrs]
        local_ip = info.get('local', '60.0.0.4')
        local_id = info.get('local_id')
        leftid = local_ip
        if local_id:
            leftid = local_id
        peer_ips = info.get('peers', ['60.0.0.5', '60.0.0.6'])
        auth_mode = info.get('ipsec_auth', STRONGSWAN_AUTH_ESP)
        return EXPECTED_IPSEC_STRONGSWAN_CONF % {
            'vpnservice_id': FAKE_VPNSERVICE_ID,
            'local_cidrs1': local_cidrs[0], 'local_cidrs2': local_cidrs[1],
            'peer_cidrs1': peer_cidrs[0], 'peer_cidrs2': peer_cidrs[1],
            'left': local_ip,
            'leftid': leftid,
            'right1': peer_ips[0], 'right2': peer_ips[1],
            'dpd_action': 'hold',
            'dpd_delay': 30,
            'dpd_timeout': 120,
            'ike_encryption_algorithm': 'aes128',
            'ike_auth_algorithm': 'sha1',
            'ike_pfs': 'modp1536',
            'ike_lifetime': 3600,
            'life_time': 3600,
            'auth_mode': auth_mode,
            'encapsulation_mode': 'tunnel',
            'conn1_id': FAKE_IPSEC_SITE_CONNECTION1_ID,
            'conn2_id': FAKE_IPSEC_SITE_CONNECTION2_ID}

    def test_ipsec_config_file_with_esp(self):
        self._test_ipsec_connection_config({})

    def test_ipsec_config_file_with_ah(self):
        overrides = {'ipsec_auth': 'ah'}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        info = {'ipsec_auth': STRONGSWAN_AUTH_AH}
        self._test_ipsec_connection_config(info)

    def test_ipsec_config_file_for_v6(self):
        overrides = {'local_cidrs': [['2002:0a00::/48'], ['2002:0b00::/48']],
                     'peer_cidrs': [['2002:1400::/48', '2002:1e00::/48'],
                                    ['2002:2800::/48', '2002:3200::/48']],
                     'local': '2002:3c00:0004::',
                     'peers': ['2002:3c00:0005::', '2002:3c00:0006::'],
                     'local_id': '2002:3c00:0004::'}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        self._test_ipsec_connection_config(overrides)

    def test_ipsec_config_file_for_v6_without_local_id(self):
        overrides = {'local_cidrs': [['2002:0a00::/48'], ['2002:0b00::/48']],
                     'peer_cidrs': [['2002:1400::/48', '2002:1e00::/48'],
                                    ['2002:2800::/48', '2002:3200::/48']],
                     'local': '2002:3c00:0004::',
                     'peers': ['2002:3c00:0005::', '2002:3c00:0006::']}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        self._test_ipsec_connection_config(overrides)

    def test_strongswan_default_config_file(self):
        expected = EXPECTED_STRONGSWAN_DEFAULT_CONF
        actual = self.process._gen_config_content(
            self.conf.strongswan.strongswan_config_template, self.vpnservice)
        self.check_config_file(expected, actual)

    def test_secrets_config_file(self):
        expected = EXPECTED_IPSEC_STRONGSWAN_SECRET_CONF
        actual = self.process._gen_config_content(
            self.conf.strongswan.ipsec_secret_template, self.vpnservice)
        self.check_config_file(expected, actual)


class TestOpenSwanProcess(IPSecDeviceLegacy):

    _test_timeout = 1
    _test_backoff = 2
    _test_retries = 5

    def setUp(self, driver=openswan_ipsec.OpenSwanDriver,
              ipsec_process=openswan_ipsec.OpenSwanProcess):
        super(TestOpenSwanProcess, self).setUp(driver, ipsec_process)
        self.conf.register_opts(openswan_ipsec.openswan_opts,
                                'openswan')
        self.conf.set_override('state_path', '/tmp')
        cfg.CONF.register_opts(openswan_ipsec.pluto_opts,
                               'pluto')
        cfg.CONF.set_override('shutdown_check_timeout', self._test_timeout,
                              group='pluto')
        cfg.CONF.set_override('shutdown_check_back_off', self._test_backoff,
                              group='pluto')
        cfg.CONF.set_override('shutdown_check_retries', self._test_retries,
                              group='pluto')
        self.addCleanup(cfg.CONF.reset)

        self.os_remove = mock.patch('os.remove').start()

        self.process = openswan_ipsec.OpenSwanProcess(self.conf,
                                                      'foo-process-id',
                                                      self.vpnservice,
                                                      mock.ANY)

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

        self.assertRaises(vpn_exception.VPNPeerAddressNotResolved,
                          self.process._get_nexthop, 'foo.peer.addr',
                          'fake-conn-id')
        self.assertEqual(expected_connection_status_dict,
                         self.process.connection_status)

        self.process.connection_status = (
            {'fake-conn-id': {'status': constants.PENDING_CREATE,
                              'updated_pending_status': False}})

        self.assertRaises(vpn_exception.VPNPeerAddressNotResolved,
                          self.process._get_nexthop, 'foo.peer.addr',
                          'fake-conn-id')
        self.assertEqual(expected_connection_status_dict,
                         self.process.connection_status)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._get_nexthop',
                return_value='172.168.1.2')
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._cleanup_control_files')
    def test_no_cleanups(self, cleanup_mock, hop_mock):
        # Not an "awesome test" but more of a check box item. Basically,
        # what happens if we didn't need to clean up any files.
        with mock.patch.object(self.process,
                               '_process_running',
                               return_value=True) as query_mock:
            self.process.start()
            self.assertEqual(1, query_mock.call_count)

            # This is really what is being tested here. If process is
            # running, we shouldn't attempt a cleanup.
            self.assertFalse(cleanup_mock.called)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._get_nexthop',
                return_value='172.168.1.2')
    @mock.patch('os.path.exists', return_value=True)
    def test_cleanup_files(self, exists_mock, hop_mock):
        # Tests the 'bones' of things really and kind of check-box-item-bogus
        # test - this really needs exercising through a higher level test.
        with mock.patch.object(self.process,
                               '_process_running',
                               return_value=False) as query_mock:
            fake_path = '/fake/path/run'
            self.process.pid_path = fake_path
            self.process.pid_file = '%s.pid' % fake_path
            self.process.start()
            self.assertEqual(1, query_mock.call_count)
            self.assertEqual(2, self.os_remove.call_count)
            self.os_remove.assert_has_calls([mock.call('%s.pid' % fake_path),
                                             mock.call('%s.ctl' % fake_path)])

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._get_nexthop',
                return_value='172.168.1.2')
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._process_running',
                return_value=False)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._cleanup_control_files')
    @mock.patch('eventlet.sleep')
    def test_restart_process_not_running(self, sleep_mock, cleanup_mock,
                                         query_mock, hop_mock):
        self.process.restart()

        # Really what is being tested - retry configuration exists and that
        # we do the right things when process check is false.
        self.assertTrue(query_mock.called)
        self.assertTrue(cleanup_mock.called)
        self.assertFalse(sleep_mock.called)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._get_nexthop',
                return_value='172.168.1.2')
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._process_running',
                return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._cleanup_control_files')
    @mock.patch('eventlet.sleep')
    def test_restart_process_doesnt_stop(self, sleep_mock, cleanup_mock,
                                         query_mock, hop_mock):
        self.process.restart()

        # Really what is being tested - retry configuration exists and that
        # we do the right things when process check is True.
        self.assertEqual(self._test_retries + 1, query_mock.call_count)
        self.assertFalse(cleanup_mock.called)
        self.assertEqual(self._test_retries, sleep_mock.call_count)
        calls = [mock.call(1), mock.call(2), mock.call(4),
                 mock.call(8), mock.call(16)]
        sleep_mock.assert_has_calls(calls)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._get_nexthop',
                return_value='172.168.1.2')
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._process_running',
                side_effect=[True, True, False, False])
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.'
                'ipsec.OpenSwanProcess._cleanup_control_files')
    @mock.patch('eventlet.sleep')
    def test_restart_process_retry_until_stop(self, sleep_mock, cleanup_mock,
                                              query_mock, hop_mock):
        self.process.restart()

        # Really what is being tested - retry configuration exists and that
        # we do the right things when process check is True a few times and
        # then returns False.
        self.assertEqual(4, query_mock.call_count)
        self.assertTrue(cleanup_mock.called)
        self.assertEqual(2, sleep_mock.call_count)

    def test_process_running_no_pid(self):
        with mock.patch('os.path.exists', return_value=False):
            self.assertFalse(
                self.process._process_running())

    # open() is used elsewhere, so we need to inject a mocked open into the
    # module to be tested.
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.open',
                create=True,
                side_effect=IOError)
    def test_process_running_open_failure(self, mock_open, mock_exists):
        self.assertFalse(self.process._process_running())
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_open.called)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'invalid'),
                             IOError])
    def test_process_running_bogus_pid(self, mock_open, mock_exists):
        with mock.patch.object(openswan_ipsec.LOG, 'error'):
            self.assertFalse(self.process._process_running())
            self.assertTrue(mock_exists.called)
            self.assertEqual(2, mock_open.call_count)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'134'), io.StringIO(u'')])
    def test_process_running_no_cmdline(self, mock_open, mock_exists):
        with mock.patch.object(openswan_ipsec.LOG, 'error') as log_mock:
            self.assertFalse(self.process._process_running())
            self.assertFalse(log_mock.called)
            self.assertEqual(2, mock_open.call_count)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'134'), io.StringIO(u'ps ax')])
    def test_process_running_cmdline_mismatch(self, mock_open, mock_exists):
        with mock.patch.object(openswan_ipsec.LOG, 'error') as log_mock:
            self.assertFalse(self.process._process_running())
            self.assertFalse(log_mock.called)
            self.assertEqual(2, mock_open.call_count)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.open',
                create=True,
                side_effect=[io.StringIO(u'134'),
                             io.StringIO(u'/usr/libexec/ipsec/pluto -ctlbase'
                                         '/some/foo/path')])
    def test_process_running_cmdline_match(self, mock_open, mock_exists):
        self.process.pid_path = '/some/foo/path'
        with mock.patch.object(openswan_ipsec.LOG, 'error') as log_mock:
            self.assertTrue(self.process._process_running())
            self.assertTrue(log_mock.called)

    def test_status_handling_for_downed_connection(self):
        """Test status handling for downed connection."""
        self._test_status_handling_for_downed_connection(PLUTO_DOWN_STATUS)

    def test_status_handling_for_connection_with_no_ipsec_sa(self):
        """Test status handling for downed connection."""
        self._test_status_handling_for_downed_connection(
            PLUTO_ACTIVE_NO_IPSEC_SA_STATUS)

    def test_status_handling_for_active_connection(self):
        """Test status handling for active connection."""
        self._test_status_handling_for_active_connection(PLUTO_ACTIVE_STATUS)

    def test_status_handling_for_ike_v2_active_connection(self):
        """Test status handling for active connection."""
        self._test_status_handling_for_ike_v2_active_connection(
            PLUTO_ACTIVE_STATUS_IKEV2)

    def test_status_handling_for_deleted_connection(self):
        """Test status handling for deleted connection."""
        self._test_status_handling_for_deleted_connection(NOT_RUNNING_STATUS)

    def test_connection_names_handling_for_multiple_subnets(self):
        """Test connection names handling for multiple subnets."""
        self._test_connection_names_handling_for_multiple_subnets(
            PLUTO_MULTIPLE_SUBNETS_ESTABLISHED_STATUS)

    def test_parse_connection_status(self):
        """Test the status of ipsec-site-connection parsed correctly."""
        self._test_parse_connection_status(NOT_RUNNING_STATUS,
                                           PLUTO_ACTIVE_STATUS,
                                           PLUTO_DOWN_STATUS)


class TestLibreSwanProcess(base.BaseTestCase):

    def setUp(self):
        super(TestLibreSwanProcess, self).setUp()
        self.vpnservice = copy.deepcopy(FAKE_VPN_SERVICE)

        self.ipsec_process = libreswan_ipsec.LibreSwanProcess(cfg.CONF,
                                                       'foo-process-id',
                                                       self.vpnservice,
                                                       mock.ANY)

    @mock.patch('os.path.exists', return_value=True)
    def test_ensure_configs_on_restart(self, exists_mock):
        openswan_ipsec.OpenSwanProcess.ensure_configs = mock.Mock()
        with mock.patch.object(
            self.ipsec_process, '_execute'
        ) as fake_execute, mock.patch.object(
            self.ipsec_process, '_ipsec_execute'
        ) as fake_ipsec_execute, mock.patch.object(
            self.ipsec_process, '_ensure_needed_files'
        ) as fake_ensure_needed_files:
            self.ipsec_process.ensure_configs()

            expected = [mock.call(['rm', '-f',
                                   self.ipsec_process._get_config_filename(
                                       'ipsec.secrets')]),
                        mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root',
                                   self.ipsec_process._get_config_filename(
                                       'ipsec.secrets')]),
                        mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root', self.ipsec_process.log_dir])]
            fake_execute.assert_has_calls(expected)
            self.assertEqual(3, fake_execute.call_count)

            expected = [mock.call(['_stackmanager', 'start']),
                        mock.call(['checknss'])]
            fake_ipsec_execute.assert_has_calls(expected)
            self.assertEqual(2, fake_ipsec_execute.call_count)

            self.assertTrue(fake_ensure_needed_files.called)
            self.assertTrue(exists_mock.called)

    @mock.patch('os.path.exists', return_value=False)
    def test_ensure_configs(self, exists_mock):
        openswan_ipsec.OpenSwanProcess.ensure_configs = mock.Mock()
        with mock.patch.object(
            self.ipsec_process, '_execute'
        ) as fake_execute, mock.patch.object(
            self.ipsec_process, '_ipsec_execute'
        ) as fake_ipsec_execute, mock.patch.object(
            self.ipsec_process, '_ensure_needed_files'
        ) as fake_ensure_needed_files:
            self.ipsec_process.ensure_configs()

            expected = [mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root',
                                   self.ipsec_process._get_config_filename(
                                       'ipsec.secrets')]),
                        mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root', self.ipsec_process.log_dir])]
            fake_execute.assert_has_calls(expected)
            self.assertEqual(2, fake_execute.call_count)

            expected = [mock.call(['_stackmanager', 'start']),
                        mock.call(['checknss'])]
            fake_ipsec_execute.assert_has_calls(expected)
            self.assertEqual(2, fake_ipsec_execute.call_count)

            self.assertTrue(fake_ensure_needed_files.called)
            self.assertTrue(exists_mock.called)

        exists_mock.reset_mock()

        with mock.patch.object(
            self.ipsec_process, '_execute'
        ) as fake_execute, mock.patch.object(
            self.ipsec_process, '_ipsec_execute'
        ) as fake_ipsec_execute, mock.patch.object(
            self.ipsec_process, '_ensure_needed_files'
        ) as fake_ensure_needed_files:
            fake_ipsec_execute.side_effect = [None, RuntimeError, None]
            self.ipsec_process.ensure_configs()

            expected = [mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root',
                                   self.ipsec_process._get_config_filename(
                                       'ipsec.secrets')]),
                        mock.call(['chown', '--from=%s' % os.getuid(),
                                   'root:root', self.ipsec_process.log_dir])]
            fake_execute.assert_has_calls(expected)
            self.assertEqual(2, fake_execute.call_count)

            expected = [mock.call(['_stackmanager', 'start']),
                        mock.call(['checknss']),
                        mock.call(['initnss'])]
            self.assertEqual(3, fake_ipsec_execute.call_count)
            fake_ipsec_execute.assert_has_calls(expected)

            self.assertTrue(fake_ensure_needed_files.called)
            self.assertTrue(exists_mock.called)


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

    def test_status_handling_for_downed_connection(self):
        """Test status handling for downed connection."""
        self._test_status_handling_for_downed_connection(CHARON_DOWN_STATUS)

    def test_status_handling_for_active_connection(self):
        """Test status handling for active connection."""
        self._test_status_handling_for_active_connection(CHARON_ACTIVE_STATUS)

    def test_status_handling_for_deleted_connection(self):
        """Test status handling for deleted connection."""
        self._test_status_handling_for_deleted_connection(NOT_RUNNING_STATUS)

    def test_parse_connection_status(self):
        """Test the status of ipsec-site-connection parsed correctly."""
        self._test_parse_connection_status(NOT_RUNNING_STATUS,
                                           CHARON_ACTIVE_STATUS,
                                           CHARON_DOWN_STATUS)


class IPsecStrongswanDeviceDriverDVR(IPSecDeviceDVR):
    def setUp(self, driver=strongswan_ipsec.StrongSwanDriver,
              ipsec_process=strongswan_ipsec.StrongSwanProcess):
        super(IPsecStrongswanDeviceDriverDVR, self).setUp(driver,
                                                          ipsec_process)
