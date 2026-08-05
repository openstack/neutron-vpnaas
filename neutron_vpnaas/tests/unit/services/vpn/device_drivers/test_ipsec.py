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
import os
from unittest import mock

import netaddr
from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import legacy_router
from neutron.agent.l3 import router_info as l3_router_info
from neutron.agent.linux import iptables_manager
from neutron.conf.agent.l3 import config as l3_config
from neutron_lib import constants
from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn.device_drivers import libreswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.tests import base

# Note: process_id == router_id == vpnservice_id

_uuid = uuidutils.generate_uuid
FAKE_UUID = _uuid()
FAKE_HOST = 'fake_host'
FAKE_ROUTER_ID = FAKE_UUID
FAKE_VPNSERVICE_ID = FAKE_UUID
FAKE_PROCESS_ID = FAKE_UUID
FAKE_IPSEC_SITE_CONNECTION1_ID = _uuid()
FAKE_IPSEC_SITE_CONNECTION2_ID = _uuid()
FAKE_IKE_POLICY = {
    'ike_version': 'v1',
    'encryption_algorithm': 'aes-128',
    'auth_algorithm': 'sha256',
    'pfs': 'group5',
    'lifetime_value': 3600
}

FAKE_IPSEC_POLICY = {
    'encryption_algorithm': 'aes-128',
    'auth_algorithm': 'sha256',
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
    # [encryption_algorithm]-[auth_algorithm];[pfs]
    phase2alg=aes128-sha256;modp1536'''

AUTH_AH = '''ah
    # AH protocol does not support encryption
    # [auth_algorithm];[pfs]
    phase2alg=sha256;modp1536'''

LIBRESWAN_CONNECTION_DETAILS = '''# rightsubnet=networkA/netmaskA, networkB/netmaskB (IKEv2 only)
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
    # [encryption_algorithm]-[auth_algorithm];[pfs]
    ike=aes128-sha256;modp1536
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
'''  # noqa: E501

IPV4_NEXT_HOP = (
    '''# NOTE: a default route is required for %defaultroute to work...
    leftnexthop=%defaultroute
    rightnexthop=%defaultroute'''
)

LIBRESWAN_IPV6_NEXT_HOP = (
    '''# To recognize the given IP addresses in this config
    # as IPv6 addresses by pluto whack. Default is ipv4
    connaddrfamily=ipv6
    # Assign gateway address as leftnexthop
    leftnexthop=%s
    # rightnexthop is not mandatory for ipsec, so no need in ipv6.'''
)

EXPECTED_LIBRESWAN_CONF = """
# Configuration for %(vpnservice_id)s
config setup
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

STRONGSWAN_AUTH_ESP = 'esp=aes128-sha256-modp1536'

STRONGSWAN_AUTH_AH = 'ah=sha256-modp1536'

EXPECTED_IPSEC_LIBRESWAN_SECRET_CONF = '''
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

PLUTO_ACTIVE_STATUS = """000 "{conn_id}/0x1": erouted;\n
000 #4: "{conn_id}/0x1":500 STATE_QUICK_R2 (IPsec SA established); \
newest IPSEC;""".format(
    conn_id=FAKE_IPSEC_SITE_CONNECTION2_ID)
PLUTO_ACTIVE_STATUS_IKEV2 = """000 "{conn_id}/0x1": erouted;\n
000 #4: "{conn_id}/0x1":500 STATE_PARENT_R2 (PARENT SA established); \
newest IPSEC;""".format(
    conn_id=FAKE_IPSEC_SITE_CONNECTION2_ID)
PLUTO_MULTIPLE_SUBNETS_ESTABLISHED_STATUS = """000 "{conn_id1}/1x1": erouted;\n
000 #4: "{conn_id1}/1x1":500 STATE_QUICK_R2 (IPsec SA established); \
newest IPSEC;\n
000 "{conn_id2}/2x1": erouted;\n
000 #4: "{conn_id2}/2x1":500 STATE_QUICK_R2 (IPsec SA established); \
newest IPSEC;\n""".format(  # noqa: E501
    conn_id1=FAKE_IPSEC_SITE_CONNECTION1_ID,
    conn_id2=FAKE_IPSEC_SITE_CONNECTION2_ID)
PLUTO_ACTIVE_NO_IPSEC_SA_STATUS = """000 "{conn_id}/0x1": erouted;\n
000 #258: "{conn_id}/0x1":500 STATE_MAIN_R2
(sent MR2, expecting MI3);""".format(
    conn_id=FAKE_IPSEC_SITE_CONNECTION2_ID)
PLUTO_DOWN_STATUS = "000 \"%(conn_id)s/0x1\": unrouted;" % {
    'conn_id': FAKE_IPSEC_SITE_CONNECTION2_ID}

CHARON_ACTIVE_STATUS = "%(conn_id)s{1}:  INSTALLED, TUNNEL" % {
    'conn_id': FAKE_IPSEC_SITE_CONNECTION2_ID}
CHARON_DOWN_STATUS = "%(conn_id)s{1}:  ROUTED, TUNNEL" % {
    'conn_id': FAKE_IPSEC_SITE_CONNECTION2_ID}

NOT_RUNNING_STATUS = "Command: ['ipsec', 'status'] Exit code: 3 Stdout:"


class BaseIPsecDeviceDriver(base.BaseTestCase):
    def setUp(self, driver=libreswan_ipsec.LibreSwanDriver,
              ipsec_process=libreswan_ipsec.LibreSwanProcess,
              vpnservice=FAKE_VPN_SERVICE):
        super().setUp()
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
        self.context = context.get_admin_context()
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

    def setUp(self, driver=libreswan_ipsec.LibreSwanDriver,
              ipsec_process=libreswan_ipsec.LibreSwanProcess):
        super().setUp(driver, ipsec_process)
        self._make_router_info_for_test()

    def _make_router_info_for_test(self):
        self.router_info = legacy_router.LegacyRouter(router_id=FAKE_ROUTER_ID,
                                                      agent=self.agent,
                                                      **self.ri_kwargs)
        self.router_info.router['distributed'] = False
        self.router_info.iptables_manager.ipv4['nat'] = self.iptables
        self.router_info.iptables_manager.apply = self.apply_mock
        self.driver.routers[FAKE_ROUTER_ID] = self.router_info

    def _test_vpnservice_updated(self, expected_param, **kwargs):
        with mock.patch.object(self.driver, 'sync') as sync:
            context = mock.Mock()
            self.driver.vpnservice_updated(context, **kwargs)
            sync.assert_called_once_with(context, expected_param)

    def test_vpnservice_updated(self):
        self._test_vpnservice_updated([])

    def test_vpnservice_updated_with_router_info(self):
        kwargs = {'router': self.router_info}
        self._test_vpnservice_updated([self.router_info], **kwargs)

    def test_create_router(self):
        process = mock.Mock(libreswan_ipsec.LibreSwanProcess)
        process.vpnservice = self.vpnservice
        self.driver.processes = {
            FAKE_ROUTER_ID: process}
        self.driver.create_router(self.router_info)
        self._test_ensure_nat_rules()
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

    def _test_ensure_nat_rules(self):
        self.router_info.iptables_manager.ipv4['nat'].assert_has_calls([
            mock.call.clear_rules_by_tag('vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 20.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 30.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 11.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 11.0.0.0/24 -d 50.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas')
        ])
        self.router_info.iptables_manager.apply.assert_called_once_with()

    def _test_ensure_nat_rules_with_multiple_locals(self):
        self.router_info.iptables_manager.ipv4['nat'].assert_has_calls([
            mock.call.clear_rules_by_tag('vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 20.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 10.0.0.0/24 -d 30.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 11.0.0.0/24 -d 20.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 11.0.0.0/24 -d 30.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 12.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 12.0.0.0/24 -d 50.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 13.0.0.0/24 -d 40.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas'),
            mock.call.add_rule(
                'POSTROUTING',
                '-s 13.0.0.0/24 -d 50.0.0.0/24 -m policy '
                '--dir out --pol ipsec -j ACCEPT ',
                top=True,
                tag='vpnaas')
        ])
        self.router_info.iptables_manager.apply.assert_called_once_with()

    def test_sync(self):
        fake_vpn_service = FAKE_VPN_SERVICE
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            fake_vpn_service]
        context = mock.Mock()
        self.driver._sync_vpn_processes = mock.Mock()
        self.driver._delete_vpn_processes = mock.Mock()
        self.driver._cleanup_stale_vpn_processes = mock.Mock()
        sync_router_ids = [fake_vpn_service['router_id']]
        self.driver.sync(context, [self.router_info])
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
            self._test_ensure_nat_rules()
            self.driver.processes[router_id].update.assert_called_once_with()

    def test__sync_with_dict_and_router_info(self):
        """Verify sync handles mixed router_information types correctly."""

        router_id_1 = 'router_1'
        router_id_2 = 'router_2'

        # A proper RouterInfo object
        router_info_1 = mock.Mock(spec=l3_router_info.RouterInfo)
        router_info_1.router_id = router_id_1

        # A dictionary, as sometimes received via RPC
        router_info_2_dict = {'id': router_id_2}

        router_information = [router_info_1, router_info_2_dict]

        self.driver.agent_rpc.get_vpn_services_on_host.return_value = []
        self.driver._sync_vpn_processes = mock.Mock()
        self.driver._delete_vpn_processes = mock.Mock()
        self.driver._cleanup_stale_vpn_processes = mock.Mock()
        self.driver.report_status = mock.Mock()

        self.driver.sync(self.context, router_information)

        self.assertIn(router_id_1, self.driver.routers)
        self.assertEqual(router_info_1, self.driver.routers[router_id_1])

        self.assertNotIn(router_id_2, self.driver.routers)

        self.driver._sync_vpn_processes.assert_called_once()
        _vpn_services, sync_router_ids = \
            self.driver._sync_vpn_processes.call_args[0]
        self.assertIn(router_id_1, sync_router_ids)
        self.assertIn(router_id_2, sync_router_ids)
        self.assertEqual(2, len(sync_router_ids))

    def test_ensure_nat_rules_with_multiple_local_subnets(self):
        """Ensure that add nat rule combinations are correct."""
        overrides = {'local_cidrs': [['10.0.0.0/24', '11.0.0.0/24'],
                                     ['12.0.0.0/24', '13.0.0.0/24']]}
        self.modify_config_for_test(overrides)
        self.driver.ensure_nat_rules(self.vpnservice)
        self._test_ensure_nat_rules_with_multiple_locals()

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
        self.driver.process_status_cache = {}
        self.driver.processes = {}
        with mock.patch.object(self.driver, 'ensure_process') as ensure_p:
            ensure_p.side_effect = self.fake_ensure_process
            self.driver._sync_vpn_processes(
                [self.vpnservice],
                [FAKE_ROUTER_ID]
            )
            self._test_ensure_nat_rules()
            self.driver.processes[
                FAKE_ROUTER_ID
            ].update.assert_called_once_with()

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

    # TODO(crohmann): Add test cases for HARouter and different ha_states
    # @ddt [(False, None),(True, 'primary'), (True, 'standby')]
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
            self.driver.sync(context, [self.router_info])
            process = self.driver.processes[FAKE_ROUTER_ID]
            self.assertEqual(new_vpn_service, process.vpnservice)
            self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
                updated_vpn_service]
            self.driver.sync(context, [self.router_info])
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
        ri = self.router_info
        ri.router_id = process_id
        ri.router['id'] = process_id
        self.driver.sync(context, [self.router_info])
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
        router_id = self.router_info.router_id
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
        router_id = self.router_info.router_id
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
        router_id = self.router_info.router_id
        connection_id = FAKE_IPSEC_SITE_CONNECTION2_ID
        ike_policy = {'ike_version': 'v2',
                      'encryption_algorithm': 'aes-128',
                      'auth_algorithm': 'sha256',
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
        router_id = self.router_info.router_id
        process = self.driver.ensure_process(router_id, self.vpnservice)
        self._execute.return_value = active_status
        names = process.get_established_connections()
        self.assertEqual(2, len(names))

    def _test_status_handling_for_deleted_connection(self,
                                                     not_running_status):
        """Test status handling for deleted connection."""
        router_id = self.router_info.router_id
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
        router_id = self.router_info.router_id
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


class IPSecDeviceDVR(BaseIPsecDeviceDriver):

    def setUp(self, driver=libreswan_ipsec.LibreSwanDriver,
              ipsec_process=libreswan_ipsec.LibreSwanProcess):
        super().setUp(driver, ipsec_process)
        mock.patch.object(dvr_snat_ns.SnatNamespace, 'create').start()
        self._make_dvr_edge_router_info_for_test()

    def _make_dvr_edge_router_info_for_test(self):
        router_info = dvr_edge_router.DvrEdgeRouter(mock.sentinel.agent,
                                                    mock.sentinel.myhost,
                                                    FAKE_ROUTER_ID,
                                                    **self.ri_kwargs)
        router_info.router['distributed'] = True
        router_info.snat_namespace = dvr_snat_ns.SnatNamespace(
            router_info.router['id'],
            mock.sentinel.agent,
            self.driver,
            mock.ANY
        )
        router_info.snat_namespace.create()
        router_info.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace='snat-' + FAKE_ROUTER_ID, use_ipv6=mock.ANY)
        router_info.snat_iptables_manager.ipv4['nat'] = self.iptables
        router_info.snat_iptables_manager.apply = self.apply_mock
        self.driver.routers[FAKE_ROUTER_ID] = router_info

    def test_sync_dvr(self):
        fake_vpn_service = FAKE_VPN_SERVICE
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            fake_vpn_service]
        context = mock.Mock()
        self.driver._sync_vpn_processes = mock.Mock()
        self.driver._delete_vpn_processes = mock.Mock()
        self.driver._cleanup_stale_vpn_processes = mock.Mock()
        sync_router_ids = [fake_vpn_service['router_id']]
        with mock.patch.object(self.driver,
                               'get_process_status_cache') as process_status:
            self.driver.sync(context, [self.driver.routers[FAKE_ROUTER_ID]])
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

    def test_ensure_nat_rules_with_dvr_edge_router(self):
        self.driver.ensure_nat_rules(FAKE_VPN_SERVICE)
        self.apply_mock.assert_called_once_with()


class IPsecStrongswanConfigGeneration(BaseIPsecDeviceDriver):

    def setUp(self, driver=strongswan_ipsec.StrongSwanDriver,
              ipsec_process=strongswan_ipsec.StrongSwanProcess):
        super().setUp(
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
            'ike_auth_algorithm': 'sha256',
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


class TestLibreSwanConfigGeneration(BaseIPsecDeviceDriver):
    """Verify that LibreSwan configuration files are generated correctly."""

    def setUp(self, driver=libreswan_ipsec.LibreSwanDriver,
              ipsec_process=libreswan_ipsec.LibreSwanProcess):
        super().setUp(driver, ipsec_process, vpnservice=FAKE_VPN_SERVICE)
        self.conf.register_opts(libreswan_ipsec.libreswan_opts, 'libreswan')
        self.conf.set_override('state_path', '/tmp')
        self.ipsec_template = self.conf.libreswan.ipsec_config_template
        self.process = ipsec_process(self.conf,
                                     'foo-process-id',
                                     self.vpnservice,
                                     mock.ANY)

    def build_ipsec_expected_config_for_test(self, info):
        """Build LibreSwan ipsec expected config for test variations."""
        auth_mode = info.get('ipsec_auth', AUTH_ESP)
        conn_details = LIBRESWAN_CONNECTION_DETAILS % {
            'auth_mode': auth_mode,
            'dpd_action': 'hold',
            'dpd_delay': 30,
            'dpd_timeout': 120,
            'ike_lifetime': 3600,
            'life_time': 3600,
            'encapsulation_mode': 'tunnel'}
        virtual_privates = []
        cidrs = info.get('local_cidrs', [['10.0.0.0/24'], ['11.0.0.0/24']])
        local_cidrs = []
        for cidr in cidrs:
            if len(cidr) == 2:
                local_cidrs.append("s={ %s }" % ' '.join(cidr))
            else:
                local_cidrs.append("=%s" % cidr[0])
            for net in cidr:
                version = netaddr.IPNetwork(net).version
                virtual_privates.append('%v{}:{}'.format(version, net))
        cidrs = info.get('peer_cidrs', [['20.0.0.0/24', '30.0.0.0/24'],
                                        ['40.0.0.0/24', '50.0.0.0/24']])
        for cidr in cidrs:
            for net in cidr:
                version = netaddr.IPNetwork(net).version
                virtual_privates.append('%v{}:{}'.format(version, net))
        peer_cidrs = [' '.join(cidr) for cidr in cidrs]
        local_ip = info.get('local', '60.0.0.4')
        local_id = info.get('local_id')
        leftid = local_ip
        if local_id:
            leftid = local_id
        version = info.get('local_ip_vers', 4)
        next_hop = (IPV4_NEXT_HOP if version == 4
                    else LIBRESWAN_IPV6_NEXT_HOP % local_ip)
        peer_ips = info.get('peers', ['60.0.0.5', '60.0.0.6'])
        virtual_privates.sort()
        return EXPECTED_LIBRESWAN_CONF % {
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
        """Test config file with IPSec policy using AH."""
        overrides = {'ipsec_auth': 'ah'}
        self.modify_config_for_test(overrides)
        self.process.update_vpnservice(self.vpnservice)
        info = {'ipsec_auth': AUTH_AH}
        self._test_ipsec_connection_config(info)

    def test_connections_with_multiple_left_subnets(self):
        """Test multiple local subnets."""
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
        expected = EXPECTED_IPSEC_LIBRESWAN_SECRET_CONF
        actual = self.process._gen_config_content(
            self.conf.libreswan.ipsec_secret_template, self.vpnservice)
        self.check_config_file(expected, actual)


class TestLibreSwanProcess(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.vpnservice = copy.deepcopy(FAKE_VPN_SERVICE)

        self.ipsec_process = libreswan_ipsec.LibreSwanProcess(cfg.CONF,
                                                              'foo-process-id',
                                                              self.vpnservice,
                                                              mock.ANY)

    @mock.patch('os.path.exists', return_value=True)
    def test_ensure_configs_on_restart(self, exists_mock):
        with mock.patch.object(
            self.ipsec_process, '_execute'
        ) as fake_execute, mock.patch.object(
            self.ipsec_process, '_ipsec_execute'
        ) as fake_ipsec_execute, mock.patch.object(
            self.ipsec_process, '_ensure_needed_files'
        ) as fake_ensure_needed_files, mock.patch.object(
            self.ipsec_process, 'ensure_config_dir'
        ), mock.patch.object(
            self.ipsec_process, 'ensure_config_file'
        ):
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
        with mock.patch.object(
            self.ipsec_process, '_execute'
        ) as fake_execute, mock.patch.object(
            self.ipsec_process, '_ipsec_execute'
        ) as fake_ipsec_execute, mock.patch.object(
            self.ipsec_process, '_ensure_needed_files'
        ) as fake_ensure_needed_files, mock.patch.object(
            self.ipsec_process, 'ensure_config_dir'
        ), mock.patch.object(
            self.ipsec_process, 'ensure_config_file'
        ):
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


class IPsecStrongswanDeviceDriverLegacy(IPSecDeviceLegacy):

    def setUp(self, driver=strongswan_ipsec.StrongSwanDriver,
              ipsec_process=strongswan_ipsec.StrongSwanProcess):
        super().setUp(driver, ipsec_process)
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
        super().setUp(driver, ipsec_process)
