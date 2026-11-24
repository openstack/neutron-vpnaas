# Copyright 2026 OpenStack Foundation
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
import os
import tempfile
from unittest import mock
import warnings

from neutron_lib import constants
from oslo_config import cfg

from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.tests import base
from neutron_vpnaas.tests.unit.services.vpn.device_drivers import test_ipsec

FAKE_CONN1_ID = test_ipsec.FAKE_IPSEC_SITE_CONNECTION1_ID
FAKE_CONN2_ID = test_ipsec.FAKE_IPSEC_SITE_CONNECTION2_ID
FAKE_PROCESS_ID = 'foo-process-id'

# Output of 'swanctl --list-sas' as wrapped by neutron-vpn-netns-wrapper,
# which prefixes the command output with "Command: ... Exit code: N
# Stdout: ... Stderr: ..." (stdout and stderr are concatenated).
IKE_SA_LINE = ('%s: #2, ESTABLISHED, IKEv2, '
              '8c4712b1eebfd67b_i 5c2a71d9f1e8a357_r')
CHILD_SA_LINE = ('  %s: #1, reqid 1, INSTALLED, TUNNEL, '
                 'esp:aes128-sha256 in c471a7f1 (1234B), '
                 'out 71d9a357 (5678B)')

SWANCTL_INSTALLED_STATUS = (
    "Command: ['swanctl', '--list-sas'] Exit code: 0 Stdout: %s\n%s Stderr:" %
    (IKE_SA_LINE % FAKE_CONN2_ID, CHILD_SA_LINE % FAKE_CONN2_ID))

SWANCTL_CONNECTING_STATUS = (
    "Command: ['swanctl', '--list-sas'] Exit code: 0 Stdout: %s: #1, "
    "CONNECTING, IKEv2, 0000000000000000_i 0000000000000000_r Stderr:" %
    FAKE_CONN2_ID)

SWANCTL_EMPTY_STATUS = ("""Command: ['swanctl', '--list-sas'] Exit code: 0 """
                        "Stdout: Stderr: ")

SWANCTL_NOT_RUNNING_STATUS = ("""Command: ['swanctl', '--list-sas'] Exit """
                              """code: 1 Stdout: Stderr: connecting to """
                              """socket '/var/run/charon.vici' failed: """)


class TestSwanctlProcess(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.conf = cfg.CONF
        self.conf.register_opts(ipsec.ipsec_opts, 'ipsec')
        self.conf.register_opts(strongswan_ipsec.strongswan_opts, 'strongswan')
        self.tmpdir = tempfile.mkdtemp()
        self.conf.set_override('state_path', self.tmpdir)
        self.vpnservice = copy.deepcopy(test_ipsec.FAKE_VPN_SERVICE)
        self.process = strongswan_ipsec.SwanctlProcess(
            self.conf,
            FAKE_PROCESS_ID,
            self.vpnservice,
            'qrouter-test')
        self._swanctl_dir = os.path.join(
            self.tmpdir, 'ipsec', FAKE_PROCESS_ID, 'etc', 'swanctl')

    def test_extract_connection_status_installed(self):
        self.process._extract_and_record_connection_status(
            SWANCTL_INSTALLED_STATUS)
        # The CHILD_SA line is the authoritative status: the connection
        # is ACTIVE because its CHILD_SA is INSTALLED. The IKE_SA line
        # is ignored (no reqid).
        self.assertEqual(
            constants.ACTIVE,
            self.process.connection_status[FAKE_CONN2_ID]['status'])

    def test_extract_connection_status_connecting(self):
        self.process._extract_and_record_connection_status(
            SWANCTL_CONNECTING_STATUS)
        self.assertEqual(
            constants.DOWN,
            self.process.connection_status[FAKE_CONN2_ID]['status'])

    def test_extract_connection_status_empty(self):
        self.process.connection_status = {FAKE_CONN1_ID: {'status': 'foo'}}
        self.process._extract_and_record_connection_status('')
        self.assertEqual({}, self.process.connection_status)

    def test_extract_connection_status_no_sa(self):
        # charon runs but no CHILD_SA is reported: any previous status
        # must be cleared so the connections are reported as DOWN.
        self.process.connection_status = {FAKE_CONN1_ID: {'status': 'foo'}}
        self.process._extract_and_record_connection_status(
            SWANCTL_EMPTY_STATUS)
        self.assertEqual({}, self.process.connection_status)

    def test_extract_connection_status_not_running(self):
        self.process.connection_status = {FAKE_CONN1_ID: {'status': 'foo'}}
        self.process._extract_and_record_connection_status(
            SWANCTL_NOT_RUNNING_STATUS)
        self.assertEqual({}, self.process.connection_status)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess,
                       '_wait_for_charon_ready')
    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_start(self, mock_execute, _mock_wait):
        self.process.start()
        mock_execute.assert_has_calls([
            mock.call(['ipsec', 'start']),
            mock.call(['swanctl', '--load-all']),
        ], any_order=False)

    def test_start_without_namespace(self):
        self.process.namespace = None
        with mock.patch.object(
                strongswan_ipsec.SwanctlProcess, '_execute') as execute:
            self.process.start()
            execute.assert_not_called()

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_stop(self, mock_execute):
        self.process.stop()
        mock_execute.assert_called_once_with(['ipsec', 'stop'])
        self.assertEqual({}, self.process.connection_status)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_reload(self, mock_execute):
        self.process.reload()
        mock_execute.assert_called_once_with(['swanctl', '--load-all'])

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_reload_secrets(self, mock_execute):
        self.process.reload_secrets()
        mock_execute.assert_called_once_with(['swanctl', '--load-creds'])

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_get_status(self, mock_execute):
        mock_execute.return_value = SWANCTL_INSTALLED_STATUS
        status = self.process.get_status()
        self.assertEqual(SWANCTL_INSTALLED_STATUS, status)
        mock_execute.assert_called_once_with(
            ['swanctl', '--list-sas'], extra_ok_codes=[1])

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_active(self, mock_execute):
        mock_execute.return_value = SWANCTL_INSTALLED_STATUS
        self.assertTrue(self.process.active)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_active_empty_status(self, mock_execute):
        mock_execute.return_value = SWANCTL_EMPTY_STATUS
        self.assertFalse(self.process.active)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_active_not_running(self, mock_execute):
        mock_execute.return_value = SWANCTL_NOT_RUNNING_STATUS
        self.assertFalse(self.process.active)

    def test_translate_dialect(self):
        self.process.translate_dialect()
        conn = self.vpnservice['ipsec_site_connections'][0]
        # stroke keywords -> swanctl/VICI keywords
        self.assertEqual('1', conn['ikepolicy']['ike_version'])
        self.assertEqual('start', conn['initiator'])
        self.assertEqual('trap', conn['dpd_action'])
        self.assertEqual('aes128', conn['ikepolicy']['encryption_algorithm'])
        self.assertEqual('sha256', conn['ikepolicy']['auth_algorithm'])
        self.assertEqual('modp1536', conn['ikepolicy']['pfs'])

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, 'copy_and_overwrite')
    def test_ensure_configs(self, _mock_copy):
        self.process.ensure_configs()
        self.assertTrue(os.path.exists(
            os.path.join(self._swanctl_dir, 'swanctl.conf')))
        self.assertTrue(os.path.exists(
            os.path.join(self._swanctl_dir, 'secrets.conf')))
        with open(os.path.join(self._swanctl_dir, 'swanctl.conf')) as f:
            content = f.read()
        self.assertIn('include secrets.conf', content)
        self.assertIn(FAKE_CONN1_ID, content)
        self.assertIn(FAKE_CONN2_ID, content)
        # ipsec.conf for the starter: minimal, no conn stanzas
        etc_dir = os.path.dirname(self._swanctl_dir)
        ipsec_conf = os.path.join(etc_dir, 'ipsec.conf')
        self.assertTrue(os.path.exists(ipsec_conf))
        with open(ipsec_conf) as f:
            content = f.read()
        self.assertIn('config setup', content)
        self.assertNotIn('conn ', content)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, 'copy_and_overwrite')
    def test_ensure_configs_copies_strongswan_d(self, mock_copy):
        self.process.ensure_configs()
        mock_copy.assert_called_once_with(
            cfg.CONF.strongswan.default_config_area,
            self.process._get_config_filename('strongswan.d'))

    @mock.patch.object(strongswan_ipsec.SwanctlProcess,
                       '_get_strongswan_piddir', return_value='/var/run')
    def test_execute_uses_namespace_wrapper(self, _mock_piddir):
        with mock.patch(
                'neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec.'
                'ip_lib.IPWrapper') as ip_wrapper_cls:
            ip_wrapper = ip_wrapper_cls.return_value
            self.process._execute(['swanctl', '--list-sas'])
            ip_wrapper.netns.execute.assert_called_once()
            cmd = ip_wrapper.netns.execute.call_args[0][0]
            self.assertTrue(
                any('neutron-vpn-netns-wrapper' in arg for arg in cmd))
            self.assertIn('--cmd=swanctl,--list-sas', cmd[-1])

    @mock.patch.object(strongswan_ipsec.StrongSwanProcess,
                       '_get_strongswan_piddir', return_value='/var/run')
    def test_strongswan_process_deprecation_warning(self, _mock_piddir):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            strongswan_ipsec.StrongSwanProcess(
                self.conf, 'id', self.vpnservice, mock.ANY)
        self.assertTrue(any(
            issubclass(w.category, DeprecationWarning) for w in caught))


class TestSwanctlConfigGeneration(test_ipsec.BaseIPsecDeviceDriver):

    def setUp(self):
        super().setUp(
            driver=strongswan_ipsec.SwanctlDriver,
            ipsec_process=strongswan_ipsec.SwanctlProcess)
        self.conf.register_opts(strongswan_ipsec.strongswan_opts, 'strongswan')
        self.conf.set_override('state_path', '/tmp')
        self.process = strongswan_ipsec.SwanctlProcess(
            self.conf, 'foo-process-id', self.vpnservice, mock.ANY)
        self.swanctl_template = self.conf.strongswan.swanctl_config_template
        self.swanctl_secrets_template = (
            self.conf.strongswan.swanctl_secrets_template)

    def test_swanctl_config_template(self):
        actual = self.process._gen_config_content(
            self.swanctl_template, self.vpnservice)
        self.assertIn('connections {', actual)
        self.assertIn(FAKE_CONN1_ID, actual)
        self.assertIn(FAKE_CONN2_ID, actual)
        self.assertIn('local_addrs = 60.0.0.4', actual)
        self.assertIn('remote_addrs = 60.0.0.5', actual)
        # both the connection and the child SA are named after the
        # IPsec site connection id
        self.assertIn('start_action = start', actual)
        self.assertIn('dpd_action = trap', actual)
        self.assertIn('local_ts = 10.0.0.0/24', actual)
        self.assertIn('remote_ts = 20.0.0.0/24, 30.0.0.0/24', actual)
        self.assertIn('proposals = aes128-sha256-modp1536', actual)
        self.assertIn('esp_proposals = aes128-sha256-modp1536', actual)
        self.assertIn('include secrets.conf', actual)

    def test_swanctl_secrets_template(self):
        actual = self.process._gen_config_content(
            self.swanctl_secrets_template, self.vpnservice)
        self.assertIn('secrets {', actual)
        self.assertIn('ike-%s' % FAKE_CONN1_ID, actual)
        self.assertIn('id-1 = 60.0.0.4', actual)
        self.assertIn('id-2 = 60.0.0.5', actual)
        self.assertIn('secret = 0scGFzc3dvcmQ=', actual)


class TestSwanctlDriver(test_ipsec.IPsecStrongswanDeviceDriverLegacy):

    def setUp(self):
        super().setUp(
            driver=strongswan_ipsec.SwanctlDriver,
            ipsec_process=strongswan_ipsec.SwanctlProcess)

    def test_create_process(self):
        process = self.driver.create_process(
            test_ipsec.FAKE_ROUTER_ID, self.vpnservice, 'qrouter-test')
        self.assertIsInstance(process, strongswan_ipsec.SwanctlProcess)

    def test_status_handling_for_active_connection(self):
        self._test_status_handling_for_active_connection(
            SWANCTL_INSTALLED_STATUS)

    def test_status_handling_for_downed_connection(self):
        self._test_status_handling_for_downed_connection(
            SWANCTL_CONNECTING_STATUS)

    def test_parse_connection_status(self):
        self._test_parse_connection_status(
            SWANCTL_NOT_RUNNING_STATUS,
            SWANCTL_INSTALLED_STATUS,
            SWANCTL_CONNECTING_STATUS)
