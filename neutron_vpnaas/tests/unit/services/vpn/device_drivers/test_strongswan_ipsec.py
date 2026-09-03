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

SWANCTL_INSTALLED_STATUS = """%s:  INSTALLED, ESTABLISHED, current (IPv4)
    child_sa:  %s_child
        INSTALLED, ESTABLISHED, current (IPv4)
""" % (FAKE_CONN2_ID, FAKE_CONN2_ID)

SWANCTL_CONNECTING_STATUS = """%s:  CONNECTING, current (IPv4)
""" % FAKE_CONN2_ID

SWANCTL_EMPTY_STATUS = 'No active Security Associations found.'


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
        self.process._extract_and_swanctl_connection_status(
            SWANCTL_INSTALLED_STATUS)
        self.assertEqual(
            constants.ACTIVE,
            self.process.connection_status[FAKE_CONN2_ID]['status'])
        self.assertEqual(
            constants.ACTIVE,
            self.process.connection_status[
                '%s_child' % FAKE_CONN2_ID]['status'])

    def test_extract_connection_status_connecting(self):
        self.process._extract_and_swanctl_connection_status(
            SWANCTL_CONNECTING_STATUS)
        self.assertEqual(
            constants.DOWN,
            self.process.connection_status[FAKE_CONN2_ID]['status'])

    def test_extract_connection_status_empty(self):
        self.process.connection_status = {FAKE_CONN1_ID: {'status': 'foo'}}
        self.process._extract_and_swanctl_connection_status('')
        self.assertEqual({}, self.process.connection_status)

    def test_check_swanctl_status_line(self):
        conn_id, status = self.process._check_swanctl_status_line(
            'INSTALLED, ESTABLISHED')
        self.assertIsNone(conn_id)
        self.assertEqual(constants.ACTIVE, status)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess,
                       '_wait_for_charon_ready')
    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_start(self, mock_execute, _mock_wait):
        self.process.start()
        mock_execute.assert_has_calls([
            mock.call(['ipsec', 'start'], check_exit_code=False),
            mock.call(['swanctl', '--load-all']),
            mock.call(['swanctl', '--load-creds']),
            mock.call(['swanctl', '--initiate', '--child', FAKE_CONN1_ID]),
            mock.call(['swanctl', '--initiate', '--child', FAKE_CONN2_ID]),
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
        mock_execute.assert_called_once_with(
            ['ipsec', 'stop'], check_exit_code=False)
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
            ['swanctl', '--list-sas'], check_exit_code=False)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_active(self, mock_execute):
        mock_execute.return_value = SWANCTL_INSTALLED_STATUS
        self.assertTrue(self.process.active)

    @mock.patch.object(strongswan_ipsec.SwanctlProcess, '_execute')
    def test_active_empty_status(self, mock_execute):
        mock_execute.return_value = SWANCTL_EMPTY_STATUS
        self.assertFalse(self.process.active)

    def test_ensure_configs(self):
        self.process.ensure_configs()
        conn_dir = os.path.join(self._swanctl_dir, 'connections')
        secrets_dir = os.path.join(self._swanctl_dir, 'secrets')
        self.assertTrue(os.path.isdir(conn_dir))
        self.assertTrue(os.path.isdir(secrets_dir))
        self.assertTrue(os.path.exists(
            os.path.join(conn_dir, '%s.conf' % FAKE_CONN1_ID)))
        self.assertTrue(os.path.exists(
            os.path.join(conn_dir, '%s.conf' % FAKE_CONN2_ID)))
        self.assertTrue(os.path.exists(
            os.path.join(secrets_dir, 'secrets.conf')))

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
        self.assertIn('local_addrs  = [ 60.0.0.4 ]', actual)
        self.assertIn('remote_addrs = [ 60.0.0.5 ]', actual)
        self.assertIn('%s_child' % FAKE_CONN1_ID, actual)

    def test_swanctl_secrets_template(self):
        actual = self.process._gen_config_content(
            self.swanctl_secrets_template, self.vpnservice)
        self.assertIn('secrets {', actual)
        self.assertIn('type: shared-secret', actual)
        self.assertIn('0scGFzc3dvcmQ=', actual)


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
