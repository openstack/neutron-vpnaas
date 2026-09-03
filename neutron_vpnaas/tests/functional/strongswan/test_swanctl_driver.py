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

import os
import shutil
import tempfile
from unittest import mock

from neutron.conf.agent.l3 import config as l3_config
from neutron.tests.functional import base
from oslo_config import cfg

from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.tests.unit.services.vpn.device_drivers import test_ipsec


class TestSwanctlConfigGeneration(base.BaseSudoTestCase):

    def setUp(self):
        super().setUp()
        self.conf = cfg.CONF
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(ipsec.ipsec_opts, 'ipsec')
        self.conf.register_opts(strongswan_ipsec.strongswan_opts,
                                'strongswan')
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.conf.set_override('state_path', self.tmpdir)
        self.process = strongswan_ipsec.SwanctlProcess(
            self.conf,
            'swanctl-test-router',
            test_ipsec.FAKE_VPN_SERVICE,
            mock.ANY)
        self._swanctl_dir = os.path.join(
            self.tmpdir, 'ipsec', 'swanctl-test-router', 'etc', 'swanctl')

    def test_ensure_configs_writes_swanctl_files(self):
        self.process.ensure_configs()
        conn_dir = os.path.join(self._swanctl_dir, 'connections')
        secrets_dir = os.path.join(self._swanctl_dir, 'secrets')
        self.assertTrue(os.path.isdir(conn_dir))
        self.assertTrue(os.path.isdir(secrets_dir))

        conn_files = os.listdir(conn_dir)
        self.assertEqual(2, len(conn_files))
        for conn_file in conn_files:
            with open(os.path.join(conn_dir, conn_file)) as fh:
                content = fh.read()
            self.assertIn('connections {', content)
            self.assertIn('local_addrs', content)

        secrets_file = os.path.join(secrets_dir, 'secrets.conf')
        self.assertTrue(os.path.exists(secrets_file))
        with open(secrets_file) as fh:
            secrets_content = fh.read()
        self.assertIn('secrets {', secrets_content)
        self.assertIn('shared-secret', secrets_content)
