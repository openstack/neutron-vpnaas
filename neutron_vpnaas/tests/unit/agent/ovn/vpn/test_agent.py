# Copyright 2026 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from oslo_service import service

from neutron_vpnaas.agent.ovn.vpn import agent
from neutron_vpnaas.tests import base


class TestOvnVpnAgent(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        with mock.patch.object(agent.config, 'get_ovn_ovsdb_log_level',
                               return_value='INFO'), \
                mock.patch.object(agent.vlog, 'use_python_logger'):
            self.agent = agent.OvnVpnAgent(mock.Mock())

    def test_stop(self):
        self.agent._sb_idl = mock.Mock()
        self.agent._ovs_idl = mock.Mock()
        with mock.patch.object(service.Service, 'stop') as mock_super_stop:
            self.agent.stop()

        self.agent._sb_idl.stop.assert_called_once_with()
        self.agent._ovs_idl.stop.assert_called_once_with()
        mock_super_stop.assert_called_once_with(True)

    def test_stop_without_idls(self):
        with mock.patch.object(service.Service, 'stop') as mock_super_stop:
            self.agent.stop()

        mock_super_stop.assert_called_once_with(True)

    def test_stop_graceful_false(self):
        self.agent._sb_idl = mock.Mock()
        self.agent._ovs_idl = mock.Mock()
        with mock.patch.object(service.Service, 'stop') as mock_super_stop:
            self.agent.stop(graceful=False)

        self.agent._sb_idl.stop.assert_called_once_with()
        self.agent._ovs_idl.stop.assert_called_once_with()
        mock_super_stop.assert_called_once_with(False)
