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

from neutron_vpnaas.agent.ovn.vpn import ovsdb
from neutron_vpnaas.tests import base


class TestVPNAgentOvnSbIdl(base.BaseTestCase):

    def _make_idl(self):
        with mock.patch.object(ovsdb.VPNAgentOvnSbIdl, '__init__',
                               return_value=None):
            return ovsdb.VPNAgentOvnSbIdl()

    def test_stop(self):
        sb_idl = self._make_idl()
        sb_idl.ovsdb_connection = mock.Mock()
        sb_idl.stop()
        sb_idl.ovsdb_connection.stop.assert_called_once_with()

    def test_stop_without_connection(self):
        self._make_idl().stop()


class TestVPNAgentOvsIdl(base.BaseTestCase):

    def test_stop(self):
        ovs_idl = ovsdb.VPNAgentOvsIdl()
        ovs_idl.ovsdb_connection = mock.Mock()
        ovs_idl.stop()
        ovs_idl.ovsdb_connection.stop.assert_called_once_with()

    def test_stop_without_connection(self):
        ovsdb.VPNAgentOvsIdl().stop()
