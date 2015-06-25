# Copyright 2015 Brocade Communications System, Inc.
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

from neutron.agent.common import config as agent_config
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_vpnaas.services.vpn import vyatta_vpn_service
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid

FAKE_ROUTER_ID = _uuid()


class TestVyattaVPNService(base.BaseTestCase):

    def setUp(self):
        super(TestVyattaVPNService, self).setUp()
        self.conf = cfg.CONF
        agent_config.register_root_helper(self.conf)
        self.ri_kwargs = {'root_helper': self.conf.AGENT.root_helper,
                          'agent_conf': self.conf,
                          'interface_driver': mock.sentinel.interface_driver}
        self.agent = mock.Mock()
        self.vyatta_service = vyatta_vpn_service.VyattaVPNService(
            self.agent)
        self.l3_agent = self.vyatta_service.l3_agent

    def test_get_router_client(self):
        self.vyatta_service.get_router_client(FAKE_ROUTER_ID)

        self.l3_agent.get_router_client.assert_called_once_with(FAKE_ROUTER_ID)

    def test_get_router(self):
        self.vyatta_service.get_router(FAKE_ROUTER_ID)

        self.l3_agent.get_router.assert_called_once_with(FAKE_ROUTER_ID)
