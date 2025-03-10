# Copyright 2018, Fujitsu Vietnam Ltd.
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

from neutron_lib import rpc as n_rpc

from neutron_vpnaas.services.vpn.service_drivers import base_ipsec
from neutron_vpnaas.services.vpn.service_drivers import ipsec_validator


IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'


class DummyIPsecVPNDriver(base_ipsec.BaseIPsecVPNDriver):
    """Dummy VPN Service Driver class for IPsec."""

    def __init__(self, service_plugin):
        super().__init__(
            service_plugin,
            ipsec_validator.IpsecVpnValidator(self))

    def create_rpc_conn(self):
        self.endpoints = [base_ipsec.IPsecVpnDriverCallBack(self)]
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(
            'dummy_ipsec_driver', self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = base_ipsec.IPsecVpnAgentApi(
            'dummy_ipsec_agent', BASE_IPSEC_VERSION, self)
