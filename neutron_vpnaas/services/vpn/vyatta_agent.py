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
#

from networking_brocade.vyatta.common import l3_agent as vyatta_l3
from neutron.agent import l3_agent as entry
from oslo_config import cfg

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn import vyatta_vpn_service


vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron_vpnaas.services.vpn.device_drivers.'
                 'vyatta_ipsec.VyattaIPSecDriver'],
        help=_("The vpn device drivers Neutron will use")),
]
cfg.CONF.register_opts(vpn_agent_opts, 'vpnagent')


class VyattaVPNAgent(vyatta_l3.L3AgentMiddleware):
    def __init__(self, host, conf=None):
        super(VyattaVPNAgent, self).__init__(host, conf)
        self.service = vyatta_vpn_service.VyattaVPNService(self)
        self.device_drivers = self.service.load_device_drivers(host)


def main():
    entry.main(
        manager='neutron_vpnaas.services.vpn.vyatta_agent.VyattaVPNAgent')
