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
from oslo_log import log as logging

from neutron_vpnaas.services.vpn import vyatta_vpn_service


LOG = logging.getLogger(__name__)

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
        self.event_observers.add(self.service)
        self.devices = self.service.load_device_drivers(host)

    def _router_added(self, router_id, router):
        super(VyattaVPNAgent, self)._router_added(router_id, router)
        for device in self.devices:
            device.create_router(router_id)

    def _router_removed(self, router_id):
        for device in self.devices:
            device.destroy_router(router_id)
        super(VyattaVPNAgent, self)._router_removed(router_id)

    def _process_router_if_compatible(self, router):
        super(VyattaVPNAgent, self)._process_router_if_compatible(router)
        for device in self.devices:
            device.sync(self.context, None)


def main():
    entry.main(
        manager='neutron_vpnaas.services.vpn.vyatta_agent.VyattaVPNAgent')
