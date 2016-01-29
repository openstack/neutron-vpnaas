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


from neutron.agent.l3 import agent as l3_agent
from neutron.agent import l3_agent as entry
from oslo_config import cfg

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn import vpn_service

vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron_vpnaas.services.vpn.device_drivers.'
                 'ipsec.OpenSwanDriver'],
        sample_default=['neutron_vpnaas.services.vpn.device_drivers.ipsec.'
                       'OpenSwanDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'cisco_ipsec.CiscoCsrIPsecDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'vyatta_ipsec.VyattaIPSecDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'strongswan_ipsec.StrongSwanDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'fedora_strongswan_ipsec.FedoraStrongSwanDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'libreswan_ipsec.LibreSwanDriver'],
        help=_("The vpn device drivers Neutron will use")),
]
cfg.CONF.register_opts(vpn_agent_opts, 'vpnagent')


class VPNAgent(l3_agent.L3NATAgentWithStateReport):
    """VPNAgent class which can handle vpn service drivers."""
    def __init__(self, host, conf=None):
        super(VPNAgent, self).__init__(host=host, conf=conf)
        self.agent_state['binary'] = 'neutron-vpn-agent'
        self.service = vpn_service.VPNService(self)
        self.device_drivers = self.service.load_device_drivers(host)

    def process_state_change(self, router_id, state):
        """Enable the vpn process when router transitioned to master.

           And disable vpn process for backup router.
        """
        for device_driver in self.device_drivers:
            if router_id in device_driver.processes:
                process = device_driver.processes[router_id]
                if state == 'master':
                    process.enable()
                else:
                    process.disable()

    def enqueue_state_change(self, router_id, state):
        """Handle HA router state changes for vpn process"""
        self.process_state_change(router_id, state)
        super(VPNAgent, self).enqueue_state_change(router_id, state)


def main():
    entry.main(manager='neutron_vpnaas.services.vpn.agent.VPNAgent')
