# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# Copyright 2017, Fujitsu Limited
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


from neutron_lib.agent import l3_extension
from oslo_config import cfg
from oslo_log import log as logging

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn import vpn_service

LOG = logging.getLogger(__name__)

vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron_vpnaas.services.vpn.device_drivers.'
                 'ipsec.OpenSwanDriver'],
        sample_default=['neutron_vpnaas.services.vpn.device_drivers.ipsec.'
                       'OpenSwanDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'strongswan_ipsec.StrongSwanDriver, '
                       'neutron_vpnaas.services.vpn.device_drivers.'
                       'libreswan_ipsec.LibreSwanDriver'],
        help=_("The vpn device drivers Neutron will use")),
]
cfg.CONF.register_opts(vpn_agent_opts, 'vpnagent')


class VPNAgent(l3_extension.L3AgentExtension):
    """VPNaaS Agent support to be used by Neutron L3 agent."""

    def initialize(self, connection, driver_type):
        LOG.debug("Loading VPNaaS")

    def consume_api(self, agent_api):
        LOG.debug("Loading consume_api for VPNaaS")
        self.agent_api = agent_api

    def __init__(self, host, conf):
        LOG.debug("Initializing VPNaaS agent")
        self.agent_api = None
        self.conf = conf
        self.host = host
        self.service = vpn_service.VPNService(self)
        self.device_drivers = self.service.load_device_drivers(self.host)

    def add_router(self, context, data):
        """Handles router add event"""
        ri = self.agent_api.get_router_info(data['id'])
        if ri is not None:
            for device_driver in self.device_drivers:
                device_driver.create_router(ri)
                device_driver.sync(context, [ri.router])
        else:
            LOG.debug("Router %s was concurrently deleted while "
                      "creating VPN for it", data['id'])

    def update_router(self, context, data):
        """Handles router update event"""
        for device_driver in self.device_drivers:
            device_driver.sync(context, [data])

    def delete_router(self, context, data):
        """Handles router delete event"""
        for device_driver in self.device_drivers:
            device_driver.destroy_router(data['id'])

    def ha_state_change(self, context, data):
        """Enable the vpn process when router transitioned to master.

        And disable vpn process for backup router.
        """
        router_id = data['router_id']
        state = data['state']
        for device_driver in self.device_drivers:
            if router_id in device_driver.processes:
                # NOTE(mnaser): We need to update the router object so it has
                #               the new HA state so we can do status updates.
                device_driver.routers[router_id].ha_state = state

                process = device_driver.processes[router_id]
                if state in ('master', 'primary'):
                    process.enable()
                else:
                    process.disable()

    def update_network(self, context, data):
        pass


class L3WithVPNaaS(VPNAgent):

    def __init__(self, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        super(L3WithVPNaaS, self).__init__(
            host=self.conf.host, conf=self.conf)
