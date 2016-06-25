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
from neutron.agent import rpc as agent_rpc
from neutron.common import constants as l3_constants
from neutron.common import topics

from neutron import context as n_context
from neutron import manager

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from neutron._i18n import _, _LE, _LI, _LW

from neutron_lib import constants as lib_const

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


class VPNAgent(manager.Manager):
    """VPNAgent class which can handle vpn service drivers."""
    def __init__(self, host, conf=None):
        #super(VPNAgent, self).__init__(host=host, conf=conf)
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF

        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.context = n_context.get_admin_context_without_session()

        self.agent_state = {
            'binary': 'neutron-vpn-agent',
            'host': host,
            'availability_zone': self.conf.AGENT.availability_zone,
            'topic': topics.L3_AGENT,
            'configurations': {
                'agent_mode': self.conf.agent_mode,
                #'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                    self.conf.handle_internal_only_routers,
                'external_network_bridge': self.conf.external_network_bridge,
                'gateway_external_network_id':
                    self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver,
                'log_agent_heartbeats': self.conf.AGENT.log_agent_heartbeats},
            'start_flag': True,
            'agent_type': lib_const.AGENT_TYPE_L3}

        report_interval = self.conf.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

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

    def _report_state(self):
        try:
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == l3_constants.AGENT_REVIVED:
                LOG.info(_LI('Agent has just been revived. '
                             'Doing a full sync.'))

            self.agent_state.pop('start_flag', None)

        except AttributeError:
            # This means the server does not support report_state
            LOG.warning(_LW("Neutron server does not support state report. "
                            "State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        LOG.info(_LI("agent_updated by server side %s!"), payload)

    def after_start(self):
        #TBD, need to add process router loop for vpnaas
        #eventlet.spawn_n(self._process_routers_loop)

        LOG.info(_LI("VPN agent started"))
        # Do the report state before we do the first full sync.
        self._report_state()


def main():
    entry.main(manager='neutron_vpnaas.services.vpn.agent.VPNAgent')
