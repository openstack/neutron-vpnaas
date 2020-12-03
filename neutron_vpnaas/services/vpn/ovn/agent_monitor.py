# Copyright 2023 SysEleven GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron_vpnaas.services.vpn.common import constants


class OVNVPNAgent(neutron_agent.NeutronAgent):
    agent_type = constants.AGENT_TYPE_VPN
    binary = "neutron-ovn-vpn-agent"

    @property
    def nb_cfg(self):
        return int(self.chassis_private.external_ids.get(
            constants.OVN_AGENT_VPN_SB_CFG_KEY, 0))

    @staticmethod
    def id_from_chassis_private(chassis_private):
        return chassis_private.external_ids.get(
            constants.OVN_AGENT_VPN_ID_KEY)

    @property
    def agent_id(self):
        return self.id_from_chassis_private(self.chassis_private)

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            constants.OVN_AGENT_VPN_DESC_KEY, '')


class ChassisVPNAgentWriteEvent(ovsdb_monitor.ChassisAgentEvent):
    events = (ovsdb_monitor.BaseEvent.ROW_CREATE,
              ovsdb_monitor.BaseEvent.ROW_UPDATE)

    @staticmethod
    def _vpnagent_nb_cfg(row):
        return int(
            row.external_ids.get(constants.OVN_AGENT_VPN_SB_CFG_KEY, -1))

    @staticmethod
    def agent_id(row):
        return row.external_ids.get(constants.OVN_AGENT_VPN_ID_KEY)

    def match_fn(self, event, row, old=None):
        if not self.agent_id(row):
            # Don't create a cached object with an agent_id of 'None'
            return False
        if event == self.ROW_CREATE:
            return True
        try:
            return self._vpnagent_nb_cfg(row) != self._vpnagent_nb_cfg(old)
        except (AttributeError, KeyError):
            return False

    def run(self, event, row, old):
        neutron_agent.AgentCache().update(constants.AGENT_TYPE_VPN, row,
                                          clear_down=True)


class OVNVPNAgentMonitor(object):
    def watch_agent_events(self):
        l3_plugin = directory.get_plugin(plugin_constants.L3)
        sb_ovn = l3_plugin._sb_ovn
        if sb_ovn:
            idl = sb_ovn.ovsdb_connection.idl
            if isinstance(idl, ovsdb_monitor.OvnSbIdl):
                idl.notify_handler.watch_event(
                    ChassisVPNAgentWriteEvent(idl.driver))
