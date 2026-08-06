# Copyright 2017 Red Hat, Inc.
# Copyright 2023 SysEleven GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid

from neutron.agent.linux import external_process
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config
from oslo_log import log as logging
from oslo_service import service
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import vlog

from neutron_vpnaas.agent.ovn.vpn import ovsdb
from neutron_vpnaas.services.vpn.common import constants
from neutron_vpnaas.services.vpn import vpn_service

LOG = logging.getLogger(__name__)

OVN_VPNAGENT_UUID_NAMESPACE = uuid.UUID('e1ce3b12-b1e0-4c81-ba27-07c0fec9c12b')


class ChassisPrivateCreateEvent(row_event.RowEvent):
    """Row create event - Chassis_Private name == our_chassis.

    On connection, we get a dump of all chassis so if we catch a creation
    of our own chassis it has to be a reconnection. In this case, we need
    to do a full sync to make sure that we capture all changes while the
    connection to OVSDB was down.
    """

    def __init__(self, vpn_agent):
        self.agent = vpn_agent
        self.first_time = True
        events = (self.ROW_CREATE,)
        super().__init__(
            events, 'Chassis_Private', (('name', '=', self.agent.chassis),))
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        if self.first_time:
            self.first_time = False
        else:
            # NOTE(lucasagomes): Re-register the ovn vpn agent
            # with the local chassis in case its entry was re-created
            # (happens when restarting the ovn-controller)
            self.agent.register_vpn_agent()
            self.agent.update_vpn_sb_cfg_key()
            LOG.info("Connection to OVSDB established, doing a full sync")
            self.agent.sync()


class SbGlobalUpdateEvent(row_event.RowEvent):
    """Row update event on SB_Global table."""

    def __init__(self, vpn_agent):
        self.agent = vpn_agent
        table = 'SB_Global'
        events = (self.ROW_UPDATE,)
        super().__init__(events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        self.agent.update_vpn_sb_cfg_key(nb_cfg=row.nb_cfg)


class OvnVpnAgent(service.Service):
    def __init__(self, conf):
        super().__init__()
        self.conf = conf
        vlog.use_python_logger(max_level=config.get_ovn_ovsdb_log_level())
        self._process_monitor = None
        self.service = None
        self.device_drivers = None

    def _load_config(self):
        self.chassis = self._get_own_chassis_name()
        try:
            self.chassis_id = uuid.UUID(self.chassis)
        except ValueError:
            # OVS system-id could be a non UUID formatted string.
            self.chassis_id = uuid.uuid5(OVN_VPNAGENT_UUID_NAMESPACE,
                                         self.chassis)
        LOG.debug("Loaded chassis name %s (UUID: %s).",
                  self.chassis, self.chassis_id)

    def start(self):
        super().start()
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='ipsec')
        self.service = vpn_service.VPNService(self)
        self.device_drivers = self.service.load_device_drivers(self.conf.host)
        self.ovs_idl = ovsdb.VPNAgentOvsIdl().start()
        self._load_config()

        tables = ('SB_Global', 'Chassis', 'Chassis_Private')
        events = (SbGlobalUpdateEvent(self),
                  ChassisPrivateCreateEvent(self),
                  )
        self.sb_idl = ovsdb.VPNAgentOvnSbIdl(
            chassis=self.chassis, tables=tables,
            events=events).start()

        # Register the agent with its corresponding Chassis and set the
        # initial sb_cfg key so the server-side AgentCache sees the agent
        # as alive immediately.
        self.register_vpn_agent()
        self.update_vpn_sb_cfg_key()

        # Do the initial sync.
        self.sync()

    def sync(self):
        for driver in self.device_drivers:
            driver.sync(driver.context, [])

    @ovn_utils.retry()
    def register_vpn_agent(self):
        # NOTE(lucasagomes): db_add() will not overwrite the UUID if
        # it's already set.
        agent_id = uuid.uuid5(self.chassis_id, 'vpn_agent')
        ext_ids = {constants.OVN_AGENT_VPN_ID_KEY: str(agent_id)}
        self.sb_idl.db_add('Chassis_Private', self.chassis, 'external_ids',
                           ext_ids).execute(check_error=True)

    def update_vpn_sb_cfg_key(self, nb_cfg=None):
        nb_cfg = (nb_cfg or
                  self.sb_idl.db_get('Chassis_Private', self.chassis,
                                     'nb_cfg').execute())
        external_ids = {constants.OVN_AGENT_VPN_SB_CFG_KEY: str(nb_cfg)}
        self.sb_idl.db_set(
            'Chassis_Private', self.chassis,
            ('external_ids', external_ids)).execute(check_error=True)

    def _get_own_chassis_name(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        As long as ovn-controller is running on this node, the key is
        guaranteed to exist and will include the chassis name.
        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['system-id']
