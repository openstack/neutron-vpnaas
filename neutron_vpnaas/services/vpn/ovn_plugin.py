#    (c) Copyright 2016 IBM Corporation
#    (c) Copyright 2023 SysEleven GmbH
#    All Rights Reserved.
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_config import cfg
from oslo_utils import importutils

from neutron_vpnaas.api.rpc.agentnotifiers import vpn_rpc_agent_api as nfy_api
from neutron_vpnaas.db.vpn import vpn_agentschedulers_db as agent_db
from neutron_vpnaas.db.vpn.vpn_db import VPNPluginDb
from neutron_vpnaas.db.vpn import vpn_ext_gw_db
from neutron_vpnaas.services.vpn.common import constants
from neutron_vpnaas.services.vpn.ovn import agent_monitor
from neutron_vpnaas.services.vpn.plugin import VPNDriverPlugin


class VPNOVNPlugin(VPNPluginDb,
                   vpn_ext_gw_db.VPNExtGWPlugin_db,
                   agent_db.AZVPNAgentSchedulerDbMixin,
                   agent_monitor.OVNVPNAgentMonitor):
    """Implementation of the VPN Service Plugin.

    This class manages the workflow of VPNaaS request/response.
    Most DB related works are implemented in class
    vpn_db.VPNPluginDb.
    """
    def __init__(self):
        self.vpn_scheduler = importutils.import_object(
            cfg.CONF.vpn_scheduler_driver)
        self.add_periodic_vpn_agent_status_check()
        self.agent_notifiers[constants.AGENT_TYPE_VPN] = \
            nfy_api.VPNAgentNotifyAPI()
        super().__init__()
        registry.subscribe(self.post_fork_initialize,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def check_router_in_use(self, context, router_id):
        pass

    def post_fork_initialize(self, resource, event, trigger, payload=None):
        self.watch_agent_events()

    def vpn_router_agent_binding_changed(self, context, router_id, host):
        pass

    supported_extension_aliases = ["vpnaas",
                                   "vpn-endpoint-groups",
                                   "service-type",
                                   "vpn-agent-scheduler"]
    path_prefix = "/vpn"


class VPNOVNDriverPlugin(VPNOVNPlugin, VPNDriverPlugin):
    def vpn_router_agent_binding_changed(self, context, router_id, host):
        super().vpn_router_agent_binding_changed(context, router_id, host)
        filters = {'router_id': [router_id]}
        vpnservices = self.get_vpnservices(context, filters=filters)
        for vpnservice in vpnservices:
            driver = self._get_driver_for_vpnservice(context, vpnservice)
            driver.update_port_bindings(context, router_id, host)
