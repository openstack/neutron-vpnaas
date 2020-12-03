# Copyright 2020, SysEleven GbmH
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
from neutron.api.rpc.agentnotifiers import utils as ag_utils
from neutron_lib import rpc as n_rpc
import oslo_messaging

from neutron_vpnaas.services.vpn.common import topics

# default messaging timeout is 60 sec, so 2 here is chosen to not block API
# call for more than 2 minutes
AGENT_NOTIFY_MAX_ATTEMPTS = 2


class VPNAgentNotifyAPI(object):
    """API for plugin to notify VPN agent."""

    def __init__(self, topic=topics.IPSEC_AGENT_TOPIC):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def agent_updated(self, context, admin_state_up, host):
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, 'agent_updated',
                   payload={'admin_state_up': admin_state_up})

    def vpnservice_removed_from_agent(self, context, router_id, host):
        """Notify agent about removed VPN service(s) of a router."""
        cctxt = self.client.prepare(server=host)
        cctxt.cast(context, 'vpnservice_removed_from_agent',
                   router_id=router_id)

    def vpnservice_added_to_agent(self, context, router_ids, host):
        """Notify agent about added VPN service(s) of router(s)."""
        # need to use call here as we want to be sure agent received
        # notification and router will not be "lost". However using call()
        # itself is not a guarantee, calling code should handle exceptions and
        # retry
        cctxt = self.client.prepare(server=host)
        call = ag_utils.retry(cctxt.call, AGENT_NOTIFY_MAX_ATTEMPTS)
        call(context, 'vpnservice_added_to_agent', router_ids=router_ids)
