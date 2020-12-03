#    (c) Copyright 2016 IBM Corporation, All Rights Reserved.
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

import abc
import random

from neutron.extensions import availability_zone as az_ext
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

from neutron_vpnaas.extensions import vpn_agentschedulers

LOG = logging.getLogger(__name__)


class VPNScheduler(object, metaclass=abc.ABCMeta):
    @property
    def l3_plugin(self):
        return directory.get_plugin(plugin_constants.L3)

    @abc.abstractmethod
    def schedule(self, plugin, context, router_id,
                 candidates=None, hints=None):
        """Schedule the router to an active VPN agent.

        Schedule the router only if it is not already scheduled.
        """
        pass

    def _get_unscheduled_routers(self, context, plugin, router_ids=None):
        """Get the list of routers with VPN services to be scheduled.

        If router IDs are omitted, look for all unscheduled routers.

        :param context: the context
        :param plugin: the core plugin
        :param router_ids: the list of routers to be checked for scheduling
        :returns: the list of routers to be scheduled
        """
        unscheduled_router_ids = plugin.get_unscheduled_vpn_routers(
            context, router_ids=router_ids)
        if unscheduled_router_ids:
            return self.l3_plugin.get_routers(
                context, filters={'id': unscheduled_router_ids})
        return []

    def _get_routers_can_schedule(self, context, plugin, routers, vpn_agent):
        """Get the subset of routers whose VPN services can be scheduled on
        the VPN agent.
        """
        # Assuming that only an active, enabled VPN agent is passed in,
        # all routers can be scheduled to it
        return routers

    def auto_schedule_routers(self, plugin, context, vpn_agent):
        """Schedule non-hosted routers to a VPN agent.

        :returns: True if routers have been successfully assigned to the agent
        """
        unscheduled_routers = self._get_unscheduled_routers(context, plugin)

        target_routers = self._get_routers_can_schedule(
            context, plugin, unscheduled_routers, vpn_agent)
        if not target_routers:
            if unscheduled_routers:
                LOG.warning('No unscheduled routers compatible with VPN agent '
                            'configuration on host %s', vpn_agent['host'])
            return []

        self._bind_routers(context, plugin, target_routers, vpn_agent)
        return [router['id'] for router in target_routers]

    def _get_candidates(self, plugin, context, sync_router):
        """Return VPN agents where a router could be scheduled."""
        active_vpn_agents = plugin.get_vpn_agents(context, active=True)
        if not active_vpn_agents:
            LOG.warning('No active VPN agents')
        return active_vpn_agents

    def _bind_routers(self, context, plugin, routers, vpn_agent):
        for router in routers:
            plugin.create_router_to_agent_binding(
                context, router['id'], vpn_agent['id'])

    def _schedule_router(self, plugin, context, router_id,
                         candidates=None):
        current_vpn_agents = plugin.get_vpn_agents_hosting_routers(
            context, [router_id])
        if current_vpn_agents:
            chosen_agent = current_vpn_agents[0]
            LOG.debug('VPN service of router %(router_id)s has already '
                      'been hosted by VPN agent %(agent_id)s',
                      {'router_id': router_id,
                      'agent_id': chosen_agent})
            return chosen_agent

        sync_router = self.l3_plugin.get_router(context, router_id)
        candidates = candidates or self._get_candidates(
            plugin, context, sync_router)
        if not candidates:
            raise vpn_agentschedulers.RouterReschedulingFailed(
                router_id=router_id)

        chosen_agent = self._choose_vpn_agent(plugin, context, candidates)
        if plugin.create_router_to_agent_binding(context, router_id,
                                                 chosen_agent['id']):
            return chosen_agent

    @abc.abstractmethod
    def _choose_vpn_agent(self, plugin, context, candidates):
        """Choose an agent from candidates based on a specific policy."""
        pass


class ChanceScheduler(VPNScheduler):
    """Randomly allocate an VPN agent for a router."""

    def schedule(self, plugin, context, router_id,
                 candidates=None):
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _choose_vpn_agent(self, plugin, context, candidates):
        return random.choice(candidates)


class LeastRoutersScheduler(VPNScheduler):
    """Allocate to an VPN agent with the least number of routers bound."""

    def schedule(self, plugin, context, router_id,
                 candidates=None):
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _choose_vpn_agent(self, plugin, context, candidates):
        candidates_dict = {c['id']: c for c in candidates}
        chosen_agent_id = plugin.get_vpn_agent_with_min_routers(
            context, candidates_dict.keys())
        return candidates_dict[chosen_agent_id]


class AZLeastRoutersScheduler(LeastRoutersScheduler):
    """Availability zone aware scheduler."""
    def _get_az_hints(self, router):
        return (router.get(az_ext.AZ_HINTS) or
                cfg.CONF.default_availability_zones)

    def _get_routers_can_schedule(self, context, plugin, routers, vpn_agent):
        """Overwrite VPNScheduler's method to filter by availability zone."""
        target_routers = []
        for r in routers:
            az_hints = self._get_az_hints(r)
            if not az_hints or vpn_agent['availability_zone'] in az_hints:
                target_routers.append(r)

        if not target_routers:
            return

        return super()._get_routers_can_schedule(
            context, plugin, target_routers, vpn_agent)

    def _get_candidates(self, plugin, context, sync_router):
        """Overwrite VPNScheduler's method to filter by availability zone."""
        all_candidates = super()._get_candidates(plugin, context, sync_router)

        candidates = []
        az_hints = self._get_az_hints(sync_router)
        for agent in all_candidates:
            if not az_hints or agent['availability_zone'] in az_hints:
                candidates.append(agent)

        return candidates
