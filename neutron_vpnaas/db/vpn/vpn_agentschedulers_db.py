# Copyright (c) 2013 OpenStack Foundation.
# Copyright (c) 2023 SysEleven GmbH.
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

import random

from neutron.extensions import router_availability_zone as router_az
from neutron import worker as neutron_worker
from neutron_lib import context as ncontext
from neutron_lib.db import api as db_api
from neutron_lib.db import model_base
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging
import sqlalchemy as sa
from sqlalchemy import func

from neutron_vpnaas._i18n import _
from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.extensions import vpn_agentschedulers
from neutron_vpnaas.services.vpn.common.constants import AGENT_TYPE_VPN


LOG = logging.getLogger(__name__)

VPN_AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('vpn_scheduler_driver',
               default='neutron_vpnaas.scheduler.vpn_agent_scheduler'
                       '.LeastRoutersScheduler',
               help=_('Driver to use for scheduling '
                      'router to a VPN agent')),
    cfg.BoolOpt('vpn_auto_schedule', default=True,
                help=_('Allow auto scheduling of routers to VPN agent.')),
    cfg.BoolOpt('allow_automatic_vpnagent_failover', default=False,
                help=_('Automatically reschedule routers from offline VPN '
                       'agents to online VPN agents.')),
]

cfg.CONF.register_opts(VPN_AGENTS_SCHEDULER_OPTS)


class RouterVPNAgentBinding(model_base.BASEV2):
    """Represents binding between neutron routers and VPN agents."""

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("routers.id", ondelete='CASCADE'),
                          primary_key=True,
                          unique=True,
                          nullable=False)
    vpn_agent_id = sa.Column(sa.String(36), primary_key=True, nullable=False)


class VPNAgentSchedulerDbMixin(
    vpn_agentschedulers.VPNAgentSchedulerPluginBase):
    """Mixin class to add VPN agent scheduler extension to plugins
    using the VPN agent.
    """

    vpn_scheduler = None
    agent_notifiers = {}

    @property
    def l3_plugin(self):
        return directory.get_plugin(plugin_const.L3)

    @property
    def core_plugin(self):
        return directory.get_plugin()

    def add_periodic_vpn_agent_status_check(self):
        if not cfg.CONF.allow_automatic_vpnagent_failover:
            LOG.info("Skipping periodic VPN agent status check because "
                     "automatic rescheduling is disabled.")
            return

        interval = max(cfg.CONF.agent_down_time // 2, 1)
        # add random initial delay to allow agents to check in after the
        # neutron server first starts. random to offset multiple servers
        initial_delay = random.randint(interval, interval * 2)

        check_worker = neutron_worker.PeriodicWorker(
            self.reschedule_vpnservices_from_down_agents,
            interval, initial_delay)
        self.add_worker(check_worker)

    def reschedule_vpnservices_from_down_agents(self):
        """Reschedule VPN services from down VPN agents.

        VPN services are scheduled per router.
        """
        context = ncontext.get_admin_context()
        try:
            down_bindings = self.get_down_router_bindings(context)

            agents_back_online = set()
            for binding in down_bindings:
                if binding.vpn_agent_id in agents_back_online:
                    continue
                agent = self.core_plugin.get_agent(context,
                                                   binding.vpn_agent_id)
                if agent['alive']:
                    agents_back_online.add(binding.vpn_agent_id)
                    continue

                LOG.warning(
                    "Rescheduling vpn services for router %(router)s from "
                    "agent %(agent)s because the agent is not alive.",
                    {'router': binding.router_id,
                     'agent': binding.vpn_agent_id})
                try:
                    self.reschedule_router(context, binding.router_id, agent)
                except (vpn_agentschedulers.RouterReschedulingFailed,
                        oslo_messaging.RemoteError):
                    # Catch individual rescheduling errors here
                    # so one broken one doesn't stop the iteration.
                    LOG.exception("Failed to reschedule vpn services for "
                                  "router %s", binding.router_id)
        except Exception:
            # we want to be thorough and catch whatever is raised
            # to avoid loop abortion
            LOG.exception("Exception encountered during vpn service "
                          "rescheduling.")

    @db_api.CONTEXT_READER
    def get_down_router_bindings(self, context):
        vpn_agents = self.get_vpn_agents(context, active=False)
        if not vpn_agents:
            return []
        vpn_agent_ids = [vpn_agent['id'] for vpn_agent in vpn_agents]

        query = context.session.query(RouterVPNAgentBinding)
        query = query.filter(
            RouterVPNAgentBinding.vpn_agent_id.in_(vpn_agent_ids))
        return query.all()

    def validate_agent_router_combination(self, context, agent, router):
        """Validate if the router can be correctly assigned to the agent.

        :raises: InvalidVPNAgent if attempting to assign router to an
          unsuitable agent (disabled, type != VPN, incompatible configuration)
        """
        if agent['agent_type'] != AGENT_TYPE_VPN:
            raise vpn_agentschedulers.InvalidVPNAgent(id=agent['id'])

    @db_api.CONTEXT_READER
    def check_agent_router_scheduling_needed(self, context, agent, router):
        """Check if the scheduling of router's VPN services is needed.

        :raises: RouterHostedByVPNAgent if router is already assigned
          to a different agent.
        :returns: True if scheduling is needed, otherwise False
        """
        router_id = router['id']
        agent_id = agent['id']
        query = context.session.query(RouterVPNAgentBinding)
        bindings = query.filter_by(router_id=router_id).all()
        if not bindings:
            return True
        for binding in bindings:
            if binding.vpn_agent_id == agent_id:
                # router already bound to the agent we need
                return False
        # Router is already bound to some agent
        raise vpn_agentschedulers.RouterHostedByVPNAgent(
            router_id=router_id,
            agent_id=bindings[0].vpn_agent_id)

    def create_router_to_agent_binding(self, context, router_id, agent_id):
        """Create router to VPN agent binding."""
        try:
            with db_api.CONTEXT_WRITER.using(context):
                binding = RouterVPNAgentBinding()
                binding.vpn_agent_id = agent_id
                binding.router_id = router_id
                context.session.add(binding)
        except db_exc.DBDuplicateEntry:
            LOG.debug('VPN service of router %(router_id)s has already been '
                      'scheduled to a VPN agent.',
                      {'router_id': router_id})
            return False
        except db_exc.DBReferenceError:
            LOG.debug('Router %s has already been removed '
                      'by concurrent operation', router_id)
            return False

        LOG.debug('VPN service of router %(router_id)s is scheduled to '
                  'VPN agent %(agent_id)s',
                  {'router_id': router_id, 'agent_id': agent_id})
        return True

    def add_router_to_vpn_agent(self, context, agent_id, router_id):
        """Add a VPN agent to host VPN services of a router."""
        with db_api.CONTEXT_WRITER.using(context):
            router = self.l3_plugin.get_router(context, router_id)
            agent = self.core_plugin.get_agent(context, agent_id)
            self.validate_agent_router_combination(context, agent, router)
            if not self.check_agent_router_scheduling_needed(
                    context, agent, router):
                return
        try:
            success = self.create_router_to_agent_binding(
                context, router['id'], agent['id'])
        except db_exc.DBError:
            success = False

        if not success:
            raise vpn_agentschedulers.RouterSchedulingFailed(
                router_id=router_id, agent_id=agent_id)

        # notify agent
        vpn_notifier = self.agent_notifiers.get(AGENT_TYPE_VPN)
        if vpn_notifier:
            vpn_notifier.vpnservice_added_to_agent(
                context, [router_id], agent['host'])

        # update port binding
        self.vpn_router_agent_binding_changed(
            context, router_id, agent['host'])

    def remove_router_from_vpn_agent(self, context, agent_id, router_id):
        """Remove the router from VPN agent.

        After removal, the VPN service(s) of the router will be non-hosted
        until there is an update which leads to re-schedule or the router is
        added to another agent manually.
        """
        agent = self.core_plugin.get_agent(context, agent_id)

        self._unbind_router(context, router_id, agent_id)

        vpn_notifier = self.agent_notifiers.get(AGENT_TYPE_VPN)
        if vpn_notifier:
            vpn_notifier.vpnservice_removed_from_agent(
                context, router_id, agent['host'])

    def _unbind_router(self, context, router_id, agent_id):
        with db_api.CONTEXT_WRITER.using(context):
            query = context.session.query(RouterVPNAgentBinding)
            query = query.filter(
                RouterVPNAgentBinding.router_id == router_id,
                RouterVPNAgentBinding.vpn_agent_id == agent_id)
            return query.delete()

    def reschedule_router(self, context, router_id, cur_agent):
        """Reschedule router to a new VPN agent

        Remove the router from the agent currently hosting it and
        schedule it again
        """
        with db_api.CONTEXT_WRITER.using(context):
            deleted = self._unbind_router(context, router_id, cur_agent['id'])
            if not deleted:
                # If nothing was deleted, the binding didn't exist anymore
                # because some other server deleted the binding concurrently.
                # Stop here.
                return

            new_agent = self.schedule_router(context, router_id)
            if not new_agent:
                # No new_agent means that another server scheduled the
                # router concurrently. Don't raise RouterReschedulingFailed.
                return

        self._notify_agents_router_rescheduled(context, router_id,
                                               cur_agent, new_agent)
        # update port binding
        self.vpn_router_agent_binding_changed(
            context, router_id, new_agent['host'])

    def _notify_agents_router_rescheduled(self, context, router_id,
                                          old_agent, new_agent):
        vpn_notifier = self.agent_notifiers.get(AGENT_TYPE_VPN)
        if not vpn_notifier:
            return

        old_host = old_agent['host']
        new_host = new_agent['host']
        if old_host != new_host:
            vpn_notifier.vpnservice_removed_from_agent(
                context, router_id, old_host)

            try:
                vpn_notifier.vpnservice_added_to_agent(
                    context, [router_id], new_host)
            except oslo_messaging.MessagingException:
                self._unbind_router(context, router_id, new_agent['id'])
                raise vpn_agentschedulers.RouterReschedulingFailed(
                    router_id=router_id)

    @db_api.CONTEXT_READER
    def list_routers_on_vpn_agent(self, context, agent_id):
        query = context.session.query(RouterVPNAgentBinding.router_id)
        query = query.filter(RouterVPNAgentBinding.vpn_agent_id == agent_id)

        router_ids = [item[0] for item in query]
        if router_ids:
            return {'routers':
                    self.l3_plugin.get_routers(context,
                    filters={'id': router_ids})}
        else:
            # Exception will be thrown if the requested agent does not exist.
            self.core_plugin.get_agent(context, agent_id)
            return {'routers': []}

    @db_api.CONTEXT_READER
    def get_vpn_agents_hosting_routers(self, context, router_ids, active=None):
        if not router_ids:
            return []
        query = context.session.query(RouterVPNAgentBinding)
        query = query.filter(RouterVPNAgentBinding.router_id.in_(router_ids))

        filters = {'id': [binding.vpn_agent_id for binding in query]}
        vpn_agents = self.core_plugin.get_agents(context, filters=filters)
        if active is not None:
            vpn_agents = [agent
                          for agent in vpn_agents
                          if agent['alive'] == active]
        return vpn_agents

    def list_vpn_agents_hosting_router(self, context, router_id):
        vpn_agents = self.get_vpn_agents_hosting_routers(context, [router_id])
        return {'agents': vpn_agents}

    def get_vpn_agents(self, context, active=None, host=None):
        filters = {'agent_type': [AGENT_TYPE_VPN]}
        if host is not None:
            filters['host'] = [host]
        vpn_agents = self.core_plugin.get_agents(context, filters=filters)
        if active is None:
            return vpn_agents
        else:
            return [vpn_agent
                    for vpn_agent in vpn_agents
                    if vpn_agent['alive'] == active]

    def get_vpn_agent_on_host(self, context, host, active=None):
        agents = self.get_vpn_agents(context, active=active, host=host)
        if agents:
            return agents[0]

    @db_api.CONTEXT_READER
    def get_unscheduled_vpn_routers(self, context, router_ids=None):
        """Get IDs of routers which have unscheduled VPN services."""
        query = context.session.query(vpn_models.VPNService.router_id)
        query = query.outerjoin(
            RouterVPNAgentBinding,
            vpn_models.VPNService.router_id == RouterVPNAgentBinding.router_id)
        query = query.filter(RouterVPNAgentBinding.vpn_agent_id.is_(None))
        if router_ids:
            query = query.filter(
                vpn_models.VPNService.router_id.in_(router_ids))
        return [router_id for router_id, in query.all()]

    def auto_schedule_routers(self, context, vpn_agent):
        if self.vpn_scheduler:
            return self.vpn_scheduler.auto_schedule_routers(
                self, context, vpn_agent)

    def schedule_router(self, context, router, candidates=None):
        """Schedule VPN services of a router to a VPN agent.

        Returns the chosen agent; None if another server scheduled the
        router concurrently.
        Raises RouterReschedulingFailed if no suitable agent is found.
        """
        if self.vpn_scheduler:
            return self.vpn_scheduler.schedule(
                self, context, router, candidates=candidates)

    @db_api.CONTEXT_READER
    def get_vpn_agent_with_min_routers(self, context, agent_ids):
        """Return VPN agent with the least number of routers."""
        if not agent_ids:
            return None
        query = context.session.query(
            RouterVPNAgentBinding.vpn_agent_id,
            func.count(RouterVPNAgentBinding.router_id).label('count'))
        query = query.group_by(RouterVPNAgentBinding.vpn_agent_id)
        query = query.order_by('count')
        query = query.filter(RouterVPNAgentBinding.vpn_agent_id.in_(agent_ids))
        used_agent_ids = [agent_id for agent_id, _ in query.all()]
        unused_agent_ids = set(agent_ids) - set(used_agent_ids)
        if unused_agent_ids:
            return unused_agent_ids.pop()
        else:
            return used_agent_ids[0]

    def get_hosts_to_notify(self, context, router_id):
        """Returns all hosts to send notification about router update"""
        agents = self.get_vpn_agents_hosting_routers(context, [router_id],
                                                     active=True)
        return [a['host'] for a in agents]


class AZVPNAgentSchedulerDbMixin(VPNAgentSchedulerDbMixin,
                                 router_az.RouterAvailabilityZonePluginBase):
    """Mixin class to add availability_zone supported VPN agent scheduler."""

    def get_router_availability_zones(self, router):
        return list({agent.availability_zone for agent in router.vpn_agents})
