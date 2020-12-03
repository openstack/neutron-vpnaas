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

from neutron.api import extensions
from neutron.api.v2 import resource
from neutron import policy
from neutron import wsgi
from neutron_lib.api import extensions as lib_extensions
from neutron_lib.api import faults as base
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import webob.exc


LOG = logging.getLogger(__name__)


VPN_ROUTER = 'vpn-router'
VPN_ROUTERS = VPN_ROUTER + 's'
VPN_AGENT = 'vpn-agent'
VPN_AGENTS = VPN_AGENT + 's'


class VPNRouterSchedulerController(wsgi.Controller):
    def get_plugin(self):
        plugin = directory.get_plugin(plugin_const.VPN)
        if not plugin:
            LOG.error('No plugin for VPN registered to handle VPN '
                      'router scheduling')
            msg = 'The resource could not be found.'
            raise webob.exc.HTTPNotFound(msg)
        return plugin

    def index(self, request, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % VPN_ROUTERS,
                       {})
        return plugin.list_routers_on_vpn_agent(
            request.context, kwargs['agent_id'])

    def create(self, request, body, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "create_%s" % VPN_ROUTER,
                       {})
        agent_id = kwargs['agent_id']
        router_id = body['router_id']
        result = plugin.add_router_to_vpn_agent(request.context, agent_id,
                                               router_id)
        notify(request.context, 'vpn_agent.router.add', router_id, agent_id)
        return result

    def delete(self, request, id, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "delete_%s" % VPN_ROUTER,
                       {})
        agent_id = kwargs['agent_id']
        result = plugin.remove_router_from_vpn_agent(request.context, agent_id,
                                                    id)
        notify(request.context, 'vpn_agent.router.remove', id, agent_id)
        return result


class VPNAgentsHostingRouterController(wsgi.Controller):
    def get_plugin(self):
        plugin = directory.get_plugin(plugin_const.VPN)
        if not plugin:
            LOG.error('VPN plugin not registered to handle agent scheduling')
            msg = 'The resource could not be found.'
            raise webob.exc.HTTPNotFound(msg)
        return plugin

    def index(self, request, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % VPN_AGENTS,
                       {})
        return plugin.list_vpn_agents_hosting_router(
            request.context, kwargs['router_id'])


class Vpn_agentschedulers(lib_extensions.ExtensionDescriptor):
    """Extension class supporting VPN agent scheduler.
    """

    @classmethod
    def get_name(cls):
        return "VPN Agent Scheduler"

    @classmethod
    def get_alias(cls):
        return "vpn-agent-scheduler"

    @classmethod
    def get_description(cls):
        return "Schedule VPN services of routers among VPN agents"

    @classmethod
    def get_updated(cls):
        return "2016-08-15T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        parent = dict(member_name="agent",
                      collection_name="agents")

        controller = resource.Resource(VPNRouterSchedulerController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            VPN_ROUTERS, controller, parent))

        parent = dict(member_name="router",
                      collection_name="routers")

        controller = resource.Resource(VPNAgentsHostingRouterController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            VPN_AGENTS, controller, parent))
        return exts

    def get_extended_resources(self, version):
        return {}


class InvalidVPNAgent(exceptions.agent.AgentNotFound):
    message = "Agent %(id)s is not a VPN Agent or has been disabled"


class RouterHostedByVPNAgent(exceptions.Conflict):
    message = ("The VPN service of router %(router_id)s has been already "
               "hosted by the VPN Agent %(agent_id)s.")


class RouterSchedulingFailed(exceptions.Conflict):
    message = ("Failed scheduling router %(router_id)s to the VPN Agent "
               "%(agent_id)s.")


class RouterReschedulingFailed(exceptions.Conflict):
    message = ("Failed rescheduling router %(router_id)s: "
               "No eligible VPN agent found.")


class VPNAgentSchedulerPluginBase(object, metaclass=abc.ABCMeta):
    """REST API to operate the VPN agent scheduler.

    All methods must be in an admin context.
    """

    @abc.abstractmethod
    def add_router_to_vpn_agent(self, context, id, router_id):
        pass

    @abc.abstractmethod
    def remove_router_from_vpn_agent(self, context, id, router_id):
        pass

    @abc.abstractmethod
    def list_routers_on_vpn_agent(self, context, id):
        pass

    @abc.abstractmethod
    def list_vpn_agents_hosting_router(self, context, router_id):
        pass


def notify(context, action, router_id, agent_id):
    info = {'id': agent_id, 'router_id': router_id}
    notifier = n_rpc.get_notifier('router')
    notifier.info(context, action, {'agent': info})
