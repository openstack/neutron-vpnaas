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

import abc

from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import oslo_messaging

from neutron_vpnaas.services.vpn.service_drivers import driver_validator

LOG = logging.getLogger(__name__)


class VpnDriver(object, metaclass=abc.ABCMeta):

    def __init__(self, service_plugin, validator=None):
        self.service_plugin = service_plugin
        if validator is None:
            validator = driver_validator.VpnDriverValidator(self)
        self.validator = validator
        self.name = ''

    @property
    def l3_plugin(self):
        return directory.get_plugin(constants.L3)

    @property
    def service_type(self):
        pass

    @abc.abstractmethod
    def create_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def update_vpnservice(
        self, context, old_vpnservice, vpnservice):
        pass

    @abc.abstractmethod
    def delete_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        pass

    @abc.abstractmethod
    def update_ipsec_site_connection(self, context, old_ipsec_site_connection,
                                     ipsec_site_connection):
        pass

    @abc.abstractmethod
    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        pass


class BaseIPsecVpnAgentApi(object):
    """Base class for IPSec API to agent."""

    def __init__(self, topic, default_version, driver):
        self.topic = topic
        self.driver = driver
        target = oslo_messaging.Target(topic=topic, version=default_version)
        self.client = n_rpc.get_client(target)

    def _agent_notification(self, context, method, router_id,
                            version=None, **kwargs):
        """Notify update for the agent.

        This method will find where is the router, and
        dispatch notification for the agent.
        """
        admin_context = context if context.is_admin else context.elevated()
        if not version:
            version = self.target.version
        l3_agents = self.driver.l3_plugin.get_l3_agents_hosting_routers(
            admin_context, [router_id],
            admin_state_up=True,
            active=True)
        for l3_agent in l3_agents:
            LOG.debug('Notify agent at %(topic)s.%(host)s the message '
                      '%(method)s %(args)s',
                      {'topic': self.topic,
                       'host': l3_agent.host,
                       'method': method,
                       'args': kwargs})
            cctxt = self.client.prepare(server=l3_agent.host, version=version)
            cctxt.cast(context, method, **kwargs)

    def vpnservice_updated(self, context, router_id, **kwargs):
        """Send update event of vpnservices."""
        kwargs['router'] = {'id': router_id}
        self._agent_notification(context, 'vpnservice_updated', router_id,
                                 **kwargs)
