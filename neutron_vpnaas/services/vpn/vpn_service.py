# Copyright 2014 OpenStack Foundation.
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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.services import provider_configuration as provconfig
from oslo_log import log as logging
from oslo_utils import importutils

from neutron_vpnaas.extensions import vpnaas

LOG = logging.getLogger(__name__)

DEVICE_DRIVERS = 'device_drivers'


class VPNService(object):
    """VPN Service observer."""

    def __init__(self, l3_agent):
        """Creates a VPN Service instance with context."""
        # TODO(pc_m): Replace l3_agent argument with config, once none of the
        # device driver implementations need the L3 agent.
        self.conf = l3_agent.conf
        registry.subscribe(
            router_added_actions, resources.ROUTER, events.AFTER_CREATE)
        registry.subscribe(
            router_removed_actions, resources.ROUTER, events.AFTER_DELETE)
        registry.subscribe(
            router_updated_actions, resources.ROUTER, events.AFTER_UPDATE)

    def load_device_drivers(self, host):
        """Loads one or more device drivers for VPNaaS."""
        drivers = []
        for device_driver in self.conf.vpnagent.vpn_device_driver:
            device_driver = provconfig.get_provider_driver_class(
                device_driver, DEVICE_DRIVERS)
            try:
                drivers.append(importutils.import_object(device_driver,
                                                         self,
                                                         host))
                LOG.debug('Loaded VPNaaS device driver: %s', device_driver)
            except ImportError:
                raise vpnaas.DeviceDriverImportError(
                    device_driver=device_driver)
        return drivers


def router_added_actions(resource, event, l3_agent, **kwargs):
    """Create the router and sync for each loaded device driver."""
    router = kwargs['router']
    for device_driver in l3_agent.device_drivers:
        device_driver.create_router(router)
        device_driver.sync(l3_agent.context, [router.router])


def router_removed_actions(resource, event, l3_agent, **kwargs):
    """Remove the router from each loaded device driver."""
    router = kwargs['router']
    for device_driver in l3_agent.device_drivers:
        device_driver.destroy_router(router.router_id)


def router_updated_actions(resource, event, l3_agent, **kwargs):
    """Perform a sync on each loaded device driver."""
    router = kwargs['router']
    for device_driver in l3_agent.device_drivers:
        device_driver.sync(l3_agent.context, [router.router])
