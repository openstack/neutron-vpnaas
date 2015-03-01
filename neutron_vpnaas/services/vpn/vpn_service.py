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

from neutron import context as n_context
from neutron.services import advanced_service
from neutron.services import provider_configuration as provconfig
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron_vpnaas.extensions import vpnaas

LOG = logging.getLogger(__name__)

DEVICE_DRIVERS = 'device_drivers'


class VPNService(advanced_service.AdvancedService):
    """VPN Service observer."""

    def __init__(self, l3_agent):
        """Creates a VPN Service instance with context.

        """
        self.context = n_context.get_admin_context_without_session()
        super(VPNService, self).__init__(l3_agent)

    def load_device_drivers(self, host):
        """Loads one or more device drivers for VPNaaS."""
        self.devices = []
        for device_driver in cfg.CONF.vpnagent.vpn_device_driver:
            device_driver = provconfig.get_provider_driver_class(
                device_driver, DEVICE_DRIVERS)
            try:
                self.devices.append(importutils.import_object(device_driver,
                                                              self,
                                                              host))
                LOG.debug('Loaded VPNaaS device driver: %s', device_driver)
            except ImportError:
                raise vpnaas.DeviceDriverImportError(
                    device_driver=device_driver)
        return self.devices

    # Overridden handlers for L3 agent events.
    def after_router_added(self, ri):
        """Create the router and sync for each loaded device driver."""
        for device in self.devices:
            device.create_router(ri)
            device.sync(self.context, [ri.router])

    def after_router_removed(self, ri):
        """Remove the router from each loaded device driver."""
        for device in self.devices:
            device.destroy_router(ri.router_id)

    def after_router_updated(self, ri):
        """Perform a sync on each loaded device driver."""
        for device in self.devices:
            device.sync(self.context, [ri.router])
