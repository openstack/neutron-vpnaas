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

from oslo_config import cfg
from oslo_utils import importutils

from neutron import context as n_context
from neutron.openstack.common import log as logging
from neutron.services import advanced_service
from neutron.services import provider_configuration as provconfig

from neutron_vpnaas.extensions import vpnaas

LOG = logging.getLogger(__name__)

DEVICE_DRIVERS = 'device_drivers'


class VPNService(advanced_service.AdvancedService):
    """VPN Service observer."""

    def __init__(self, l3_agent):
        """Creates a VPN Service instance with context.

        DO NOT CALL THIS DIRECTLY! Use the instance() class method to Creates
        a singleton instance of the service.
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
            device.create_router(ri.router_id)
            device.sync(self.context, [ri.router])

    def after_router_removed(self, ri):
        """Remove the router from each loaded device driver."""
        for device in self.devices:
            device.destroy_router(ri.router_id)

    def after_router_updated(self, ri):
        """Perform a sync on each loaded device driver."""
        for device in self.devices:
            device.sync(self.context, [ri.router])

    # Device driver methods calling back to L3 agent
    def get_namespace(self, router_id):
        """Get namespace of router.

        :router_id: router_id
        :returns: namespace string.
            Note if the router is not exist, this function
            returns None
        """
        router_info = self.l3_agent.router_info.get(router_id)
        if not router_info:
            return
        # Added for handling the distributed Routers within SNAT namespace
        if router_info.router['distributed']:
            #return self.get_snat_ns_name(router_id)
            return self.l3_agent.get_snat_ns_name(router_id)
        else:
            return router_info.ns_name

    def get_router_based_iptables_manager(self, router_info):
        """Returns router based iptables manager

        In DVR routers the IPsec VPN service should run inside
        the snat namespace. So the iptables manager used for
        snat namespace is different from the iptables manager
        used for the qr namespace in a non dvr based router.

        This function will check the router type and then will
        return the right iptables manager. If DVR enabled router
        it will return the snat_iptables_manager otherwise it will
        return the legacy iptables_manager.
        """
        if router_info.router['distributed']:
            return router_info.snat_iptables_manager
        else:
            return router_info.iptables_manager

    def add_nat_rule(self, router_id, chain, rule, top=False):
        """Add nat rule in namespace.

        :param router_id: router_id
        :param chain: a string of chain name
        :param rule: a string of rule
        :param top: if top is true, the rule
            will be placed on the top of chain
            Note if there is no rotuer, this method do nothing
        """
        router_info = self.l3_agent.router_info.get(router_id)
        if not router_info:
            return
        iptables_manager = self.get_router_based_iptables_manager(router_info)
        iptables_manager.ipv4['nat'].add_rule(chain, rule, top=top)

    def remove_nat_rule(self, router_id, chain, rule, top=False):
        """Remove nat rule in namespace.

        :param router_id: router_id
        :param chain: a string of chain name
        :param rule: a string of rule
        :param top: unused
            needed to have same argument with add_nat_rule
        """
        router_info = self.l3_agent.router_info.get(router_id)
        if not router_info:
            return
        iptables_manager = self.get_router_based_iptables_manager(router_info)
        iptables_manager.ipv4['nat'].remove_rule(chain, rule, top=top)

    def iptables_apply(self, router_id):
        """Apply IPtables.

        :param router_id: router_id
        This method do nothing if there is no router
        """
        router_info = self.l3_agent.router_info.get(router_id)
        if not router_info:
            return
        iptables_manager = self.get_router_based_iptables_manager(router_info)
        iptables_manager.apply()
