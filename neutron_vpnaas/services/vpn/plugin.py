
#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

from neutron.db import servicetype_db as st_db
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron_lib import context as ncontext
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import flavors as flav_exc
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_log import log as logging

from neutron_vpnaas.db.vpn import vpn_db
from neutron_vpnaas.extensions import vpn_flavors

LOG = logging.getLogger(__name__)


def add_provider_configuration(type_manager, service_type):
    type_manager.add_provider_configuration(
        service_type,
        pconf.ProviderConfiguration('neutron_vpnaas'))


class VPNPlugin(vpn_db.VPNPluginDb):

    """Implementation of the VPN Service Plugin.

    This class manages the workflow of VPNaaS request/response.
    Most DB related works are implemented in class
    vpn_db.VPNPluginDb.
    """
    supported_extension_aliases = ["vpnaas",
                                   "vpn-endpoint-groups",
                                   "service-type",
                                   "vpn-flavors"]
    path_prefix = "/vpn"


class VPNDriverPlugin(VPNPlugin, vpn_db.VPNPluginRpcDbMixin):
    """VpnPlugin which supports VPN Service Drivers."""
    #TODO(nati) handle ikepolicy and ipsecpolicy update usecase
    def __init__(self):
        super(VPNDriverPlugin, self).__init__()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        add_provider_configuration(self.service_type_manager, constants.VPN)
        # Load the service driver from neutron.conf.
        self.drivers, self.default_provider = service_base.load_drivers(
            constants.VPN, self)
        self._check_orphan_vpnservice_associations()
        # Associate driver names to driver objects
        for driver_name, driver in self.drivers.items():
            driver.name = driver_name
        LOG.info(("VPN plugin using service drivers: %(service_drivers)s, "
                  "default: %(default_driver)s"),
                 {'service_drivers': self.drivers.keys(),
                  'default_driver': self.default_provider})
        vpn_db.subscribe()

    @property
    def _flavors_plugin(self):
        return directory.get_plugin(constants.FLAVORS)

    def start_rpc_listeners(self):
        servers = []
        for driver_name, driver in self.drivers.items():
            if hasattr(driver, 'start_rpc_listeners'):
                servers.extend(driver.start_rpc_listeners())
        return servers

    def _check_orphan_vpnservice_associations(self):
        context = ncontext.get_admin_context()
        vpnservices = self.get_vpnservices(context)
        vpnservice_ids = [vpnservice['id'] for vpnservice in vpnservices]

        stm = self.service_type_manager
        provider_names = stm.get_provider_names_by_resource_ids(
            context, vpnservice_ids)

        lost_providers = set()
        lost_vpnservices = []
        for vpnservice_id, provider in provider_names.items():
            if provider not in self.drivers:
                lost_providers.add(provider)
                lost_vpnservices.append(vpnservice_id)
        if lost_providers or lost_vpnservices:
            # Provider are kept internally, we need to inform users about
            # the related VPN services.
            msg = (
                "Delete associated vpnservices %(vpnservices)s before "
                "removing providers %(providers)s."
            ) % {'vpnservices': lost_vpnservices,
                 'providers': list(lost_providers)}
            LOG.exception(msg)
            raise SystemExit(msg)

        # Deal with upgrade. Associate existing VPN services to default
        # provider.
        unasso_vpnservices = [
            vpnservice_id for vpnservice_id in vpnservice_ids
            if vpnservice_id not in provider_names]
        if unasso_vpnservices:
            LOG.info(
                ("Associating VPN services %(unasso_vpnservices)s to "
                 "default provider %(default_provider)s."),
                {'unasso_vpnservices': unasso_vpnservices,
                 'default_provider': self.default_provider})
            for vpnservice_id in unasso_vpnservices:
                stm.add_resource_association(
                    context, constants.VPN,
                    self.default_provider, vpnservice_id)

    def _get_provider_for_flavor(self, context, flavor_id):
        if flavor_id:
            if self._flavors_plugin is None:
                raise vpn_flavors.FlavorsPluginNotLoaded()

            fl_db = self._flavors_plugin.get_flavor(context, flavor_id)
            if fl_db['service_type'] != constants.VPN:
                raise lib_exc.InvalidServiceType(
                    service_type=fl_db['service_type'])
            if not fl_db['enabled']:
                raise flav_exc.FlavorDisabled()
            providers = self._flavors_plugin.get_flavor_next_provider(
                context, fl_db['id'])
            provider = providers[0].get('provider')
            if provider not in self.drivers:
                raise vpn_flavors.NoProviderFoundForFlavor(flavor_id=flavor_id)
        else:
            # Use default provider
            provider = self.default_provider

        LOG.debug("Selected provider %s", provider)
        return provider

    def _get_driver_for_vpnservice(self, context, vpnservice):
        stm = self.service_type_manager
        provider_names = stm.get_provider_names_by_resource_ids(
            context, [vpnservice['id']])
        provider = provider_names.get(vpnservice['id'])
        return self.drivers[provider]

    def _get_driver_for_ipsec_site_connection(self, context,
                                              ipsec_site_connection):
        # Only vpnservice_id is required as the vpnservice should be already
        # associated with a provider after its creation.
        vpnservice = {'id': ipsec_site_connection['vpnservice_id']}
        return self._get_driver_for_vpnservice(context, vpnservice)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection['ipsec_site_connection'])
        driver.validator.validate_ipsec_site_connection(
            context,
            ipsec_site_connection['ipsec_site_connection'])
        ipsec_site_connection = super(
            VPNDriverPlugin, self).create_ipsec_site_connection(
                context, ipsec_site_connection)
        driver.create_ipsec_site_connection(context, ipsec_site_connection)
        return ipsec_site_connection

    def delete_ipsec_site_connection(self, context, ipsec_conn_id):
        ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        super(VPNDriverPlugin, self).delete_ipsec_site_connection(
            context, ipsec_conn_id)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.delete_ipsec_site_connection(context, ipsec_site_connection)

    def update_ipsec_site_connection(
            self, context,
            ipsec_conn_id, ipsec_site_connection):
        old_ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        driver = self._get_driver_for_ipsec_site_connection(
            context, old_ipsec_site_connection)
        driver.validator.validate_ipsec_site_connection(
            context,
            ipsec_site_connection['ipsec_site_connection'])
        ipsec_site_connection = super(
            VPNDriverPlugin, self).update_ipsec_site_connection(
                context,
                ipsec_conn_id,
                ipsec_site_connection)
        driver.update_ipsec_site_connection(
            context, old_ipsec_site_connection, ipsec_site_connection)
        return ipsec_site_connection

    def create_vpnservice(self, context, vpnservice):
        provider = self._get_provider_for_flavor(
            context, vpnservice['vpnservice'].get('flavor_id'))
        vpnservice = super(
            VPNDriverPlugin, self).create_vpnservice(context, vpnservice)
        self.service_type_manager.add_resource_association(
            context, constants.VPN, provider, vpnservice['id'])
        driver = self.drivers[provider]
        driver.create_vpnservice(context, vpnservice)
        return vpnservice

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        old_vpn_service = self.get_vpnservice(context, vpnservice_id)
        new_vpn_service = super(
            VPNDriverPlugin, self).update_vpnservice(context, vpnservice_id,
                                                     vpnservice)
        driver = self._get_driver_for_vpnservice(context, old_vpn_service)
        driver.update_vpnservice(context, old_vpn_service, new_vpn_service)
        return new_vpn_service

    def delete_vpnservice(self, context, vpnservice_id):
        vpnservice = self._get_vpnservice(context, vpnservice_id)
        super(VPNDriverPlugin, self).delete_vpnservice(context, vpnservice_id)
        driver = self._get_driver_for_vpnservice(context, vpnservice)
        self.service_type_manager.del_resource_associations(
            context, [vpnservice_id])
        driver.delete_vpnservice(context, vpnservice)
