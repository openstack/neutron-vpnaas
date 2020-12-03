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

import abc

from neutron_lib.api.definitions import vpn
from neutron_lib.api import extensions
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import constants as nconstants
from neutron_lib.services import base as service_base

from neutron.api.v2 import resource_helper

from neutron_vpnaas._i18n import _


class RouteInUseByVPN(nexception.InUse):
    """Operational error indicating a route is used for VPN.

    :param destinations: Destination CIDRs that are peers for VPN
    """
    message = _("Route(s) to %(destinations)s are used for VPN")


class VPNGatewayNotReady(nexception.BadRequest):
    message = _("VPN gateway not ready")


class VPNGatewayInError(nexception.Conflict):
    message = _("VPN gateway is in ERROR state. "
                "Please remove all errored VPN services and try again.")


class NoVPNAgentAvailable(nexception.ServiceUnavailable):
    message = _("No VPN agent available")


class Vpnaas(extensions.APIExtensionDescriptor):
    api_definition = vpn

    @classmethod
    def get_resources(cls):
        special_mappings = {'ikepolicies': 'ikepolicy',
                            'ipsecpolicies': 'ipsecpolicy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, vpn.RESOURCE_ATTRIBUTE_MAP)
        plural_mappings['peer_cidrs'] = 'peer_cidr'
        return resource_helper.build_resource_info(
            plural_mappings,
            vpn.RESOURCE_ATTRIBUTE_MAP,
            nconstants.VPN,
            register_quota=True,
            translate_name=True)

    @classmethod
    def get_plugin_interface(cls):
        return VPNPluginBase


class VPNPluginBase(service_base.ServicePluginBase, metaclass=abc.ABCMeta):

    def get_plugin_type(self):
        return nconstants.VPN

    def get_plugin_description(self):
        return 'VPN service plugin'

    @abc.abstractmethod
    def get_vpnservices(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_vpnservice(self, context, vpnservice_id, fields=None):
        pass

    @abc.abstractmethod
    def create_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        pass

    @abc.abstractmethod
    def delete_vpnservice(self, context, vpnservice_id):
        pass

    @abc.abstractmethod
    def get_ipsec_site_connections(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_ipsec_site_connection(self, context,
                                  ipsecsite_conn_id, fields=None):
        pass

    @abc.abstractmethod
    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        pass

    @abc.abstractmethod
    def update_ipsec_site_connection(self, context,
                                     ipsecsite_conn_id, ipsec_site_connection):
        pass

    @abc.abstractmethod
    def delete_ipsec_site_connection(self, context, ipsecsite_conn_id):
        pass

    @abc.abstractmethod
    def get_ikepolicy(self, context, ikepolicy_id, fields=None):
        pass

    @abc.abstractmethod
    def get_ikepolicies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ikepolicy(self, context, ikepolicy):
        pass

    @abc.abstractmethod
    def update_ikepolicy(self, context, ikepolicy_id, ikepolicy):
        pass

    @abc.abstractmethod
    def delete_ikepolicy(self, context, ikepolicy_id):
        pass

    @abc.abstractmethod
    def get_ipsecpolicies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_ipsecpolicy(self, context, ipsecpolicy_id, fields=None):
        pass

    @abc.abstractmethod
    def create_ipsecpolicy(self, context, ipsecpolicy):
        pass

    @abc.abstractmethod
    def update_ipsecpolicy(self, context, ipsecpolicy_id, ipsecpolicy):
        pass

    @abc.abstractmethod
    def delete_ipsecpolicy(self, context, ipsecpolicy_id):
        pass
