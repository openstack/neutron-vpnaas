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

from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import constants as nconstants
from neutron_lib.services import base as service_base

import six

from neutron.api.v2 import resource_helper

from neutron_vpnaas._i18n import _


class VPNServiceNotFound(nexception.NotFound):
    message = _("VPNService %(vpnservice_id)s could not be found")


class IPsecSiteConnectionNotFound(nexception.NotFound):
    message = _("ipsec_site_connection %(ipsec_site_conn_id)s not found")


class IPsecSiteConnectionDpdIntervalValueError(nexception.InvalidInput):
    message = _("ipsec_site_connection %(attr)s is "
                "equal to or less than dpd_interval")


class IPsecSiteConnectionMtuError(nexception.InvalidInput):
    message = _("ipsec_site_connection MTU %(mtu)d is too small "
                "for ipv%(version)s")


class IPsecSiteConnectionPeerCidrError(nexception.InvalidInput):
    message = _("ipsec_site_connection peer cidr %(peer_cidr)s is "
                "invalid CIDR")


class IKEPolicyNotFound(nexception.NotFound):
    message = _("IKEPolicy %(ikepolicy_id)s could not be found")


class IPsecPolicyNotFound(nexception.NotFound):
    message = _("IPsecPolicy %(ipsecpolicy_id)s could not be found")


class IKEPolicyInUse(nexception.InUse):
    message = _("IKEPolicy %(ikepolicy_id)s is in use by existing "
                "IPsecSiteConnection and can't be updated or deleted")


class VPNServiceInUse(nexception.InUse):
    message = _("VPNService %(vpnservice_id)s is still in use")


class SubnetInUseByVPNService(nexception.InUse):
    message = _("Subnet %(subnet_id)s is used by VPNService %(vpnservice_id)s")


class SubnetInUseByEndpointGroup(nexception.InUse):
    message = _("Subnet %(subnet_id)s is used by endpoint group %(group_id)s")


class VPNStateInvalidToUpdate(nexception.BadRequest):
    message = _("Invalid state %(state)s of vpnaas resource %(id)s"
                " for updating")


class IPsecPolicyInUse(nexception.InUse):
    message = _("IPsecPolicy %(ipsecpolicy_id)s is in use by existing "
                "IPsecSiteConnection and can't be updated or deleted")


class DeviceDriverImportError(nexception.NeutronException):
    message = _("Can not load driver :%(device_driver)s")


class SubnetIsNotConnectedToRouter(nexception.BadRequest):
    message = _("Subnet %(subnet_id)s is not "
                "connected to Router %(router_id)s")


class RouterIsNotExternal(nexception.BadRequest):
    message = _("Router %(router_id)s has no external network gateway set")


class VPNPeerAddressNotResolved(nexception.InvalidInput):
    message = _("Peer address %(peer_address)s cannot be resolved")


class ExternalNetworkHasNoSubnet(nexception.BadRequest):
    message = _("Router's %(router_id)s external network has "
                "no %(ip_version)s subnet")


class VPNEndpointGroupNotFound(nexception.NotFound):
    message = _("Endpoint group %(endpoint_group_id)s could not be found")


class InvalidEndpointInEndpointGroup(nexception.InvalidInput):
    message = _("Endpoint '%(endpoint)s' is invalid for group "
                "type '%(group_type)s': %(why)s")


class MissingEndpointForEndpointGroup(nexception.BadRequest):
    message = _("No endpoints specified for endpoint group '%(group)s'")


class NonExistingSubnetInEndpointGroup(nexception.InvalidInput):
    message = _("Subnet %(subnet)s in endpoint group does not exist")


class MixedIPVersionsForIPSecEndpoints(nexception.BadRequest):
    message = _("Endpoints in group %(group)s do not have the same IP "
                "version, as required for IPSec site-to-site connection")


class MixedIPVersionsForPeerCidrs(nexception.BadRequest):
    message = _("Peer CIDRs do not have the same IP version, as required "
                "for IPSec site-to-site connection")


class MixedIPVersionsForIPSecConnection(nexception.BadRequest):
    message = _("IP versions are not compatible between peer and local "
                "endpoints")


class InvalidEndpointGroup(nexception.BadRequest):
    message = _("Endpoint group%(suffix)s %(which)s cannot be specified, "
                "when VPN Service has subnet specified")


class WrongEndpointGroupType(nexception.BadRequest):
    message = _("Endpoint group %(which)s type is '%(group_type)s' and "
                "should be '%(expected)s'")


class PeerCidrsInvalid(nexception.BadRequest):
    message = _("Peer CIDRs cannot be specified, when using endpoint "
                "groups")


class MissingPeerCidrs(nexception.BadRequest):
    message = _("Missing peer CIDRs for IPsec site-to-site connection")


class MissingRequiredEndpointGroup(nexception.BadRequest):
    message = _("Missing endpoint group%(suffix)s %(which)s for IPSec "
                "site-to-site connection")


class EndpointGroupInUse(nexception.BadRequest):
    message = _("Endpoint group %(group_id)s is in use and cannot be deleted")


def _validate_subnet_list_or_none(data, key_specs=None):
    if data is not None:
        return validators.validate_subnet_list(data, key_specs)

validators.add_validator('type:subnet_list_or_none',
                        _validate_subnet_list_or_none)

vpn_supported_initiators = ['bi-directional', 'response-only']
vpn_supported_encryption_algorithms = ['3des', 'aes-128',
                                       'aes-192', 'aes-256']
vpn_dpd_supported_actions = [
    'hold', 'clear', 'restart', 'restart-by-peer', 'disabled'
]
vpn_supported_transform_protocols = ['esp', 'ah', 'ah-esp']
vpn_supported_encapsulation_mode = ['tunnel', 'transport']
#TODO(nati) add kilobytes when we support it
vpn_supported_lifetime_units = ['seconds']
vpn_supported_pfs = ['group2', 'group5', 'group14']
vpn_supported_ike_versions = ['v1', 'v2']
vpn_supported_auth_mode = ['psk']
vpn_supported_auth_algorithms = ['sha1', 'sha256', 'sha384', 'sha512']
vpn_supported_phase1_negotiation_mode = ['main']

vpn_lifetime_limits = (60, validators.UNLIMITED)
positive_int = (0, validators.UNLIMITED)

RESOURCE_ATTRIBUTE_MAP = {

    'vpnservices': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'subnet_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid_or_none': None},
                      'is_visible': True, 'default': None},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True},
        'external_v4_ip': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'external_v6_ip': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },

    'ipsec_site_connections': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'local_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'is_visible': True, 'default': ''},
        'peer_address': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'peer_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:string': None},
                    'is_visible': True},
        'peer_cidrs': {'allow_post': True, 'allow_put': True,
                       'convert_to': converters.convert_to_list,
                       'validate': {'type:subnet_list_or_none': None},
                       'is_visible': True,
                       'default': None},
        'local_ep_group_id': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_or_none': None},
                              'is_visible': True, 'default': None},
        'peer_ep_group_id': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid_or_none': None},
                             'is_visible': True, 'default': None},
        'route_mode': {'allow_post': False, 'allow_put': False,
                       'default': 'static',
                       'is_visible': True},
        'mtu': {'allow_post': True, 'allow_put': True,
                'default': '1500',
                'validate': {'type:range': positive_int},
                'convert_to': converters.convert_to_int,
                'is_visible': True},
        'initiator': {'allow_post': True, 'allow_put': True,
                      'default': 'bi-directional',
                      'validate': {'type:values': vpn_supported_initiators},
                      'is_visible': True},
        'auth_mode': {'allow_post': False, 'allow_put': False,
                      'default': 'psk',
                      'validate': {'type:values': vpn_supported_auth_mode},
                      'is_visible': True},
        'psk': {'allow_post': True, 'allow_put': True,
                'validate': {'type:string': None},
                'is_visible': True},
        'dpd': {'allow_post': True, 'allow_put': True,
                'convert_to': converters.convert_none_to_empty_dict,
                'is_visible': True,
                'default': {},
                'validate': {
                    'type:dict_or_empty': {
                        'action': {
                            'type:values': vpn_dpd_supported_actions,
                        },
                        'interval': {
                            'type:range': positive_int
                        },
                        'timeout': {
                            'type:range': positive_int
                        }}}},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'vpnservice_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},
        'ikepolicy_id': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:uuid': None},
                         'is_visible': True},
        'ipsecpolicy_id': {'allow_post': True, 'allow_put': False,
                           'validate': {'type:uuid': None},
                           'is_visible': True}
    },

    'ipsecpolicies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'transform_protocol': {
            'allow_post': True,
            'allow_put': True,
            'default': 'esp',
            'validate': {
                'type:values': vpn_supported_transform_protocols},
            'is_visible': True},
        'auth_algorithm': {
            'allow_post': True,
            'allow_put': True,
            'default': 'sha1',
            'validate': {
                'type:values': vpn_supported_auth_algorithms
            },
            'is_visible': True},
        'encryption_algorithm': {
            'allow_post': True,
            'allow_put': True,
            'default': 'aes-128',
            'validate': {
                'type:values': vpn_supported_encryption_algorithms
            },
            'is_visible': True},
        'encapsulation_mode': {
            'allow_post': True,
            'allow_put': True,
            'default': 'tunnel',
            'validate': {
                'type:values': vpn_supported_encapsulation_mode
            },
            'is_visible': True},
        'lifetime': {'allow_post': True, 'allow_put': True,
                     'convert_to': converters.convert_none_to_empty_dict,
                     'default': {},
                     'validate': {
                         'type:dict_or_empty': {
                             'units': {
                                 'type:values': vpn_supported_lifetime_units,
                             },
                             'value': {
                                 'type:range': vpn_lifetime_limits
                             }}},
                     'is_visible': True},
        'pfs': {'allow_post': True, 'allow_put': True,
                'default': 'group5',
                'validate': {'type:values': vpn_supported_pfs},
                'is_visible': True}
    },

    'ikepolicies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'auth_algorithm': {'allow_post': True, 'allow_put': True,
                           'default': 'sha1',
                           'validate': {
                               'type:values': vpn_supported_auth_algorithms},
                           'is_visible': True},
        'encryption_algorithm': {
            'allow_post': True, 'allow_put': True,
            'default': 'aes-128',
            'validate': {'type:values': vpn_supported_encryption_algorithms},
            'is_visible': True},
        'phase1_negotiation_mode': {
            'allow_post': True, 'allow_put': True,
            'default': 'main',
            'validate': {
                'type:values': vpn_supported_phase1_negotiation_mode
            },
            'is_visible': True},
        'lifetime': {'allow_post': True, 'allow_put': True,
                     'convert_to': converters.convert_none_to_empty_dict,
                     'default': {},
                     'validate': {
                         'type:dict_or_empty': {
                             'units': {
                                 'type:values': vpn_supported_lifetime_units,
                             },
                             'value': {
                                 'type:range': vpn_lifetime_limits,
                             }}},
                     'is_visible': True},
        'ike_version': {'allow_post': True, 'allow_put': True,
                        'default': 'v1',
                        'validate': {
                            'type:values': vpn_supported_ike_versions},
                        'is_visible': True},
        'pfs': {'allow_post': True, 'allow_put': True,
                'default': 'group5',
                'validate': {'type:values': vpn_supported_pfs},
                'is_visible': True}
    },
}


class Vpnaas(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "VPN service"

    @classmethod
    def get_alias(cls):
        return "vpnaas"

    @classmethod
    def get_description(cls):
        return "Extension for VPN service"

    @classmethod
    def get_namespace(cls):
        return "https://wiki.openstack.org/Neutron/VPNaaS"

    @classmethod
    def get_updated(cls):
        return "2013-05-29T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        special_mappings = {'ikepolicies': 'ikepolicy',
                            'ipsecpolicies': 'ipsecpolicy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, RESOURCE_ATTRIBUTE_MAP)
        plural_mappings['peer_cidrs'] = 'peer_cidr'
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   nconstants.VPN,
                                                   register_quota=True,
                                                   translate_name=True)

    @classmethod
    def get_plugin_interface(cls):
        return VPNPluginBase

    def update_attributes_map(self, attributes):
        super(Vpnaas, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class VPNPluginBase(service_base.ServicePluginBase):

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
