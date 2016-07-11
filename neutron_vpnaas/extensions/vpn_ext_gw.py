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

import six

from neutron_lib.api import converters
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants as nconstants

VPN_GW = 'vpn_external_gateway_info'
ROUTERS = 'routers'
RESOURCE_ATTRIBUTE_MAP = {
    ROUTERS: {
        VPN_GW: {'allow_post': True, 'allow_put': True,
                           'is_visible': True, 'default': None,
                           'enforce_policy': True,
                           'validate': {
                               'type:dict_or_nodata': {
                                   'network_id': {'type:uuid': None,
                                                  'required': True},
                                   'external_fixed_ips': {
                                       'convert_list_to':
                                       converters.convert_kvp_list_to_dict,
                                       'type:fixed_ips': None,
                                       'default': None,
                                       'required': False,
                                   }
                               }
                           }}
    },
}

@six.add_metaclass(abc.ABCMeta)
class Vpn_ext_gw(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "VPN External Gateway"

    @classmethod
    def get_alias(cls):
        return "vpn_ext_gw"

    @classmethod
    def get_description(cls):
        return "VPN external ports support"

    @classmethod
    def get_updated(cls):
        return "2016-07-08T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   nconstants.VPN,
                                                   register_quota=True,
                                                   translate_name=True)

    def get_required_extensions(self):
        return ["vpnaas"]

    def update_attributes_map(self, attributes):
        super(Vpn_ext_gw, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}



