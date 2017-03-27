#    (c) Copyright 2015 NEC Corporation, All Rights Reserved.
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

from neutron.api.v2 import resource_helper

from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib.db import constants as db_const
from neutron_lib.plugins import constants as nconstants

from neutron_vpnaas.services.vpn.common import constants


RESOURCE_ATTRIBUTE_MAP = {

    'endpoint_groups': {
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
        'type': {'allow_post': True, 'allow_put': False,
                 'validate': {
                     'type:values': constants.VPN_SUPPORTED_ENDPOINT_TYPES,
                 },
                 'is_visible': True},
        'endpoints': {'allow_post': True, 'allow_put': False,
                      'convert_to': converters.convert_to_list,
                      'is_visible': True},
    },
}


class Vpn_endpoint_groups(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "VPN Endpoint Groups"

    @classmethod
    def get_alias(cls):
        return "vpn-endpoint-groups"

    @classmethod
    def get_description(cls):
        return "VPN endpoint groups support"

    @classmethod
    def get_updated(cls):
        return "2015-08-04T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   nconstants.VPN,
                                                   register_quota=True,
                                                   translate_name=True)

    def get_required_extensions(self):
        return ["vpnaas"]

    def update_attributes_map(self, attributes):
        super(Vpn_endpoint_groups, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class VPNEndpointGroupsPluginBase(object):

    @abc.abstractmethod
    def create_endpoint_group(self, context, endpoint_group):
        pass

    @abc.abstractmethod
    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        pass

    @abc.abstractmethod
    def delete_endpoint_group(self, context, endpoint_group_id):
        pass

    @abc.abstractmethod
    def get_endpoint_group(self, context, endpoint_group_id, fields=None):
        pass

    @abc.abstractmethod
    def get_endpoint_groups(self, context, filters=None, fields=None):
        pass
