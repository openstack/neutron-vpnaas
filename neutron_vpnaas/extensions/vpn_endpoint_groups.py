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

from neutron_lib.api.definitions import vpn_endpoint_groups
from neutron_lib.api import extensions
from neutron_lib.plugins import constants as nconstants

from neutron.api.v2 import resource_helper


class Vpn_endpoint_groups(extensions.APIExtensionDescriptor):
    api_definition = vpn_endpoint_groups

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, vpn_endpoint_groups.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            vpn_endpoint_groups.RESOURCE_ATTRIBUTE_MAP,
            nconstants.VPN,
            register_quota=True,
            translate_name=True)


class VPNEndpointGroupsPluginBase(object, metaclass=abc.ABCMeta):

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
