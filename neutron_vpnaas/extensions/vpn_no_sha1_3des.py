# Copyright 2025 Red Hat, Inc.
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
#

from neutron_lib.api.definitions import vpn_no_sha1_3des
from neutron_lib.api import extensions
from neutron_lib.plugins import constants as nconstants

from neutron.api.v2 import resource_helper


class Vpn_no_sha1_3des(extensions.APIExtensionDescriptor):
    api_definition = vpn_no_sha1_3des

    @classmethod
    def get_resources(cls):
        special_mappings = {'ikepolicies': 'ikepolicy',
                            'ipsecpolicies': 'ipsecpolicy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, vpn_no_sha1_3des.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            vpn_no_sha1_3des.RESOURCE_ATTRIBUTE_MAP,
            nconstants.VPN,
            register_quota=True,
            translate_name=True)
