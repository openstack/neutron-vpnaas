# Copyright 2017 Eayun, Inc.
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

from neutron_lib.api import extensions
from neutron_lib import exceptions as nexception

from neutron_vpnaas._i18n import _


class FlavorsPluginNotLoaded(nexception.NotFound):
    message = _("Flavors plugin not found")


class NoProviderFoundForFlavor(nexception.NotFound):
    message = _("No service provider found for flavor %(flavor_id)s")


EXTENDED_ATTRIBUTES_2_0 = {
    'vpnservices': {
        'flavor_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid_or_none': None},
                      'is_visible': True, 'default': None}
    }
}


class Vpn_flavors(extensions.ExtensionDescriptor):
    """Extension class supporting flavors for vpnservices."""

    @classmethod
    def get_name(cls):
        return "VPN Service Flavor Extension"

    @classmethod
    def get_alias(cls):
        return 'vpn-flavors'

    @classmethod
    def get_description(cls):
        return "Flavor support for vpnservices."

    @classmethod
    def get_updated(cls):
        return "2017-04-19T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    def get_required_extensions(self):
        return ["vpnaas"]

    def get_optional_extensions(self):
        return ["flavors"]
