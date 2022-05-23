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

from neutron_lib.api.definitions import vpn_flavors
from neutron_lib.api import extensions
from neutron_lib import exceptions as nexception

from neutron_vpnaas._i18n import _


class FlavorsPluginNotLoaded(nexception.NotFound):
    message = _("Flavors plugin not found")


class NoProviderFoundForFlavor(nexception.NotFound):
    message = _("No service provider found for flavor %(flavor_id)s")


class Vpn_flavors(extensions.APIExtensionDescriptor):
    """Extension class supporting flavors for vpnservices."""
    api_definition = vpn_flavors
