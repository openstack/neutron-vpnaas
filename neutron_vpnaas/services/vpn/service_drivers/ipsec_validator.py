# Copyright 2015 Awcloud Inc.  All rights reserved.
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

from neutron_lib import exceptions as nexception

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn.service_drivers import driver_validator


class IpsecValidationFailure(nexception.BadRequest):
    message = _("IPSec does not support %(resource)s attribute %(key)s "
                "with value '%(value)s'")


class IpsecVpnValidator(driver_validator.VpnDriverValidator):

    """Driver-specific validator methods for the Openswan, Strongswan
    and Libreswan.
    """

    def _check_transform_protocol(self, context, transform_protocol):
        """Restrict selecting ah-esp as IPSec Policy transform protocol.

        For those *Swan implementations, the 'ah-esp' transform protocol
        is not supported and therefore the request should be rejected.
        """
        if transform_protocol == "ah-esp":
            raise IpsecValidationFailure(
                resource='IPsec Policy',
                key='transform_protocol',
                value=transform_protocol)

    def validate_ipsec_policy(self, context, ipsec_policy):
        transform_protocol = ipsec_policy.get('transform_protocol')
        self._check_transform_protocol(context, transform_protocol)

    def validate_ipsec_site_connection(self, context, ipsec_sitecon):
        if 'ipsecpolicy_id' in ipsec_sitecon:
            ipsec_policy = self.driver.service_plugin.get_ipsecpolicy(
                context, ipsec_sitecon['ipsecpolicy_id'])
            self.validate_ipsec_policy(context, ipsec_policy)
