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
from neutron_vpnaas.db.vpn import vpn_validator


class IpsecValidationFailure(nexception.BadRequest):
    message = _("IPSec does not support %(resource)s attribute %(key)s "
                "with value '%(value)s'")


class IkeValidationFailure(nexception.BadRequest):
    message = _("IKE does not support %(resource)s attribute %(key)s "
                "with value '%(value)s'")


class IpsecVpnValidator(vpn_validator.VpnReferenceValidator):

    """Validator methods for the Openswan, Strongswan and Libreswan."""

    def __init__(self, service_plugin):
        self.service_plugin = service_plugin
        super(IpsecVpnValidator, self).__init__()

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

    def _check_auth_algorithm(self, context, auth_algorithm):
        """Restrict selecting sha384 and sha512 as IPSec Policy auth algorithm.

        For those *Swan implementations, the 'sha384' and 'sha512' auth
        algorithm is not supported and therefore request should be rejected.
        """
        if auth_algorithm in ["sha384", "sha512"]:
            raise IpsecValidationFailure(
                resource='IPsec Policy',
                key='auth_algorithm',
                value=auth_algorithm)

    def validate_ipsec_policy(self, context, ipsec_policy):
        transform_protocol = ipsec_policy.get('transform_protocol')
        self._check_transform_protocol(context, transform_protocol)
        auth_algorithm = ipsec_policy.get('auth_algorithm')
        self._check_auth_algorithm(context, auth_algorithm)

    def validate_ike_policy(self, context, ike_policy):
        """Restrict selecting sha384 and sha512 as IKE Policy auth algorithm.

        For those *Swan implementations, the 'sha384' and 'sha512' auth
        algorithm is not supported and therefore request should be rejected.
        """
        auth_algorithm = ike_policy.get('auth_algorithm')
        if auth_algorithm in ["sha384", "sha512"]:
            raise IkeValidationFailure(
                resource='IKE Policy',
                key='auth_algorithm',
                value=auth_algorithm)
