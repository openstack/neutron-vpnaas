# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import netaddr
from netaddr import core as net_exc
from neutron_lib import exceptions as nexception
from oslo_log import log as logging

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn.service_drivers import driver_validator


LIFETIME_LIMITS = {'IKE Policy': {'min': 60, 'max': 86400},
                   'IPSec Policy': {'min': 120, 'max': 2592000}}
MIN_CSR_MTU = 1500
MAX_CSR_MTU = 9192

LOG = logging.getLogger(__name__)


class CsrValidationFailure(nexception.BadRequest):
    message = _("Cisco CSR does not support %(resource)s attribute %(key)s "
                "with value '%(value)s'")


class CiscoCsrVpnValidator(driver_validator.VpnDriverValidator):

    """Driver-specific validator methods for the Cisco CSR."""

    def validate_lifetime(self, for_policy, policy_info):
        """Ensure lifetime in secs and value is supported, based on policy."""
        units = policy_info['lifetime']['units']
        if units != 'seconds':
            raise CsrValidationFailure(resource=for_policy,
                                       key='lifetime:units',
                                       value=units)
        value = policy_info['lifetime']['value']
        if (value < LIFETIME_LIMITS[for_policy]['min'] or
            value > LIFETIME_LIMITS[for_policy]['max']):
            raise CsrValidationFailure(resource=for_policy,
                                       key='lifetime:value',
                                       value=value)

    def validate_ike_version(self, policy_info):
        """Ensure IKE policy is v1 for current REST API."""
        version = policy_info['ike_version']
        if version != 'v1':
            raise CsrValidationFailure(resource='IKE Policy',
                                       key='ike_version',
                                       value=version)

    def validate_mtu(self, conn_info):
        """Ensure the MTU value is supported."""
        mtu = conn_info['mtu']
        if mtu < MIN_CSR_MTU or mtu > MAX_CSR_MTU:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='mtu',
                                       value=mtu)

    def validate_public_ip_present(self, router):
        """Ensure there is one gateway IP specified for the router used."""
        gw_port = router.gw_port
        if not gw_port or len(gw_port.fixed_ips) != 1:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='router:gw_port:ip_address',
                                       value='missing')

    def validate_peer_id(self, ipsec_conn):
        """Ensure that an IP address is specified for peer ID."""
        # TODO(pcm) Should we check peer_address too?
        peer_id = ipsec_conn['peer_id']
        try:
            netaddr.IPAddress(peer_id)
        except net_exc.AddrFormatError:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='peer_id', value=peer_id)

    def validate_ipsec_encap_mode(self, ipsec_policy):
        """Ensure IPSec policy encap mode is tunnel for current REST API."""
        mode = ipsec_policy['encapsulation_mode']
        if mode != 'tunnel':
            raise CsrValidationFailure(resource='IPsec Policy',
                                       key='encapsulation_mode',
                                       value=mode)

    def validate_ike_auth_algorithm(self, ike_policy):
        """Ensure IKE Policy auth algorithm is supported."""
        auth_algorithm = ike_policy.get('auth_algorithm')
        if auth_algorithm in ["sha384", "sha512"]:
            raise CsrValidationFailure(resource='IKE Policy',
                                       key='auth_algorithm',
                                       value=auth_algorithm)

    def validate_ipsec_auth_algorithm(self, ipsec_policy):
        """Ensure IPSec Policy auth algorithm is supported."""
        auth_algorithm = ipsec_policy.get('auth_algorithm')
        if auth_algorithm in ["sha384", "sha512"]:
            raise CsrValidationFailure(resource='IPsec Policy',
                                       key='auth_algorithm',
                                       value=auth_algorithm)

    def validate_ipsec_site_connection(self, context, ipsec_sitecon):
        """Validate IPSec site connection for Cisco CSR.

        Do additional checks that relate to the Cisco CSR.
        """
        service_plugin = self.driver.service_plugin

        if 'ikepolicy_id' in ipsec_sitecon:
            ike_policy = service_plugin.get_ikepolicy(
                context, ipsec_sitecon['ikepolicy_id'])
            self.validate_lifetime('IKE Policy', ike_policy)
            self.validate_ike_version(ike_policy)
            self.validate_ike_auth_algorithm(ike_policy)

        if 'ipsecpolicy_id' in ipsec_sitecon:
            ipsec_policy = service_plugin.get_ipsecpolicy(
                context, ipsec_sitecon['ipsecpolicy_id'])
            self.validate_lifetime('IPSec Policy', ipsec_policy)
            self.validate_ipsec_auth_algorithm(ipsec_policy)
            self.validate_ipsec_encap_mode(ipsec_policy)

        if 'vpnservice_id' in ipsec_sitecon:
            vpn_service = service_plugin.get_vpnservice(
                context, ipsec_sitecon['vpnservice_id'])
            router = self.l3_plugin._get_router(
                context, vpn_service['router_id'])
            self.validate_public_ip_present(router)

        if 'mtu' in ipsec_sitecon:
            self.validate_mtu(ipsec_sitecon)

        if 'peer_id' in ipsec_sitecon:
            self.validate_peer_id(ipsec_sitecon)

        LOG.debug("IPSec connection validated for Cisco CSR")
