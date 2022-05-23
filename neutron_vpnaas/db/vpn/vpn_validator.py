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

import socket

import netaddr
from neutron.db import l3_db
from neutron.db import models_v2
from neutron_lib.api import validators
from neutron_lib import exceptions as nexception
from neutron_lib.exceptions import vpn as vpn_exception
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn.common import constants


class VpnReferenceValidator(object):

    """
    Baseline validation routines for VPN resources.
    The validations here should be common to all VPN service providers and
    only raise exceptions from neutron_vpnaas.extensions.vpnaas.
    """

    IP_MIN_MTU = {4: 68, 6: 1280}

    @property
    def l3_plugin(self):
        try:
            return self._l3_plugin
        except AttributeError:
            self._l3_plugin = directory.get_plugin(plugin_const.L3)
            return self._l3_plugin

    @property
    def core_plugin(self):
        try:
            return self._core_plugin
        except AttributeError:
            self._core_plugin = directory.get_plugin()
            return self._core_plugin

    def _check_dpd(self, ipsec_sitecon):
        """Ensure that DPD timeout is greater than DPD interval."""
        if ipsec_sitecon['dpd_timeout'] <= ipsec_sitecon['dpd_interval']:
            raise vpn_exception.IPsecSiteConnectionDpdIntervalValueError(
                attr='dpd_timeout')

    def _check_mtu(self, context, mtu, ip_version):
        if mtu < VpnReferenceValidator.IP_MIN_MTU[ip_version]:
            raise vpn_exception.IPsecSiteConnectionMtuError(
                mtu=mtu, version=ip_version)

    def _validate_peer_address(self, ip_version, router):
        # NOTE: peer_address ip version should match with
        # at least one external gateway address ip version.
        # ipsec won't work with IPv6 LLA and neutron unaware GUA.
        # So to support vpnaas with ipv6, external network must
        # have ipv6 subnet
        for fixed_ip in router.gw_port['fixed_ips']:
            addr = fixed_ip['ip_address']
            if ip_version == netaddr.IPAddress(addr).version:
                return

        raise vpn_exception.ExternalNetworkHasNoSubnet(
            router_id=router.id,
            ip_version="IPv6" if ip_version == 6 else "IPv4")

    def resolve_peer_address(self, ipsec_sitecon, router):
        address = ipsec_sitecon['peer_address']
        # check if address is an ip address or fqdn
        invalid_ip_address = validators.validate_ip_address(address)
        if invalid_ip_address:
            # resolve fqdn
            try:
                addrinfo = socket.getaddrinfo(address, None)[0]
                ipsec_sitecon['peer_address'] = addrinfo[-1][0]
            except socket.gaierror:
                raise vpn_exception.VPNPeerAddressNotResolved(
                    peer_address=address)

        ip_version = netaddr.IPAddress(ipsec_sitecon['peer_address']).version
        self._validate_peer_address(ip_version, router)

    def _get_local_subnets(self, context, endpoint_group):
        if endpoint_group['type'] != constants.SUBNET_ENDPOINT:
            raise vpn_exception.WrongEndpointGroupType(
                group_type=endpoint_group['type'], which=endpoint_group['id'],
                expected=constants.SUBNET_ENDPOINT)
        subnet_ids = endpoint_group['endpoints']
        return context.session.query(models_v2.Subnet).filter(
            models_v2.Subnet.id.in_(subnet_ids)).all()

    def _get_peer_cidrs(self, endpoint_group):
        if endpoint_group['type'] != constants.CIDR_ENDPOINT:
            raise vpn_exception.WrongEndpointGroupType(
                group_type=endpoint_group['type'], which=endpoint_group['id'],
                expected=constants.CIDR_ENDPOINT)
        return endpoint_group['endpoints']

    def _check_local_endpoint_ip_versions(self, group_id, local_subnets):
        """Ensure all subnets in endpoint group have the same IP version.

        Will return the IP version, so it can be used for inter-group testing.
        """
        if len(local_subnets) == 1:
            return local_subnets[0]['ip_version']
        ip_versions = set([subnet['ip_version'] for subnet in local_subnets])
        if len(ip_versions) > 1:
            raise vpn_exception.MixedIPVersionsForIPSecEndpoints(
                group=group_id)
        return ip_versions.pop()

    def _check_peer_endpoint_ip_versions(self, group_id, peer_cidrs):
        """Ensure all CIDRs in endpoint group have the same IP version.

        Will return the IP version, so it can be used for inter-group testing.
        """
        if len(peer_cidrs) == 1:
            return netaddr.IPNetwork(peer_cidrs[0]).version
        ip_versions = set([netaddr.IPNetwork(pc).version for pc in peer_cidrs])
        if len(ip_versions) > 1:
            raise vpn_exception.MixedIPVersionsForIPSecEndpoints(
                group=group_id)
        return ip_versions.pop()

    def _check_peer_cidrs(self, peer_cidrs):
        """Ensure all CIDRs have the valid format."""
        for peer_cidr in peer_cidrs:
            msg = validators.validate_subnet(peer_cidr)
            if msg:
                raise vpn_exception.IPsecSiteConnectionPeerCidrError(
                    peer_cidr=peer_cidr)

    def _check_peer_cidrs_ip_versions(self, peer_cidrs):
        """Ensure all CIDRs have the same IP version."""
        if len(peer_cidrs) == 1:
            return netaddr.IPNetwork(peer_cidrs[0]).version
        ip_versions = set([netaddr.IPNetwork(pc).version for pc in peer_cidrs])
        if len(ip_versions) > 1:
            raise vpn_exception.MixedIPVersionsForPeerCidrs()
        return ip_versions.pop()

    def _check_local_subnets_on_router(self, context, router, local_subnets):
        for subnet in local_subnets:
            self._check_subnet_id(context, router, subnet['id'])

    def _validate_compatible_ip_versions(self, local_ip_version,
                                         peer_ip_version):
        if local_ip_version != peer_ip_version:
            raise vpn_exception.MixedIPVersionsForIPSecConnection()

    def validate_ipsec_conn_optional_args(self, ipsec_sitecon, subnet):
        """Ensure that proper combinations of optional args are used.

        When VPN service has a subnet, then we must have peer_cidrs, and
        cannot have any endpoint groups. If no subnet for the service, then
        we must have both endpoint groups, and no peer_cidrs. Method will
        form a string indicating which endpoints are incorrect, for any
        exception raised.
        """

        local_epg_id = ipsec_sitecon.get('local_ep_group_id')
        peer_epg_id = ipsec_sitecon.get('peer_ep_group_id')
        peer_cidrs = ipsec_sitecon.get('peer_cidrs')
        if subnet:
            if not peer_cidrs:
                raise vpn_exception.MissingPeerCidrs()
            epgs = []
            if local_epg_id:
                epgs.append('local')
            if peer_epg_id:
                epgs.append('peer')
            if epgs:
                which = ' and '.join(epgs)
                suffix = 's' if len(epgs) > 1 else ''
                raise vpn_exception.InvalidEndpointGroup(which=which,
                                                         suffix=suffix)
        else:
            if peer_cidrs:
                raise vpn_exception.PeerCidrsInvalid()
            epgs = []
            if not local_epg_id:
                epgs.append('local')
            if not peer_epg_id:
                epgs.append('peer')
            if epgs:
                which = ' and '.join(epgs)
                suffix = 's' if len(epgs) > 1 else ''
                raise vpn_exception.MissingRequiredEndpointGroup(
                    which=which, suffix=suffix)

    def assign_sensible_ipsec_sitecon_defaults(self, ipsec_sitecon,
                                               prev_conn=None):
        """Provide defaults for optional items, if missing.

        With endpoint groups capabilities, the peer_cidr (legacy mode)
        and endpoint group IDs (new mode), are optional. For updating,
        we need to provide the previous values for any missing values,
        so that we can detect if the update request is attempting to
        mix modes.

        Flatten the nested DPD information, and set default values for
        any missing information. For connection updates, the previous
        values will be used as defaults for any missing items.
        """

        if prev_conn:
            ipsec_sitecon.setdefault(
                'peer_cidrs', [pc['cidr'] for pc in prev_conn['peer_cidrs']])
            ipsec_sitecon.setdefault('local_ep_group_id',
                                     prev_conn['local_ep_group_id'])
            ipsec_sitecon.setdefault('peer_ep_group_id',
                                     prev_conn['peer_ep_group_id'])
        else:
            prev_conn = {'dpd_action': 'hold',
                         'dpd_interval': 30,
                         'dpd_timeout': 120}
        dpd = ipsec_sitecon.get('dpd', {})
        ipsec_sitecon['dpd_action'] = dpd.get('action',
                                              prev_conn['dpd_action'])
        ipsec_sitecon['dpd_interval'] = dpd.get('interval',
                                                prev_conn['dpd_interval'])
        ipsec_sitecon['dpd_timeout'] = dpd.get('timeout',
                                               prev_conn['dpd_timeout'])

    def validate_ipsec_site_connection(self, context, ipsec_sitecon,
                                       local_ip_version, vpnservice=None):
        """Reference implementation of validation for IPSec connection.

        This makes sure that IP versions are the same. For endpoint groups,
        we use the local subnet(s) IP versions, and peer CIDR(s) IP versions.
        For legacy mode, we use the (sole) subnet IP version, and the peer
        CIDR(s). All IP versions must be the same.

        This method also checks peer_cidrs format(legacy mode),
        MTU (based on the local IP version), and DPD settings.
        """
        if not local_ip_version:
            # Using endpoint groups
            local_subnets = self._get_local_subnets(
                context, ipsec_sitecon['local_epg_subnets'])
            self._check_local_subnets_on_router(
                context, vpnservice['router_id'], local_subnets)
            local_ip_version = self._check_local_endpoint_ip_versions(
                ipsec_sitecon['local_ep_group_id'], local_subnets)
            peer_cidrs = self._get_peer_cidrs(ipsec_sitecon['peer_epg_cidrs'])
            peer_ip_version = self._check_peer_endpoint_ip_versions(
                ipsec_sitecon['peer_ep_group_id'], peer_cidrs)
        else:
            self._check_peer_cidrs(ipsec_sitecon['peer_cidrs'])
            peer_ip_version = self._check_peer_cidrs_ip_versions(
                ipsec_sitecon['peer_cidrs'])
        self._validate_compatible_ip_versions(local_ip_version,
                                              peer_ip_version)

        self._check_dpd(ipsec_sitecon)
        mtu = ipsec_sitecon.get('mtu')
        if mtu:
            self._check_mtu(context, mtu, local_ip_version)

    def _check_router(self, context, router_id):
        router = self.l3_plugin.get_router(context, router_id)
        if not router.get(l3_db.EXTERNAL_GW_INFO):
            raise vpn_exception.RouterIsNotExternal(router_id=router_id)

    def _check_subnet_id(self, context, router_id, subnet_id):
        ports = self.core_plugin.get_ports(
            context,
            filters={
                'fixed_ips': {'subnet_id': [subnet_id]},
                'device_id': [router_id]})
        if not ports:
            raise vpn_exception.SubnetIsNotConnectedToRouter(
                subnet_id=subnet_id,
                router_id=router_id)

    def validate_vpnservice(self, context, vpnservice):
        self._check_router(context, vpnservice['router_id'])
        if vpnservice['subnet_id'] is not None:
            self._check_subnet_id(context, vpnservice['router_id'],
                                  vpnservice['subnet_id'])

    def validate_ipsec_policy(self, context, ipsec_policy):
        """Reference implementation of validation for IPSec Policy.

        Service driver can override and implement specific logic
        for IPSec Policy validation.
        """
        pass

    def _validate_cidrs(self, cidrs):
        """Ensure valid IPv4/6 CIDRs."""
        for cidr in cidrs:
            msg = validators.validate_subnet(cidr)
            if msg:
                raise vpn_exception.InvalidEndpointInEndpointGroup(
                    group_type=constants.CIDR_ENDPOINT, endpoint=cidr,
                    why=_("Invalid CIDR"))

    def _validate_subnets(self, context, subnet_ids):
        """Ensure UUIDs OK and subnets exist."""
        for subnet_id in subnet_ids:
            msg = validators.validate_uuid(subnet_id)
            if msg:
                raise vpn_exception.InvalidEndpointInEndpointGroup(
                    group_type=constants.SUBNET_ENDPOINT, endpoint=subnet_id,
                    why=_('Invalid UUID'))
            try:
                self.core_plugin.get_subnet(context, subnet_id)
            except nexception.SubnetNotFound:
                raise vpn_exception.NonExistingSubnetInEndpointGroup(
                    subnet=subnet_id)

    def validate_endpoint_group(self, context, endpoint_group):
        """Reference validator for endpoint group.

        Ensures that there is at least one endpoint, all the endpoints in the
        group are of the same type, and that the endpoints are "valid".
        Note: Only called for create, as endpoints cannot be changed.
        """
        endpoints = endpoint_group['endpoints']
        if not endpoints:
            raise vpn_exception.MissingEndpointForEndpointGroup(
                group=endpoint_group)
        group_type = endpoint_group['type']
        if group_type == constants.CIDR_ENDPOINT:
            self._validate_cidrs(endpoints)
        elif group_type == constants.SUBNET_ENDPOINT:
            self._validate_subnets(context, endpoints)

    def validate_ike_policy(self, context, ike_policy):
        """Reference implementation of validation for IKE Policy.

        Service driver can override and implement specific logic
        for IKE Policy validation.
        """
        pass
