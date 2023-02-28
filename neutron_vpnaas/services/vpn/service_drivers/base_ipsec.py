# Copyright 2015, Nachi Ueno, NTT I3, Inc.
# All Rights Reserved.
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

import netaddr
import oslo_messaging

from neutron.db.models import l3agent
from neutron.db.models import servicetype
from neutron_lib import constants as lib_constants
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory

from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.services.vpn import service_drivers


IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'


class IPsecVpnDriverCallBack(object):
    """Callback for IPSecVpnDriver rpc."""

    # history
    #   1.0 Initial version

    target = oslo_messaging.Target(version=BASE_IPSEC_VERSION)

    def __init__(self, driver):
        super(IPsecVpnDriverCallBack, self).__init__()
        self.driver = driver

    def _get_agent_hosting_vpn_services(self, context, host):
        plugin = directory.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, lib_constants.AGENT_TYPE_L3, host)
        agent_conf = plugin.get_configuration_dict(agent)
        # Retrieve the agent_mode to check if this is the
        # right agent to deploy the vpn service. In the
        # case of distributed the vpn service should reside
        # only on a dvr_snat node.
        agent_mode = agent_conf.get('agent_mode', 'legacy')
        if not agent.admin_state_up or agent_mode == 'dvr':
            return []
        query = context.session.query(vpn_models.VPNService)
        query = query.join(vpn_models.IPsecSiteConnection)
        query = query.join(l3agent.RouterL3AgentBinding,
                           l3agent.RouterL3AgentBinding.router_id ==
                           vpn_models.VPNService.router_id)
        query = query.join(
            servicetype.ProviderResourceAssociation,
            servicetype.ProviderResourceAssociation.resource_id ==
            vpn_models.VPNService.id)
        query = query.filter(
            l3agent.RouterL3AgentBinding.l3_agent_id == agent.id)
        query = query.filter(
            servicetype.ProviderResourceAssociation.provider_name ==
            self.driver.name)
        return query

    @db_api.CONTEXT_READER
    def get_vpn_services_on_host(self, context, host=None):
        """Returns the vpnservices on the host."""
        vpnservices = self._get_agent_hosting_vpn_services(
            context, host)
        plugin = self.driver.service_plugin
        local_cidr_map = plugin._build_local_subnet_cidr_map(context)
        return [self.driver.make_vpnservice_dict(vpnservice, local_cidr_map)
                for vpnservice in vpnservices]

    def update_status(self, context, status):
        """Update status of vpnservices."""
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class IPsecVpnAgentApi(service_drivers.BaseIPsecVpnAgentApi):
    """Agent RPC API for IPsecVPNAgent."""

    target = oslo_messaging.Target(version=BASE_IPSEC_VERSION)

    # pylint: disable=useless-super-delegation
    def __init__(self, topic, default_version, driver):
        super(IPsecVpnAgentApi, self).__init__(
            topic, default_version, driver)


class BaseIPsecVPNDriver(service_drivers.VpnDriver, metaclass=abc.ABCMeta):
    """Base VPN Service Driver class."""

    def __init__(self, service_plugin, validator=None):
        super(BaseIPsecVPNDriver, self).__init__(service_plugin, validator)
        self.create_rpc_conn()

    @property
    def service_type(self):
        return IPSEC

    @abc.abstractmethod
    def create_rpc_conn(self):
        pass

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        router_id = self.service_plugin.get_vpnservice_router_id(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, router_id)

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        router_id = self.service_plugin.get_vpnservice_router_id(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, router_id)

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        router_id = self.service_plugin.get_vpnservice_router_id(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, router_id)

    def create_ikepolicy(self, context, ikepolicy):
        pass

    def delete_ikepolicy(self, context, ikepolicy):
        pass

    def update_ikepolicy(self, context, old_ikepolicy, ikepolicy):
        pass

    def create_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def delete_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def update_ipsecpolicy(self, context, old_ipsec_policy, ipsecpolicy):
        pass

    def _get_gateway_ips(self, router):
        """Obtain the IPv4 and/or IPv6 GW IP for the router.

        If there are multiples, (arbitrarily) use the first one.
        """
        v4_ip = v6_ip = None
        for fixed_ip in router.gw_port['fixed_ips']:
            addr = fixed_ip['ip_address']
            vers = netaddr.IPAddress(addr).version
            if vers == 4:
                if v4_ip is None:
                    v4_ip = addr
            elif v6_ip is None:
                v6_ip = addr
        return v4_ip, v6_ip

    @db_api.CONTEXT_WRITER
    def create_vpnservice(self, context, vpnservice_dict):
        """Get the gateway IP(s) and save for later use.

        For the reference implementation, this side's tunnel IP (external_ip)
        will be the router's GW IP. IPSec connections will use a GW IP of
        the same version, as is used for the peer, so we will collect the
        first IP for each version (if they exist) and save them.
        """
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_dict['id'])
        v4_ip, v6_ip = self._get_gateway_ips(vpnservice.router)
        vpnservice_dict['external_v4_ip'] = v4_ip
        vpnservice_dict['external_v6_ip'] = v6_ip
        self.service_plugin.set_external_tunnel_ips(context,
                                                    vpnservice_dict['id'],
                                                    v4_ip=v4_ip, v6_ip=v6_ip)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def get_external_ip_based_on_peer(self, vpnservice, ipsec_site_con):
        """Use service's external IP, based on peer IP version."""
        vers = netaddr.IPAddress(ipsec_site_con['peer_address']).version
        if vers == 4:
            ip_to_use = vpnservice.external_v4_ip
        else:
            ip_to_use = vpnservice.external_v6_ip
        # TODO(pcm): Add validator to check that connection's peer address has
        # a version that is available in service table, so can fail early and
        # don't need a check here.
        return ip_to_use

    def make_vpnservice_dict(self, vpnservice, local_cidr_map):
        """Convert vpnservice information for vpn agent.

        also converting parameter name for vpn agent driver
        """
        vpnservice_dict = dict(vpnservice)
        # Populate tenant_id for RPC compat
        vpnservice_dict['tenant_id'] = vpnservice_dict['project_id']
        vpnservice_dict['ipsec_site_connections'] = []
        if vpnservice.subnet:
            vpnservice_dict['subnet'] = dict(vpnservice.subnet)
        else:
            vpnservice_dict['subnet'] = None
            # NOTE: Following is used for rolling upgrades, where agent may be
            # at version N, and server at N+1. We need to populate the subnet
            # with (only) the CIDR from the first connection's local endpoint
            # group.
            subnet_cidr = None
        # Not removing external_ip from vpnservice_dict, as some providers
        # may be still using it from vpnservice_dict. Will use whichever IP
        # is specified.
        vpnservice_dict['external_ip'] = (
            vpnservice.external_v4_ip or vpnservice.external_v6_ip)
        for ipsec_site_connection in vpnservice.ipsec_site_connections:
            ipsec_site_connection_dict = dict(ipsec_site_connection)
            try:
                netaddr.IPAddress(ipsec_site_connection_dict['peer_id'])
                if ipsec_site_connection_dict['local_id']:
                    netaddr.IPAddress(ipsec_site_connection_dict['local_id'])
            except netaddr.core.AddrFormatError:
                ipsec_site_connection_dict['peer_id'] = (
                    '@' + ipsec_site_connection_dict['peer_id'])
                if ipsec_site_connection_dict['local_id']:
                    ipsec_site_connection_dict['local_id'] = (
                        '@' + ipsec_site_connection_dict['local_id'])
            ipsec_site_connection_dict['ikepolicy'] = dict(
                ipsec_site_connection.ikepolicy)
            ipsec_site_connection_dict['ipsecpolicy'] = dict(
                ipsec_site_connection.ipsecpolicy)
            vpnservice_dict['ipsec_site_connections'].append(
                ipsec_site_connection_dict)
            if vpnservice.subnet:
                local_cidrs = [vpnservice.subnet.cidr]
                peer_cidrs = [
                    peer_cidr.cidr
                    for peer_cidr in ipsec_site_connection.peer_cidrs]
            else:
                local_cidrs = [local_cidr_map[ep.endpoint]
                    for ep in ipsec_site_connection.local_ep_group.endpoints]
                peer_cidrs = [
                    ep.endpoint
                    for ep in ipsec_site_connection.peer_ep_group.endpoints]
                if not subnet_cidr:
                    epg = ipsec_site_connection.local_ep_group
                    subnet_cidr = local_cidr_map[epg.endpoints[0].endpoint]
            ipsec_site_connection_dict['peer_cidrs'] = peer_cidrs
            ipsec_site_connection_dict['local_cidrs'] = local_cidrs
            ipsec_site_connection_dict['local_ip_vers'] = netaddr.IPNetwork(
                local_cidrs[0]).version
            ipsec_site_connection_dict['external_ip'] = (
                self.get_external_ip_based_on_peer(vpnservice,
                                                   ipsec_site_connection_dict))
        if not vpnservice.subnet:
            vpnservice_dict['subnet'] = {'cidr': subnet_cidr}

        return vpnservice_dict
