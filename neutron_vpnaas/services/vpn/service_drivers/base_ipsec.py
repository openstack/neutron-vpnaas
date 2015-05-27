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
from oslo_log import log as logging
import oslo_messaging
import six

from neutron_vpnaas.services.vpn import service_drivers


LOG = logging.getLogger(__name__)

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

    def get_vpn_services_on_host(self, context, host=None):
        """Returns the vpnservices on the host."""
        plugin = self.driver.service_plugin
        vpnservices = plugin._get_agent_hosting_vpn_services(
            context, host)
        return [self.driver.make_vpnservice_dict(vpnservice)
                for vpnservice in vpnservices]

    def update_status(self, context, status):
        """Update status of vpnservices."""
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class IPsecVpnAgentApi(service_drivers.BaseIPsecVpnAgentApi):
    """Agent RPC API for IPsecVPNAgent."""

    target = oslo_messaging.Target(version=BASE_IPSEC_VERSION)

    def __init__(self, topic, default_version, driver):
        super(IPsecVpnAgentApi, self).__init__(
            topic, default_version, driver)


@six.add_metaclass(abc.ABCMeta)
class BaseIPsecVPNDriver(service_drivers.VpnDriver):
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
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

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

    def create_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def assign_ipsec_sitecon_external_ip(self, vpnservice, ipsec_site_con):
        """Assign external_ip to ipsec siteconn.

        We need to assign ip from gateway based on the
        ip version of peer_address.
        """
        ip_version = netaddr.IPAddress(ipsec_site_con['peer_address']).version
        # *Swan use same ip version for left and right gateway ips
        # If gateway has multiple GUA, we assign the first one, as
        # any GUA can be used to reach the external network
        for fixed_ip in vpnservice.router.gw_port['fixed_ips']:
            addr = fixed_ip['ip_address']
            if ip_version == netaddr.IPAddress(addr).version:
                ipsec_site_con['external_ip'] = addr
                break

    def make_vpnservice_dict(self, vpnservice):
        """Convert vpnservice information for vpn agent.

        also converting parameter name for vpn agent driver
        """
        vpnservice_dict = dict(vpnservice)
        vpnservice_dict['ipsec_site_connections'] = []
        vpnservice_dict['subnet'] = dict(
            vpnservice.subnet)
        # Not removing external_ip from vpnservice_dict, as some providers
        # may be still using it from vpnservice_dict
        vpnservice_dict['external_ip'] = vpnservice.router.gw_port[
            'fixed_ips'][0]['ip_address']
        for ipsec_site_connection in vpnservice.ipsec_site_connections:
            ipsec_site_connection_dict = dict(ipsec_site_connection)
            try:
                netaddr.IPAddress(ipsec_site_connection_dict['peer_id'])
            except netaddr.core.AddrFormatError:
                ipsec_site_connection_dict['peer_id'] = (
                    '@' + ipsec_site_connection_dict['peer_id'])
            ipsec_site_connection_dict['ikepolicy'] = dict(
                ipsec_site_connection.ikepolicy)
            ipsec_site_connection_dict['ipsecpolicy'] = dict(
                ipsec_site_connection.ipsecpolicy)
            vpnservice_dict['ipsec_site_connections'].append(
                ipsec_site_connection_dict)
            peer_cidrs = [
                peer_cidr.cidr
                for peer_cidr in ipsec_site_connection.peer_cidrs]
            ipsec_site_connection_dict['peer_cidrs'] = peer_cidrs
            self.assign_ipsec_sitecon_external_ip(
                vpnservice, ipsec_site_connection_dict)
        return vpnservice_dict
