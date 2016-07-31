# Copyright 2016, Yi Jing Zhu, IBM.
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
import collections
import netaddr

from neutron.common import rpc as n_rpc
from neutron.common import utils as nutils
from neutron import context as nctx
from oslo_log import log as logging
from oslo_utils import uuidutils
from oslo_config import cfg

from neutron_vpnaas.extensions.vpn_ext_gw import VPN_GW
from neutron_vpnaas.extensions.vpn_ext_gw import RouterIsNotVPNExternal
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn.service_drivers import base_ipsec
from neutron_vpnaas.services.vpn.service_drivers import ipsec_validator

from networking_ovn.common import constants as ovn_const
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.common import utils

LOG = logging.getLogger(__name__)

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'

PROVEIDER_NETWORK4VPN = 'provider-network4vpn'
TRANSIT_NETWORK4VPN = 'transit-network4vpn'
TRANSIT_SUBNET4VPN = 'transit-subnet4vpn'
VPN_TRANSIT_LIP = '169.254.0.1'
VPN_TRANSIT_RIP = '169.254.0.2'

OvnPortInfo = collections.namedtuple('OvnPortInfo', ['type', 'options',
                                                     'addresses',
                                                     'port_security',
                                                     'parent_name', 'tag'])


class IPsecHelper(object):
    def __init__(self):
        self._nb_ovn = None
    
    @property
    def _ovn(self):
        if self._nb_ovn is None:
            self._nb_ovn = impl_idl_ovn.OvsdbNbOvnIdl(self)
        return self._nb_ovn
    
    def _get_vpn_internal_port(self, router_id, port_name, host):
        lswitch_name = self.get_transit_network(router_id)
        external_ids = {
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}
        switches = self._ovn.get_all_logical_switches_with_ports()

        for switch in switches:
            if switch['name'] == lswitch_name:
                for switch_port in switch['ports']:
                    ovn_port = self._ovn.get_logical_switch_port(switch_port)
                    if ovn_port['external_ids'] == external_ids:
                        addresses = ovn_port['addresses'][0].split(' ')
                        ovn_port['mac_address'] = addresses[0]
                        ovn_port['fixed_ips'] = [addresses[1]]
                        return ovn_port

        return None

    def _make_vpn_port(self, port, host, ptype='external', router_id=None):
        parent_name = None
        tag = None
        port_type = None
        options = {}
        addresses = port['port']['mac_address'] + ' ' + \
                    port['port']['fixed_ips'][0]
        port_security = []
        ovn_port_info = OvnPortInfo(port_type, options, [addresses],
                                    port_security, parent_name, tag)
        
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                            port['port']['name']}
        lswitch_name = self.get_transit_network(router_id)
        
        ovn_port = self._get_vpn_internal_port(router_id, port['port']['name'],
                                               host)

        if ovn_port:
            return ovn_port['name']

        with self._ovn.transaction(check_error=True) as txn:
            # The lport_name *must* be neutron port['id'].  It must match the
            # iface-id set in the Interfaces table of the Open_vSwitch
            # database which nova sets to be the port ID.
            ovn_port = txn.add(self._ovn.create_lswitch_port(
                lport_name=uuidutils.generate_uuid(),
                lswitch_name=lswitch_name,
                addresses=ovn_port_info.addresses,
                external_ids=external_ids,
                parent_name=ovn_port_info.parent_name,
                tag=ovn_port_info.tag,
                enabled=True,
                options=ovn_port_info.options,
                type=ovn_port_info.type,
                port_security=ovn_port_info.port_security))
        
        return ovn_port.lport
    
    def make_vpn_internal_port(self, port, host, router_id):
        port['port']['fixed_ips'] = [VPN_TRANSIT_RIP]
        port['port']['mac_address'] = nutils.get_random_mac(
            cfg.CONF.base_mac.split(':'))
        return self._make_vpn_port(port, host, ptype='internal',
                                   router_id=router_id)
    
    def get_vpn_namespace_port_name(self, router_id, host):
        return 'vns' + router_id + ' ' + str(host)
    
    def get_vpn_router_port_name(self, router_id):
        return 'vr' + router_id
    
    def del_vpn_internal_port(self, host, tenant_id):
        pass
    
    def get_transit_network(self, router_id):
        switches = self._ovn.get_all_logical_switches_ids()
        ext_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                       TRANSIT_NETWORK4VPN + '-' + router_id}
        for key in switches.keys():
            if switches[key] == ext_ids:
                return key
        return None
    
    def get_subnet_by_id(self, subnet_id):
        pass
    
    def make_transit_network(self, router_id):
        network = self.get_transit_network(router_id)
        if network:
            return network
        
        ext_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                       TRANSIT_NETWORK4VPN + '-' + router_id}
        lswitch_name = utils.ovn_name(uuidutils.generate_uuid())
        with self._ovn.transaction(check_error=True) as txn:
            network = txn.add(self._ovn.create_lswitch(
                lswitch_name=lswitch_name,
                external_ids=ext_ids))
        return network.name
    
    def del_transit_network(self, router_id):
        network = self.get_transit_network(router_id)
        if network:
            self._ovn.delete_lswitch(lswitch_name=network).execute(
                check_error=True)
    
    def add_router_transit_port(self, router_id, tenant_id):
        mac = nutils.get_random_mac(cfg.CONF.base_mac.split(':'))
        port_name = self.get_vpn_router_port_name(router_id)
        port = {
            'name': port_name,
            'fixed_ips': [VPN_TRANSIT_LIP],
            'mac_address': mac
        }
        ovn_port = self._get_vpn_internal_port(router_id, port_name, None)
        if ovn_port:
            return
        
        lport = self._make_vpn_port({'port': port}, None, ptype='internal',
                                    router_id=router_id)
        
        lrouter = utils.ovn_name(router_id)
        networks = ["%s/%s" % (VPN_TRANSIT_LIP, 28)]
        
        lrouter_port_name = utils.ovn_lrouter_port_name(lport)
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.add_lrouter_port(name=lrouter_port_name,
                                               lrouter=lrouter,
                                               mac=mac,
                                               networks=networks))
            
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                lport, lrouter_port_name))
    
    def del_router_transit_port(self, router_id, tenant_id):
        port_name = self.get_vpn_router_port_name(router_id)
        ovn_port = self._get_vpn_internal_port(router_id, port_name, None)
        if ovn_port == None:
            return
        
        lrouter = utils.ovn_name(router_id)
        lrouter_port_name = utils.ovn_lrouter_port_name(ovn_port['name'])
        self._ovn.delete_lrouter_port(lrouter_port_name, lrouter).execute(
            check_error=True)
    
    def _get_peer_cidrs(self, vpnservice):
        cidrs = []
        for ipsec_site_connection in vpnservice.ipsec_site_connections:
            for peer_cidr in ipsec_site_connection.peer_cidrs:
                cidrs.append(peer_cidr.cidr)
        return cidrs
    
    def set_static_route(self, vpnservice):
        cidrs = self._get_peer_cidrs(vpnservice)
        router_id = vpnservice['router_id']
        port_name = self.get_vpn_namespace_port_name(router_id, None)
        port = self._get_vpn_internal_port(router_id, port_name, None)
        
        if not port:
            return
        
        nexthop = port['fixed_ips'][0]
        router_name = utils.ovn_name(router_id)
        with self._ovn.transaction(check_error=True) as txn:
            for cidr in cidrs:
                txn.add(self._ovn.add_static_route(router_name,
                                                   ip_prefix=cidr,
                                                   nexthop=nexthop))
    
    def del_static_route(self, cidrs, vpnservice):
        router_id = vpnservice['router_id']
        port_name = self.get_vpn_namespace_port_name(router_id, None)
        port = self._get_vpn_internal_port(router_id, port_name, None)

        if not port:
            return
        
        nexthop = port['fixed_ips'][0]
        router_name = utils.ovn_name(router_id)
        
        with self._ovn.transaction(check_error=True) as txn:
            for cidr in cidrs:
                txn.add(self._ovn.delete_static_route(router_name,
                                                      ip_prefix=cidr,
                                                      nexthop=nexthop))

class IPsecVpnOvnDriverCallBack(base_ipsec.IPsecVpnDriverCallBack):
    def __init__(self, driver):
        super(IPsecVpnOvnDriverCallBack, self).__init__(driver)
        self.admin_ctx = nctx.get_admin_context()
        self._OVNHelper = None
    
    @property
    def _IPsecHelper(self):
        if self._OVNHelper is None:
            self._OVNHelper = IPsecHelper()
        return self._OVNHelper
    
    def get_provider_network4vpn(self, context):
        return None
    
    def get_transit_network4vpn(self, context, router_id=None):
        return self._IPsecHelper.get_transit_network(router_id)
    
    def get_subnet_info(self, context, subnet_id=None):
        return None
    
    def find_vpn_port(self, context, port_name, ptype=None, router_id=None,
                      host=None):
        if ptype == 'internal':
            return self._IPsecHelper._get_vpn_internal_port(router_id,
                                                            port_name, host)
        elif ptype == 'external':
            return self._IPsecHelper._gen_external_port(host, router_id)
        return None


class BaseOvnIPsecVPNDriver(base_ipsec.BaseIPsecVPNDriver):
    def __init__(self, service_plugin):
        self._OVNHelper = None
        super(BaseOvnIPsecVPNDriver, self).__init__(
            service_plugin,
            ipsec_validator.IpsecVpnValidator(service_plugin))
    
    @property
    def _IPsecHelper(self):
        if self._OVNHelper is None:
            self._OVNHelper = IPsecHelper()
        return self._OVNHelper

    def _get_gateway_ips(self, router):
        """Obtain the IPv4 and/or IPv6 GW IP for the router.

        If there are multiples, (arbitrarily) use the first one.
        """
        if router[VPN_GW] == None or router[VPN_GW].port == None:
            raise RouterIsNotVPNExternal(router_id=router['id'])
        
        v4_ip = v6_ip = None
        for fixed_ip in router[VPN_GW].port['fixed_ips']:
            addr = fixed_ip['ip_address']
            vers = netaddr.IPAddress(addr).version
            if vers == 4:
                if v4_ip is None:
                    v4_ip = addr
            elif v6_ip is None:
                v6_ip = addr
        return v4_ip, v6_ip
    
    def _setup(self, context, vpnservice_id):
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)

        # self._IPsecHelper._make_vpn_port('vg', vpnservice['router_id'], None)
        self._IPsecHelper.make_transit_network(vpnservice['router_id'])
        
        self._IPsecHelper.add_router_transit_port(vpnservice['router_id'],
                                                  vpnservice['tenant_id'])
        # prepare transit port for namespaces
        port_dict = dict(name=self._IPsecHelper.get_vpn_namespace_port_name(
            vpnservice['router_id'], None))
        self._IPsecHelper.make_vpn_internal_port({'port': port_dict}, None,
                                                 vpnservice['router_id'])

    def _cleanup(self, context, vpnservice):
        router_id = vpnservice['router_id']
        tenant_id = vpnservice['tenant_id']
        # delete vpn internal port
        self._IPsecHelper.del_vpn_internal_port(None, router_id)

        # del router transit port
        self._IPsecHelper.del_router_transit_port(router_id, tenant_id)

        # del transit network
        self._IPsecHelper.del_transit_network(router_id)

    def _set_requirements(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self._IPsecHelper.set_static_route(vpnservice)

    def _del_requirements(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        peer_cidrs = ipsec_site_connection['peer_cidrs']
        self._IPsecHelper.del_static_route(peer_cidrs, vpnservice)

    def create_vpnservice(self, context, vpnservice_dict):
        super(BaseOvnIPsecVPNDriver, self).create_vpnservice(context,
                                                             vpnservice_dict)
        self._setup(context, vpnservice_dict['id'])
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_dict['id'])
        self.agent_rpc.prepare_namespace(context, vpnservice['router_id'])

    def delete_vpnservice(self, context, vpnservice):
        router_id = vpnservice['router_id']
        super(BaseOvnIPsecVPNDriver, self).delete_vpnservice(context,
                                                             vpnservice)
        services = self.service_plugin.get_vpnservices(context)
        router_ids = [s['router_id'] for s in services]
        if router_id not in router_ids:
            self.agent_rpc.cleanup_namespace(context, vpnservice['router_id'])
            self._cleanup(context, vpnservice)
    
    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        self._set_requirements(context, ipsec_site_connection)
        super(BaseOvnIPsecVPNDriver, self).create_ipsec_site_connection(
            context, ipsec_site_connection)
    
    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        self._del_requirements(context, ipsec_site_connection)
        super(BaseOvnIPsecVPNDriver, self).delete_ipsec_site_connection(
            context, ipsec_site_connection)

    def update_ipsec_site_connection(
            self, context, old_ipsec_site_connection, ipsec_site_connection):
        self._del_requirements(context, old_ipsec_site_connection)
        self._set_requirements(context, ipsec_site_connection)
        super(BaseOvnIPsecVPNDriver, self).update_ipsec_site_connection(
            context, old_ipsec_site_connection, ipsec_site_connection)


class IPsecOvnVpnAgentApi(base_ipsec.IPsecVpnAgentApi):
    def prepare_namespace(self, context, router_id, **kwargs):
        kwargs['router'] = {'id': router_id}
        self._agent_notification(context, 'prepare_namespace', router_id,
                                 **kwargs)
    
    def cleanup_namespace(self, context, router_id, **kwargs):
        kwargs['router'] = {'id': router_id}
        self._agent_notification(context, 'cleanup_namespace', router_id,
                                 **kwargs)


class IPsecOvnVPNDriver(BaseOvnIPsecVPNDriver):
    """VPN Service Driver class for IPsec."""
    
    def __init__(self, service_plugin):
        super(IPsecOvnVPNDriver, self).__init__(service_plugin)
    
    def create_rpc_conn(self):
        self.endpoints = [IPsecVpnOvnDriverCallBack(self)]
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(
            topics.IPSEC_DRIVER_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = IPsecOvnVpnAgentApi(
            topics.IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION, self)
