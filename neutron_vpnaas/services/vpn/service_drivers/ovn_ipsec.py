# Copyright 2016, Yi Jing Zhu, IBM.
# Copyright 2023, SysEleven GmbH
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

import netaddr

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib import context as nctx
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from neutron_lib import rpc as n_rpc

from oslo_config import cfg
from oslo_db import exception as o_exc
from oslo_log import log as logging

from neutron_vpnaas.db.vpn import vpn_agentschedulers_db as agent_db
from neutron_vpnaas.db.vpn.vpn_ext_gw_db import RouterIsNotVPNExternal
from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.services.vpn.common import constants as v_constants
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn.service_drivers import base_ipsec


LOG = logging.getLogger(__name__)

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'

TRANSIT_NETWORK_PREFIX = 'vpn-transit-network-'
TRANSIT_SUBNET_PREFIX = 'vpn-transit-subnet-'
TRANSIT_PORT_PREFIX = 'vpn-ns-'
VPN_GW_PORT_PREFIX = 'vpn-gw-'
VPN_TRANSIT_LIP = '169.254.0.1'
VPN_TRANSIT_RIP = '169.254.0.2'
VPN_TRANSIT_CIDR = '169.254.0.0/28'
HIDDEN_PROJECT_ID = ''


class IPsecVpnOvnDriverCallBack(base_ipsec.IPsecVpnDriverCallBack):
    def __init__(self, driver):
        super().__init__(driver)
        self.admin_ctx = nctx.get_admin_context()

    @property
    def core_plugin(self):
        return self.driver.core_plugin

    @property
    def service_plugin(self):
        return self.driver.service_plugin

    def _get_vpn_gateway(self, context, router_id):
        return self.service_plugin.get_vpn_gw_by_router_id(context, router_id)

    def get_vpn_transit_network_details(self, context, router_id):
        vpn_gw = self._get_vpn_gateway(context, router_id)
        network_id = vpn_gw.gw_port['network_id']
        external_network = self.core_plugin.get_network(context, network_id)

        details = {
            'gw_port': vpn_gw.gw_port,
            'transit_port': vpn_gw.transit_port,
            'transit_gateway_ip': VPN_TRANSIT_LIP,
            'external_network': external_network,
        }
        return details

    def get_subnet_info(self, context, subnet_id=None):
        try:
            return self.core_plugin.get_subnet(context, subnet_id)
        except n_exc.SubnetNotFound:
            return None

    def _get_agent_hosting_vpn_services(self, context, host):
        agent = self.service_plugin.get_vpn_agent_on_host(context, host)
        if not agent:
            return []

        # We're here because a VPN agent asked for the VPN services it's
        # hosting. This means, the agent is alive. This is a chance to
        # schedule VPN services of routers that are still unscheduled.
        if cfg.CONF.vpn_auto_schedule:
            self.service_plugin.auto_schedule_routers(context, agent)

        query = context.session.query(vpn_models.VPNService)
        query = query.join(vpn_models.IPsecSiteConnection)
        query = query.join(agent_db.RouterVPNAgentBinding,
                           agent_db.RouterVPNAgentBinding.router_id ==
                           vpn_models.VPNService.router_id)
        query = query.filter(
            agent_db.RouterVPNAgentBinding.vpn_agent_id == agent['id'])
        return query


@registry.has_registry_receivers
class BaseOvnIPsecVPNDriver(base_ipsec.BaseIPsecVPNDriver):
    def __init__(self, service_plugin):
        self._l3_plugin = None
        self._core_plugin = None
        super().__init__(service_plugin)

    @property
    def l3_plugin(self):
        if self._l3_plugin is None:
            self._l3_plugin = directory.get_plugin(plugin_constants.L3)
        return self._l3_plugin

    @property
    def core_plugin(self):
        if self._core_plugin is None:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_UPDATE])
    def _handle_router_precommit_update(self, resource, event, trigger,
                                        payload):
        """Check that a router update won't remove routes we need for VPN."""
        LOG.debug("Router %s PRECOMMIT_UPDATE event: %s",
                  payload.resource_id, payload.request_body)
        router_id = payload.resource_id
        context = payload.context
        router_data = payload.request_body
        routes_removed = router_data.get('routes_removed')

        if not routes_removed:
            return

        removed_cidrs = {r['destination'] for r in routes_removed}
        vpn_cidrs = set(
            self.service_plugin.get_peer_cidrs_for_router(context, router_id))
        conflict_cidrs = removed_cidrs.intersection(vpn_cidrs)

        if conflict_cidrs:
            raise vpnaas.RouteInUseByVPN(
                destinations=", ".join(conflict_cidrs))

    def get_vpn_gw_port_name(self, router_id):
        return VPN_GW_PORT_PREFIX + router_id

    def get_vpn_namespace_port_name(self, router_id):
        return TRANSIT_PORT_PREFIX + router_id

    def get_transit_network_name(self, router_id):
        return TRANSIT_NETWORK_PREFIX + router_id

    def get_transit_subnet_name(self, router_id):
        return TRANSIT_SUBNET_PREFIX + router_id

    def make_transit_network(self, router_id, tenant_id, agent_host,
                             gateway_update):
        context = nctx.get_admin_context()
        network_data = {
            'tenant_id': HIDDEN_PROJECT_ID,
            'name': self.get_transit_network_name(router_id),
            'admin_state_up': True,
            'shared': False,
        }
        network = p_utils.create_network(self.core_plugin, context,
                                         {'network': network_data})
        gateway_update['transit_network_id'] = network['id']

        # The subnet tenant_id must be of the user, otherwise updating the
        # router by the user may fail (it needs access to all subnets)
        subnet_data = {
            'tenant_id': tenant_id,
            'name': self.get_transit_subnet_name(router_id),
            'gateway_ip': VPN_TRANSIT_LIP,
            'cidr': VPN_TRANSIT_CIDR,
            'network_id': network['id'],
            'ip_version': 4,
            'enable_dhcp': False,
        }
        subnet = p_utils.create_subnet(self.core_plugin, context,
                                       {'subnet': subnet_data})
        gateway_update['transit_subnet_id'] = subnet['id']

        self.l3_plugin.add_router_interface(context, router_id,
                                            {'subnet_id': subnet['id']})

        fixed_ip = {'subnet_id': subnet['id'], 'ip_address': VPN_TRANSIT_RIP}
        port_data = {
            'tenant_id': HIDDEN_PROJECT_ID,
            'network_id': network['id'],
            'fixed_ips': [fixed_ip],
            'device_id': subnet['id'],
            'device_owner': v_constants.DEVICE_OWNER_TRANSIT_NETWORK,
            'admin_state_up': True,
            portbindings.HOST_ID: agent_host,
            'name': self.get_vpn_namespace_port_name(router_id)
        }
        port = p_utils.create_port(self.core_plugin, context,
                                   {"port": port_data})
        gateway_update['transit_port_id'] = port['id']

    def _del_port(self, context, port_id):
        try:
            self.core_plugin.delete_port(context, port_id, l3_port_check=False)
        except n_exc.PortNotFound:
            pass

    def _remove_router_interface(self, context, router_id, subnet_id):
        try:
            self.l3_plugin.remove_router_interface(
                context, router_id, {'subnet_id': subnet_id})
        except (n_exc.l3.RouterInterfaceNotFoundForSubnet,
                n_exc.SubnetNotFound):
            pass

    def _del_subnet(self, context, subnet_id):
        try:
            self.core_plugin.delete_subnet(context, subnet_id)
        except n_exc.SubnetNotFound:
            pass

    def _del_network(self, context, network_id):
        try:
            self.core_plugin.delete_network(context, network_id)
        except n_exc.NetworkNotFound:
            pass

    def del_transit_network(self, gw):
        context = nctx.get_admin_context()
        router_id = gw['router_id']

        port_id = gw.get('transit_port_id')
        if port_id:
            self._del_port(context, port_id)

        subnet_id = gw.get('transit_subnet_id')
        if subnet_id:
            self._remove_router_interface(context, router_id, subnet_id)
            self._del_subnet(context, subnet_id)

        network_id = gw.get('transit_network_id')
        if network_id:
            self._del_network(context, network_id)

    def make_gw_port(self, router_id, network_id, agent_host, gateway_update):
        context = nctx.get_admin_context()
        port_data = {'tenant_id': HIDDEN_PROJECT_ID,
                     'network_id': network_id,
                     'fixed_ips': lib_constants.ATTR_NOT_SPECIFIED,
                     'device_id': router_id,
                     'device_owner': v_constants.DEVICE_OWNER_VPN_ROUTER_GW,
                     'admin_state_up': True,
                     portbindings.HOST_ID: agent_host,
                     'name': self.get_vpn_gw_port_name(router_id)}
        gw_port = p_utils.create_port(self.core_plugin, context.elevated(),
                                      {'port': port_data})

        if not gw_port['fixed_ips']:
            LOG.debug('No IPs available for external network %s', network_id)
        gateway_update['gw_port_id'] = gw_port['id']

    def del_gw_port(self, gateway):
        context = nctx.get_admin_context()
        port_id = gateway.get('gw_port_id')
        if port_id:
            self._del_port(context, port_id)

    def _get_peer_cidrs(self, vpnservice):
        cidrs = []
        for ipsec_site_connection in vpnservice.ipsec_site_connections:
            if ipsec_site_connection.peer_cidrs:
                for peer_cidr in ipsec_site_connection.peer_cidrs:
                    cidrs.append(peer_cidr.cidr)
            if ipsec_site_connection.peer_ep_group is not None:
                for ep in ipsec_site_connection.peer_ep_group.endpoints:
                    cidrs.append(ep.endpoint)
        return cidrs

    def _routes_update(self, cidrs, nexthop):
        routes = [{'destination': cidr, 'nexthop': nexthop}
                  for cidr in cidrs]
        return {'router': {'routes': routes}}

    def _update_static_routes(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin.get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        router_id = vpnservice['router_id']
        gw = self.service_plugin.get_vpn_gw_by_router_id(context, router_id)

        nexthop = gw.transit_port['fixed_ips'][0]['ip_address']

        router = self.l3_plugin.get_router(context, router_id)
        old_routes = router.get('routes', [])

        old_cidrs = set([r['destination'] for r in old_routes
                         if r['nexthop'] == nexthop])
        new_cidrs = set(
            self.service_plugin.get_peer_cidrs_for_router(context, router_id))

        to_remove = old_cidrs - new_cidrs
        if to_remove:
            self.l3_plugin.remove_extraroutes(context, router_id,
                self._routes_update(to_remove, nexthop))

        to_add = new_cidrs - old_cidrs
        if to_add:
            self.l3_plugin.add_extraroutes(context, router_id,
                self._routes_update(to_add, nexthop))

    def _get_gateway_ips(self, router):
        """Obtain the IPv4 and/or IPv6 GW IP for the router.

        If there are multiples, (arbitrarily) use the first one.
        """
        gateway = self.service_plugin.get_vpn_gw_dict_by_router_id(
            nctx.get_admin_context(),
            router['id'])
        if gateway is None or gateway['external_fixed_ips'] is None:
            raise RouterIsNotVPNExternal(router_id=router['id'])

        v4_ip = v6_ip = None
        for fixed_ip in gateway['external_fixed_ips']:
            addr = fixed_ip['ip_address']
            vers = netaddr.IPAddress(addr).version
            if vers == lib_constants.IP_VERSION_4:
                if v4_ip is None:
                    v4_ip = addr
            elif v6_ip is None:
                v6_ip = addr
        return v4_ip, v6_ip

    def _update_gateway(self, context, gateway_id, **kwargs):
        gateway = {'gateway': kwargs}
        return self.service_plugin.update_gateway(context, gateway_id, gateway)

    @db_api.retry_if_session_inactive()
    def _ensure_gateway(self, context, vpnservice):
        gw = self.service_plugin.get_vpn_gw_dict_by_router_id(
            context, vpnservice['router_id'], refresh=True)
        if not gw:
            gateway = {'gateway': {
                'router_id': vpnservice['router_id'],
                'tenant_id': vpnservice['tenant_id'],
            }}
            # create_gateway may raise oslo_db.exception.DBDuplicateEntry
            # if someone else created one in the meantime
            return self.service_plugin.create_gateway(context, gateway)

        if gw['status'] == lib_constants.ERROR:
            raise vpnaas.VPNGatewayInError()

        # Raise an exception if an existing gateway is in status
        # PENDING_CREATE or PENDING_DELETE.
        # One of the next retries should succeed.
        if gw['status'] != lib_constants.ACTIVE:
            raise o_exc.RetryRequest(vpnaas.VPNGatewayNotReady())
        return gw

    @db_api.CONTEXT_WRITER
    def _setup(self, context, vpnservice_dict):
        router_id = vpnservice_dict['router_id']
        agent = self.service_plugin.schedule_router(context, router_id)
        if not agent:
            raise vpnaas.NoVPNAgentAvailable
        agent_host = agent['host']

        gateway = self._ensure_gateway(context, vpnservice_dict)

        # If the gateway status is ACTIVE the ports have been created already
        if gateway['status'] == lib_constants.ACTIVE:
            return

        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_dict['id'])
        network_id = vpnservice.router.gw_port.network_id
        gateway_update = {}  # keeps track of already-created IDs
        try:
            self.make_gw_port(router_id, network_id, agent_host,
                              gateway_update)
            self.make_transit_network(router_id,
                                      vpnservice_dict['tenant_id'],
                                      agent_host,
                                      gateway_update)
        except Exception:
            self._update_gateway(context, gateway['id'],
                status=lib_constants.ERROR,
                **gateway_update)
            raise

        self._update_gateway(context, gateway['id'],
            status=lib_constants.ACTIVE,
            **gateway_update)

    def _cleanup(self, context, router_id):
        gw = self.service_plugin.get_vpn_gw_dict_by_router_id(context,
                                                              router_id)
        if not gw:
            return
        self._update_gateway(context, gw['id'],
                             status=lib_constants.PENDING_DELETE)
        try:
            self.del_gw_port(gw)
            self.del_transit_network(gw)
            self.service_plugin.delete_gateway(context, gw['id'])
        except Exception:
            LOG.exception("Cleanup of VPN gateway for router %s failed.",
                          router_id)
            self._update_gateway(context, gw['id'],
                                 status=lib_constants.ERROR)
            raise

    def create_vpnservice(self, context, vpnservice_dict):
        try:
            self._setup(context, vpnservice_dict)
        except Exception:
            LOG.exception("Setting up the VPN gateway for router %s failed.",
                          vpnservice_dict['router_id'])
            self.service_plugin.set_vpnservice_status(
                context, vpnservice_dict['id'], lib_constants.ERROR,
                updated_pending_status=True)
            raise
        super().create_vpnservice(context, vpnservice_dict)

    def delete_vpnservice(self, context, vpnservice):
        router_id = vpnservice['router_id']
        super().delete_vpnservice(context, vpnservice)
        services = self.service_plugin.get_vpnservices(context)
        router_ids = [s['router_id'] for s in services]
        if router_id not in router_ids:
            self._cleanup(context, router_id)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        self._update_static_routes(context, ipsec_site_connection)
        super().create_ipsec_site_connection(context, ipsec_site_connection)

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        self._update_static_routes(context, ipsec_site_connection)
        super().delete_ipsec_site_connection(context, ipsec_site_connection)

    def update_ipsec_site_connection(
            self, context, old_ipsec_site_connection, ipsec_site_connection):
        self._update_static_routes(context, ipsec_site_connection)
        super().update_ipsec_site_connection(
            context, old_ipsec_site_connection, ipsec_site_connection)

    def _update_port_binding(self, context, port_id, host):
        port_data = {'binding:host_id': host}
        self.core_plugin.update_port(context, port_id, {'port': port_data})

    def update_port_bindings(self, context, router_id, host):
        gw = self.service_plugin.get_vpn_gw_dict_by_router_id(context,
                                                              router_id)
        if not gw:
            return
        port_id = gw.get('gw_port_id')
        if port_id:
            self._update_port_binding(context, port_id, host)
        port_id = gw.get('transit_port_id')
        if port_id:
            self._update_port_binding(context, port_id, host)


class IPsecOvnVpnAgentApi(base_ipsec.IPsecVpnAgentApi):
    def _agent_notification(self, context, method, router_id,
                            version=None, **kwargs):
        """Notify update for the agent.

        This method will find where is the router, and
        dispatch notification for the agent.
        """
        admin_context = context if context.is_admin else context.elevated()
        if not version:
            version = self.target.version

        vpn_agents = self.driver.service_plugin.get_vpn_agents_hosting_routers(
            admin_context, [router_id], active=True)

        for vpn_agent in vpn_agents:
            LOG.debug('Notify agent at %(topic)s.%(host)s the message '
                      '%(method)s %(args)s',
                      {'topic': self.topic,
                       'host': vpn_agent['host'],
                       'method': method,
                       'args': kwargs})
            cctxt = self.client.prepare(server=vpn_agent['host'],
                                        version=version)
            cctxt.cast(context, method, **kwargs)


class IPsecOvnVPNDriver(BaseOvnIPsecVPNDriver):
    """VPN Service Driver class for IPsec."""

    def create_rpc_conn(self):
        self.agent_rpc = IPsecOvnVpnAgentApi(
            topics.IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION, self)

    def start_rpc_listeners(self):
        self.endpoints = [IPsecVpnOvnDriverCallBack(self)]
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(
            topics.IPSEC_DRIVER_TOPIC, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()
