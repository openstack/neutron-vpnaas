#    (c) Copyright 2016 IBM Corporation, All Rights Reserved.
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

from neutron_lib import constants as l3_constants

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
import sqlalchemy as sa
from sqlalchemy import orm

from neutron._i18n import _
from neutron.common import utils
from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import extraroute_db
from neutron.extensions import l3
from neutron.plugins.common import utils as p_utils

from neutron_vpnaas.extensions.vpn_ext_gw import VPN_GW

LOG = logging.getLogger(__name__)

DEVICE_OWNER_VPN_ROUTER_GW = l3_constants.DEVICE_OWNER_NETWORK_PREFIX + \
                             "vpn_outer_gateway"

class VPNEXTGWInfo(model_base.BASEV2):
    __tablename__ = 'vpn_ext_gws'
    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
    port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete="CASCADE"),
        primary_key=True)
    port = orm.relationship(models_v2.Port, lazy='joined')
    router = orm.relationship(l3_db.Router,
                              backref=orm.backref(VPN_GW,
                                                  uselist=False,
                                                  lazy='joined',
                                                  cascade='delete'))


class VPNExtGW_dbonly_mixin(extraroute_db.ExtraRoute_db_mixin):
    """Mixin class to support vpn external ports configuration on router."""

    def _extend_router_dict_vpn_ext_gw(self, router_res, router_db):
        router_res[VPN_GW] = \
            (VPNExtGW_dbonly_mixin._make_vpn_ext_gw_dict(
                router_db))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_vpn_ext_gw'])

    def _get_vpn_gw_port(self, context, router):
        return None

    def _update_current_vpn_gw_port(self, context, router_id, vpn_gw_port,
                                ext_ips):
        self._core_plugin.update_port(context, vpn_gw_port,
                                      {'port':{'fixed_ips': ext_ips}})
        context.session.expire(vpn_gw_port)

    def _delete_current_vpn_gw_port(self, context, router_id, router,
                                new_network_id):
        """Delete gw port if attached to an old network."""
        return None
        '''
        port_requires_deletion = (
            router.gw_port and router.gw_port['network_id'] != new_network_id)
        if not port_requires_deletion:
            return
        admin_ctx = context.elevated()
        old_network_id = router.gw_port['network_id']

        if self.get_floatingips_count(
                admin_ctx, {'router_id': [router_id]}):
            raise l3.RouterExternalGatewayInUseByFloatingIp(
                router_id=router_id, net_id=router.gw_port['network_id'])
        gw_ips = [x['ip_address'] for x in router.gw_port.fixed_ips]
        with context.session.begin(subtransactions=True):
            gw_port = router.gw_port
            router.gw_port = None
            context.session.add(router)
            context.session.expire(gw_port)
            self._check_router_gw_port_in_use(context, router_id)
        self._core_plugin.delete_port(
            admin_ctx, gw_port['id'], l3_port_check=False)
        registry.notify(resources.ROUTER_GATEWAY,
                        events.AFTER_DELETE, self,
                        router_id=router_id,
                        network_id=old_network_id,
                        gateway_ips=gw_ips)
        '''

    def _create_vpn_router_gw_port(self, context, router, network_id, ext_ips):
        # Port has no 'tenant-id', as it is hidden from user
        port_data = {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'fixed_ips': ext_ips or l3_constants.ATTR_NOT_SPECIFIED,
                     'device_id': router['id'],
                     'device_owner': DEVICE_OWNER_VPN_ROUTER_GW,
                     'admin_state_up': True,
                     'name': ''}
        gw_port = p_utils.create_port(self._core_plugin,
                                      context.elevated(), {'port': port_data})

        if not gw_port['fixed_ips']:
            LOG.debug('No IPs available for external network %s',
                      network_id)

        with context.session.begin(subtransactions=True):
            gw_port = self._core_plugin._get_port(context.elevated(),
                                                         gw_port['id'])

            vpn_router_port = VPNEXTGWInfo(
                router_id=router['id'],
                port_id=gw_port['id']
            )
            router['vpn_external_gateway_info'] = vpn_router_port
            context.session.add(router)
            context.session.add(vpn_router_port)

    def _create_vpn_gw_port(self, context, router_id, router, new_network_id,
                        ext_ips):
        '''
        new_valid_gw_port_attachment = (
            new_network_id and (not router.gw_port or
                                router.gw_port[
                                    'network_id'] != new_network_id))
        '''
        new_valid_gw_port_attachment = True
        if new_valid_gw_port_attachment:
            subnets = self._core_plugin.get_subnets_by_network(context,
                                                               new_network_id)
            try:
                kwargs = {'context': context, 'router_id': router_id,
                          'network_id': new_network_id, 'subnets': subnets}
                registry.notify(
                    resources.ROUTER_GATEWAY, events.BEFORE_CREATE, self,
                    **kwargs)
            except exceptions.CallbackFailure as e:
                # raise the underlying exception
                raise e.errors[0].error

            #self._check_for_dup_router_subnets(context, router,
            #                                   new_network_id, subnets)
            self._create_vpn_router_gw_port(context, router,
                                        new_network_id, ext_ips)
            registry.notify(resources.ROUTER_GATEWAY,
                            events.AFTER_CREATE,
                            self._create_vpn_gw_port,
                            gw_ips=ext_ips,
                            network_id=new_network_id,
                            router_id=router_id)

    def _update_router_vpn_gw_info(self, context, router_id, info,
                                   router=None):
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        vpn_gw_port = None
        router = router or self._get_router(context, router_id)
        vpn_ext_info = router['vpn_external_gateway_info']
        if vpn_ext_info:
            vpn_gw_port = vpn_ext_info.port
        ext_ips = info.get('external_fixed_ips') if info else []
        ext_ip_change = self._check_for_external_ip_change(
            context, vpn_gw_port, ext_ips)
        network_id = self._validate_gw_info(context, vpn_gw_port, info,
                                            ext_ips)
        if vpn_gw_port and ext_ip_change and vpn_gw_port['network_id'] \
                == network_id:
            self._update_current_vpn_gw_port(context, router_id, vpn_gw_port,
                                         ext_ips)
        else:
            self._delete_current_vpn_gw_port(context, router_id, router,
                                         network_id)
            self._create_vpn_gw_port(context, router_id, router, network_id,
                                 ext_ips)

    def create_router(self, context, router):
        r = router['router']
        vpn_gw_info = r.pop(VPN_GW, None)
        router_dict = super(VPNExtGW_dbonly_mixin, self).create_router(
            context, router)
        router_db = self._get_router(context, router_dict['id'])
        vpn_gw = None
        try:
            if vpn_gw_info:
                self._update_router_vpn_gw_info(context, router_db['id'],
                                                vpn_gw_info, router=router_db)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.debug(
                    "Could not update vpn gateway info, deleting router.")
                self.delete_router(context, router_db['id'])
        router[VPN_GW] = vpn_gw
        return self._make_router_dict(router_db)

    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            # check if route exists and have permission to access
            router_db = self._get_router(context, id)
            if 'routes' in r:
                self._update_extra_routes(context, router_db, r['routes'])
            routes = self._get_extra_routes_by_router_id(context, id)
        router_updated = super(VPNExtGW_dbonly_mixin, self). \
            update_router(context, id, router)
        router_updated['routes'] = routes

        return router_updated

    def _get_subnets_by_cidr(self, context, cidr):
        query_subnets = context.session.query(models_v2.Subnet)
        return query_subnets.filter_by(cidr=cidr).all()

    def _validate_routes_nexthop(self, cidrs, ips, routes, nexthop):
        # Note(nati): Nexthop should be connected,
        # so we need to check
        # nexthop belongs to one of cidrs of the router ports
        if not netaddr.all_matching_cidrs(nexthop, cidrs):
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is not connected with router'))
        # Note(nati) nexthop should not be same as fixed_ips
        if nexthop in ips:
            raise extraroute.InvalidRoutes(
                routes=routes,
                reason=_('the nexthop is used by router'))

    def _validate_routes(self, context,
                         router_id, routes):
        if len(routes) > cfg.CONF.max_routes:
            raise extraroute.RoutesExhausted(
                router_id=router_id,
                quota=cfg.CONF.max_routes)

        context = context.elevated()
        filters = {'device_id': [router_id]}
        ports = self._core_plugin.get_ports(context, filters)
        cidrs = []
        ips = []
        for port in ports:
            for ip in port['fixed_ips']:
                cidrs.append(self._core_plugin.get_subnet(
                    context, ip['subnet_id'])['cidr'])
                ips.append(ip['ip_address'])
        for route in routes:
            self._validate_routes_nexthop(
                cidrs, ips, routes, route['nexthop'])

    def _update_extra_routes(self, context, router, routes):
        self._validate_routes(context, router['id'],
                              routes)
        old_routes, routes_dict = self._get_extra_routes_dict_by_router_id(
            context, router['id'])
        added, removed = utils.diff_list_of_dict(old_routes,
                                                 routes)
        LOG.debug('Added routes are %s', added)
        for route in added:
            router_routes = RouterRoute(
                router_id=router['id'],
                destination=route['destination'],
                nexthop=route['nexthop'])
            context.session.add(router_routes)

        LOG.debug('Removed routes are %s', removed)
        for route in removed:
            context.session.delete(
                routes_dict[(route['destination'], route['nexthop'])])

    @staticmethod
    def _make_vpn_ext_gw_dict(router_db):
        vpn_gw_info = router_db[VPN_GW]
        if vpn_gw_info and vpn_gw_info.port:
            nw_id = vpn_gw_info.port['network_id']
            return {
                'network_id': nw_id,
                'external_fixed_ips': [
                    {'subnet_id': ip["subnet_id"],
                     'ip_address': ip["ip_address"]}
                    for ip in vpn_gw_info.port['fixed_ips']
                    ]
            }
        return None

    def _get_vpn_gw_info_by_router_id(self, context, id):
        query = context.session.query(RouterRoute)
        query = query.filter_by(router_id=id)
        return self._make_vpn_ext_gw_dict(query)

    def _get_extra_routes_dict_by_router_id(self, context, id):
        query = context.session.query(RouterRoute)
        query = query.filter_by(router_id=id)
        routes = []
        routes_dict = {}
        for route in query:
            routes.append({'destination': route['destination'],
                           'nexthop': route['nexthop']})
            routes_dict[(route['destination'], route['nexthop'])] = route
        return routes, routes_dict

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        super(VPNExtGW_dbonly_mixin,
              self)._confirm_router_interface_not_in_use(
            context, router_id, subnet_id)
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet['cidr'])
        extra_routes = self._get_extra_routes_by_router_id(context, router_id)
        for route in extra_routes:
            if netaddr.all_matching_cidrs(route['nexthop'], [subnet_cidr]):
                raise extraroute.RouterInterfaceInUseByRoute(
                    router_id=router_id, subnet_id=subnet_id)


class VPNExtGW_db_mixin(VPNExtGW_dbonly_mixin,
                        l3_db.L3_NAT_db_mixin):
    """Mixin class to support extra route configuration on router with rpc."""
    pass
