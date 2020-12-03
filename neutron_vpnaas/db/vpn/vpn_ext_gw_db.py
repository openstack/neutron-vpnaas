#    (c) Copyright 2016 IBM Corporation, All Rights Reserved.
#    (c) Copyright 2023 SysEleven GmbH
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

from neutron.db.models import l3 as l3_models
from neutron.db import models_v2
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib.db import api as db_api
from neutron_lib.db import model_base
from neutron_lib.db import model_query
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn.common import constants as v_constants


LOG = logging.getLogger(__name__)


class RouterIsNotVPNExternal(n_exc.BadRequest):
    message = _("Router %(router_id)s has no VPN external network gateway set")


class RouterHasVPNExternal(n_exc.BadRequest):
    message = _(
        "Router %(router_id)s already has VPN external network gateway")


class VPNNetworkInUse(n_exc.NetworkInUse):
    message = _("Network %(network_id)s is used by VPN service")


class VPNExtGW(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    __tablename__ = 'vpn_ext_gws'
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'),
                          nullable=False, unique=True)
    status = sa.Column(sa.String(16), nullable=False)
    gw_port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete='SET NULL'))
    transit_port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete='SET NULL'))
    transit_network_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('networks.id', ondelete='SET NULL'))
    transit_subnet_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('subnets.id', ondelete='SET NULL'))

    gw_port = orm.relationship(models_v2.Port, lazy='joined',
                               foreign_keys=[gw_port_id])
    transit_port = orm.relationship(models_v2.Port, lazy='joined',
                                    foreign_keys=[transit_port_id])
    transit_network = orm.relationship(models_v2.Network)
    transit_subnet = orm.relationship(models_v2.Subnet)
    router = orm.relationship(l3_models.Router)


@registry.has_registry_receivers
class VPNExtGWPlugin_db(object):
    """DB class to support vpn external ports configuration."""

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    @property
    def _vpn_plugin(self):
        return directory.get_plugin(plugin_const.VPN)

    @staticmethod
    @registry.receives(resources.PORT, [events.BEFORE_DELETE])
    def _prevent_vpn_port_delete_callback(resource, event,
                                          trigger, payload=None):
        vpn_plugin = directory.get_plugin(plugin_const.VPN)
        if vpn_plugin:
            vpn_plugin.prevent_vpn_port_deletion(payload.context,
                                                 payload.resource_id)

    @db_api.CONTEXT_READER
    def _id_used(self, context, id_column, resource_id):
        return context.session.query(VPNExtGW).filter(
            sa.and_(
                id_column == resource_id,
                VPNExtGW.status != lib_constants.PENDING_DELETE
            )
        ).count() > 0

    def prevent_vpn_port_deletion(self, context, port_id):
        """Checks to make sure a port is allowed to be deleted.

        Raises an exception if this is not the case.  This should be called by
        any plugin when the API requests the deletion of a port, since some
        ports for L3 are not intended to be deleted directly via a DELETE
        to /ports, but rather via other API calls that perform the proper
        deletion checks.
        """
        try:
            port = self._core_plugin.get_port(context, port_id)
        except n_exc.PortNotFound:
            # non-existent ports don't need to be protected from deletion
            return

        port_id_column = {
            v_constants.DEVICE_OWNER_VPN_ROUTER_GW: VPNExtGW.gw_port_id,
            v_constants.DEVICE_OWNER_TRANSIT_NETWORK:
                VPNExtGW.transit_port_id,
        }.get(port['device_owner'])

        if not port_id_column:
            # This is not a VPN port
            return

        if self._id_used(context, port_id_column, port_id):
            reason = _('has device owner %s') % port['device_owner']
            raise n_exc.ServicePortInUse(port_id=port['id'], reason=reason)

    @staticmethod
    @registry.receives(resources.SUBNET, [events.BEFORE_DELETE])
    def _prevent_vpn_subnet_delete_callback(resource, event,
                                            trigger, payload=None):
        vpn_plugin = directory.get_plugin(plugin_const.VPN)
        if vpn_plugin:
            vpn_plugin.prevent_vpn_subnet_deletion(payload.context,
                                                   payload.resource_id)

    def prevent_vpn_subnet_deletion(self, context, subnet_id):
        if self._id_used(context, VPNExtGW.transit_subnet_id, subnet_id):
            reason = _('Subnet is used by VPN service')
            raise n_exc.SubnetInUse(subnet_id=subnet_id, reason=reason)

    @staticmethod
    @registry.receives(resources.NETWORK, [events.BEFORE_DELETE])
    def _prevent_vpn_network_delete_callback(resource, event,
                                             trigger, payload=None):
        vpn_plugin = directory.get_plugin(plugin_const.VPN)
        if vpn_plugin:
            vpn_plugin.prevent_vpn_network_deletion(payload.context,
                                                    payload.resource_id)

    def prevent_vpn_network_deletion(self, context, network_id):
        if self._id_used(context, VPNExtGW.transit_network_id, network_id):
            raise VPNNetworkInUse(network_id=network_id)

    def _make_vpn_ext_gw_dict(self, gateway_db):
        if not gateway_db:
            return None
        gateway = {
            'id': gateway_db['id'],
            'tenant_id': gateway_db['tenant_id'],
            'router_id': gateway_db['router_id'],
            'status': gateway_db['status'],
        }
        if gateway_db.gw_port:
            gateway['network_id'] = gateway_db.gw_port['network_id']
            gateway['external_fixed_ips'] = [
                {'subnet_id': ip["subnet_id"], 'ip_address': ip["ip_address"]}
                for ip in gateway_db.gw_port['fixed_ips']
            ]
        for key in ('gw_port_id', 'transit_port_id', 'transit_network_id',
                    'transit_subnet_id'):
            value = gateway_db.get(key)
            if value:
                gateway[key] = value
        return gateway

    def _get_vpn_gw_by_router_id(self, context, router_id):
        try:
            gateway_db = context.session.query(VPNExtGW).filter(
                VPNExtGW.router_id == router_id).one()
        except exc.NoResultFound:
            return None
        return gateway_db

    @db_api.CONTEXT_READER
    def get_vpn_gw_by_router_id(self, context, router_id):
        return self._get_vpn_gw_by_router_id(context, router_id)

    @db_api.CONTEXT_READER
    def get_vpn_gw_dict_by_router_id(self, context, router_id, refresh=False):
        gateway_db = self._get_vpn_gw_by_router_id(context, router_id)
        if gateway_db and refresh:
            context.session.refresh(gateway_db)
        return self._make_vpn_ext_gw_dict(gateway_db)

    def create_gateway(self, context, gateway):
        info = gateway['gateway']

        with db_api.CONTEXT_WRITER.using(context):
            gateway_db = VPNExtGW(
                id=uuidutils.generate_uuid(),
                tenant_id=info['tenant_id'],
                router_id=info['router_id'],
                status=lib_constants.PENDING_CREATE,
                gw_port_id=info.get('gw_port_id'),
                transit_port_id=info.get('transit_port_id'),
                transit_network_id=info.get('transit_network_id'),
                transit_subnet_id=info.get('transit_subnet_id'))
            context.session.add(gateway_db)

        return self._make_vpn_ext_gw_dict(gateway_db)

    def update_gateway(self, context, gateway_id, gateway):
        info = gateway['gateway']
        with db_api.CONTEXT_WRITER.using(context):
            gateway_db = model_query.get_by_id(context, VPNExtGW, gateway_id)
            gateway_db.update(info)
            return self._make_vpn_ext_gw_dict(gateway_db)

    def delete_gateway(self, context, gateway_id):
        with db_api.CONTEXT_WRITER.using(context):
            query = context.session.query(VPNExtGW)
            return query.filter(VPNExtGW.id == gateway_id).delete()
