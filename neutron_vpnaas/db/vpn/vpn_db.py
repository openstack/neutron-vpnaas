#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as n_constants
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_agentschedulers_db as l3_agent_db
from neutron.extensions import l3 as l3_exception
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants
from neutron.plugins.common import utils
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
from sqlalchemy.orm import exc

from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.db.vpn import vpn_validator
from neutron_vpnaas.extensions import vpnaas

LOG = logging.getLogger(__name__)


class VPNPluginDb(vpnaas.VPNPluginBase, base_db.CommonDbMixin):
    """VPN plugin database class using SQLAlchemy models."""

    def _get_validator(self):
        """Obtain validator to use for attribute validation.

        Subclasses may override this with a different valdiator, as needed.
        Note: some UTs will directly create a VPNPluginDb object and then
        call its methods, instead of creating a VPNDriverPlugin, which
        will have a service driver associated that will provide a
        validator object. As a result, we use the reference validator here.
        """
        return vpn_validator.VpnReferenceValidator()

    def update_status(self, context, model, v_id, status):
        with context.session.begin(subtransactions=True):
            v_db = self._get_resource(context, model, v_id)
            v_db.update({'status': status})

    def _get_resource(self, context, model, v_id):
        try:
            r = self._get_by_id(context, model, v_id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, vpn_models.IPsecSiteConnection):
                    raise vpnaas.IPsecSiteConnectionNotFound(
                        ipsec_site_conn_id=v_id
                    )
                elif issubclass(model, vpn_models.IKEPolicy):
                    raise vpnaas.IKEPolicyNotFound(ikepolicy_id=v_id)
                elif issubclass(model, vpn_models.IPsecPolicy):
                    raise vpnaas.IPsecPolicyNotFound(ipsecpolicy_id=v_id)
                elif issubclass(model, vpn_models.VPNService):
                    raise vpnaas.VPNServiceNotFound(vpnservice_id=v_id)
                ctx.reraise = True
        return r

    def assert_update_allowed(self, obj):
        status = getattr(obj, 'status', None)
        _id = getattr(obj, 'id', None)
        if utils.in_pending_status(status):
            raise vpnaas.VPNStateInvalidToUpdate(id=_id, state=status)

    def _make_ipsec_site_connection_dict(self, ipsec_site_conn, fields=None):

        res = {'id': ipsec_site_conn['id'],
               'tenant_id': ipsec_site_conn['tenant_id'],
               'name': ipsec_site_conn['name'],
               'description': ipsec_site_conn['description'],
               'peer_address': ipsec_site_conn['peer_address'],
               'peer_id': ipsec_site_conn['peer_id'],
               'route_mode': ipsec_site_conn['route_mode'],
               'mtu': ipsec_site_conn['mtu'],
               'auth_mode': ipsec_site_conn['auth_mode'],
               'psk': ipsec_site_conn['psk'],
               'initiator': ipsec_site_conn['initiator'],
               'dpd': {
                   'action': ipsec_site_conn['dpd_action'],
                   'interval': ipsec_site_conn['dpd_interval'],
                   'timeout': ipsec_site_conn['dpd_timeout']
               },
               'admin_state_up': ipsec_site_conn['admin_state_up'],
               'status': ipsec_site_conn['status'],
               'vpnservice_id': ipsec_site_conn['vpnservice_id'],
               'ikepolicy_id': ipsec_site_conn['ikepolicy_id'],
               'ipsecpolicy_id': ipsec_site_conn['ipsecpolicy_id'],
               'peer_cidrs': [pcidr['cidr']
                              for pcidr in ipsec_site_conn['peer_cidrs']]
               }

        return self._fields(res, fields)

    def _get_subnet_ip_version(self, context, vpnservice_id):
        vpn_service_db = self._get_vpnservice(context, vpnservice_id)
        subnet = vpn_service_db.subnet['cidr']
        ip_version = netaddr.IPNetwork(subnet).version
        return ip_version

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        validator = self._get_validator()
        validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        tenant_id = self._get_tenant_id_for_create(context, ipsec_sitecon)
        with context.session.begin(subtransactions=True):
            #Check permissions
            self._get_resource(context, vpn_models.VPNService,
                               ipsec_sitecon['vpnservice_id'])
            self._get_resource(context, vpn_models.IKEPolicy,
                               ipsec_sitecon['ikepolicy_id'])
            self._get_resource(context, vpn_models.IPsecPolicy,
                               ipsec_sitecon['ipsecpolicy_id'])
            vpnservice_id = ipsec_sitecon['vpnservice_id']
            ip_version = self._get_subnet_ip_version(context, vpnservice_id)
            validator.validate_ipsec_site_connection(context,
                                                     ipsec_sitecon,
                                                     ip_version)
            vpnservice = self._get_vpnservice(context, vpnservice_id)
            validator.resolve_peer_address(ipsec_sitecon, vpnservice.router)
            ipsec_site_conn_db = vpn_models.IPsecSiteConnection(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ipsec_sitecon['name'],
                description=ipsec_sitecon['description'],
                peer_address=ipsec_sitecon['peer_address'],
                peer_id=ipsec_sitecon['peer_id'],
                route_mode='static',
                mtu=ipsec_sitecon['mtu'],
                auth_mode='psk',
                psk=ipsec_sitecon['psk'],
                initiator=ipsec_sitecon['initiator'],
                dpd_action=ipsec_sitecon['dpd_action'],
                dpd_interval=ipsec_sitecon['dpd_interval'],
                dpd_timeout=ipsec_sitecon['dpd_timeout'],
                admin_state_up=ipsec_sitecon['admin_state_up'],
                status=constants.PENDING_CREATE,
                vpnservice_id=vpnservice_id,
                ikepolicy_id=ipsec_sitecon['ikepolicy_id'],
                ipsecpolicy_id=ipsec_sitecon['ipsecpolicy_id']
            )
            context.session.add(ipsec_site_conn_db)
            for cidr in ipsec_sitecon['peer_cidrs']:
                peer_cidr_db = vpn_models.IPsecPeerCidr(
                    cidr=cidr,
                    ipsec_site_connection_id=ipsec_site_conn_db['id']
                )
                context.session.add(peer_cidr_db)
        return self._make_ipsec_site_connection_dict(ipsec_site_conn_db)

    def update_ipsec_site_connection(
            self, context,
            ipsec_site_conn_id, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        changed_peer_cidrs = False
        validator = self._get_validator()
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context, vpn_models.IPsecSiteConnection, ipsec_site_conn_id)
            vpnservice_id = ipsec_site_conn_db['vpnservice_id']
            ip_version = self._get_subnet_ip_version(context, vpnservice_id)
            validator.assign_sensible_ipsec_sitecon_defaults(
                ipsec_sitecon, ipsec_site_conn_db)
            validator.validate_ipsec_site_connection(
                context,
                ipsec_sitecon,
                ip_version)
            if 'peer_address' in ipsec_sitecon:
                vpnservice = self._get_vpnservice(context, vpnservice_id)
                validator.resolve_peer_address(ipsec_sitecon,
                                               vpnservice.router)
            self.assert_update_allowed(ipsec_site_conn_db)

            if "peer_cidrs" in ipsec_sitecon:
                changed_peer_cidrs = True
                old_peer_cidr_list = ipsec_site_conn_db['peer_cidrs']
                old_peer_cidr_dict = dict(
                    (peer_cidr['cidr'], peer_cidr)
                    for peer_cidr in old_peer_cidr_list)
                new_peer_cidr_set = set(ipsec_sitecon["peer_cidrs"])
                old_peer_cidr_set = set(old_peer_cidr_dict)

                new_peer_cidrs = list(new_peer_cidr_set)
                for peer_cidr in old_peer_cidr_set - new_peer_cidr_set:
                    context.session.delete(old_peer_cidr_dict[peer_cidr])
                for peer_cidr in new_peer_cidr_set - old_peer_cidr_set:
                    pcidr = vpn_models.IPsecPeerCidr(
                        cidr=peer_cidr,
                        ipsec_site_connection_id=ipsec_site_conn_id)
                    context.session.add(pcidr)
                del ipsec_sitecon["peer_cidrs"]
            if ipsec_sitecon:
                ipsec_site_conn_db.update(ipsec_sitecon)
        result = self._make_ipsec_site_connection_dict(ipsec_site_conn_db)
        if changed_peer_cidrs:
            result['peer_cidrs'] = new_peer_cidrs
        return result

    def delete_ipsec_site_connection(self, context, ipsec_site_conn_id):
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context, vpn_models.IPsecSiteConnection, ipsec_site_conn_id)
            context.session.delete(ipsec_site_conn_db)

    def _get_ipsec_site_connection(
            self, context, ipsec_site_conn_id):
        return self._get_resource(
            context, vpn_models.IPsecSiteConnection, ipsec_site_conn_id)

    def get_ipsec_site_connection(self, context,
                                  ipsec_site_conn_id, fields=None):
        ipsec_site_conn_db = self._get_ipsec_site_connection(
            context, ipsec_site_conn_id)
        return self._make_ipsec_site_connection_dict(
            ipsec_site_conn_db, fields)

    def get_ipsec_site_connections(self, context, filters=None, fields=None):
        return self._get_collection(context, vpn_models.IPsecSiteConnection,
                                    self._make_ipsec_site_connection_dict,
                                    filters=filters, fields=fields)

    def update_ipsec_site_conn_status(self, context, conn_id, new_status):
        with context.session.begin():
            self._update_connection_status(context, conn_id, new_status, True)

    def _update_connection_status(self, context, conn_id, new_status,
                                  updated_pending):
        """Update the connection status, if changed.

        If the connection is not in a pending state, unconditionally update
        the status. Likewise, if in a pending state, and have an indication
        that the status has changed, then update the database.
        """
        try:
            conn_db = self._get_ipsec_site_connection(context, conn_id)
        except vpnaas.IPsecSiteConnectionNotFound:
            return
        if not utils.in_pending_status(conn_db.status) or updated_pending:
            conn_db.status = new_status

    def _make_ikepolicy_dict(self, ikepolicy, fields=None):
        res = {'id': ikepolicy['id'],
               'tenant_id': ikepolicy['tenant_id'],
               'name': ikepolicy['name'],
               'description': ikepolicy['description'],
               'auth_algorithm': ikepolicy['auth_algorithm'],
               'encryption_algorithm': ikepolicy['encryption_algorithm'],
               'phase1_negotiation_mode': ikepolicy['phase1_negotiation_mode'],
               'lifetime': {
                   'units': ikepolicy['lifetime_units'],
                   'value': ikepolicy['lifetime_value'],
               },
               'ike_version': ikepolicy['ike_version'],
               'pfs': ikepolicy['pfs']
               }

        return self._fields(res, fields)

    def create_ikepolicy(self, context, ikepolicy):
        ike = ikepolicy['ikepolicy']
        tenant_id = self._get_tenant_id_for_create(context, ike)
        lifetime_info = ike.get('lifetime', [])
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with context.session.begin(subtransactions=True):
            ike_db = vpn_models.IKEPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ike['name'],
                description=ike['description'],
                auth_algorithm=ike['auth_algorithm'],
                encryption_algorithm=ike['encryption_algorithm'],
                phase1_negotiation_mode=ike['phase1_negotiation_mode'],
                lifetime_units=lifetime_units,
                lifetime_value=lifetime_value,
                ike_version=ike['ike_version'],
                pfs=ike['pfs']
            )

            context.session.add(ike_db)
        return self._make_ikepolicy_dict(ike_db)

    def update_ikepolicy(self, context, ikepolicy_id, ikepolicy):
        ike = ikepolicy['ikepolicy']
        with context.session.begin(subtransactions=True):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ikepolicy_id=ikepolicy_id).first():
                raise vpnaas.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(
                context, vpn_models.IKEPolicy, ikepolicy_id)
            if ike:
                lifetime_info = ike.get('lifetime')
                if lifetime_info:
                    if lifetime_info.get('units'):
                        ike['lifetime_units'] = lifetime_info['units']
                    if lifetime_info.get('value'):
                        ike['lifetime_value'] = lifetime_info['value']
                ike_db.update(ike)
        return self._make_ikepolicy_dict(ike_db)

    def delete_ikepolicy(self, context, ikepolicy_id):
        with context.session.begin(subtransactions=True):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ikepolicy_id=ikepolicy_id).first():
                raise vpnaas.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(
                context, vpn_models.IKEPolicy, ikepolicy_id)
            context.session.delete(ike_db)

    def get_ikepolicy(self, context, ikepolicy_id, fields=None):
        ike_db = self._get_resource(
            context, vpn_models.IKEPolicy, ikepolicy_id)
        return self._make_ikepolicy_dict(ike_db, fields)

    def get_ikepolicies(self, context, filters=None, fields=None):
        return self._get_collection(context, vpn_models.IKEPolicy,
                                    self._make_ikepolicy_dict,
                                    filters=filters, fields=fields)

    def _make_ipsecpolicy_dict(self, ipsecpolicy, fields=None):

        res = {'id': ipsecpolicy['id'],
               'tenant_id': ipsecpolicy['tenant_id'],
               'name': ipsecpolicy['name'],
               'description': ipsecpolicy['description'],
               'transform_protocol': ipsecpolicy['transform_protocol'],
               'auth_algorithm': ipsecpolicy['auth_algorithm'],
               'encryption_algorithm': ipsecpolicy['encryption_algorithm'],
               'encapsulation_mode': ipsecpolicy['encapsulation_mode'],
               'lifetime': {
                   'units': ipsecpolicy['lifetime_units'],
                   'value': ipsecpolicy['lifetime_value'],
               },
               'pfs': ipsecpolicy['pfs']
               }

        return self._fields(res, fields)

    def create_ipsecpolicy(self, context, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        tenant_id = self._get_tenant_id_for_create(context, ipsecp)
        lifetime_info = ipsecp['lifetime']
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with context.session.begin(subtransactions=True):
            ipsecp_db = vpn_models.IPsecPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ipsecp['name'],
                description=ipsecp['description'],
                transform_protocol=ipsecp['transform_protocol'],
                auth_algorithm=ipsecp['auth_algorithm'],
                encryption_algorithm=ipsecp['encryption_algorithm'],
                encapsulation_mode=ipsecp['encapsulation_mode'],
                lifetime_units=lifetime_units,
                lifetime_value=lifetime_value,
                pfs=ipsecp['pfs'])
            context.session.add(ipsecp_db)
        return self._make_ipsecpolicy_dict(ipsecp_db)

    def update_ipsecpolicy(self, context, ipsecpolicy_id, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        with context.session.begin(subtransactions=True):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ipsecpolicy_id=ipsecpolicy_id).first():
                raise vpnaas.IPsecPolicyInUse(ipsecpolicy_id=ipsecpolicy_id)
            ipsecp_db = self._get_resource(
                context, vpn_models.IPsecPolicy, ipsecpolicy_id)
            if ipsecp:
                lifetime_info = ipsecp.get('lifetime')
                if lifetime_info:
                    if lifetime_info.get('units'):
                        ipsecp['lifetime_units'] = lifetime_info['units']
                    if lifetime_info.get('value'):
                        ipsecp['lifetime_value'] = lifetime_info['value']
                ipsecp_db.update(ipsecp)
        return self._make_ipsecpolicy_dict(ipsecp_db)

    def delete_ipsecpolicy(self, context, ipsecpolicy_id):
        with context.session.begin(subtransactions=True):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ipsecpolicy_id=ipsecpolicy_id).first():
                raise vpnaas.IPsecPolicyInUse(ipsecpolicy_id=ipsecpolicy_id)
            ipsec_db = self._get_resource(
                context, vpn_models.IPsecPolicy, ipsecpolicy_id)
            context.session.delete(ipsec_db)

    def get_ipsecpolicy(self, context, ipsecpolicy_id, fields=None):
        ipsec_db = self._get_resource(
            context, vpn_models.IPsecPolicy, ipsecpolicy_id)
        return self._make_ipsecpolicy_dict(ipsec_db, fields)

    def get_ipsecpolicies(self, context, filters=None, fields=None):
        return self._get_collection(context, vpn_models.IPsecPolicy,
                                    self._make_ipsecpolicy_dict,
                                    filters=filters, fields=fields)

    def _make_vpnservice_dict(self, vpnservice, fields=None):
        res = {'id': vpnservice['id'],
               'name': vpnservice['name'],
               'description': vpnservice['description'],
               'tenant_id': vpnservice['tenant_id'],
               'subnet_id': vpnservice['subnet_id'],
               'router_id': vpnservice['router_id'],
               'admin_state_up': vpnservice['admin_state_up'],
               'external_v4_ip': vpnservice['external_v4_ip'],
               'external_v6_ip': vpnservice['external_v6_ip'],
               'status': vpnservice['status']}
        return self._fields(res, fields)

    def create_vpnservice(self, context, vpnservice):
        vpns = vpnservice['vpnservice']
        tenant_id = self._get_tenant_id_for_create(context, vpns)
        validator = self._get_validator()
        with context.session.begin(subtransactions=True):
            validator.validate_vpnservice(context, vpns)
            vpnservice_db = vpn_models.VPNService(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=vpns['name'],
                description=vpns['description'],
                subnet_id=vpns['subnet_id'],
                router_id=vpns['router_id'],
                admin_state_up=vpns['admin_state_up'],
                status=constants.PENDING_CREATE)
            context.session.add(vpnservice_db)
        return self._make_vpnservice_dict(vpnservice_db)

    def set_external_tunnel_ips(self, context, vpnservice_id, v4_ip=None,
                                v6_ip=None):
        """Update the external tunnel IP(s) for service."""
        vpns = {'external_v4_ip': v4_ip, 'external_v6_ip': v6_ip}
        with context.session.begin(subtransactions=True):
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        vpns = vpnservice['vpnservice']
        with context.session.begin(subtransactions=True):
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            self.assert_update_allowed(vpns_db)
            if vpns:
                vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def delete_vpnservice(self, context, vpnservice_id):
        with context.session.begin(subtransactions=True):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                vpnservice_id=vpnservice_id
            ).first():
                raise vpnaas.VPNServiceInUse(vpnservice_id=vpnservice_id)
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            context.session.delete(vpns_db)

    def _get_vpnservice(self, context, vpnservice_id):
        return self._get_resource(context, vpn_models.VPNService,
                                  vpnservice_id)

    def get_vpnservice(self, context, vpnservice_id, fields=None):
        vpns_db = self._get_resource(context, vpn_models.VPNService,
                                     vpnservice_id)
        return self._make_vpnservice_dict(vpns_db, fields)

    def get_vpnservices(self, context, filters=None, fields=None):
        return self._get_collection(context, vpn_models.VPNService,
                                    self._make_vpnservice_dict,
                                    filters=filters, fields=fields)

    def check_router_in_use(self, context, router_id):
        vpnservices = self.get_vpnservices(
            context, filters={'router_id': [router_id]})
        if vpnservices:
            plural = "s" if len(vpnservices) > 1 else ""
            services = ",".join([v['id'] for v in vpnservices])
            raise l3_exception.RouterInUse(
                router_id=router_id,
                reason="is currently used by VPN service%(plural)s "
                       "(%(services)s)" % {'plural': plural,
                                           'services': services})

    def check_subnet_in_use(self, context, subnet_id):
        with context.session.begin(subtransactions=True):
            vpnservices = context.session.query(
                vpn_models.VPNService).filter_by(subnet_id=subnet_id).first()
            if vpnservices:
                raise vpnaas.SubnetInUseByVPNService(
                    subnet_id=subnet_id,
                    vpnservice_id=vpnservices['id'])


class VPNPluginRpcDbMixin(object):
    def _get_agent_hosting_vpn_services(self, context, host):

        plugin = manager.NeutronManager.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, n_constants.AGENT_TYPE_L3, host)
        agent_conf = plugin.get_configuration_dict(agent)
        # Retreive the agent_mode to check if this is the
        # right agent to deploy the vpn service. In the
        # case of distributed the vpn service should reside
        # only on a dvr_snat node.
        agent_mode = agent_conf.get('agent_mode', 'legacy')
        if not agent.admin_state_up or agent_mode == 'dvr':
            return []
        query = context.session.query(vpn_models.VPNService)
        query = query.join(vpn_models.IPsecSiteConnection)
        query = query.join(vpn_models.IKEPolicy)
        query = query.join(vpn_models.IPsecPolicy)
        query = query.join(vpn_models.IPsecPeerCidr)
        query = query.join(l3_agent_db.RouterL3AgentBinding,
                           l3_agent_db.RouterL3AgentBinding.router_id ==
                           vpn_models.VPNService.router_id)
        query = query.filter(
            l3_agent_db.RouterL3AgentBinding.l3_agent_id == agent.id)
        return query

    def update_status_by_agent(self, context, service_status_info_list):
        """Updating vpnservice and vpnconnection status.

        :param context: context variable
        :param service_status_info_list: list of status
        The structure is
        [{id: vpnservice_id,
          status: ACTIVE|DOWN|ERROR,
          updated_pending_status: True|False
          ipsec_site_connections: {
              ipsec_site_connection_id: {
                  status: ACTIVE|DOWN|ERROR,
                  updated_pending_status: True|False
              }
          }]
        The agent will set updated_pending_status as True,
        when agent update any pending status.
        """
        with context.session.begin(subtransactions=True):
            for vpnservice in service_status_info_list:
                try:
                    vpnservice_db = self._get_vpnservice(
                        context, vpnservice['id'])
                except vpnaas.VPNServiceNotFound:
                    LOG.warn(_LW('vpnservice %s in db is already deleted'),
                             vpnservice['id'])
                    continue

                if (not utils.in_pending_status(vpnservice_db.status)
                    or vpnservice['updated_pending_status']):
                    vpnservice_db.status = vpnservice['status']
                for conn_id, conn in vpnservice[
                    'ipsec_site_connections'].items():
                    self._update_connection_status(
                        context, conn_id, conn['status'],
                        conn['updated_pending_status'])


def vpn_callback(resource, event, trigger, **kwargs):
    vpnservice = manager.NeutronManager.get_service_plugins().get(
        constants.VPN)
    if vpnservice:
        context = kwargs.get('context')
        if resource == resources.ROUTER_GATEWAY:
            check_func = vpnservice.check_router_in_use
            resource_id = kwargs.get('router_id')
        elif resource == resources.ROUTER_INTERFACE:
            check_func = vpnservice.check_subnet_in_use
            resource_id = kwargs.get('subnet_id')
        check_func(context, resource_id)


def migration_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    router = kwargs['router']
    vpnservice = manager.NeutronManager.get_service_plugins().get(
        constants.VPN)
    if vpnservice:
        vpnservice.check_router_in_use(context, router['id'])
    return True


def subscribe():
    registry.subscribe(
        vpn_callback, resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
    registry.subscribe(
        vpn_callback, resources.ROUTER_INTERFACE, events.BEFORE_DELETE)
    registry.subscribe(
        migration_callback, resources.ROUTER, events.BEFORE_UPDATE)

# NOTE(armax): multiple VPN service plugins (potentially out of tree) may
# inherit from vpn_db and may need the callbacks to be processed. Having an
# implicit subscription (through the module import) preserves the existing
# behavior, and at the same time it avoids fixing it manually in each and
# every vpn plugin outta there. That said, The subscription is also made
# explicitly in the reference vpn plugin. The subscription operation is
# idempotent so there is no harm in registering the same callback multiple
# times.
subscribe()
