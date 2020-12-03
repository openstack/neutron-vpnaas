#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    (c) Copyright 2015 Cisco Systems Inc.
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

from neutron.db import models_v2
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import l3 as l3_exception
from neutron_lib.exceptions import vpn as vpn_exception
from neutron_lib.plugins import constants as p_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.orm import exc


from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.db.vpn import vpn_validator
from neutron_vpnaas.extensions import vpn_endpoint_groups
from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.services.vpn.common import constants as v_constants

LOG = logging.getLogger(__name__)


class VPNPluginDb(vpnaas.VPNPluginBase,
                  vpn_endpoint_groups.VPNEndpointGroupsPluginBase):
    """VPN plugin database class using SQLAlchemy models."""

    def _get_validator(self):
        """Obtain validator to use for attribute validation.

        Subclasses may override this with a different validator, as needed.
        Note: some UTs will directly create a VPNPluginDb object and then
        call its methods, instead of creating a VPNDriverPlugin, which
        will have a service driver associated that will provide a
        validator object. As a result, we use the reference validator here.
        """
        return vpn_validator.VpnReferenceValidator()

    def update_status(self, context, model, v_id, status):
        with db_api.CONTEXT_WRITER.using(context):
            v_db = self._get_resource(context, model, v_id)
            v_db.update({'status': status})

    def _get_resource(self, context, model, v_id):
        try:
            r = model_query.get_by_id(context, model, v_id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, vpn_models.IPsecSiteConnection):
                    raise vpn_exception.IPsecSiteConnectionNotFound(
                        ipsec_site_conn_id=v_id
                    )
                elif issubclass(model, vpn_models.IKEPolicy):
                    raise vpn_exception.IKEPolicyNotFound(ikepolicy_id=v_id)
                elif issubclass(model, vpn_models.IPsecPolicy):
                    raise vpn_exception.IPsecPolicyNotFound(
                        ipsecpolicy_id=v_id)
                elif issubclass(model, vpn_models.VPNService):
                    raise vpn_exception.VPNServiceNotFound(vpnservice_id=v_id)
                elif issubclass(model, vpn_models.VPNEndpointGroup):
                    raise vpn_exception.VPNEndpointGroupNotFound(
                        endpoint_group_id=v_id)
                ctx.reraise = True
        return r

    def assert_update_allowed(self, obj):
        status = getattr(obj, 'status', None)
        _id = getattr(obj, 'id', None)
        if utils.in_pending_status(status):
            raise vpn_exception.VPNStateInvalidToUpdate(id=_id, state=status)

    def _make_ipsec_site_connection_dict(self, ipsec_site_conn, fields=None):

        res = {'id': ipsec_site_conn['id'],
               'tenant_id': ipsec_site_conn['tenant_id'],
               'name': ipsec_site_conn['name'],
               'description': ipsec_site_conn['description'],
               'peer_address': ipsec_site_conn['peer_address'],
               'peer_id': ipsec_site_conn['peer_id'],
               'local_id': ipsec_site_conn['local_id'],
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
                              for pcidr in ipsec_site_conn['peer_cidrs']],
               'local_ep_group_id': ipsec_site_conn['local_ep_group_id'],
               'peer_ep_group_id': ipsec_site_conn['peer_ep_group_id'],
               }

        return db_utils.resource_fields(res, fields)

    def get_endpoint_info(self, context, ipsec_sitecon):
        """Obtain all endpoint info, and store in connection for validation."""
        ipsec_sitecon['local_epg_subnets'] = self.get_endpoint_group(
            context, ipsec_sitecon['local_ep_group_id'])
        ipsec_sitecon['peer_epg_cidrs'] = self.get_endpoint_group(
            context, ipsec_sitecon['peer_ep_group_id'])

    def validate_connection_info(self, context, validator, ipsec_sitecon,
                                 vpnservice):
        """Collect info and validate connection.

        If endpoint groups used (default), collect the group info and
        do not specify the IP version (as it will come from endpoints).
        Otherwise, get the IP version from the (legacy) subnet for
        validation purposes.

        NOTE: Once the deprecated subnet is removed, the caller can just
        call get_endpoint_info() and validate_ipsec_site_connection().
        """
        if ipsec_sitecon['local_ep_group_id']:
            self.get_endpoint_info(context, ipsec_sitecon)
            ip_version = None
        else:
            ip_version = vpnservice.subnet.ip_version
        validator.validate_ipsec_site_connection(context, ipsec_sitecon,
                                                 ip_version, vpnservice)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        validator = self._get_validator()
        validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        with db_api.CONTEXT_WRITER.using(context):
            #Check permissions
            vpnservice_id = ipsec_sitecon['vpnservice_id']
            self._get_resource(context, vpn_models.VPNService, vpnservice_id)
            self._get_resource(context, vpn_models.IKEPolicy,
                               ipsec_sitecon['ikepolicy_id'])
            self._get_resource(context, vpn_models.IPsecPolicy,
                               ipsec_sitecon['ipsecpolicy_id'])
            vpnservice = self._get_vpnservice(context, vpnservice_id)
            validator.validate_ipsec_conn_optional_args(ipsec_sitecon,
                                                        vpnservice.subnet)
            self.validate_connection_info(context, validator, ipsec_sitecon,
                                          vpnservice)
            validator.resolve_peer_address(ipsec_sitecon, vpnservice.router)

            ipsec_site_conn_db = vpn_models.IPsecSiteConnection(
                id=uuidutils.generate_uuid(),
                tenant_id=ipsec_sitecon['tenant_id'],
                name=ipsec_sitecon['name'],
                description=ipsec_sitecon['description'],
                peer_address=ipsec_sitecon['peer_address'],
                peer_id=ipsec_sitecon['peer_id'],
                local_id=ipsec_sitecon['local_id'],
                route_mode='static',
                mtu=ipsec_sitecon['mtu'],
                auth_mode='psk',
                psk=ipsec_sitecon['psk'],
                initiator=ipsec_sitecon['initiator'],
                dpd_action=ipsec_sitecon['dpd_action'],
                dpd_interval=ipsec_sitecon['dpd_interval'],
                dpd_timeout=ipsec_sitecon['dpd_timeout'],
                admin_state_up=ipsec_sitecon['admin_state_up'],
                status=lib_constants.PENDING_CREATE,
                vpnservice_id=vpnservice_id,
                ikepolicy_id=ipsec_sitecon['ikepolicy_id'],
                ipsecpolicy_id=ipsec_sitecon['ipsecpolicy_id'],
                local_ep_group_id=ipsec_sitecon['local_ep_group_id'],
                peer_ep_group_id=ipsec_sitecon['peer_ep_group_id']
            )
            context.session.add(ipsec_site_conn_db)
            for cidr in ipsec_sitecon['peer_cidrs']:
                peer_cidr_db = vpn_models.IPsecPeerCidr(
                    cidr=cidr,
                    ipsec_site_connection_id=ipsec_site_conn_db.id
                )
                context.session.add(peer_cidr_db)
        return self._make_ipsec_site_connection_dict(ipsec_site_conn_db)

    def update_ipsec_site_connection(
            self, context,
            ipsec_site_conn_id, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        changed_peer_cidrs = False
        validator = self._get_validator()
        with db_api.CONTEXT_WRITER.using(context):
            ipsec_site_conn_db = self._get_resource(
                context, vpn_models.IPsecSiteConnection, ipsec_site_conn_id)
            vpnservice_id = ipsec_site_conn_db['vpnservice_id']
            vpnservice = self._get_vpnservice(context, vpnservice_id)

            validator.assign_sensible_ipsec_sitecon_defaults(
                ipsec_sitecon, ipsec_site_conn_db)
            validator.validate_ipsec_conn_optional_args(ipsec_sitecon,
                                                        vpnservice.subnet)
            self.validate_connection_info(context, validator, ipsec_sitecon,
                                          vpnservice)
            if 'peer_address' in ipsec_sitecon:
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
            # Note: Unconditionally remove peer_cidrs, as they will be set to
            # previous, if unchanged (to be able to validate above).
            del ipsec_sitecon["peer_cidrs"]
            if ipsec_sitecon:
                ipsec_site_conn_db.update(ipsec_sitecon)
            result = self._make_ipsec_site_connection_dict(ipsec_site_conn_db)
        if changed_peer_cidrs:
            result['peer_cidrs'] = new_peer_cidrs
        return result

    def delete_ipsec_site_connection(self, context, ipsec_site_conn_id):
        with db_api.CONTEXT_WRITER.using(context):
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
        return model_query.get_collection(
            context, vpn_models.IPsecSiteConnection,
            self._make_ipsec_site_connection_dict,
            filters=filters, fields=fields)

    def update_ipsec_site_conn_status(self, context, conn_id, new_status):
        with db_api.CONTEXT_WRITER.using(context):
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
        except vpn_exception.IPsecSiteConnectionNotFound:
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

        return db_utils.resource_fields(res, fields)

    def create_ikepolicy(self, context, ikepolicy):
        ike = ikepolicy['ikepolicy']
        validator = self._get_validator()
        lifetime_info = ike['lifetime']
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with db_api.CONTEXT_WRITER.using(context):
            validator.validate_ike_policy(context, ike)
            ike_db = vpn_models.IKEPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=ike['tenant_id'],
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
        validator = self._get_validator()
        with db_api.CONTEXT_WRITER.using(context):
            validator.validate_ike_policy(context, ike)
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ikepolicy_id=ikepolicy_id).first():
                raise vpn_exception.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
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
        with db_api.CONTEXT_WRITER.using(context):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ikepolicy_id=ikepolicy_id).first():
                raise vpn_exception.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(
                context, vpn_models.IKEPolicy, ikepolicy_id)
            context.session.delete(ike_db)

    @db_api.CONTEXT_READER
    def get_ikepolicy(self, context, ikepolicy_id, fields=None):
        ike_db = self._get_resource(
            context, vpn_models.IKEPolicy, ikepolicy_id)
        return self._make_ikepolicy_dict(ike_db, fields)

    @db_api.CONTEXT_READER
    def get_ikepolicies(self, context, filters=None, fields=None):
        return model_query.get_collection(context, vpn_models.IKEPolicy,
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

        return db_utils.resource_fields(res, fields)

    def create_ipsecpolicy(self, context, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        validator = self._get_validator()
        lifetime_info = ipsecp['lifetime']
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with db_api.CONTEXT_WRITER.using(context):
            validator.validate_ipsec_policy(context, ipsecp)
            ipsecp_db = vpn_models.IPsecPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=ipsecp['tenant_id'],
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
        validator = self._get_validator()
        with db_api.CONTEXT_WRITER.using(context):
            validator.validate_ipsec_policy(context, ipsecp)
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ipsecpolicy_id=ipsecpolicy_id).first():
                raise vpn_exception.IPsecPolicyInUse(
                    ipsecpolicy_id=ipsecpolicy_id)
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
        with db_api.CONTEXT_WRITER.using(context):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                    ipsecpolicy_id=ipsecpolicy_id).first():
                raise vpn_exception.IPsecPolicyInUse(
                    ipsecpolicy_id=ipsecpolicy_id)
            ipsec_db = self._get_resource(
                context, vpn_models.IPsecPolicy, ipsecpolicy_id)
            context.session.delete(ipsec_db)

    @db_api.CONTEXT_READER
    def get_ipsecpolicy(self, context, ipsecpolicy_id, fields=None):
        ipsec_db = self._get_resource(
            context, vpn_models.IPsecPolicy, ipsecpolicy_id)
        return self._make_ipsecpolicy_dict(ipsec_db, fields)

    @db_api.CONTEXT_READER
    def get_ipsecpolicies(self, context, filters=None, fields=None):
        return model_query.get_collection(context, vpn_models.IPsecPolicy,
                                          self._make_ipsecpolicy_dict,
                                          filters=filters, fields=fields)

    def _make_vpnservice_dict(self, vpnservice, fields=None):
        res = {'id': vpnservice['id'],
               'name': vpnservice['name'],
               'description': vpnservice['description'],
               'tenant_id': vpnservice['tenant_id'],
               'subnet_id': vpnservice['subnet_id'],
               'router_id': vpnservice['router_id'],
               'flavor_id': vpnservice['flavor_id'],
               'admin_state_up': vpnservice['admin_state_up'],
               'external_v4_ip': vpnservice['external_v4_ip'],
               'external_v6_ip': vpnservice['external_v6_ip'],
               'status': vpnservice['status']}
        return db_utils.resource_fields(res, fields)

    def create_vpnservice(self, context, vpnservice):
        vpns = vpnservice['vpnservice']
        flavor_id = vpns.get('flavor_id', None)
        validator = self._get_validator()
        with db_api.CONTEXT_WRITER.using(context):
            validator.validate_vpnservice(context, vpns)
            vpnservice_db = vpn_models.VPNService(
                id=uuidutils.generate_uuid(),
                tenant_id=vpns['tenant_id'],
                name=vpns['name'],
                description=vpns['description'],
                subnet_id=vpns['subnet_id'],
                router_id=vpns['router_id'],
                flavor_id=flavor_id,
                admin_state_up=vpns['admin_state_up'],
                status=lib_constants.PENDING_CREATE)
            context.session.add(vpnservice_db)
        return self._make_vpnservice_dict(vpnservice_db)

    def set_external_tunnel_ips(self, context, vpnservice_id, v4_ip=None,
                                v6_ip=None):
        """Update the external tunnel IP(s) for service."""
        vpns = {'external_v4_ip': v4_ip, 'external_v6_ip': v6_ip}
        with db_api.CONTEXT_WRITER.using(context):
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def set_vpnservice_status(self, context, vpnservice_id, status,
                              updated_pending_status=False):
        vpns = {'status': status}
        with db_api.CONTEXT_WRITER.using(context):
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            if (utils.in_pending_status(vpns_db.status) and
                    not updated_pending_status):
                raise vpnaas.VPNStateInvalidToUpdate(
                    id=vpnservice_id, state=vpns_db.status)
            vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        vpns = vpnservice['vpnservice']
        with db_api.CONTEXT_WRITER.using(context):
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            self.assert_update_allowed(vpns_db)
            if vpns:
                vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def delete_vpnservice(self, context, vpnservice_id):
        with db_api.CONTEXT_WRITER.using(context):
            if context.session.query(vpn_models.IPsecSiteConnection).filter_by(
                vpnservice_id=vpnservice_id
            ).first():
                raise vpn_exception.VPNServiceInUse(
                    vpnservice_id=vpnservice_id)
            vpns_db = self._get_resource(context, vpn_models.VPNService,
                                         vpnservice_id)
            context.session.delete(vpns_db)

    @db_api.CONTEXT_READER
    def _get_vpnservice(self, context, vpnservice_id):
        return self._get_resource(context, vpn_models.VPNService,
                                  vpnservice_id)

    @db_api.CONTEXT_READER
    def get_vpnservice(self, context, vpnservice_id, fields=None):
        vpns_db = self._get_resource(context, vpn_models.VPNService,
                                     vpnservice_id)
        return self._make_vpnservice_dict(vpns_db, fields)

    @db_api.CONTEXT_READER
    def get_vpnservices(self, context, filters=None, fields=None):
        return model_query.get_collection(context, vpn_models.VPNService,
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

    def check_subnet_in_use(self, context, subnet_id, router_id):
        with db_api.CONTEXT_READER.using(context):
            vpnservices = context.session.query(
                vpn_models.VPNService).filter_by(
                    subnet_id=subnet_id, router_id=router_id).first()
            if vpnservices:
                raise vpn_exception.SubnetInUseByVPNService(
                    subnet_id=subnet_id,
                    vpnservice_id=vpnservices['id'])

            query = context.session.query(vpn_models.IPsecSiteConnection)
            query = query.join(
                vpn_models.VPNEndpointGroup,
                vpn_models.VPNEndpointGroup.id ==
                vpn_models.IPsecSiteConnection.local_ep_group_id).filter(
                vpn_models.VPNEndpointGroup.endpoint_type ==
                v_constants.SUBNET_ENDPOINT)
            query = query.join(
                vpn_models.VPNEndpoint,
                vpn_models.VPNEndpoint.endpoint_group_id ==
                vpn_models.IPsecSiteConnection.local_ep_group_id).filter(
                vpn_models.VPNEndpoint.endpoint == subnet_id)
            query = query.join(
                vpn_models.VPNService,
                vpn_models.VPNService.id ==
                vpn_models.IPsecSiteConnection.vpnservice_id).filter(
                vpn_models.VPNService.router_id == router_id)
            connection = query.first()
            if connection:
                raise vpn_exception.SubnetInUseByIPsecSiteConnection(
                    subnet_id=subnet_id,
                    ipsec_site_connection_id=connection['id'])

    def check_subnet_in_use_by_endpoint_group(self, context, subnet_id):
        with db_api.CONTEXT_READER.using(context):
            query = context.session.query(vpn_models.VPNEndpointGroup)
            query = query.filter(vpn_models.VPNEndpointGroup.endpoint_type ==
                                 v_constants.SUBNET_ENDPOINT)
            query = query.join(
                vpn_models.VPNEndpoint,
                sa.and_(vpn_models.VPNEndpoint.endpoint_group_id ==
                     vpn_models.VPNEndpointGroup.id,
                     vpn_models.VPNEndpoint.endpoint == subnet_id))
            group = query.first()
            if group:
                raise vpn_exception.SubnetInUseByEndpointGroup(
                    subnet_id=subnet_id, group_id=group['id'])

    def _make_endpoint_group_dict(self, endpoint_group, fields=None):
        res = {'id': endpoint_group['id'],
               'tenant_id': endpoint_group['tenant_id'],
               'name': endpoint_group['name'],
               'description': endpoint_group['description'],
               'type': endpoint_group['endpoint_type'],
               'endpoints': [ep['endpoint']
                             for ep in endpoint_group['endpoints']]}
        return db_utils.resource_fields(res, fields)

    def create_endpoint_group(self, context, endpoint_group):
        group = endpoint_group['endpoint_group']
        validator = self._get_validator()
        with db_api.CONTEXT_WRITER.using(context):
            validator.validate_endpoint_group(context, group)
            endpoint_group_db = vpn_models.VPNEndpointGroup(
                id=uuidutils.generate_uuid(),
                tenant_id=group['tenant_id'],
                name=group['name'],
                description=group['description'],
                endpoint_type=group['type'])
            context.session.add(endpoint_group_db)
            for endpoint in group['endpoints']:
                endpoint_db = vpn_models.VPNEndpoint(
                    endpoint=endpoint,
                    endpoint_group_id=endpoint_group_db.id
                )
                context.session.add(endpoint_db)
        return self._make_endpoint_group_dict(endpoint_group_db)

    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        group_changes = endpoint_group['endpoint_group']
        # Note: Endpoints cannot be changed, so will not do validation
        with db_api.CONTEXT_WRITER.using(context):
            endpoint_group_db = self._get_resource(context,
                                                   vpn_models.VPNEndpointGroup,
                                                   endpoint_group_id)
            endpoint_group_db.update(group_changes)
        return self._make_endpoint_group_dict(endpoint_group_db)

    def delete_endpoint_group(self, context, endpoint_group_id):
        with db_api.CONTEXT_WRITER.using(context):
            self.check_endpoint_group_not_in_use(context, endpoint_group_id)
            endpoint_group_db = self._get_resource(
                context, vpn_models.VPNEndpointGroup, endpoint_group_id)
            context.session.delete(endpoint_group_db)

    @db_api.CONTEXT_READER
    def get_endpoint_group(self, context, endpoint_group_id, fields=None):
        endpoint_group_db = self._get_resource(
            context, vpn_models.VPNEndpointGroup, endpoint_group_id)
        return self._make_endpoint_group_dict(endpoint_group_db, fields)

    @db_api.CONTEXT_READER
    def get_endpoint_groups(self, context, filters=None, fields=None):
        return model_query.get_collection(context, vpn_models.VPNEndpointGroup,
                                          self._make_endpoint_group_dict,
                                          filters=filters, fields=fields)

    def check_endpoint_group_not_in_use(self, context, group_id):
        query = context.session.query(vpn_models.IPsecSiteConnection)
        query = query.filter(
            sa.or_(
                vpn_models.IPsecSiteConnection.local_ep_group_id == group_id,
                vpn_models.IPsecSiteConnection.peer_ep_group_id == group_id)
        )
        if query.first():
            raise vpn_exception.EndpointGroupInUse(group_id=group_id)

    def get_vpnservice_router_id(self, context, vpnservice_id):
        with db_api.CONTEXT_READER.using(context):
            vpnservice = self._get_vpnservice(context, vpnservice_id)
            return vpnservice['router_id']

    @db_api.CONTEXT_READER
    def get_peer_cidrs_for_router(self, context, router_id):
        filters = {'router_id': [router_id]}
        vpnservices = model_query.get_collection_query(
            context, vpn_models.VPNService, filters=filters).all()
        cidrs = []
        for vpnservice in vpnservices:
            for ipsec_site_connection in vpnservice.ipsec_site_connections:
                if ipsec_site_connection.peer_cidrs:
                    for peer_cidr in ipsec_site_connection.peer_cidrs:
                        cidrs.append(peer_cidr.cidr)
                if ipsec_site_connection.peer_ep_group is not None:
                    for ep in ipsec_site_connection.peer_ep_group.endpoints:
                        cidrs.append(ep.endpoint)
        return cidrs


class VPNPluginRpcDbMixin(object):
    def _build_local_subnet_cidr_map(self, context):
        """Build a dict of all local endpoint subnets, with list of CIDRs."""
        query = context.session.query(models_v2.Subnet.id,
                                      models_v2.Subnet.cidr)
        query = query.join(vpn_models.VPNEndpoint,
                           vpn_models.VPNEndpoint.endpoint ==
                           models_v2.Subnet.id)
        query = query.join(vpn_models.VPNEndpointGroup,
                           vpn_models.VPNEndpointGroup.id ==
                           vpn_models.VPNEndpoint.endpoint_group_id)
        query = query.join(vpn_models.IPsecSiteConnection,
                           vpn_models.IPsecSiteConnection.local_ep_group_id ==
                           vpn_models.VPNEndpointGroup.id)
        return {sn.id: sn.cidr for sn in query.all()}

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
        when agent updates any pending status.
        """
        with db_api.CONTEXT_WRITER.using(context):
            for vpnservice in service_status_info_list:
                try:
                    vpnservice_db = self._get_vpnservice(
                        context, vpnservice['id'])
                except vpn_exception.VPNServiceNotFound:
                    LOG.warning('vpnservice %s in db is already deleted',
                                vpnservice['id'])
                    continue

                if (not utils.in_pending_status(vpnservice_db.status) or
                    vpnservice['updated_pending_status']):
                    vpnservice_db.status = vpnservice['status']
                for conn_id, conn in vpnservice[
                    'ipsec_site_connections'].items():
                    self._update_connection_status(
                        context, conn_id, conn['status'],
                        conn['updated_pending_status'])


def vpn_router_gateway_callback(resource, event, trigger, payload=None):
    # the event payload objects
    vpn_plugin = directory.get_plugin(p_constants.VPN)
    if vpn_plugin:
        context = payload.context
        router_id = payload.resource_id
        if resource == resources.ROUTER_GATEWAY:
            vpn_plugin.check_router_in_use(context, router_id)
        elif resource == resources.ROUTER_INTERFACE:
            subnet_id = payload.metadata.get('subnet_id')
            vpn_plugin.check_subnet_in_use(context, subnet_id, router_id)


def migration_callback(resource, event, trigger, payload):
    context = payload.context
    router = payload.latest_state
    vpn_plugin = directory.get_plugin(p_constants.VPN)
    if vpn_plugin:
        vpn_plugin.check_router_in_use(context, router['id'])
    return True


def subnet_callback(resource, event, trigger, payload=None):
    """Respond to subnet based notifications - see if subnet in use."""
    context = payload.context
    subnet_id = payload.resource_id
    vpn_plugin = directory.get_plugin(p_constants.VPN)
    if vpn_plugin:
        vpn_plugin.check_subnet_in_use_by_endpoint_group(context, subnet_id)


def subscribe():
    registry.subscribe(
        vpn_router_gateway_callback, resources.ROUTER_GATEWAY,
        events.BEFORE_DELETE)
    registry.subscribe(
        vpn_router_gateway_callback, resources.ROUTER_INTERFACE,
        events.BEFORE_DELETE)
    registry.subscribe(
        migration_callback, resources.ROUTER, events.BEFORE_UPDATE)
    registry.subscribe(
        subnet_callback, resources.SUBNET, events.BEFORE_DELETE)


# NOTE(armax): multiple VPN service plugins (potentially out of tree) may
# inherit from vpn_db and may need the callbacks to be processed. Having an
# implicit subscription (through the module import) preserves the existing
# behavior, and at the same time it avoids fixing it manually in each and
# every vpn plugin outta there. That said, The subscription is also made
# explicitly in the reference vpn plugin. The subscription operation is
# idempotent so there is no harm in registering the same callback multiple
# times.
subscribe()
