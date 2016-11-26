#    (c) Copyright 2015 Cisco Systems Inc.
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
#

"""Multiple local subnets

Revision ID: 2cb4ee992b41
Revises: 2c82e782d734
Create Date: 2015-09-09 20:32:54.254267

"""

from alembic import op
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.sql import expression as sa_expr

from neutron.db import migration

from neutron_vpnaas.services.vpn.common import constants as v_constants


# revision identifiers, used by Alembic.
revision = '2cb4ee992b41'
down_revision = '2c82e782d734'
depends_on = ('28ee739a7e4b',)

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.MITAKA]


vpnservices = sa.Table(
    'vpnservices', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('name', sa.String(255)),
    sa.Column('description', sa.String(255)),
    sa.Column('status', sa.String(16), nullable=False),
    sa.Column('admin_state_up', sa.Boolean(), nullable=False),
    sa.Column('external_v4_ip', sa.String(16)),
    sa.Column('external_v6_ip', sa.String(64)),
    sa.Column('subnet_id', sa.String(36)),
    sa.Column('router_id', sa.String(36), nullable=False))

ipsec_site_conns = sa.Table(
    'ipsec_site_connections', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('name', sa.String(255)),
    sa.Column('description', sa.String(255)),
    sa.Column('peer_address', sa.String(255), nullable=False),
    sa.Column('peer_id', sa.String(255), nullable=False),
    sa.Column('route_mode', sa.String(8), nullable=False),
    sa.Column('mtu', sa.Integer, nullable=False),
    sa.Column('initiator', sa.Enum("bi-directional", "response-only",
                                   name="vpn_initiators"), nullable=False),
    sa.Column('auth_mode', sa.String(16), nullable=False),
    sa.Column('psk', sa.String(255), nullable=False),
    sa.Column('dpd_action', sa.Enum("hold", "clear", "restart", "disabled",
                                    "restart-by-peer", name="vpn_dpd_actions"),
              nullable=False),
    sa.Column('dpd_interval', sa.Integer, nullable=False),
    sa.Column('dpd_timeout', sa.Integer, nullable=False),
    sa.Column('status', sa.String(16), nullable=False),
    sa.Column('admin_state_up', sa.Boolean(), nullable=False),
    sa.Column('vpnservice_id', sa.String(36), nullable=False),
    sa.Column('ipsecpolicy_id', sa.String(36), nullable=False),
    sa.Column('ikepolicy_id', sa.String(36), nullable=False),
    sa.Column('local_ep_group_id', sa.String(36)),
    sa.Column('peer_ep_group_id', sa.String(36)))

ipsecpeercidrs = sa.Table(
    'ipsecpeercidrs', sa.MetaData(),
    sa.Column('cidr', sa.String(32), nullable=False, primary_key=True),
    sa.Column('ipsec_site_connection_id', sa.String(36), primary_key=True))


def _make_endpoint_groups(new_groups, new_endpoints):
    """Create endpoint groups and their corresponding endpoints."""
    md = sa.MetaData()
    engine = op.get_bind()
    sa.Table('vpn_endpoint_groups', md, autoload=True, autoload_with=engine)
    op.bulk_insert(md.tables['vpn_endpoint_groups'], new_groups)
    sa.Table('vpn_endpoints', md, autoload=True, autoload_with=engine)
    op.bulk_insert(md.tables['vpn_endpoints'], new_endpoints)


def _update_connections(connection_map):
    """Store the endpoint group IDs in the connections."""
    for conn_id, mapping in connection_map.items():
        stmt = ipsec_site_conns.update().where(
            ipsec_site_conns.c.id == conn_id).values(
                local_ep_group_id=mapping['local'],
                peer_ep_group_id=mapping['peer'])
        op.execute(stmt)


def upgrade():
    new_groups = []
    new_endpoints = []
    service_map = {}
    session = sa.orm.Session(bind=op.get_bind())
    vpn_services = session.query(vpnservices).filter(
        vpnservices.c.subnet_id is not None).all()
    for vpn_service in vpn_services:
        subnet_id = vpn_service.subnet_id
        if subnet_id is None:
            continue  # Skip new service entries
        # Define the subnet group
        group_id = uuidutils.generate_uuid()
        group = {'id': group_id,
                 'name': '',
                 'description': '',
                 'tenant_id': vpn_service.tenant_id,
                 'endpoint_type': v_constants.SUBNET_ENDPOINT}
        new_groups.append(group)
        # Define the (sole) endpoint
        endpoint = {'endpoint_group_id': group_id,
                    'endpoint': subnet_id}
        new_endpoints.append(endpoint)
        # Save info to use for connections
        service_map[vpn_service.id] = group_id

    connection_map = {}
    ipsec_conns = session.query(ipsec_site_conns).all()
    for connection in ipsec_conns:
        peer_cidrs = session.query(ipsecpeercidrs.c.cidr).filter(
            ipsecpeercidrs.c.ipsec_site_connection_id == connection.id).all()
        if not peer_cidrs:
            continue  # Skip new style connections
        # Define the CIDR group
        group_id = uuidutils.generate_uuid()
        group = {'id': group_id,
                 'name': '',
                 'description': '',
                 'tenant_id': connection.tenant_id,
                 'endpoint_type': v_constants.CIDR_ENDPOINT}
        new_groups.append(group)
        # Define the endpoint(s)
        for peer_cidr in peer_cidrs:
            endpoint = {'endpoint_group_id': group_id,
                        'endpoint': peer_cidr[0]}
            new_endpoints.append(endpoint)
        # Save the endpoint group ID info for the connection
        vpn_service = connection.vpnservice_id
        connection_map[connection.id] = {'local': service_map[vpn_service],
                                         'peer': group_id}

    # Create all the defined endpoint groups and their endpoints
    _make_endpoint_groups(new_groups, new_endpoints)
    # Refer to new groups, in the IPSec connections
    _update_connections(connection_map)

    # Remove the peer_cidrs from IPSec connections
    op.execute(sa_expr.table('ipsecpeercidrs').delete())
    # Remove the subnets from VPN services
    stmt = vpnservices.update().where(
        vpnservices.c.subnet_id is not None).values(
            subnet_id=None)
    op.execute(stmt)
    session.commit()
