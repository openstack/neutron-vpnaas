# Copyright 2014 OpenStack Foundation
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

"""start neutron-vpnaas chain

Revision ID: start_neutron_vpnaas
Revises: None
Create Date: 2014-12-09 18:50:01.946832

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'start_neutron_vpnaas'
down_revision = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if 'ipsecpolicies' in existing:
        return

    op.create_table(
        'ipsecpolicies',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('transform_protocol',
                  sa.Enum("esp", "ah", "ah-esp",
                          name="ipsec_transform_protocols"),
                  nullable=False),
        sa.Column('auth_algorithm',
                  sa.Enum('sha1', name="vpn_auth_algorithms"),
                  nullable=False),
        sa.Column('encryption_algorithm',
                  sa.Enum('3des', 'aes-128', 'aes-256', 'aes-192',
                          name="vpn_encrypt_algorithms"),
                  nullable=False),
        sa.Column('encapsulation_mode',
                  sa.Enum("tunnel", "transport",
                          name="ipsec_encapsulations"),
                  nullable=False),
        sa.Column('lifetime_units',
                  sa.Enum("seconds", "kilobytes",
                          name="vpn_lifetime_units"),
                  nullable=False),
        sa.Column('lifetime_value', sa.Integer(), nullable=False),
        sa.Column('pfs',
                  sa.Enum('group2', 'group5', 'group14',
                          name="vpn_pfs"),
                  nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ikepolicies',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('auth_algorithm',
                  sa.Enum('sha1', name="vpn_auth_algorithms"),
                  nullable=False),
        sa.Column('encryption_algorithm',
                  sa.Enum('3des', 'aes-128', 'aes-256', 'aes-192',
                          name="vpn_encrypt_algorithms"),
                  nullable=False),
        sa.Column('phase1_negotiation_mode',
                  sa.Enum("main", name="ike_phase1_mode"),
                  nullable=False),
        sa.Column('lifetime_units',
                  sa.Enum("seconds", "kilobytes",
                          name="vpn_lifetime_units"),
                  nullable=False),
        sa.Column('lifetime_value', sa.Integer(), nullable=False),
        sa.Column('ike_version',
                  sa.Enum("v1", "v2", name="ike_versions"),
                  nullable=False),
        sa.Column('pfs',
                  sa.Enum('group2', 'group5', 'group14',
                          name="vpn_pfs"),
                  nullable=False),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'vpnservices',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id']),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id']),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ipsec_site_connections',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('peer_address', sa.String(length=255), nullable=False),
        sa.Column('peer_id', sa.String(length=255), nullable=False),
        sa.Column('route_mode', sa.String(length=8), nullable=False),
        sa.Column('mtu', sa.Integer(), nullable=False),
        sa.Column('initiator',
                  sa.Enum("bi-directional", "response-only",
                          name="vpn_initiators"),
                  nullable=False),
        sa.Column('auth_mode', sa.String(length=16), nullable=False),
        sa.Column('psk', sa.String(length=255), nullable=False),
        sa.Column('dpd_action',
                  sa.Enum("hold", "clear", "restart", "disabled",
                          "restart-by-peer", name="vpn_dpd_actions"),
                  nullable=False),
        sa.Column('dpd_interval', sa.Integer(), nullable=False),
        sa.Column('dpd_timeout', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('vpnservice_id', sa.String(length=36), nullable=False),
        sa.Column('ipsecpolicy_id', sa.String(length=36), nullable=False),
        sa.Column('ikepolicy_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['vpnservice_id'], ['vpnservices.id']),
        sa.ForeignKeyConstraint(['ipsecpolicy_id'], ['ipsecpolicies.id']),
        sa.ForeignKeyConstraint(['ikepolicy_id'], ['ikepolicies.id']),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'ipsecpeercidrs',
        sa.Column('cidr', sa.String(length=32), nullable=False),
        sa.Column('ipsec_site_connection_id', sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(['ipsec_site_connection_id'],
                                ['ipsec_site_connections.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('cidr', 'ipsec_site_connection_id'))
