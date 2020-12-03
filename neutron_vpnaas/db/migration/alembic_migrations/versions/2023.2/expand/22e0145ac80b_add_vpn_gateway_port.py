# Copyright 2016 MingShuang Xian/IBM
# Copyright 2023 SysEleven GmbH
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

"""Add table for vpn gateway (gateway port and transit network)

Revision ID: 22e0145ac80b
Revises: 3b739d6906cf
Create Date: 2016-09-18 09:01:18.660362

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '22e0145ac80b'
down_revision = '3b739d6906cf'


def upgrade():
    op.create_table(
        'vpn_ext_gws',
        sa.Column('id', sa.String(length=36), nullable=False,
                  primary_key=True),
        sa.Column('project_id', sa.String(length=255),
                  index=True),
        sa.Column('router_id', sa.String(length=36), nullable=False,
                  unique=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('gw_port_id', sa.String(length=36)),
        sa.Column('transit_port_id', sa.String(length=36)),
        sa.Column('transit_network_id', sa.String(length=36)),
        sa.Column('transit_subnet_id', sa.String(length=36)),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id']),
        sa.ForeignKeyConstraint(['gw_port_id'], ['ports.id'],
                                ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['transit_port_id'], ['ports.id'],
                                ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['transit_network_id'], ['networks.id'],
                                ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['transit_subnet_id'], ['subnets.id'],
                                ondelete='SET NULL'),
    )
