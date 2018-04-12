#    (c) Copyright 2015 Cisco Systems Inc.
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""VPNaaS endpoint groups

Revision ID: 41b509d10b5e
Revises: 24f28869838b
Create Date: 2015-08-06 18:21:03.241664

"""

from alembic import op
import sqlalchemy as sa

from neutron_vpnaas.services.vpn.common import constants

# revision identifiers, used by Alembic.
revision = '41b509d10b5e'
down_revision = '24f28869838b'


def upgrade():
    op.create_table(
        'vpn_endpoint_groups',
        sa.Column('id', sa.String(length=36), nullable=False,
                  primary_key=True),
        sa.Column('tenant_id', sa.String(length=255),
                  index=True),
        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=255)),
        sa.Column('endpoint_type',
                  sa.Enum(constants.SUBNET_ENDPOINT, constants.CIDR_ENDPOINT,
                          constants.VLAN_ENDPOINT, constants.NETWORK_ENDPOINT,
                          constants.ROUTER_ENDPOINT,
                          name='endpoint_type'),
                  nullable=False),
    )
    op.create_table(
        'vpn_endpoints',
        sa.Column('endpoint', sa.String(length=255), nullable=False),
        sa.Column('endpoint_group_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['endpoint_group_id'],
                                ['vpn_endpoint_groups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('endpoint', 'endpoint_group_id'),
    )
