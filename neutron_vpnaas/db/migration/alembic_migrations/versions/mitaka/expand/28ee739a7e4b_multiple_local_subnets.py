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

Revision ID: 28ee739a7e4b
Revises: 41b509d10b5e
Create Date: 2015-09-09 20:32:54.231765

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '28ee739a7e4b'
down_revision = '41b509d10b5e'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.MITAKA]


def upgrade():
    op.add_column('ipsec_site_connections',
                  sa.Column('local_ep_group_id',
                            sa.String(length=36),
                            nullable=True))
    op.add_column('ipsec_site_connections',
                  sa.Column('peer_ep_group_id',
                            sa.String(length=36),
                            nullable=True))
    op.create_foreign_key(constraint_name=None,
                          source_table='ipsec_site_connections',
                          referent_table='vpn_endpoint_groups',
                          local_cols=['local_ep_group_id'],
                          remote_cols=['id'])
    op.create_foreign_key(constraint_name=None,
                          source_table='ipsec_site_connections',
                          referent_table='vpn_endpoint_groups',
                          local_cols=['peer_ep_group_id'],
                          remote_cols=['id'])
    op.alter_column('vpnservices', 'subnet_id',
                    existing_type=sa.String(length=36), nullable=True)
