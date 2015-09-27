# Copyright 2015 OpenStack Foundation
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

"""Add fields to VPN service table

Revision ID: 24f28869838b
Revises: 30018084ed99
Create Date: 2015-07-06 14:52:24.339246

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '24f28869838b'
down_revision = '30018084ed99'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY]


def upgrade():
    op.add_column('vpnservices',
                  sa.Column('external_v4_ip', sa.String(16), nullable=True))
    op.add_column('vpnservices',
                  sa.Column('external_v6_ip', sa.String(64), nullable=True))
