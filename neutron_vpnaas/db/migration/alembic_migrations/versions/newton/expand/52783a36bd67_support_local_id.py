# Copyright 2016 <Yi Jing Zhu/IBM>
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

"""support local id

Revision ID: 52783a36bd67
Revises: fe637dc3f042
Create Date: 2016-04-26 21:40:40.244196

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '52783a36bd67'
down_revision = 'fe637dc3f042'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.NEWTON]


def upgrade():
    op.add_column('ipsec_site_connections',
                  sa.Column('local_id',
                            sa.String(length=255),
                            nullable=True))
