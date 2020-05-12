# Copyright 2017 Eayun, Inc.
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

"""add flavor id to vpnservices

Revision ID: 95601446dbcc
Revises: 38893903cbde
Create Date: 2017-04-10 10:14:41.724811

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '95601446dbcc'
down_revision = '38893903cbde'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.PIKE, migration.QUEENS,
                     migration.ROCKY, migration.STEIN,
                     migration.TRAIN, migration.USSURI]


def upgrade():
    op.add_column('vpnservices',
                  sa.Column('flavor_id', sa.String(length=36), nullable=True))
    op.create_foreign_key('fk_vpnservices_flavors_id',
                          'vpnservices', 'flavors',
                          ['flavor_id'], ['id'])
