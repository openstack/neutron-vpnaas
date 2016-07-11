# Copyright 2016 <PUT YOUR NAME/COMPANY HERE>
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

"""integration with ovn networking

Revision ID: d87df9a74b67
Revises: 52783a36bd67
Create Date: 2016-07-06 05:45:56.931540

"""

# revision identifiers, used by Alembic.
revision = 'd87df9a74b67'
down_revision = '52783a36bd67'

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        'vpn_ext_gws',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('router_id', 'port_id'),
        sa.ForeignKeyConstraint(
            ['router_id'],
            ['routers.id'],
            ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['port_id'],
            ['ports.id'],
            ondelete='CASCADE'
        ),
    )

