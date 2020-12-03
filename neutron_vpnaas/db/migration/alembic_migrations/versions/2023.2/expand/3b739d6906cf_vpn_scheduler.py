# Copyright 2016 MingShuang Xian/IBM
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

"""vpn scheduler

Revision ID: 3b739d6906cf
Revises: 5f884db48ba9
Create Date: 2016-08-15 03:32:46.124718

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3b739d6906cf'
down_revision = '5f884db48ba9'


def upgrade():
    op.create_table(
        'routervpnagentbindings',
        sa.Column('router_id', sa.String(length=36),
                  unique=True, nullable=False),
        sa.Column('vpn_agent_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id', 'vpn_agent_id'),
    )
