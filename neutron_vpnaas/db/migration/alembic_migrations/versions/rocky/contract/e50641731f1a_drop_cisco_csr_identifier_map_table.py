# Copyright 2018, Fujitsu Vietnam Limited
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

"""drop cisco_csr_identifier_map table

Revision ID: e50641731f1a
Revises: b6a2519ab7dc
Create Date: 2018-02-28 10:28:59.846652

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = 'e50641731f1a'
down_revision = 'b6a2519ab7dc'


def upgrade():
    op.drop_table('cisco_csr_identifier_map')
