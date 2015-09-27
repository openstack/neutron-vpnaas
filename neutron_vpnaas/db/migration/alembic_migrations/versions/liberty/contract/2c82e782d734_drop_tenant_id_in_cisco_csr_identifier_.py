# Copyright 2015 Mirantis Inc.
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

"""drop_tenant_id_in_cisco_csr_identifier_map

Revision ID: 2c82e782d734
Revises: 333dfd6afaa2
Create Date: 2015-08-20 15:17:09.897944

"""

from alembic import op

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '2c82e782d734'
down_revision = '333dfd6afaa2'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY]


def upgrade():
    op.drop_column('cisco_csr_identifier_map', 'tenant_id')
