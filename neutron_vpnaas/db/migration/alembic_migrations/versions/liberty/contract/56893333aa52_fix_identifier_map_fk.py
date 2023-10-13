# Copyright(c) 2015, Oracle and/or its affiliates.  All Rights Reserved.
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

"""fix identifier map fk

Revision ID: 56893333aa52
Revises: kilo
Create Date: 2015-06-11 12:09:01.263253

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column
from sqlalchemy.sql import expression as expr
from sqlalchemy.sql import func
from sqlalchemy.sql import table

from neutron.db import migration
from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '56893333aa52'
down_revision = 'kilo'
branch_labels = (cli.CONTRACT_BRANCH,)


def upgrade():
    insp = sa.inspect(op.get_bind())
    if 'cisco_csr_identifier_map' not in insp.get_table_names():
        return
    # re-size existing data if necessary
    identifier_map = table('cisco_csr_identifier_map',
                           column('ipsec_site_conn_id', sa.String(36)))
    ipsec_site_conn_id = identifier_map.columns['ipsec_site_conn_id']

    op.execute(identifier_map.update(values={
        ipsec_site_conn_id: expr.case([(func.length(ipsec_site_conn_id) > 36,
                                      func.substr(ipsec_site_conn_id, 1, 36))],
                                      else_=ipsec_site_conn_id)}))

    # Need to drop foreign key constraint before mysql will allow changes

    with migration.remove_fks_from_table('cisco_csr_identifier_map'):
        op.alter_column(table_name='cisco_csr_identifier_map',
                        column_name='ipsec_site_conn_id',
                        type_=sa.String(36),
                        existing_nullable=False)
