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

"""add_index_tenant_id

Revision ID: 3ea02b2a773e
Revises: start_neutron_vpnaas
Create Date: 2015-02-10 17:51:10.752504

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '3ea02b2a773e'
down_revision = 'start_neutron_vpnaas'

TABLES = ['ipsecpolicies', 'ikepolicies', 'ipsec_site_connections',
          'vpnservices']


def upgrade():
    for table in TABLES:
        op.create_index(op.f('ix_%s_tenant_id' % table),
                        table, ['tenant_id'], unique=False)
