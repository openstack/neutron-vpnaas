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

"""support sha256

Revision ID: fe637dc3f042
Revises: 28ee739a7e4b
Create Date: 2016-04-08 22:33:53.286083

"""

from neutron.db import migration
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fe637dc3f042'
down_revision = '28ee739a7e4b'

new_auth = sa.Enum('sha1', 'sha256', name='vpn_auth_algorithms')


def upgrade():
    migration.alter_enum('ikepolicies', 'auth_algorithm', new_auth,
                nullable=False, do_drop=False)
    migration.alter_enum('ipsecpolicies', 'auth_algorithm', new_auth,
                nullable=False, do_rename=False, do_create=False)
