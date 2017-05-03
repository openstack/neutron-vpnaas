# Copyright 2016 <Dongcan Ye/Awcloud>
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

"""add_auth_algorithm_sha384_and_sha512

Revision ID: 38893903cbde
Revises: 52783a36bd67
Create Date: 2016-11-04 18:00:49.219140

"""

from neutron.db import migration
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '38893903cbde'
down_revision = '52783a36bd67'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.OCATA]

new_auth = sa.Enum('sha1', 'sha256', 'sha384', 'sha512',
                   name='vpn_auth_algorithms')


def upgrade():
    migration.alter_enum('ikepolicies', 'auth_algorithm', new_auth,
                nullable=False, do_drop=False)
    migration.alter_enum('ipsecpolicies', 'auth_algorithm', new_auth,
                nullable=False, do_rename=False, do_create=False)
