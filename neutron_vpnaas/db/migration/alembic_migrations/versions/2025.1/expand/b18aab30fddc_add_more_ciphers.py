# Copyright 2025 SysEleven GmbH
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

from alembic import op
import sqlalchemy as sa

"""add more ciphers

Revision ID: b18aab30fddc
Revises: 22e0145ac80b
Create Date: 2023-10-11 15:40:27.845720

"""

# revision identifiers, used by Alembic.
revision = 'b18aab30fddc'
down_revision = '22e0145ac80b'


new_auth = sa.Enum(
    'sha1', 'sha256', 'sha384', 'sha512', 'aes-xcbc', 'aes-cmac',
    name="vpn_pfs",
)

new_enc = sa.Enum(
    '3des',
    'aes-128', 'aes-192', 'aes-256',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'aes-128-ccm-8', 'aes-192-ccm-8', 'aes-256-ccm-8',
    'aes-128-ccm-12', 'aes-192-ccm-12', 'aes-256-ccm-12',
    'aes-128-ccm-16', 'aes-192-ccm-16', 'aes-256-ccm-16',
    'aes-128-gcm-8', 'aes-192-gcm-8', 'aes-256-gcm-8',
    'aes-128-gcm-12', 'aes-192-gcm-12', 'aes-256-gcm-12',
    'aes-128-gcm-16', 'aes-192-gcm-16', 'aes-256-gcm-16',
    name="vpn_encrypt_algorithms",
)

new_pfs = sa.Enum(
    'group2', 'group5', 'group14', 'group15',
    'group16', 'group17', 'group18', 'group19', 'group20', 'group21',
    'group22', 'group23', 'group24', 'group25', 'group26', 'group27',
    'group28', 'group29', 'group30', 'group31',
    name="vpn_pfs",
)


def upgrade():
    op.alter_column('ikepolicies', 'pfs', type_=new_pfs,
                    existing_nullable=False)
    op.alter_column('ikepolicies', 'auth_algorithm', type_=new_auth,
                    existing_nullable=False)
    op.alter_column('ikepolicies', 'encryption_algorithm', type_=new_enc,
                    existing_nullable=False)

    op.alter_column('ipsecpolicies', 'pfs', type_=new_pfs,
                    existing_nullable=False)
    op.alter_column('ipsecpolicies', 'auth_algorithm', type_=new_auth,
                    existing_nullable=False)
    op.alter_column('ipsecpolicies', 'encryption_algorithm', type_=new_enc,
                    existing_nullable=False)
