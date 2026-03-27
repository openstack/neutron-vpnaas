# Copyright 2025 Red Hat, Inc.
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

"""remove deprecated sha1 and 3des

Revision ID: 842256a43ce2
Revises: b18aab30fddc
Create Date: 2025-04-23 12:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '842256a43ce2'
down_revision = 'b18aab30fddc'

TABLE_NAMES = ('ikepolicies', 'ipsecpolicies')

new_auth = sa.Enum(
    'sha256', 'sha384', 'sha512', 'aes-xcbc', 'aes-cmac',
    name="vpn_auth_algorithms",
)

new_enc = sa.Enum(
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


def expand_drop_exceptions():
    """Remove deprecated 'sha1' and '3des' from the auth and encryption enums

    The 'sha1' auth algorithm and '3des' encryption algorithm are deprecated
    and insecure. This migration migrates existing rows to safe defaults and
    then shrinks the enum columns to remove these values.
    """
    return {
        sa.Column: [
            'ikepolicies.auth_algorithm',
            'ikepolicies.encryption_algorithm',
            'ipsecpolicies.auth_algorithm',
            'ipsecpolicies.encryption_algorithm',
        ],
    }


def upgrade():
    for table in TABLE_NAMES:
        op.execute(
            sa.text(
                f"UPDATE {table} SET auth_algorithm = 'sha256' "
                f"WHERE auth_algorithm = 'sha1'"
            )
        )
        op.execute(
            sa.text(
                f"UPDATE {table} SET encryption_algorithm = 'aes-256' "
                f"WHERE encryption_algorithm = '3des'"
            )
        )

    for table in TABLE_NAMES:
        op.alter_column(table, 'auth_algorithm', type_=new_auth,
                        existing_nullable=False)
        op.alter_column(table, 'encryption_algorithm', type_=new_enc,
                        existing_nullable=False)
