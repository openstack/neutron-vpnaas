# Copyright 2020 cmss, Inc.  All rights reserved.
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

"""add_aggressive_negotiation_modes

Revision ID: 5f884db48ba9
Revises: 95601446dbcc
Create Date: 2020-05-12 14:37:46.320070

"""

# revision identifiers, used by Alembic.
revision = '5f884db48ba9'
down_revision = '95601446dbcc'

phase1_negotiation_modes = sa.Enum('main', 'aggressive',
                                   name='ike_phase1_mode')


def upgrade():
    op.alter_column('ikepolicies', 'phase1_negotiation_mode',
                    type_=phase1_negotiation_modes,
                    existing_nullable=False)
