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

"""Initial no-op Liberty expand rule.

Revision ID: 30018084ed99
Revises: kilo
Create Date: 2015-07-16 00:00:00.000000

"""

from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '30018084ed99'
down_revision = 'kilo'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    pass
