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

"""Populate VPN service table fields

Revision ID: 333dfd6afaa2
Revises: 56893333aa52
Create Date: 2015-07-27 16:43:59.123456

"""

from alembic import op
import netaddr
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '333dfd6afaa2'
down_revision = '56893333aa52'
depends_on = '24f28869838b'

VPNService = sa.Table('vpnservices', sa.MetaData(),
                      sa.Column('router_id', sa.String(36), nullable=False),
                      sa.Column('external_v4_ip', sa.String(16)),
                      sa.Column('external_v6_ip', sa.String(64)),
                      sa.Column('id', sa.String(36), nullable=False,
                                primary_key=True))
Router = sa.Table('routers', sa.MetaData(),
                  sa.Column('gw_port_id', sa.String(36)),
                  sa.Column('id', sa.String(36), nullable=False,
                            primary_key=True))
Port = sa.Table('ports', sa.MetaData(),
                sa.Column('id', sa.String(36), nullable=False,
                          primary_key=True))
IPAllocation = sa.Table('ipallocations', sa.MetaData(),
                        sa.Column('ip_address', sa.String(64),
                                  nullable=False, primary_key=True),
                        sa.Column('port_id', sa.String(36)))


def _migrate_external_ips(engine):
    """Use router external IPs to populate external_v*_ip entries.

    For each service, look through the associated router's
    gw_port['fixed_ips'] list and store any IPv4 and/or IPv6
    addresses into the new fields. If there are multiple
    addresses for an IP version, then only the first one will
    be stored (the same as the reference driver does).
    """
    insp = sa.inspect(engine)
    if 'cisco_csr_identifier_map' not in insp.get_table_names():
        return
    session = sa.orm.Session(bind=engine.connect())
    services = session.query(VPNService).all()
    for service in services:
        addresses = session.query(IPAllocation.c.ip_address).filter(
            service.router_id == Router.c.id,
            Router.c.gw_port_id == Port.c.id,
            Port.c.id == IPAllocation.c.port_id).all()
        have_version = []
        for address in addresses:
            version = netaddr.IPAddress(address[0]).version
            if version in have_version:
                continue
            have_version.append(version)
            update = {'external_v%s_ip' % version: address[0]}
            op.execute(VPNService.update().where(
                VPNService.c.id == service.id).values(update))
    session.commit()


def upgrade():
    # Use the router to populate the fields
    for_engine = op.get_bind()
    _migrate_external_ips(for_engine)
