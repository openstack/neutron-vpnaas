#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2

import sqlalchemy as sa
from sqlalchemy import orm


class IPsecPeerCidr(model_base.BASEV2):
    """Internal representation of a IPsec Peer Cidrs."""

    cidr = sa.Column(sa.String(32), nullable=False, primary_key=True)
    ipsec_site_connection_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ipsec_site_connections.id',
                      ondelete="CASCADE"),
        primary_key=True)


class IPsecPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 IPsecPolicy Object."""
    __tablename__ = 'ipsecpolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    transform_protocol = sa.Column(sa.Enum("esp", "ah", "ah-esp",
                                           name="ipsec_transform_protocols"),
                                   nullable=False)
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    encapsulation_mode = sa.Column(sa.Enum("tunnel", "transport",
                                           name="ipsec_encapsulations"),
                                   nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


class IKEPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 IKEPolicy Object."""
    __tablename__ = 'ikepolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    phase1_negotiation_mode = sa.Column(sa.Enum("main",
                                                name="ike_phase1_mode"),
                                        nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    ike_version = sa.Column(sa.Enum("v1", "v2", name="ike_versions"),
                            nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


class IPsecSiteConnection(model_base.BASEV2,
                          models_v2.HasId, models_v2.HasTenant):
    """Represents a IPsecSiteConnection Object."""
    __tablename__ = 'ipsec_site_connections'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    peer_address = sa.Column(sa.String(255), nullable=False)
    peer_id = sa.Column(sa.String(255), nullable=False)
    route_mode = sa.Column(sa.String(8), nullable=False)
    mtu = sa.Column(sa.Integer, nullable=False)
    initiator = sa.Column(sa.Enum("bi-directional", "response-only",
                                  name="vpn_initiators"), nullable=False)
    auth_mode = sa.Column(sa.String(16), nullable=False)
    psk = sa.Column(sa.String(255), nullable=False)
    dpd_action = sa.Column(sa.Enum("hold", "clear",
                                   "restart", "disabled",
                                   "restart-by-peer", name="vpn_dpd_actions"),
                           nullable=False)
    dpd_interval = sa.Column(sa.Integer, nullable=False)
    dpd_timeout = sa.Column(sa.Integer, nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    vpnservice_id = sa.Column(sa.String(36),
                              sa.ForeignKey('vpnservices.id'),
                              nullable=False)
    ipsecpolicy_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ipsecpolicies.id'),
                               nullable=False)
    ikepolicy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('ikepolicies.id'),
                             nullable=False)
    ipsecpolicy = orm.relationship(
        IPsecPolicy, backref='ipsec_site_connection')
    ikepolicy = orm.relationship(IKEPolicy, backref='ipsec_site_connection')
    peer_cidrs = orm.relationship(IPsecPeerCidr,
                                  backref='ipsec_site_connection',
                                  lazy='joined',
                                  cascade='all, delete, delete-orphan')


class VPNService(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 VPNService Object."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    external_v4_ip = sa.Column(sa.String(16))
    external_v6_ip = sa.Column(sa.String(64))
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=False)
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'),
                          nullable=False)
    subnet = orm.relationship(models_v2.Subnet)
    router = orm.relationship(l3_db.Router)
    ipsec_site_connections = orm.relationship(
        IPsecSiteConnection,
        backref='vpnservice',
        cascade="all, delete-orphan")
