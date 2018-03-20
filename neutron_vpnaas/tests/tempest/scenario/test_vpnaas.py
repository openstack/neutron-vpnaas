# Copyright (c) 2017 Midokura SARL
# All Rights Reserved.
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

import netaddr
from oslo_config import cfg
import testtools

from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import constants

from neutron_vpnaas.tests.tempest.scenario import base


CONF = config.CONF

# NOTE(huntxu): This is a workaround due to a upstream bug [1].
# VPNaaS 4in6 and 6in4 is not working properly with LibreSwan 3.19+.
# In OpenStack zuul checks the base CentOS 7 node is using Libreswan 3.20 on
# CentOS 7.4. So we need to provide a way to skip the 4in6 and 6in4 test cases
# for zuul.
#
# Once the upstream bug gets fixed and the base node uses a newer version of
# Libreswan with that fix, we can remove this.
#
# [1] https://github.com/libreswan/libreswan/issues/175
CONF.register_opt(
    cfg.BoolOpt('skip_4in6_6in4_tests',
                default=False,
                help='Whether to skip 4in6 and 6in4 test cases.'),
    'neutron_vpnaas_plugin_options'
)


class Vpnaas(base.BaseTempestTestCase):
    """Test the following topology

          +-------------------+
          | public            |
          | network           |
          |                   |
          +-+---------------+-+
            |               |
            |               |
    +-------+-+           +-+-------+
    | LEFT    |           | RIGHT   |
    | router  | <--VPN--> | router  |
    |         |           |         |
    +----+----+           +----+----+
         |                     |
    +----+----+           +----+----+
    | LEFT    |           | RIGHT   |
    | network |           | network |
    |         |           |         |
    +---------+           +---------+
    """

    credentials = ['primary', 'admin']
    inner_ipv6 = False
    outer_ipv6 = False

    @classmethod
    @utils.requires_ext(extension="vpnaas", service="network")
    def resource_setup(cls):
        super(Vpnaas, cls).resource_setup()

        # common
        cls.keypair = cls.create_keypair()
        cls.secgroup = cls.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup-'))['security_group']
        cls.security_groups.append(cls.secgroup)
        cls.create_loginable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.create_pingable_secgroup_rule(secgroup_id=cls.secgroup['id'])
        cls.ikepolicy = cls.create_ikepolicy(
            data_utils.rand_name("ike-policy-"))
        cls.ipsecpolicy = cls.create_ipsecpolicy(
            data_utils.rand_name("ipsec-policy-"))

        cls.extra_subnet_attributes = {}
        if cls.inner_ipv6:
            cls.create_v6_pingable_secgroup_rule(
                secgroup_id=cls.secgroup['id'])
            cls.extra_subnet_attributes['ipv6_address_mode'] = 'slaac'
            cls.extra_subnet_attributes['ipv6_ra_mode'] = 'slaac'

        # LEFT
        cls.router = cls.create_router(
            data_utils.rand_name('left-router'),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        cls.network = cls.create_network(network_name='left-network')
        ip_version = 6 if cls.inner_ipv6 else 4
        cls.subnet = cls.create_subnet(
            cls.network, ip_version=ip_version, name='left-subnet',
            **cls.extra_subnet_attributes)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        # Gives an internal IPv4 subnet for floating IP to the left server,
        # we use it to ssh into the left server.
        if cls.inner_ipv6:
            v4_subnet = cls.create_subnet(
                cls.network, ip_version=4, name='left-v4-subnet')
            cls.create_router_interface(cls.router['id'], v4_subnet['id'])

        # RIGHT
        cls._right_network, cls._right_subnet, cls._right_router = \
            cls._create_right_network()

    @classmethod
    def create_v6_pingable_secgroup_rule(cls, secgroup_id=None, client=None):
        # NOTE(huntxu): This method should be moved into the base class, along
        # with the v4 version.
        """This rule is intended to permit inbound ping6
        """

        rule_list = [{'protocol': 'ipv6-icmp',
                      'direction': 'ingress',
                      'port_range_min': 128,  # type
                      'port_range_max': 0,  # code
                      'ethertype': 'IPv6',
                      'remote_ip_prefix': '::/0'}]
        client = client or cls.os_primary.network_client
        cls.create_secgroup_rules(rule_list, client=client,
                                  secgroup_id=secgroup_id)

    @classmethod
    def _create_right_network(cls):
        router = cls.create_router(
            data_utils.rand_name('right-router'),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        network = cls.create_network(network_name='right-network')
        v4_cidr = netaddr.IPNetwork('10.10.0.0/24')
        v6_cidr = netaddr.IPNetwork('2003:1::/64')
        cidr = v6_cidr if cls.inner_ipv6 else v4_cidr
        ip_version = 6 if cls.inner_ipv6 else 4
        subnet = cls.create_subnet(
            network, ip_version=ip_version, cidr=cidr, name='right-subnet',
            **cls.extra_subnet_attributes)
        cls.create_router_interface(router['id'], subnet['id'])

        return network, subnet, router

    def _create_server(self, create_floating_ip=True, network=None):
        if network is None:
            network = self.network
        port = self.create_port(network, security_groups=[self.secgroup['id']])
        if create_floating_ip:
            fip = self.create_and_associate_floatingip(port['id'])
        else:
            fip = None
        server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'port': port['id']}])['server']
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       server['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        return {'port': port, 'fip': fip, 'server': server}

    def _setup_vpn(self):
        sites = [
            dict(name="left", network=self.network, subnet=self.subnet,
                 router=self.router),
            dict(name="right", network=self._right_network,
                 subnet=self._right_subnet, router=self._right_router),
        ]
        psk = data_utils.rand_name('mysecret')
        for i in range(0, 2):
            site = sites[i]
            site['vpnservice'] = self.create_vpnservice(
                site['subnet']['id'], site['router']['id'],
                name=data_utils.rand_name('%s-vpnservice' % site['name']))
        for i in range(0, 2):
            site = sites[i]
            vpnservice = site['vpnservice']
            peer = sites[1 - i]
            if self.outer_ipv6:
                peer_address = peer['vpnservice']['external_v6_ip']
                if not peer_address:
                    msg = "Public network must have an IPv6 subnet."
                    raise self.skipException(msg)
            else:
                peer_address = peer['vpnservice']['external_v4_ip']
            self.create_ipsec_site_connection(
                self.ikepolicy['id'],
                self.ipsecpolicy['id'],
                vpnservice['id'],
                peer_address=peer_address,
                peer_id=peer_address,
                peer_cidrs=[peer['subnet']['cidr']],
                psk=psk,
                name=data_utils.rand_name(
                    '%s-ipsec-site-connection' % site['name']))

    def _get_ip_on_subnet_for_port(self, port, subnet_id):
        for fixed_ip in port['fixed_ips']:
            if fixed_ip['subnet_id'] == subnet_id:
                return fixed_ip['ip_address']
        msg = "Cannot get IP address on specified subnet %s for port %r." % (
            subnet_id, port)
        raise self.fail(msg)

    def _test_vpnaas(self):
        # RIGHT
        right_server = self._create_server(network=self._right_network,
            create_floating_ip=False)
        right_ip = self._get_ip_on_subnet_for_port(
            right_server['port'], self._right_subnet['id'])

        # LEFT
        left_server = self._create_server()
        ssh_client = ssh.Client(left_server['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'])

        # check LEFT -> RIGHT connectivity via VPN
        self.check_remote_connectivity(ssh_client, right_ip,
                                       should_succeed=False)
        self._setup_vpn()
        self.check_remote_connectivity(ssh_client, right_ip)

        # Test VPN traffic and floating IP traffic don't interfere each other.
        if not self.inner_ipv6:
            # Assign a floating-ip and check connectivity.
            # This is NOT via VPN.
            fip = self.create_and_associate_floatingip(
                right_server['port']['id'])
            self.check_remote_connectivity(ssh_client,
                                           fip['floating_ip_address'])

            # check LEFT -> RIGHT connectivity via VPN again, to ensure
            # the above floating-ip doesn't interfere the traffic.
            self.check_remote_connectivity(ssh_client, right_ip)


class Vpnaas4in4(Vpnaas):

    @decorators.idempotent_id('aa932ab2-63aa-49cf-a2a0-8ae71ac2bc24')
    def test_vpnaas(self):
        self._test_vpnaas()


class Vpnaas4in6(Vpnaas):
    outer_ipv6 = True

    @decorators.idempotent_id('2d5f18dc-6186-4deb-842b-051325bd0466')
    @testtools.skipUnless(CONF.network_feature_enabled.ipv6,
                          'IPv6 tests are disabled.')
    @testtools.skipIf(
        CONF.neutron_vpnaas_plugin_options.skip_4in6_6in4_tests,
        'VPNaaS 4in6 test is skipped.')
    def test_vpnaas_4in6(self):
        self._test_vpnaas()


class Vpnaas6in4(Vpnaas):
    inner_ipv6 = True

    @decorators.idempotent_id('10febf33-c5b7-48af-aa13-94b4fb585a55')
    @testtools.skipUnless(CONF.network_feature_enabled.ipv6,
                          'IPv6 tests are disabled.')
    @testtools.skipIf(
        CONF.neutron_vpnaas_plugin_options.skip_4in6_6in4_tests,
        'VPNaaS 6in4 test is skipped.')
    def test_vpnaas_6in4(self):
        self._test_vpnaas()


class Vpnaas6in6(Vpnaas):
    inner_ipv6 = True
    outer_ipv6 = True

    @decorators.idempotent_id('8b503ffc-aeb0-4938-8dba-73c7323e276d')
    @testtools.skipUnless(CONF.network_feature_enabled.ipv6,
                          'IPv6 tests are disabled.')
    def test_vpnaas_6in6(self):
        self._test_vpnaas()
