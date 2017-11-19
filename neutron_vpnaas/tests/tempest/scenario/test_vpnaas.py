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

from tempest.common import utils
from tempest.common import waiters
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import constants

from neutron_vpnaas.tests.tempest.scenario import base


CONF = config.CONF


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

        # LEFT
        cls.router = cls.create_router(
            data_utils.rand_name('left-router'),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        cls.network = cls.create_network(network_name='left-network')
        cls.subnet = cls.create_subnet(cls.network,
                                       name='left-subnet')
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        # RIGHT
        cls._right_network, cls._right_subnet, cls._right_router = \
            cls._create_right_network()

    @classmethod
    def _create_right_network(cls):
        router = cls.create_router(
            data_utils.rand_name('right-router'),
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        network = cls.create_network(network_name='right-network')
        subnet = cls.create_subnet(network,
            cidr=netaddr.IPNetwork('10.10.0.0/24'),
            name='right-subnet')
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

    @decorators.idempotent_id('aa932ab2-63aa-49cf-a2a0-8ae71ac2bc24')
    def test_vpnaas(self):
        # RIGHT
        right_server = self._create_server(network=self._right_network,
            create_floating_ip=False)

        # LEFT
        left_server = self._create_server()
        ssh_client = ssh.Client(left_server['fip']['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'])

        # check LEFT -> RIGHT connectivity via VPN
        self.check_remote_connectivity(ssh_client,
            right_server['port']['fixed_ips'][0]['ip_address'],
            should_succeed=False)
        self._setup_vpn()
        self.check_remote_connectivity(ssh_client,
            right_server['port']['fixed_ips'][0]['ip_address'])

        # Assign a floating-ip and check connectivity.
        # This is NOT via VPN.
        fip = self.create_and_associate_floatingip(right_server['port']['id'])
        self.check_remote_connectivity(ssh_client, fip['floating_ip_address'])

        # check LEFT -> RIGHT connectivity via VPN again, to ensure
        # the above floating-ip doesn't interfere the traffic.
        self.check_remote_connectivity(ssh_client,
            right_server['port']['fixed_ips'][0]['ip_address'])
