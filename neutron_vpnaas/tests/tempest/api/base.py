# Copyright 2012 OpenStack Foundation
# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

from tempest.lib.common.utils import data_utils

from neutron_tempest_plugin.api import base
from neutron_tempest_plugin import config

from neutron_vpnaas.tests.tempest.api import clients

CONF = config.CONF


class BaseNetworkTest(base.BaseNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(BaseNetworkTest, cls).resource_setup()
        cls.vpnservices = []
        cls.ikepolicies = []
        cls.ipsecpolicies = []
        cls.ipsec_site_connections = []
        cls.endpoint_groups = []

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = super(BaseNetworkTest, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new)
        # Neutron uses a different clients manager than the one in the Tempest
        return clients.Manager(manager.credentials)

    @classmethod
    def resource_cleanup(cls):
        if CONF.service_available.neutron:
            # Clean up ipsec connections
            for ipsec_site_connection in cls.ipsec_site_connections:
                cls._try_delete_resource(
                    cls.client.delete_ipsec_site_connection,
                    ipsec_site_connection['id'])

            # Clean up ipsec endpoint group
            for endpoint_group in cls.endpoint_groups:
                cls._try_delete_resource(cls.client.delete_endpoint_group,
                                         endpoint_group['id'])

            # Clean up ipsec policies
            for ipsecpolicy in cls.ipsecpolicies:
                cls._try_delete_resource(cls.client.delete_ipsecpolicy,
                                         ipsecpolicy['id'])
            # Clean up ike policies
            for ikepolicy in cls.ikepolicies:
                cls._try_delete_resource(cls.client.delete_ikepolicy,
                                         ikepolicy['id'])
            # Clean up vpn services
            for vpnservice in cls.vpnservices:
                cls._try_delete_resource(cls.client.delete_vpnservice,
                                         vpnservice['id'])
        super(BaseNetworkTest, cls).resource_cleanup()

    @classmethod
    def create_vpnservice(cls, subnet_id, router_id, name=None):
        """Wrapper utility that returns a test vpn service."""
        if name is None:
            name = data_utils.rand_name("vpnservice-")
        body = cls.client.create_vpnservice(
            subnet_id=subnet_id, router_id=router_id, admin_state_up=True,
            name=name)
        vpnservice = body['vpnservice']
        cls.vpnservices.append(vpnservice)
        return vpnservice

    @classmethod
    def create_vpnservice_no_subnet(cls, router_id):
        """Wrapper utility that returns a test vpn service."""
        body = cls.client.create_vpnservice(
            router_id=router_id, admin_state_up=True,
            name=data_utils.rand_name("vpnservice-"))
        vpnservice = body['vpnservice']
        cls.vpnservices.append(vpnservice)
        return vpnservice

    @classmethod
    def create_ikepolicy(cls, name):
        """Wrapper utility that returns a test ike policy."""
        body = cls.client.create_ikepolicy(name=name)
        ikepolicy = body['ikepolicy']
        cls.ikepolicies.append(ikepolicy)
        return ikepolicy

    @classmethod
    def create_ipsecpolicy(cls, name):
        """Wrapper utility that returns a test ipsec policy."""
        body = cls.client.create_ipsecpolicy(name=name)
        ipsecpolicy = body['ipsecpolicy']
        cls.ipsecpolicies.append(ipsecpolicy)
        return ipsecpolicy

    @classmethod
    def create_ipsec_site_connection(cls, ikepolicy_id, ipsecpolicy_id,
                                     vpnservice_id, psk="secret",
                                     peer_address="172.24.4.233",
                                     peer_id="172.24.4.233",
                                     peer_cidrs=None,
                                     name=None):
        """Wrapper utility that returns a test vpn connection."""
        if peer_cidrs is None:
            peer_cidrs = ['1.1.1.0/24', '2.2.2.0/24']
        if name is None:
            name = data_utils.rand_name("ipsec_site_connection-")
        body = cls.client.create_ipsec_site_connection(
            psk=psk,
            initiator="bi-directional",
            ipsecpolicy_id=ipsecpolicy_id,
            admin_state_up=True,
            mtu=1500,
            ikepolicy_id=ikepolicy_id,
            vpnservice_id=vpnservice_id,
            peer_address=peer_address,
            peer_id=peer_id,
            peer_cidrs=peer_cidrs,
            name=name)
        ipsec_site_connection = body['ipsec_site_connection']
        cls.ipsec_site_connections.append(ipsec_site_connection)
        return ipsec_site_connection

    @classmethod
    def create_endpoint_group(cls, name, type, endpoints):
        """Wrapper utility that returns a test ipsec policy."""
        body = cls.client.create_endpoint_group(
            endpoints=endpoints,
            type=type,
            description='endpoint type:' + type,
            name=name)
        endpoint_group = body['endpoint_group']
        cls.endpoint_groups.append(endpoint_group)
        return endpoint_group


class BaseAdminNetworkTest(BaseNetworkTest):
    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(BaseAdminNetworkTest, cls).setup_clients()
        cls.admin_client = cls.os_admin.network_client
        cls.identity_admin_client = cls.os_admin.tenants_client
