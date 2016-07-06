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

import netaddr
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.tests.tempest import config

from neutron_vpnaas.tests.tempest.api import clients

CONF = config.CONF


class BaseNetworkTest(test.BaseTestCase):
    """
    Base class for the Neutron tests that use the Tempest Neutron REST client

    Per the Neutron API Guide, API v1.x was removed from the source code tree
    (docs.openstack.org/api/openstack-network/2.0/content/Overview-d1e71.html)
    Therefore, v2.x of the Neutron API is assumed. It is also assumed that the
    following options are defined in the [network] section of etc/tempest.conf:

        tenant_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant networks

        tenant_network_mask_bits with the mask bits to be used to partition the
        block defined by tenant-network_cidr

    Finally, it is assumed that the following option is defined in the
    [service_available] section of etc/tempest.conf

        neutron as True
    """

    force_tenant_isolation = False
    credentials = ['primary']

    # Default to ipv4.
    _ip_version = 4

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = test.BaseTestCase.get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new)
        # Neutron uses a different clients manager than the one in the Tempest
        return clients.Manager(manager.credentials)

    @classmethod
    def skip_checks(cls):
        super(BaseNetworkTest, cls).skip_checks()
        # Create no network resources for these tests.
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")
        if cls._ip_version == 6 and not CONF.network_feature_enabled.ipv6:
            raise cls.skipException("IPv6 Tests are disabled.")

    @classmethod
    def setup_clients(cls):
        super(BaseNetworkTest, cls).setup_clients()
        cls.client = cls.os.network_client

    @classmethod
    def resource_setup(cls):
        super(BaseNetworkTest, cls).resource_setup()
        cls.network_cfg = CONF.network
        cls.networks = []
        cls.shared_networks = []
        cls.subnets = []
        cls.ports = []
        cls.routers = []
        cls.vpnservices = []
        cls.ikepolicies = []
        cls.ipsecpolicies = []
        cls.ipsec_site_connections = []
        cls.endpoint_groups = []

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
            # Clean up routers
            for router in cls.routers:
                ports = cls.client.list_router_interfaces(router['id'])
                for port in ports['ports']:
                    router_info = {'router_id': router['id'],
                                   'port_id': port['id']}
                    cls._try_delete_resource(
                        cls.client.remove_router_interface_with_port_id,
                        **router_info)
                router_info = {'router_id': router['id'],
                               'external_gateway_info': {}}
                cls._try_delete_resource(cls.client.update_router,
                                         **router_info)
                cls._try_delete_resource(cls.client.delete_router,
                                         router['id'])
            # Clean up ports
            for port in cls.ports:
                cls._try_delete_resource(cls.client.delete_port,
                                         port['id'])
            # Clean up subnets
            for subnet in cls.subnets:
                cls._try_delete_resource(cls.client.delete_subnet,
                                         subnet['id'])
            # Clean up networks
            for network in cls.networks:
                cls._try_delete_resource(cls.client.delete_network,
                                         network['id'])
            # Clean up shared networks
            for network in cls.shared_networks:
                cls._try_delete_resource(cls.admin_client.delete_network,
                                         network['id'])

    @classmethod
    def _try_delete_resource(cls, delete_callable, *args, **kwargs):
        """Cleanup resources in case of test-failure

        Some resources are explicitly deleted by the test.
        If the test failed to delete a resource, this method will execute
        the appropriate delete methods. Otherwise, the method ignores NotFound
        exceptions thrown for resources that were correctly deleted by the
        test.

        :param delete_callable: delete method
        :param args: arguments for delete method
        :param kwargs: keyword arguments for delete method
        """
        try:
            delete_callable(*args, **kwargs)
        # if resource is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    @classmethod
    def create_network(cls, network_name=None, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network-')

        body = cls.client.create_network(name=network_name, **kwargs)
        network = body['network']
        cls.networks.append(network)
        return network

    @classmethod
    def create_shared_network(cls, network_name=None):
        network_name = network_name or data_utils.rand_name('sharednetwork-')
        post_body = {'name': network_name, 'shared': True}
        body = cls.admin_client.create_network(**post_body)
        network = body['network']
        cls.shared_networks.append(network)
        return network

    @classmethod
    def create_router_interface(cls, router_id, subnet_id):
        """Wrapper utility that returns a router interface."""
        interface = cls.client.add_router_interface_with_subnet_id(
            router_id, subnet_id)
        return interface

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):
        """Wrapper utility that returns a test subnet."""

        # allow tests to use admin client
        if not client:
            client = cls.client

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else cls._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or netaddr.IPNetwork(CONF.network.project_network_cidr)
            mask_bits = mask_bits or CONF.network.project_network_mask_bits
        elif ip_version == 6:
            cidr = (
                cidr or netaddr.IPNetwork(CONF.network.tenant_network_v6_cidr))
            mask_bits = mask_bits or CONF.network.tenant_network_v6_mask_bits
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(netaddr.IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                body = client.create_subnet(
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=ip_version,
                    gateway_ip=gateway_ip,
                    **kwargs)
                break
            except lib_exc.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise ValueError(message)
        subnet = body['subnet']
        cls.subnets.append(subnet)
        return subnet

    @classmethod
    def create_port(cls, network, **kwargs):
        """Wrapper utility that returns a test port."""
        body = cls.client.create_port(network_id=network['id'],
                                      **kwargs)
        port = body['port']
        cls.ports.append(port)
        return port

    @classmethod
    def update_port(cls, port, **kwargs):
        """Wrapper utility that updates a test port."""
        body = cls.client.update_port(port['id'],
                                      **kwargs)
        return body['port']

    @classmethod
    def create_router(cls, router_name=None, admin_state_up=False,
                      external_network_id=None, enable_snat=None,
                      **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat:
            ext_gw_info['enable_snat'] = enable_snat
        body = cls.client.create_router(
            router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        cls.routers.append(router)
        return router

    @classmethod
    def create_vpnservice(cls, subnet_id, router_id):
        """Wrapper utility that returns a test vpn service."""
        body = cls.client.create_vpnservice(
            subnet_id=subnet_id, router_id=router_id, admin_state_up=True,
            name=data_utils.rand_name("vpnservice-"))
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
                                     vpnservice_id):
        """Wrapper utility that returns a test vpn connection."""
        body = cls.client.create_ipsec_site_connection(
            psk="secret",
            initiator="bi-directional",
            ipsecpolicy_id=ipsecpolicy_id,
            admin_state_up=True,
            mtu=1500,
            ikepolicy_id=ikepolicy_id,
            vpnservice_id=vpnservice_id,
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_cidrs=['1.1.1.0/24', '2.2.2.0/24'],
            name=data_utils.rand_name("ipsec_site_connection-"))
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
        cls.admin_client = cls.os_adm.network_client
        cls.identity_admin_client = cls.os_adm.tenants_client
