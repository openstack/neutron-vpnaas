# Copyright 2012,2016 OpenStack Foundation
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

from neutron_lib.db import constants as db_const
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron_tempest_plugin import config

from neutron_vpnaas.tests.tempest.api import base

CONF = config.CONF

_LONG_NAME = 'x' * (db_const.NAME_FIELD_SIZE + 1)
_LONG_DESCRIPTION = 'y' * (db_const.DESCRIPTION_FIELD_SIZE + 1)


class VPNaaSTestJSON(base.BaseAdminNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:
        List, Show, Create, Delete, and Update VPN Service
        List, Show, Create, Delete, and Update IKE policy
        List, Show, Create, Delete, and Update IPSec policy
    """

    @classmethod
    def resource_setup(cls):
        if not test.is_extension_enabled('vpnaas', 'network'):
            msg = "vpnaas extension not enabled."
            raise cls.skipException(msg)
        super(VPNaaSTestJSON, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        network_name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name)
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(
            data_utils.rand_name("router"),
            external_network_id=CONF.network.public_network_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.vpnservice = cls.create_vpnservice(cls.subnet['id'],
                                               cls.router['id'])
        vpnservice2 = cls.create_vpnservice_no_subnet(cls.router['id'])
        cls.vpnservice_no_subnet = vpnservice2

        cls.ikepolicy = cls.create_ikepolicy(
            data_utils.rand_name("ike-policy-"))
        cls.ipsecpolicy = cls.create_ipsecpolicy(
            data_utils.rand_name("ipsec-policy-"))

        cls.endpoint_group_local = cls.create_endpoint_group(
            data_utils.rand_name("endpoint-group-local-"),
            'subnet',
            cls.subnet['id'])

        cls.endpoint_group_remote = cls.create_endpoint_group(
            data_utils.rand_name("endpoint-group-remote-"),
            'cidr',
            ["10.101.0.0/24", "10.102.0.0/24"])

        cls.ipsec_site_connection = cls.create_ipsec_site_connection(
            cls.ikepolicy['id'],
            cls.ipsecpolicy['id'],
            cls.vpnservice['id'])

    def _delete_ike_policy(self, ike_policy_id):
        # Deletes a ike policy and verifies if it is deleted or not
        ike_list = list()
        all_ike = self.client.list_ikepolicies()
        for ike in all_ike['ikepolicies']:
            ike_list.append(ike['id'])
        if ike_policy_id in ike_list:
            self.client.delete_ikepolicy(ike_policy_id)
            # Asserting that the policy is not found in list after deletion
            ikepolicies = self.client.list_ikepolicies()
            ike_id_list = list()
            for i in ikepolicies['ikepolicies']:
                ike_id_list.append(i['id'])
            self.assertNotIn(ike_policy_id, ike_id_list)

    def _delete_ipsec_policy(self, ipsec_policy_id):
        # Deletes an ike policy if it exists
        try:
            self.client.delete_ipsecpolicy(ipsec_policy_id)

        except lib_exc.NotFound:
            pass

    def _delete_ipsec_site_connection(self, conn_id):
        # Deletes an ipsec site connection if it exists
        try:
            self.client.delete_ipsec_site_connection(conn_id)
        except lib_exc.NotFound:
            pass

    def _assertExpected(self, expected, actual):
        # Check if not expected keys/values exists in actual response body
        for key, value in expected.items():
            self.assertIn(key, actual)
            self.assertEqual(value, actual[key])

    def _delete_vpn_service(self, vpn_service_id):
        self.client.delete_vpnservice(vpn_service_id)
        # Asserting if vpn service is found in the list after deletion
        body = self.client.list_vpnservices()
        vpn_services = [vs['id'] for vs in body['vpnservices']]
        self.assertNotIn(vpn_service_id, vpn_services)

    def _delete_endpoint_group(self, endpoint_group_id):
        # Delete a endpoint-group and verifies if it is deleted or not
        endpoint_group_list = list()
        all_endpoint = self.client.list_endpoint_groups()
        for endpoint in all_endpoint['endpoint_groups']:
            endpoint_group_list.append(endpoint['id'])
        if endpoint_group_id in endpoint_group_list:
            self.client.delete_endpoint_group(endpoint_group_id)
            # Asserting that the endpoint is not found in list after deletion
            endpoint_group = self.client.list_endpoint_groups()
            for e in endpoint_group['endpoint_groups']:
                endpoint_group_list.append(e['id'])
            self.assertNotIn(endpoint_group_list, endpoint_group_id)

    def _get_tenant_id(self):
        """
        Returns the tenant_id of the client current user
        """
        return self.client.tenant_id

    @decorators.attr(type='smoke')
    def test_admin_create_ipsec_policy_for_tenant(self):
        tenant_id = self._get_tenant_id()
        # Create IPSec policy for the newly created tenant
        name = data_utils.rand_name('ipsec-policy')
        body = (self.admin_client.
                create_ipsecpolicy(name=name, tenant_id=tenant_id))
        ipsecpolicy = body['ipsecpolicy']
        self.assertIsNotNone(ipsecpolicy['id'])
        self.addCleanup(self.admin_client.delete_ipsecpolicy,
                        ipsecpolicy['id'])

        # Assert that created ipsec policy is found in API list call
        body = self.client.list_ipsecpolicies()
        ipsecpolicies = [policy['id'] for policy in body['ipsecpolicies']]
        self.assertIn(ipsecpolicy['id'], ipsecpolicies)

    @decorators.attr(type='smoke')
    def test_admin_create_vpn_service_for_tenant(self):
        tenant_id = self._get_tenant_id()

        # Create vpn service for the newly created tenant
        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router-'),
                                     external_network_id=self.ext_net_id)
        self.create_router_interface(router2['id'], subnet2['id'])
        name = data_utils.rand_name('vpn-service')
        body = self.admin_client.create_vpnservice(
            subnet_id=subnet2['id'],
            router_id=router2['id'],
            name=name,
            admin_state_up=True,
            tenant_id=tenant_id)
        vpnservice = body['vpnservice']
        self.assertIsNotNone(vpnservice['id'])
        self.addCleanup(self.admin_client.delete_vpnservice, vpnservice['id'])
        # Assert that created vpnservice is found in API list call
        body = self.client.list_vpnservices()
        vpn_services = [vs['id'] for vs in body['vpnservices']]
        self.assertIn(vpnservice['id'], vpn_services)

    @decorators.attr(type='smoke')
    def test_admin_create_ike_policy_for_tenant(self):
        tenant_id = self._get_tenant_id()

        # Create IKE policy for the newly created tenant
        name = data_utils.rand_name('ike-policy')
        body = (self.admin_client.
                create_ikepolicy(name=name, ike_version="v1",
                                 encryption_algorithm="aes-128",
                                 auth_algorithm="sha1",
                                 tenant_id=tenant_id))
        ikepolicy = body['ikepolicy']
        self.assertIsNotNone(ikepolicy['id'])
        self.addCleanup(self.admin_client.delete_ikepolicy, ikepolicy['id'])

        # Assert that created ike policy is found in API list call
        body = self.client.list_ikepolicies()
        ikepolicies = [ikp['id'] for ikp in body['ikepolicies']]
        self.assertIn(ikepolicy['id'], ikepolicies)

    @decorators.attr(type='smoke')
    def test_list_vpn_services(self):
        # Verify the VPN service exists in the list of all VPN services
        body = self.client.list_vpnservices()
        vpnservices = body['vpnservices']
        self.assertIn(self.vpnservice['id'], [v['id'] for v in vpnservices])

    @decorators.attr(type='smoke')
    def test_create_update_delete_vpn_service(self):
        # Creates a VPN service and sets up deletion
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router1 = self.create_router(data_utils.rand_name('router-'),
                                     external_network_id=self.ext_net_id)
        self.create_router_interface(router1['id'], subnet1['id'])
        name = data_utils.rand_name('vpn-service1')
        body = self.client.create_vpnservice(subnet_id=subnet1['id'],
                                             router_id=router1['id'],
                                             name=name,
                                             admin_state_up=True)
        vpnservice = body['vpnservice']
        self.addCleanup(self._delete_vpn_service, vpnservice['id'])
        # Assert if created vpnservices are not found in vpnservices list
        body = self.client.list_vpnservices()
        vpn_services = [vs['id'] for vs in body['vpnservices']]
        self.assertIsNotNone(vpnservice['id'])
        self.assertIn(vpnservice['id'], vpn_services)

        # TODO(raies): implement logic to update  vpnservice
        # VPNaaS client function to update is implemented.
        # But precondition is that current state of vpnservice
        # should be "ACTIVE" not "PENDING*"

    @decorators.attr(type='smoke')
    def test_show_vpn_service(self):
        # Verifies the details of a vpn service
        body = self.client.show_vpnservice(self.vpnservice['id'])
        vpnservice = body['vpnservice']
        self.assertEqual(self.vpnservice['id'], vpnservice['id'])
        self.assertEqual(self.vpnservice['name'], vpnservice['name'])
        self.assertEqual(self.vpnservice['description'],
                         vpnservice['description'])
        self.assertEqual(self.vpnservice['router_id'], vpnservice['router_id'])
        self.assertEqual(self.vpnservice['subnet_id'], vpnservice['subnet_id'])
        self.assertEqual(self.vpnservice['tenant_id'], vpnservice['tenant_id'])
        valid_status = ["ACTIVE", "DOWN", "BUILD", "ERROR", "PENDING_CREATE",
                        "PENDING_UPDATE", "PENDING_DELETE"]
        self.assertIn(vpnservice['status'], valid_status)

    @decorators.attr(type='smoke')
    def test_list_ike_policies(self):
        # Verify the ike policy exists in the list of all IKE policies
        body = self.client.list_ikepolicies()
        ikepolicies = body['ikepolicies']
        self.assertIn(self.ikepolicy['id'], [i['id'] for i in ikepolicies])

    @decorators.attr(type='smoke')
    def test_create_update_delete_ike_policy(self):
        # Creates a IKE policy
        name = data_utils.rand_name('ike-policy')
        body = (self.client.create_ikepolicy(
                name=name,
                ike_version="v1",
                encryption_algorithm="aes-128",
                auth_algorithm="sha1"))
        ikepolicy = body['ikepolicy']
        self.assertIsNotNone(ikepolicy['id'])
        self.addCleanup(self._delete_ike_policy, ikepolicy['id'])

        # Update IKE Policy
        new_ike = {'name': data_utils.rand_name("New-IKE"),
                   'description': "Updated ike policy",
                   'encryption_algorithm': "aes-256",
                   'ike_version': "v2",
                   'pfs': "group14",
                   'lifetime': {'units': "seconds", 'value': 2000}}
        self.client.update_ikepolicy(ikepolicy['id'], **new_ike)
        # Confirm that update was successful by verifying using 'show'
        body = self.client.show_ikepolicy(ikepolicy['id'])
        ike_policy = body['ikepolicy']
        for key, value in new_ike.items():
            self.assertIn(key, ike_policy)
            self.assertEqual(value, ike_policy[key])

        # Verification of ike policy delete
        self.client.delete_ikepolicy(ikepolicy['id'])
        body = self.client.list_ikepolicies()
        ikepolicies = [ikp['id'] for ikp in body['ikepolicies']]
        self.assertNotIn(ike_policy['id'], ikepolicies)

    @decorators.attr(type='smoke')
    def test_show_ike_policy(self):
        # Verifies the details of a ike policy
        body = self.client.show_ikepolicy(self.ikepolicy['id'])
        ikepolicy = body['ikepolicy']
        self.assertEqual(self.ikepolicy['id'], ikepolicy['id'])
        self.assertEqual(self.ikepolicy['name'], ikepolicy['name'])
        self.assertEqual(self.ikepolicy['description'],
                         ikepolicy['description'])
        self.assertEqual(self.ikepolicy['encryption_algorithm'],
                         ikepolicy['encryption_algorithm'])
        self.assertEqual(self.ikepolicy['auth_algorithm'],
                         ikepolicy['auth_algorithm'])
        self.assertEqual(self.ikepolicy['tenant_id'],
                         ikepolicy['tenant_id'])
        self.assertEqual(self.ikepolicy['pfs'],
                         ikepolicy['pfs'])
        self.assertEqual(self.ikepolicy['phase1_negotiation_mode'],
                         ikepolicy['phase1_negotiation_mode'])
        self.assertEqual(self.ikepolicy['ike_version'],
                         ikepolicy['ike_version'])

    @decorators.attr(type='smoke')
    def test_list_ipsec_policies(self):
        # Verify the ipsec policy exists in the list of all ipsec policies
        body = self.client.list_ipsecpolicies()
        ipsecpolicies = body['ipsecpolicies']
        self.assertIn(self.ipsecpolicy['id'], [i['id'] for i in ipsecpolicies])

    @decorators.attr(type='smoke')
    def test_create_update_delete_ipsec_policy(self):
        # Creates an ipsec policy
        ipsec_policy_body = {'name': data_utils.rand_name('ipsec-policy'),
                             'pfs': 'group5',
                             'encryption_algorithm': "aes-128",
                             'auth_algorithm': 'sha1'}
        resp_body = self.client.create_ipsecpolicy(**ipsec_policy_body)
        ipsecpolicy = resp_body['ipsecpolicy']
        self.addCleanup(self._delete_ipsec_policy, ipsecpolicy['id'])
        self._assertExpected(ipsec_policy_body, ipsecpolicy)
        # Verification of ipsec policy update
        new_ipsec = {'description': 'Updated ipsec policy',
                     'pfs': 'group2',
                     'name': data_utils.rand_name("New-IPSec"),
                     'encryption_algorithm': "aes-256",
                     'lifetime': {'units': "seconds", 'value': '2000'}}
        body = self.client.update_ipsecpolicy(ipsecpolicy['id'],
                                              **new_ipsec)
        updated_ipsec_policy = body['ipsecpolicy']
        self._assertExpected(new_ipsec, updated_ipsec_policy)
        # Verification of ipsec policy delete
        self.client.delete_ipsecpolicy(ipsecpolicy['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.client.delete_ipsecpolicy, ipsecpolicy['id'])

    @decorators.attr(type='smoke')
    def test_show_ipsec_policy(self):
        # Verifies the details of an ipsec policy
        body = self.client.show_ipsecpolicy(self.ipsecpolicy['id'])
        ipsecpolicy = body['ipsecpolicy']
        self._assertExpected(self.ipsecpolicy, ipsecpolicy)

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpnservice_long_name(self):
        """
        Test excessively long name.

        Without REST checks, this call would return 500 INTERNAL SERVER
        error on internal db failure instead.
        """
        name = _LONG_NAME
        self.assertRaises(
            lib_exc.BadRequest, self.client.create_vpnservice,
            subnet_id=self.subnet['id'], router_id=self.router['id'],
            name=name, admin_state_up=True)

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpnservice_long_description(self):
        name = data_utils.rand_name('vpn-service1')
        description = _LONG_DESCRIPTION
        self.assertRaises(
            lib_exc.BadRequest, self.client.create_vpnservice,
            subnet_id=self.subnet['id'], router_id=self.router['id'],
            name=name, description=description, admin_state_up=True)

    @decorators.attr(type='smoke')
    def test_list_vpn_connections(self):
        # Verify the VPN service exists in the list of all VPN services
        body = self.client.list_ipsec_site_connections()
        ipsec_site_connections = body['ipsec_site_connections']
        self.assertIn(self.ipsec_site_connection['id'],
                      [v['id'] for v in ipsec_site_connections])

    @decorators.attr(type='smoke')
    def test_create_delete_vpn_connection_with_legacy_mode(self):
        # Verify create VPN connection
        name = data_utils.rand_name("ipsec_site_connection-")
        body = self.client.create_ipsec_site_connection(
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_cidrs=['10.1.1.0/24', '10.2.2.0/24'],
            name=name,
            mtu=1500,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")
        ipsec_site_connection = body['ipsec_site_connection']
        self.assertEqual(ipsec_site_connection['name'], name)
        self.assertEqual(ipsec_site_connection['mtu'], 1500)
        self.addCleanup(self._delete_ipsec_site_connection,
                        ipsec_site_connection['id'])

        # Verification of IPsec connection delete
        self.client.delete_ipsec_site_connection(ipsec_site_connection['id'])
        body = self.client.list_ipsec_site_connections()
        ipsec_site_connections = body['ipsec_site_connections']
        self.assertNotIn(ipsec_site_connection['id'],
                      [v['id'] for v in ipsec_site_connections])

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_connection_missing_peer_cidr(self):
        # Verify create VPN connection with JSON missing peer cidr
        # in legacy mode
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            name=name,
            mtu=1500,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_service_subnet_not_on_router(self):
        # Verify create VPN service with a subnet not on router
        tenant_id = self._get_tenant_id()

        # Create vpn service for the newly created tenant
        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router-'),
                                     external_network_id=self.ext_net_id)
        self.addCleanup(self.admin_client.delete_router, router2['id'])
        self.addCleanup(self.admin_client.delete_network, network2['id'])
        name = data_utils.rand_name('vpn-service')
        self.assertRaises(
            lib_exc.BadRequest,
            self.admin_client.create_vpnservice,
            subnet_id=subnet2['id'],
            router_id=router2['id'],
            name=name,
            admin_state_up=True,
            tenant_id=tenant_id)

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_connection_small_MTU(self):
        # Verify create VPN connection with small MTU
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_cidrs=['10.1.1.0/24', '10.2.2.0/24'],
            name=name,
            mtu=63,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_connection_small_dpd(self):
        # Verify create VPN connection with small dpd
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_cidrs=['10.1.1.0/24', '10.2.2.0/24'],
            name=name,
            dpd=59,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_connection_wrong_peer_cidr(self):
        # Verify create VPN connection with wrong peer cidr
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_cidrs=['1.0.0.0/33'],
            name=name,
            mtu=1500,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_connection_with_cidr_and_endpoint_group(self):
        tenant_id = self._get_tenant_id()
        # Create endpoint group for the newly created tenant
        name = data_utils.rand_name('endpoint_group')
        subnet_id = self.subnet['id']
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='subnet',
                        endpoints=subnet_id)
        endpoint_group_local = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group,
                        endpoint_group_local['id'])
        name = data_utils.rand_name('endpoint_group')
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='cidr',
                        endpoints=["10.103.0.0/24", "10.104.0.0/24"])
        endpoint_group_remote = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group,
                        endpoint_group_remote['id'])
        # Create connections
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice_no_subnet['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_cidr="10.1.0.0/24",
            peer_ep_group_id=endpoint_group_local['id'],
            local_ep_group_id=endpoint_group_remote['id'],
            name=name,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_connection_with_missing_remote_endpoint_group(self):
        # Verify create VPN connection without subnet in vpnservice
        # and has only local endpoint group
        tenant_id = self._get_tenant_id()
        # Create endpoint group for the newly created tenant
        tenant_id = self._get_tenant_id()
        name = data_utils.rand_name('endpoint_group')
        subnet_id = self.subnet['id']
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='subnet',
                        endpoints=subnet_id)
        endpoint_group = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group, endpoint_group['id'])
        # Create connections
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice_no_subnet['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            local_ep_group_id=endpoint_group['id'],
            name=name,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_vpn_connection_with_missing_local_endpoint_group(self):
        # Verify create VPN connection without subnet in vpnservice
        # and only have only local endpoint group
        tenant_id = self._get_tenant_id()
        # Create endpoint group for the newly created tenant
        tenant_id = self._get_tenant_id()
        name = data_utils.rand_name('endpoint_group')
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='cidr',
                        endpoints=["10.101.0.0/24", "10.102.0.0/24"])
        endpoint_group = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group, endpoint_group['id'])
        # Create connections
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice_no_subnet['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_ep_group_id=endpoint_group['id'],
            name=name,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_connection_with_mix_ip_endpoint_group(self):
        tenant_id = self._get_tenant_id()
        # Create endpoint group for the newly created tenant
        name = data_utils.rand_name('endpoint_group')
        subnet_id = self.subnet['id']
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='subnet',
                        endpoints=subnet_id)
        endpoint_group_local = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group,
                        endpoint_group_local['id'])
        name_v6 = data_utils.rand_name('endpoint_group')
        body_v6 = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name_v6,
                        type='cidr',
                        endpoints=["fec0:101::/64", "fec0:102::/64"])
        endpoint_group_remote = body_v6['endpoint_group']
        self.addCleanup(self._delete_endpoint_group,
                        endpoint_group_remote['id'])
        # Create connections
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertEqual(endpoint_group_local['type'], 'subnet')
        self.assertEqual(endpoint_group_remote['type'], 'cidr')
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice_no_subnet['id'],
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            peer_ep_group_id=endpoint_group_local['id'],
            local_ep_group_id=endpoint_group_remote['id'],
            name=name,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_connection_with_subnet_and_remote_endpoint_group(self):
        tenant_id = self._get_tenant_id()
        # Create endpoint group for the newly created tenant
        name = data_utils.rand_name('endpoint_group')
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='cidr',
                        endpoints=["10.101.0.0/24", "10.102.0.0/24"])
        endpoint_group = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group, endpoint_group['id'])
        # Create connections
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            peer_ep_group_id=endpoint_group['id'],
            name=name,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_connection_with_subnet_and_local_endpoint_group(self):
        tenant_id = self._get_tenant_id()
        # Create endpoint group for the newly created tenant
        name = data_utils.rand_name('endpoint_group')
        subnet_id = self.subnet['id']
        body = self.client.create_endpoint_group(
                        tenant_id=tenant_id,
                        name=name,
                        type='subnet',
                        endpoints=subnet_id)
        endpoint_group = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group, endpoint_group['id'])
        # Create connections
        name = data_utils.rand_name("ipsec_site_connection-")
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_ipsec_site_connection,
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice['id'],
            peer_address="172.24.4.233",
            local_ep_group_id=endpoint_group['id'],
            name=name,
            admin_state_up=True,
            initiator="bi-directional",
            psk="secret")

    @decorators.attr(type='smoke')
    def test_create_update_delete_endpoint_group(self):
        # Creates a endpoint-group
        name = data_utils.rand_name('endpoint_group')
        body = (self.client.create_endpoint_group(
                name=name,
                type='cidr',
                endpoints=["10.2.0.0/24", "10.3.0.0/24"]))
        endpoint_group = body['endpoint_group']
        self.assertIsNotNone(endpoint_group['id'])
        self.addCleanup(self._delete_endpoint_group, endpoint_group['id'])
        # Update endpoint-group
        body = {'name': data_utils.rand_name("new_endpoint_group")}
        self.client.update_endpoint_group(endpoint_group['id'],
                        name=name)
        # Confirm that update was successful by verifying using 'show'
        body = self.client.show_endpoint_group(endpoint_group['id'])
        endpoint_group = body['endpoint_group']
        self.assertEqual(name, endpoint_group['name'])
        # Verification of endpoint-group delete
        endpoint_group_id = endpoint_group['id']
        self.client.delete_endpoint_group(endpoint_group['id'])
        body = self.client.list_endpoint_groups()
        endpoint_group = [enp['id'] for enp in body['endpoint_groups']]
        self.assertNotIn(endpoint_group_id, endpoint_group)

    @decorators.attr(type='smoke')
    def test_admin_create_endpoint_group_for_tenant(self):
        # Create endpoint group for the newly created tenant
        tenant_id = self._get_tenant_id()
        name = data_utils.rand_name('endpoint_group')
        body = (self.client.
                create_endpoint_group(
                        name=name,
                        type='cidr',
                        endpoints=["10.2.0.0/24", "10.3.0.0/24"],
                        tenant_id=tenant_id))
        endpoint_group = body['endpoint_group']
        self.assertIsNotNone(endpoint_group['id'])
        self.addCleanup(self._delete_endpoint_group, endpoint_group['id'])
        # Assert that created endpoint group is found in API list call
        endpoint_group_id = endpoint_group['id']
        self.client.delete_endpoint_group(endpoint_group['id'])
        body = self.client.list_endpoint_groups()
        endpoint_group = [enp['id'] for enp in body['endpoint_groups']]
        self.assertNotIn(endpoint_group_id, endpoint_group)

    @decorators.attr(type='smoke')
    def test_show_endpoint_group(self):
        # Verifies the details of an endpoint group
        body = self.client.show_endpoint_group(self.endpoint_group_local['id'])
        endpoint_group = body['endpoint_group']
        self.assertEqual(self.endpoint_group_local['id'], endpoint_group['id'])
        self.assertEqual(self.endpoint_group_local['name'],
                         endpoint_group['name'])
        self.assertEqual(self.endpoint_group_local['description'],
                         endpoint_group['description'])
        self.assertEqual(self.endpoint_group_local['tenant_id'],
                         endpoint_group['tenant_id'])
        self.assertEqual(self.endpoint_group_local['type'],
                         endpoint_group['type'])
        self.assertEqual(self.endpoint_group_local['endpoints'],
                         endpoint_group['endpoints'])
        # Verifies the details of an endpoint group
        body = self.client.show_endpoint_group(
                         self.endpoint_group_remote['id'])
        endpoint_group = body['endpoint_group']
        #endpoint_group_remote = endpoint_group['id']
        self.assertEqual(self.endpoint_group_remote['id'],
                         endpoint_group['id'])
        self.assertEqual(self.endpoint_group_remote['name'],
                         endpoint_group['name'])
        self.assertEqual(self.endpoint_group_remote['description'],
                         endpoint_group['description'])
        self.assertEqual(self.endpoint_group_remote['tenant_id'],
                         endpoint_group['tenant_id'])
        self.assertEqual(self.endpoint_group_remote['type'],
                         endpoint_group['type'])
        self.assertEqual(self.endpoint_group_remote['endpoints'],
                         endpoint_group['endpoints'])

    @decorators.attr(type='smoke')
    def test_create_delete_vpn_connection_with_ep_group(self):
        # Creates a endpoint-group with type cidr
        name = data_utils.rand_name('endpoint_group')
        body = self.client.create_endpoint_group(
                name=name,
                type='cidr',
                endpoints=["10.2.0.0/24", "10.3.0.0/24"])
        endpoint_group_remote = body['endpoint_group']
        self.addCleanup(self._delete_endpoint_group,
                        endpoint_group_remote['id'])
        # Creates a endpoint-group with type subnet
        name = data_utils.rand_name('endpoint_group')
        subnet_id = self.subnet['id']
        body2 = self.client.create_endpoint_group(
                name=name,
                type='subnet',
                endpoints=subnet_id)
        endpoint_group_local = body2['endpoint_group']
        self.addCleanup(self._delete_endpoint_group,
                        endpoint_group_local['id'])
        # Verify create VPN connection
        name = data_utils.rand_name("ipsec_site_connection-")
        body = self.client.create_ipsec_site_connection(
            ipsecpolicy_id=self.ipsecpolicy['id'],
            ikepolicy_id=self.ikepolicy['id'],
            vpnservice_id=self.vpnservice_no_subnet['id'],
            peer_ep_group_id=endpoint_group_remote['id'],
            local_ep_group_id=endpoint_group_local['id'],
            name=name,
            mtu=1500,
            admin_state_up=True,
            initiator="bi-directional",
            peer_address="172.24.4.233",
            peer_id="172.24.4.233",
            psk="secret")
        ipsec_site_connection = body['ipsec_site_connection']
        self.assertEqual(ipsec_site_connection['name'], name)
        self.assertEqual(ipsec_site_connection['mtu'], 1500)
        self.addCleanup(self._delete_ipsec_site_connection,
                        ipsec_site_connection['id'])

        # Verification of IPsec connection delete
        self.client.delete_ipsec_site_connection(ipsec_site_connection['id'])
        body = self.client.list_ipsec_site_connections()
        ipsec_site_connections = body['ipsec_site_connections']
        self.assertNotIn(ipsec_site_connection['id'],
                      [v['id'] for v in ipsec_site_connections])

    @decorators.attr(type=['negative', 'smoke'])
    def test_fail_create_endpoint_group_when_wrong_type(self):
        # Creates a endpoint-group with wrong type
        name = data_utils.rand_name('endpoint_group')
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_endpoint_group,
            name=name,
            type='subnet',
            endpoints=["10.2.0.0/24", "10.3.0.0/24"])

    @decorators.attr(type=['negative', 'smoke'])
    def test_fail_create_endpoint_group_when_provide_subnet_id_with_cidr(self):
        # Creates a endpoint-group when provide subnet id with type cidr
        name = data_utils.rand_name('endpoint_group')
        subnet_id = self.subnet['id']
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_endpoint_group,
            name=name,
            type='cidr',
            endpoints=subnet_id)

    @decorators.attr(type=['negative', 'smoke'])
    def test_fail_create_endpoint_group_with_mixed_IP_version(self):
        # Creates a endpoint-group with mixed IP version
        name = data_utils.rand_name('endpoint_group')
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.create_endpoint_group,
            name=name,
            type='cidr',
            endpoints=["10.2.0.0/24", "2000::1"])
