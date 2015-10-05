# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import concurrent.futures
import exceptions
import multiprocessing
import re
import time

from oslo_utils import uuidutils
from rally.common import log as logging
from rally.plugins.openstack import scenario as rally_base
from rally.task import atomic

import vpn_utils

LOG = logging.getLogger(__name__)
LOCK = multiprocessing.RLock()
MAX_RESOURCES = 2


class VpnBase(rally_base.OpenStackScenario):

    def setup(self):
        """Creates and initializes data structures to hold various resources"""

        self.snat_namespaces = []
        self.qrouter_namespaces = []
        self.router_ids = []
        self.rally_router_gw_ips = []
        self.rally_routers = []
        self.rally_networks = []
        self.rally_subnets = []
        self.rally_cidrs = []
        self.ike_policy = None
        self.ipsec_policy = None
        self.vpn_services = []
        self.ipsec_site_connections = []
        self.servers = []
        self.server_private_ips = []
        self.suffixes = [uuidutils.generate_uuid(), uuidutils.generate_uuid()]
        self.key_names = map(lambda x: "rally_keypair_" + x, self.suffixes)
        self.key_file_paths = map(lambda x: '/tmp/' + x, self.key_names)
        self.neutron_client = self.clients("neutron")
        self.neutron_admin_client = self.admin_clients("neutron")
        self.nova_client = self.clients("nova")

    @atomic.action_timer("cleanup")
    def cleanup(self):
        """Cleans up all the resources"""

        vpn_utils.delete_servers(self.nova_client, self.servers)
        vpn_utils.delete_hosts_from_knownhosts_file(self.server_private_ips)
        vpn_utils.delete_key_files(self.key_file_paths)
        self._delete_ipsec_site_connections()
        self._delete_vpn_services()
        self._delete_ipsec_policy()
        self._delete_ike_policy()
        vpn_utils.delete_network(
            self.neutron_client, self.neutron_admin_client, self.rally_routers,
            self.rally_networks, self.rally_subnets)

    @atomic.action_timer("_create_ike_policy")
    def _create_ike_policy(self, **kwargs):
        """Creates IKE policy

        :return: IKE policy
        """
        LOG.debug("CREATING IKE_POLICY")
        ike_policy = self.neutron_client.create_ikepolicy({
            "ikepolicy": {
                "phase1_negotiation_mode":
                    kwargs.get("phase1_negotiation_mode", "main"),
                "auth_algorithm": kwargs.get("auth_algorithm", "sha1"),
                "encryption_algorithm":
                    kwargs.get("encryption_algorithm", "aes-128"),
                "pfs": kwargs.get("pfs", "group5"),
                "lifetime": {
                    "units": "seconds",
                    "value": kwargs.get("value", 7200)},
                "ike_version": kwargs.get("ike_version", "v1"),
                "name": "rally_ikepolicy"
            }
        })
        return ike_policy

    @atomic.action_timer("_create_ipsec_policy")
    def _create_ipsec_policy(self, **kwargs):
        """Creates IPSEC policy

        :return: IPSEC policy
        """
        LOG.debug("CREATING IPSEC_POLICY")
        ipsec_policy = self.neutron_client.create_ipsecpolicy({
            "ipsecpolicy": {
                "name": "rally_ipsecpolicy",
                "transform_protocol": kwargs.get("transform_protocol", "esp"),
                "auth_algorithm": kwargs.get("auth_algorithm", "sha1"),
                "encapsulation_mode":
                    kwargs.get("encapsulation_mode", "tunnel"),
                "encryption_algorithm":
                    kwargs.get("encryption_algorithm", "aes-128"),
                "pfs": kwargs.get("pfs", "group5"),
                "lifetime": {
                    "units": "seconds",
                    "value": kwargs.get("value", 7200)
                }
            }
        })
        return ipsec_policy

    @atomic.action_timer("_create_vpn_service")
    def _create_vpn_service(self, rally_subnet, rally_router, vpn_suffix=None):
        """Creates VPN service endpoints

        :param rally_subnet: local subnet
        :param rally_router: router endpoint
        :param vpn_suffix: suffix name for vpn service
        :return: VPN service
        """
        LOG.debug("CREATING VPN_SERVICE")
        vpn_service = self.neutron_client.create_vpnservice({
            "vpnservice": {
                "subnet_id": rally_subnet["subnet"]["id"],
                "router_id": rally_router["router"]["id"],
                "name": "rally_vpn_service_" + vpn_suffix,
                "admin_state_up": True
            }
        })
        return vpn_service

    @atomic.action_timer("_create_ipsec_site_connection")
    def _create_ipsec_site_connection(self, local_index, peer_index, **kwargs):
        """Creates IPSEC site connection

        :param local_index: parameter to point to the local end-point
        :param peer_index: parameter to point to the peer end-point
        :return: IPSEC site connection
        """
        LOG.debug("CREATING IPSEC_SITE_CONNECTION")
        ipsec_site_conn = self.neutron_client.create_ipsec_site_connection({
            "ipsec_site_connection": {
                "psk": kwargs.get("secret", "secret"),
                "initiator": "bi-directional",
                "ipsecpolicy_id": self.ipsec_policy["ipsecpolicy"]["id"],
                "admin_state_up": True,
                "peer_cidrs": self.rally_cidrs[peer_index],
                "mtu": kwargs.get("mtu", "1500"),
                "ikepolicy_id": self.ike_policy["ikepolicy"]["id"],
                "dpd": {
                    "action": "disabled",
                    "interval": 60,
                    "timeout": 240
                },
                "vpnservice_id":
                    self.vpn_services[local_index]["vpnservice"]["id"],
                "peer_address": self.rally_router_gw_ips[peer_index],
                "peer_id": self.rally_router_gw_ips[peer_index],
                "name": "rally_ipsec_site_connection_" +
                        self.suffixes[local_index]
            }
        })
        return ipsec_site_conn

    def _get_resource(self, resource_tag, resource_id):
        """Gets the resource(vpn_service or ipsec_site_connection)

        :param resource_tag: "vpnservice" or "ipsec_site_connection"
        :param resource_id: id of the resource
        :return: resource (vpn_service or ipsec_site_connection)
        """
        if resource_tag == "vpnservice":
            vpn_service = self.neutron_client.show_vpnservice(resource_id)
            if vpn_service:
                return vpn_service
        elif resource_tag == 'ipsec_site_connection':
            ipsec_site_conn = self.neutron_client.show_ipsec_site_connection(
                resource_id)
            if ipsec_site_conn:
                return ipsec_site_conn

    @atomic.action_timer("_wait_for_status_change")
    def _wait_for_status_change(self, resource, resource_tag, final_status,
                                wait_timeout=60, check_interval=1):
        """Wait for resource's status change

        Wait till the status of the resource changes to final state or till
        the time exceeds the wait_timeout value.
        :param resource: resource whose status has to be checked
        :param final_status: desired final status of the resource
        :param resource_tag: to identify the resource as vpnservice or
        ipsec_site_connection
        :param wait_timeout: timeout value in seconds
        :param check_interval: time to sleep before each check for the status
        change
        :return: resource
        """
        start_time = time.time()
        while True:
            resource = self._get_resource(resource_tag,
                                          resource[resource_tag]['id'])
            current_status = resource[resource_tag]['status']
            if current_status == final_status:
                return resource
            time.sleep(check_interval)
            if time.time() - start_time > wait_timeout:
                raise exceptions.Exception(
                    "Timeout waiting for resource {} to change to {} status".
                    format(resource[resource_tag]['name'], final_status)
                )

    def _assert_statuses(self, ipsec_site_conn, vpn_service,
                         final_status, **kwargs):
        """Assert statuses of vpn_service and ipsec_site_connection

        :param ipsec_site_conn: ipsec_site_connection object
        :param vpn_service: vpn_service object
        :param final_status: status of vpn and ipsec_site_connection object
        """

        vpn_service = self._wait_for_status_change(
            vpn_service,
            resource_tag="vpnservice",
            final_status=final_status,
            wait_timeout=kwargs.get("vpn_service_creation_timeout"),
            check_interval=5)

        ipsec_site_conn = self._wait_for_status_change(
            ipsec_site_conn,
            resource_tag="ipsec_site_connection",
            final_status=final_status,
            wait_timeout=kwargs.get("ipsec_site_connection_creation_timeout"),
            check_interval=5)

        LOG.debug("VPN SERVICE STATUS %s", vpn_service['vpnservice']['status'])
        LOG.debug("IPSEC_SITE_CONNECTION STATUS: %s",
                  ipsec_site_conn['ipsec_site_connection']['status'])

        self._validate_status(vpn_service, ipsec_site_conn, final_status)

    def _validate_status(self, vpn_service, ipsec_site_conn, final_status):
        """Validate the statuses of vpn_service, ipsec_site_connection and
        evaluate the final_status

        :param ipsec_site_conn: ipsec_site_connection of an instance
        :param vpn_service: vpn_service of an instance
        :param final_status: status of vpn and ipsec_site_connection instance
        """

        assert(final_status == vpn_service['vpnservice']['status']), (
                "VPN SERVICE IS NOT IN %s STATE" % final_status)
        assert(final_status == ipsec_site_conn['ipsec_site_connection']
        ['status']), ("THE IPSEC SITE CONNECTION IS NOT IN %s STATE"
                      % final_status)

    @atomic.action_timer("_verify_vpn_connection")
    def _verify_vpn_connection(self, local_index, peer_index):
        """Verifies the vpn connectivity between the endpoints

        :param local_index: parameter to point to the local end-point
        :param peer_index: parameter to point to the peer end-point
        :return: True or False
        """
        qg = vpn_utils.get_interfaces(self.snat_namespaces[peer_index])
        if qg:
            p = re.compile(r"qg-\w+-\w+")
            m = p.search(qg)
            if m:
                qg_interface = m.group()
            else:
                qg_interface = None

            if qg_interface:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
                    tcpdump_future = e.submit(vpn_utils.start_tcpdump,
                             self.snat_namespaces[peer_index],
                             qg_interface)
                    ssh_future = e.submit(vpn_utils.ssh_and_ping_server,
                             self.server_private_ips[local_index],
                             self.server_private_ips[peer_index],
                             self.qrouter_namespaces[local_index],
                             self.key_file_paths[local_index])
                    assert(ssh_future.result()), "SSH/Ping failed"
                    lines = tcpdump_future.result().split('\n')
                    for line in lines:
                        if 'ESP' in line:
                            return True
        return False

    @atomic.action_timer("_delete_ipsec_site_connection")
    def _delete_ipsec_site_connections(self):
        """Deletes IPSEC site connections"""

        if self.ipsec_site_connections:
            for site_conn in self.ipsec_site_connections:
                if "rally" in (site_conn['ipsec_site_connection']['name']):
                    LOG.debug("DELETING IPSEC_SITE_CONNECTION %s",
                              site_conn['ipsec_site_connection']['id'])
                    self.neutron_client.delete_ipsec_site_connection(
                        site_conn['ipsec_site_connection']['id'])

    @atomic.action_timer("_delete_vpn_service")
    def _delete_vpn_services(self):
        """Deletes VPN service endpoints"""

        if self.vpn_services:
            for vpn_service in self.vpn_services:
                if "rally" in vpn_service['vpnservice']['name']:
                    LOG.debug("DELETING VPN_SERVICE %s",
                              vpn_service['vpnservice']['id'])
                    self.neutron_client.delete_vpnservice(
                        vpn_service['vpnservice']['id'])

    @atomic.action_timer("_delete_ipsec_policy")
    def _delete_ipsec_policy(self):
        """Deletes IPSEC policy

        :param ipsec_policy: ipsec_policy object
        :return:
        """
        LOG.debug("DELETING IPSEC POLICY")
        if (self.ipsec_policy and
                "rally" in self.ipsec_policy['ipsecpolicy']['name']):
            self.neutron_client.delete_ipsecpolicy(
                self.ipsec_policy['ipsecpolicy']['id'])

    @atomic.action_timer("_delete_ike_policy")
    def _delete_ike_policy(self):
        """Deletes IKE policy

        :param ike_policy: ike_policy object
        :return:
        """
        LOG.debug("DELETING IKE POLICY")
        if (self.ike_policy and
                "rally" in self.ike_policy['ikepolicy']['name']):
            self.neutron_client.delete_ikepolicy(
                self.ike_policy['ikepolicy']['id'])

    def create_networks_and_servers(self, **kwargs):
        with LOCK:
            keypairs = []
            for x in range(MAX_RESOURCES):
                router, network, subnet, cidr = vpn_utils.create_network(
                    self.neutron_client, self.neutron_admin_client,
                    self.suffixes[x])
                self.rally_cidrs.append(cidr)
                self.rally_subnets.append(subnet)
                self.rally_networks.append(network)
                self.rally_routers.append(router)
                self.router_ids.append(router["router"]['id'])
                self.rally_router_gw_ips.append(
                    router["router"]["external_gateway_info"]
                    ["external_fixed_ips"][0]["ip_address"])
                self.snat_namespaces.append(
                    vpn_utils.wait_for_namespace_creation(
                        "snat-", router, **kwargs))
                self.qrouter_namespaces.append(
                    vpn_utils.wait_for_namespace_creation(
                        "qrouter-", router, **kwargs))
                keypairs.append(vpn_utils.create_keypair(
                    self.nova_client, self.key_names[x],
                    self.key_file_paths[x]))

                kwargs.update({
                    "nics":
                        [{"net-id": self.rally_networks[x]["network"]["id"]}],
                        "sec_group_suffix": self.suffixes[x],
                        "server_suffix": self.suffixes[x]
                })
                server = vpn_utils.create_nova_vm(
                    self.nova_client, keypairs[x], **kwargs)
                self.server_private_ips.append(vpn_utils.get_server_ip(
                        self.nova_client, server.id, self.suffixes[x]))
                self.servers.append(server)

    def check_route(self):
        LOG.debug("VERIFYING THAT THERE IS A ROUTE BETWEEN ROUTER "
                  "GATEWAYS")
        for ns in self.snat_namespaces:
            for ip in self.rally_router_gw_ips:
                assert(True == vpn_utils.ping(ns, ip)), (
                        "PING FAILED FROM NAMESPACE " + ns + " TO IP "
                        + ip)

    def update_router(self, router_id, admin_state_up=False):
        """Updates router

        :param router_id: router id
        :param admin_state_up: update 'admin_state_up' of the router
        :return:
        """
        req_body = {'router': {'admin_state_up': admin_state_up}}
        self.neutron_client.update_router(router_id, req_body)

    def create_vpn_services(self):
        with LOCK:
            for x in range(MAX_RESOURCES):
                self.vpn_services.append(self._create_vpn_service(
                    self.rally_subnets[x], self.rally_routers[x],
                    self.suffixes[x]))

    def create_ipsec_site_connections(self, **kwargs):
        with LOCK:
            self.ipsec_site_connections = [
                self._create_ipsec_site_connection(0, 1, **kwargs),
                self._create_ipsec_site_connection(1, 0, **kwargs)
            ]

    def assert_statuses(self, final_status, **kwargs):
        LOG.debug("ASSERTING ACTIVE STATUSES FOR VPN-SERVICES AND "
                  "VPN-CONNECTIONS")
        for x in range(MAX_RESOURCES):
            self._assert_statuses(self.ipsec_site_connections[x],
                                  self.vpn_services[x], final_status, **kwargs)

    def assert_vpn_connectivity(self):
        LOG.debug("VERIFY THE VPN CONNECTIVITY")
        with LOCK:
            assert(self._verify_vpn_connection(0, 1)), "VPN CONNECTION FAILED"
            assert(self._verify_vpn_connection(1, 0)), "VPN CONNECTION FAILED"
