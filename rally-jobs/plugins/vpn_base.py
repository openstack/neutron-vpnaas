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
import re
import threading
import time

from oslo_utils import uuidutils
from rally.common import logging
from rally.plugins.openstack import scenario as rally_base
from rally.task import atomic

import vpn_utils

LOG = logging.getLogger(__name__)
LOCK = threading.RLock()
MAX_RESOURCES = 2


class VpnBase(rally_base.OpenStackScenario):

    def setup(self, **kwargs):
        """Create and initialize data structures to hold various resources"""

        with LOCK:
            LOG.debug('SETUP RESOURCES')
            self.neutron_admin_client = self.admin_clients("neutron")
            if kwargs['use_admin_client']:
                self.neutron_client = self.neutron_admin_client
                self.keystone_client = self.admin_clients("keystone")
                self.nova_client = self.admin_clients("nova")
            else:
                self.neutron_client = self.clients("neutron")
                self.nova_client = self.clients("nova")
            self.suffixes = [uuidutils.generate_uuid(),
                             uuidutils.generate_uuid()]
            self.remote_key_files = ['rally_keypair_' + x
                                     for x in self.suffixes]
            self.local_key_files = ['/tmp/' + x for x in self.remote_key_files]
            self.private_key_file = kwargs["private_key"]
            self.keypairs = []
            self.tenant_ids = []
            self.ns_controller_tuples = []
            self.qrouterns_compute_tuples = []
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
            self.server_fips = []

    def create_tenants(self):
        """Create tenants"""

        for x in range(MAX_RESOURCES):
            tenant_id = vpn_utils.create_tenant(
                self.keystone_client, self.suffixes[x])
            with LOCK:
                self.tenant_ids.append(tenant_id)

    def create_networks(self, **kwargs):
        """Create networks to test vpn connectivity"""

        for x in range(MAX_RESOURCES):
            if self.tenant_ids:
                router, network, subnet, cidr = vpn_utils.create_network(
                    self.neutron_client, self.neutron_admin_client,
                    self.suffixes[x], tenant_id=self.tenant_ids[x],
                    DVR_flag=kwargs["DVR_flag"],
                    ext_net_name=kwargs["ext-net"])
            else:
                router, network, subnet, cidr = vpn_utils.create_network(
                    self.neutron_client, self.neutron_admin_client,
                    self.suffixes[x], DVR_flag=kwargs["DVR_flag"],
                    ext_net_name=kwargs["ext-net"])
            with LOCK:
                self.rally_cidrs.append(cidr)
                self.rally_subnets.append(subnet)
                self.rally_networks.append(network)
                self.rally_routers.append(router)
                self.router_ids.append(router["router"]['id'])
                self.rally_router_gw_ips.append(
                    router["router"]["external_gateway_info"]
                    ["external_fixed_ips"][0]["ip_address"])

            if(kwargs["DVR_flag"]):
                ns, controller = vpn_utils.wait_for_namespace_creation(
                    "snat-", router["router"]['id'],
                    kwargs['controller_creds'],
                    self.private_key_file,
                    kwargs['namespace_creation_timeout'])
            else:
                ns, controller = vpn_utils.wait_for_namespace_creation(
                    "qrouter-", router["router"]['id'],
                    kwargs['controller_creds'],
                    self.private_key_file,
                    kwargs['namespace_creation_timeout'])
            with LOCK:
                self.ns_controller_tuples.append((ns, controller))

    def create_servers(self, **kwargs):
        """Create servers"""

        for x in range(MAX_RESOURCES):
            kwargs.update({
                "nics":
                    [{"net-id": self.rally_networks[x]["network"]["id"]}],
                "sec_group_suffix": self.suffixes[x],
                "server_suffix": self.suffixes[x]
            })
            keypair = vpn_utils.create_keypair(
                self.nova_client, self.suffixes[x])
            server = vpn_utils.create_server(
                self.nova_client, keypair, **kwargs)
            vpn_utils.assert_server_status(server, **kwargs)
            with LOCK:
                self.servers.append(server)
                self.keypairs.append(keypair)
                self.server_private_ips.append(vpn_utils.get_server_ip(
                    self.nova_client, server.id, self.suffixes[x]))
            if(kwargs["DVR_flag"]):
                qrouter, compute = vpn_utils.wait_for_namespace_creation(
                    "qrouter-", self.router_ids[x],
                    kwargs['compute_creds'],
                    self.private_key_file,
                    kwargs['namespace_creation_timeout'])

                vpn_utils.write_key_to_compute_node(
                    keypair, self.local_key_files[x],
                    self.remote_key_files[x], compute,
                    self.private_key_file)
                with LOCK:
                    self.qrouterns_compute_tuples.append((qrouter, compute))
            else:
                vpn_utils.write_key_to_local_path(self.keypairs[x],
                                                  self.local_key_files[x])
                fip = vpn_utils.add_floating_ip(self.nova_client, server)
                with LOCK:
                    self.server_fips.append(fip)

    def check_route(self):
        """Verify route exists between the router gateways"""

        LOG.debug("VERIFY ROUTE EXISTS BETWEEN THE ROUTER GATEWAYS")
        for tuple in self.ns_controller_tuples:
            for ip in self.rally_router_gw_ips:
                assert(vpn_utils.ping_router_gateway(
                        tuple, ip, self.private_key_file)), (
                        "PING TO IP " + ip + " FAILED")

    @atomic.action_timer("_create_ike_policy")
    def _create_ike_policy(self, **kwargs):
        """Create IKE policy

        :return: IKE policy
        """
        LOG.debug('CREATING IKE_POLICY')
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
        """Create IPSEC policy

        :return: IPSEC policy
        """
        LOG.debug('CREATING IPSEC_POLICY')
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
        """Create VPN service endpoints

        :param rally_subnet: local subnet
        :param rally_router: router endpoint
        :param vpn_suffix: suffix name for vpn service
        :return: VPN service
        """
        LOG.debug('CREATING VPN_SERVICE')
        vpn_service = self.neutron_client.create_vpnservice({
            "vpnservice": {
                "subnet_id": rally_subnet["subnet"]["id"],
                "router_id": rally_router["router"]["id"],
                "name": "rally_vpn_service_" + vpn_suffix,
                "admin_state_up": True
            }
        })
        return vpn_service

    def create_vpn_services(self):
        """Create VPN services"""

        for x in range(MAX_RESOURCES):
            vpn_service = self._create_vpn_service(
                self.rally_subnets[x], self.rally_routers[x], self.suffixes[x])
            with LOCK:
                self.vpn_services.append(vpn_service)

    @atomic.action_timer("_create_ipsec_site_connection")
    def _create_ipsec_site_connection(self, local_index, peer_index, **kwargs):
        """Create IPSEC site connection

        :param local_index: parameter to point to the local end-point
        :param peer_index: parameter to point to the peer end-point
        :return: IPSEC site connection
        """
        LOG.debug('CREATING IPSEC_SITE_CONNECTION')
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

    def create_ipsec_site_connections(self, **kwargs):
        """Create IPSEC site connections"""

        a = self._create_ipsec_site_connection(0, 1, **kwargs)
        b = self._create_ipsec_site_connection(1, 0, **kwargs)
        with LOCK:
            self.ipsec_site_connections = [a, b]

    def _get_resource(self, resource_tag, resource_id):
        """Get the resource(vpn_service or ipsec_site_connection)

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
        LOG.debug('WAIT_FOR_%s_STATUS_CHANGE ', resource[resource_tag]['id'])

        start_time = time.time()
        while True:
            resource = self._get_resource(
                resource_tag, resource[resource_tag]['id'])
            current_status = resource[resource_tag]['status']
            if current_status == final_status:
                return resource
            time.sleep(check_interval)
            if time.time() - start_time > wait_timeout:
                raise Exception(
                    "Timeout waiting for resource {} to change to {} status".
                    format(resource[resource_tag]['name'], final_status))

    @atomic.action_timer("wait_time_for_status_change")
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
        LOG.debug("IPSEC_SITE_CONNECTION STATUS %s",
                  ipsec_site_conn['ipsec_site_connection']['status'])

    def assert_statuses(self, final_status, **kwargs):
        """Assert active statuses for VPN services and VPN connections

        :param final_status: the final status you expect the resource to be in
        """

        LOG.debug("ASSERTING ACTIVE STATUSES FOR VPN-SERVICES AND "
                  "IPSEC-SITE-CONNECTIONS")
        for x in range(MAX_RESOURCES):
            self._assert_statuses(
                self.ipsec_site_connections[x], self.vpn_services[x],
                final_status, **kwargs)

    def _get_qg_interface(self, peer_index):
        """Get the qg- interface

        :param peer_index: parameter to point to the local end-point
        :return: qg-interface
        """
        qg = vpn_utils.get_interfaces(
            self.ns_controller_tuples[peer_index],
            self.private_key_file)
        p = re.compile(r"qg-\w+-\w+")
        for line in qg:
            m = p.search(line)
            if m:
                return m.group()
        return None

    @atomic.action_timer("_verify_vpn_connection")
    def _verify_vpn_connectivity(self, local_index, peer_index, **kwargs):
        """Verify the vpn connectivity between the endpoints

        Get the qg- interface from the snat namespace corresponding to the
        peer router and start a tcp dump. Concurrently, SSH into the nova
        instance  on the local subnet from the qrouter namespace and try
        to ping the nova instance on the peer subnet. Inspect the captured
        packets to see if they are encrypted.
        :param local_index: parameter to point to the local end-point
        :param peer_index: parameter to point to the peer end-point
        :return: True if vpn connectivity test passes
                 False if the test fails
        """
        qg_interface = self._get_qg_interface(peer_index)
        if qg_interface:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
                tcpdump_future = e.submit(vpn_utils.start_tcpdump,
                         self.ns_controller_tuples[peer_index],
                         qg_interface, self.private_key_file)
                if(kwargs["DVR_flag"]):
                    ssh_future = e.submit(
                        vpn_utils.ssh_and_ping_server,
                        self.server_private_ips[local_index],
                        self.server_private_ips[peer_index],
                        self.qrouterns_compute_tuples[local_index],
                        self.remote_key_files[local_index],
                        self.private_key_file)
                else:
                    ssh_future = e.submit(
                        vpn_utils.ssh_and_ping_server_with_fip,
                        self.server_fips[local_index],
                        self.server_private_ips[peer_index],
                        self.local_key_files[local_index],
                        self.private_key_file)

            assert(ssh_future.result()), "SSH/Ping failed"
            for line in tcpdump_future.result():
                if 'ESP' in line:
                    return True
        return False

    def verify_vpn_connectivity(self, **kwargs):
        """Verify VPN connectivity"""

        LOG.debug("VERIFY THE VPN CONNECTIVITY")
        with LOCK:
            assert(self._verify_vpn_connectivity(
                0, 1, **kwargs)), "VPN CONNECTION FAILED"
        with LOCK:
            assert(self._verify_vpn_connectivity(
                1, 0, **kwargs)), "VPN CONNECTION FAILED"

    def update_router(self, router_id, admin_state_up=False):
        """Update router's admin_state_up field

        :param router_id: uuid of the router
        :param admin_state_up: True or False
        """
        LOG.debug('UPDATE ROUTER')
        router_args = {'router': {'admin_state_up': admin_state_up}}
        self.neutron_client.update_router(router_id, router_args)

    @atomic.action_timer("_delete_ipsec_site_connection")
    def _delete_ipsec_site_connections(self):
        """Delete IPSEC site connections"""

        for site_conn in self.ipsec_site_connections:
            LOG.debug("DELETING IPSEC_SITE_CONNECTION %s",
                      site_conn['ipsec_site_connection']['id'])
            self.neutron_client.delete_ipsec_site_connection(
                site_conn['ipsec_site_connection']['id'])

    @atomic.action_timer("_delete_vpn_service")
    def _delete_vpn_services(self):
        """Delete VPN service endpoints"""

        for vpn_service in self.vpn_services:
            LOG.debug("DELETING VPN_SERVICE %s",
                      vpn_service['vpnservice']['id'])
            self.neutron_client.delete_vpnservice(
                vpn_service['vpnservice']['id'])

    @atomic.action_timer("_delete_ipsec_policy")
    def _delete_ipsec_policy(self):
        """Delete IPSEC policy"""

        LOG.debug("DELETING IPSEC POLICY")
        if self.ipsec_policy:
            self.neutron_client.delete_ipsecpolicy(
                self.ipsec_policy['ipsecpolicy']['id'])

    @atomic.action_timer("_delete_ike_policy")
    def _delete_ike_policy(self):
        """Delete IKE policy"""

        LOG.debug('DELETING IKE POLICY')
        if self.ike_policy:
            self.neutron_client.delete_ikepolicy(
                self.ike_policy['ikepolicy']['id'])

    @atomic.action_timer("cleanup")
    def cleanup(self):
        """Clean the resources"""

        vpn_utils.delete_servers(self.nova_client, self.servers)
        if self.server_fips:
            vpn_utils.delete_floating_ips(self.nova_client, self.server_fips)
        vpn_utils.delete_keypairs(self.nova_client, self.keypairs)

        if self.qrouterns_compute_tuples:
            vpn_utils.delete_hosts_from_knownhosts_file(
                self.server_private_ips, self.qrouterns_compute_tuples,
                self.private_key_file)
            vpn_utils.delete_keyfiles(
                self.local_key_files, self.remote_key_files,
                self.qrouterns_compute_tuples, self.private_key_file)
        else:
            vpn_utils.delete_hosts_from_knownhosts_file(
                    self.server_private_ips)
            vpn_utils.delete_keyfiles(self.local_key_files)

        self._delete_ipsec_site_connections()
        self._delete_vpn_services()
        self._delete_ipsec_policy()
        self._delete_ike_policy()
        vpn_utils.delete_networks(
            self.neutron_client, self.neutron_admin_client, self.rally_routers,
            self.rally_networks, self.rally_subnets)
        if self.tenant_ids:
            vpn_utils.delete_tenants(self.keystone_client, self.tenant_ids)
