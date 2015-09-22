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
import os
from oslo_config import cfg
import re
import stat
import time


def noop(*args, **kwargs):
    pass
cfg.CONF.register_cli_opts = noop

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from rally.common import log as logging
from rally.plugins.openstack import scenario
from rally.task import utils as task_utils

LOG = logging.getLogger(__name__)


class VpnUtils(scenario.OpenStackScenario):
    """Utility class for VPNaaS scenarios with basic atomic actions."""
    SUBNET_IP_VERSION = 4

    def _create_network(self, neutron_client, network_suffix, cidr):
        """Create neutron network

        :param neutron_client: neutron client
        :param network_suffix: str, suffix name of the new network
        :param cidr: subnet cidr
        :return: router, subnet , network
        """
        def create_network(neutron_client, network_suffix, isExternal=False):
            network_name = "rally_network_" + network_suffix
            network_args = {"name": network_name,
                            "router:external": isExternal}

            LOG.debug("ADDING NEW NETWORK: %s", network_name)
            rally_network = neutron_client.create_network(
                {"network": network_args})
            return rally_network

        def create_subnet(neutron_client, rally_network, network_suffix, cidr):
            network_id = rally_network["network"]["id"]
            subnet_name = "rally_subnet_" + network_suffix
            subnet_args = {"name": subnet_name,
                           "cidr": cidr,
                           "network_id": network_id,
                           "ip_version": self.SUBNET_IP_VERSION}

            LOG.debug("ADDING SUBNET: %s", subnet_name)
            rally_subnet = neutron_client.create_subnet(
                {"subnet": subnet_args})
            return rally_subnet

        def create_router(private_subnet, public_network_id):
            router_name = "rally_router_" + network_suffix
            gw_info = {"network_id": public_network_id}
            router_args = {"name": router_name,
                           "external_gateway_info": gw_info}

            LOG.debug("ADDING ROUTER: %s", router_name)
            rally_router = neutron_client.create_router(
                {"router": router_args})

            # create router interface - connect subnet to it
            LOG.debug("ADDING ROUTER INTERFACE")
            neutron_client.add_interface_router(
                rally_router['router']["id"],
                {"subnet_id": private_subnet["subnet"]["id"]})
            return rally_router

        # check for external network and create one if not found
        def get_external_network():
            for network in neutron_client.list_networks()['networks']:
                if network['router:external']:
                    public_network_id = network['id']
                    LOG.debug("PUBLIC NETWORK ALREADY EXISTS")
                    break
            else:
                public_network = create_network(self.admin_clients("neutron"),
                                                "public", True)
                create_subnet(self.admin_clients("neutron"), public_network,
                              "public", "172.16.1.0/24")
                public_network_id = public_network['network']['id']
            return public_network_id

        # create public network_id
        public_network_id = get_external_network()
        # create private network
        private_network = create_network(neutron_client, network_suffix)
        # create subnet
        private_subnet = create_subnet(neutron_client,
                                       private_network,
                                       network_suffix,
                                       cidr)
        # create router
        rally_router = create_router(private_subnet, public_network_id)

        return rally_router, private_network, private_subnet

    def _create_keypair(self, nova_client, key_name, key_file):
        """Create keypair

        :param nova_client: nova_client
        :param key_name: key_name
        :param key_file: key_file_name
        :return: keypair
        """
        LOG.debug("ADDING NEW KEYPAIR")
        keypair = nova_client.keypairs.create(key_name)
        f = open(key_file, 'w')
        os.chmod(key_file, stat.S_IREAD | stat.S_IWRITE)
        f.write(keypair.private_key)
        f.close()
        return keypair

    def _create_nova_vm(self, nova_client, keypair, **kwargs):
        """Create nova instance

        :param nova_client: nova client
        :param keypair: str, key-pair to allow ssh
        :return: new nova instance
        """
        # add sec-group
        sec_group_suffix = "rally_secgroup_" + kwargs["sec_group_suffix"]
        LOG.debug("ADDING NEW SECURITY GROUP %s", sec_group_suffix)
        secgroup = nova_client.security_groups.create(sec_group_suffix,
                                                      sec_group_suffix)
        # add security rules for SSH and ICMP
        nova_client.security_group_rules.create(secgroup.id, from_port=22,
                    to_port=22, ip_protocol="tcp", cidr="0.0.0.0/0")

        nova_client.security_group_rules.create(secgroup.id, from_port=-1,
                    to_port=-1, ip_protocol="icmp", cidr="0.0.0.0/0")

        # boot new nova instance
        server_name = "rally_server_" + (kwargs["server_suffix"])

        LOG.debug("BOOTING NEW INSTANCE: %s", server_name)

        server = nova_client.servers.create(server_name,
                                            image=kwargs["image"],
                                            flavor=kwargs["flavor"],
                                            key_name=keypair.name,
                                            security_groups=[secgroup.id],
                                            nics=kwargs["nics"])
        # wait for instance to become active
        LOG.debug("WAITING FOR INSTANCE TO BECOME ACTIVE")
        server = task_utils.wait_for(
            server,
            is_ready=task_utils.resource_is("ACTIVE"),
            update_resource=task_utils.get_from_manager(),
            timeout=kwargs["nova_server_boot_timeout"],
            check_interval=5)
        LOG.debug("SERVER STATUS: %s", server.status)

        # assert if instance is 'active'
        assert('ACTIVE' == server.status), (
            "THE INSTANCE IS NOT IN ACTIVE STATE")
        return server

    def _get_server_ip(self, nova_client, server_id, network_suffix):
        """

        :param nova_client: nova client
        :param server_id: uuid of the nova instance whose ip is wanted
        :param network_suffix: network name suffix
        :return: ip address of the instance
        """
        network_name = "rally_network_" + network_suffix
        server_details = nova_client.servers.get(server_id)
        server_ip = server_details.addresses[network_name][0]["addr"]
        return server_ip

    def _create_ike_policy(self,
                           neutron_client,
                           **kwargs):
        """Creates IKE policy

        :param neutron_client:neutron client
        :return:created ike_policy
        """
        LOG.debug("CREATING IKE_POLICY")
        ike_policy = neutron_client.create_ikepolicy({
            "ikepolicy": {
                "phase1_negotiation_mode":
                    kwargs["phase1_negotiation_mode"] or "main",
                "auth_algorithm": kwargs["auth_algorithm"] or "sha1",
                "encryption_algorithm":
                    kwargs["encryption_algorithm"] or "aes-128",
                "pfs": kwargs["pfs"] or "group5",
                "lifetime": {
                    "units": "seconds",
                    "value": kwargs["value"] or 7200},
                "ike_version": kwargs["ike_version"] or "v1",
                "name": "rally_ikepolicy"
            }
        })
        return ike_policy

    def _create_ipsec_policy(self,
                             neutron_client,
                             **kwargs):
        """Creates IPSEC policy

        :param neutron_client: neutron client
        :return: created IPSEC policy
        """
        LOG.debug("CREATING IPSEC_POLICY")
        ipsec_policy = neutron_client.create_ipsecpolicy({
            "ipsecpolicy": {
                "name": "rally_ipsecpolicy",
                "transform_protocol": kwargs["transform_protocol"] or "esp",
                "auth_algorithm": kwargs["auth_algorithm"] or "sha1",
                "encapsulation_mode": kwargs["encapsulation_mode"] or "tunnel",
                "encryption_algorithm":
                    kwargs["encryption_algorithm"] or "aes-128",
                "pfs": kwargs["pfs"] or "group5",
                "lifetime": {
                    "units": "seconds",
                    "value": kwargs["value"] or 7200
                }
            }
        })
        return ipsec_policy

    def _create_vpn_service(self, neutron_client, rally_subnet, rally_router,
                            name=None):
        """Creates VPN service endpoints

        :param neutron_client: neutron client
        :param name: name of vpn service
        :param rally_subnet: local subnet
        :param rally_router: router endpoint
        :return: vpn_service
        """
        LOG.debug("CREATING VPN_SERVICE")
        vpn_service = neutron_client.create_vpnservice({
            "vpnservice": {
                "subnet_id": rally_subnet["subnet"]["id"],
                "router_id": rally_router["router"]["id"],
                "name": "rally_vpn_service_" + name,
                "admin_state_up": True
            }
        })
        return vpn_service

    def _create_ipsec_site_connection(
            self, neutron_client, ike_policy,
            ipsec_policy, peer_cidrs,
            peer_id, peer_address,
            vpn_service, name=None,
            mtu=None, secret=None):
        """Creates IPSEC site connections

        :param neutron_client: neutron client
        :param ike_policy: ikepolicy
        :param ipsec_policy: ipsecpolicy
        :param peer_cidrs: list of peer cidrs
        :param peer_id: peer_id
        :param peer_address: peer_address
        :param vpn_service: vpn_service
        :param secret: pre shared secret
        :param mtu: max transmission unit
        :param name: name of the ipsec site connections
        :return:ipsec_site_connection
        """
        LOG.debug("CREATING IPSEC_SITE_CONNECTION")
        ipsec_site_connection = neutron_client.create_ipsec_site_connection({
            "ipsec_site_connection": {
                "psk": secret or "secret",
                "initiator": "bi-directional",
                "ipsecpolicy_id": ipsec_policy["ipsecpolicy"]["id"],
                "admin_state_up": True,
                "peer_cidrs": peer_cidrs,
                "mtu": mtu or "1500",
                "ikepolicy_id": ike_policy["ikepolicy"]["id"],
                "dpd": {
                    "action": "disabled",
                    "interval": 60,
                    "timeout": 240
                },
                "vpnservice_id": vpn_service["vpnservice"]["id"],
                "peer_address": peer_address,
                "peer_id": peer_id,
                "name": "rally_ipsec_site_connection_" + name
            }
        })
        return ipsec_site_connection

    def _get_resource(self, resource_tag, resource_id):
        """Gets the resource(vpn_service or ipsec_site_connection)

        :param resource_tag: "vpnservice" or "ipsec_site_connection"
        :param resource_id: id of the resource
        :return:
        """
        neutron_client = self.clients("neutron")
        if resource_tag == "vpnservice":
            vpn_service = neutron_client.show_vpnservice(resource_id)
            if vpn_service:
                return vpn_service
        elif resource_tag == 'ipsec_site_connection':
            ipsec_site_connection = neutron_client.show_ipsec_site_connection(
                resource_id)
            if ipsec_site_connection:
                return ipsec_site_connection

    def _wait_for_status_change(self, resource, final_status,
                                resource_tag, wait_timeout=60,
                                check_interval=1):
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
            resource = self._get_resource(
                resource_tag,
                resource[resource_tag]['id'])
            current_status = resource[resource_tag]['status']
            if current_status == final_status:
                return resource
            time.sleep(check_interval)
            if time.time() - start_time > wait_timeout:
                self._cleanup(called_from="VpnUtils._wait_for_status_change")
                raise exceptions.Exception("Timeout while waiting for status "
                                           "change to %s.", final_status)

    def _assert_statuses(self, vpn_service, ipsec_site_connection,
                         ipsec_site_connection_creation_timeout=60,
                         vpn_service_creation_timeout=60):
        """Assert statuses of vpn_service and ipsec_site_connection

        :param vpn_service: vpn_service
        :param ipsec_site_connection: ipsec_site_connection
        :param ipsec_site_connection_creation_timeout: timeout in seconds
        :param vpn_service_creation_timeout: timeout in seconds
        :return:
        """

        vpn_service = self._wait_for_status_change(
            vpn_service,
            resource_tag="vpnservice",
            final_status="ACTIVE",
            wait_timeout=vpn_service_creation_timeout,
            check_interval=5)
        LOG.debug("VPN-SERVICE STATUS: %s",
                  vpn_service['vpnservice']['status'])

        assert('ACTIVE' == vpn_service['vpnservice']['status']), (
                     "VPN_SERVICE IS NOT IN ACTIVE STATE")

        ipsec_site_connection = self._wait_for_status_change(
            ipsec_site_connection,
            resource_tag="ipsec_site_connection",
            final_status="ACTIVE",
            wait_timeout=ipsec_site_connection_creation_timeout,
            check_interval=5)
        LOG.debug("IPSEC_SITE_CONNECTION STATUS: %s",
                  ipsec_site_connection['ipsec_site_connection']['status'])

        assert('ACTIVE' ==
            ipsec_site_connection['ipsec_site_connection']['status']), (
            "THE INSTANCE IS NOT IN ACTIVE STATE")

    def _verify_vpn_connectivity(self, server_ips, snat_namespaces,
                                 qrouter_namespaces, key_file_names,
                                 first, second):
        """Verifies the vpn connectivity between the endpoints

        :param server_ips: list of private ips of the servers between
        which the vpn connectivity has to verified.
        :param snat_namespaces: snat_namespaces of the 2 routers
        :param qrouter_namespaces: qrouter_namespaces of the 2 routers
        :param key_file_names: path to private key files
        :param first: parameter to point to the self
        :param second: parameter to point to the peer
        :return: True or False
        """
        LOG.debug("VERIFY THE VPN CONNECTIVITY")
        qg = self._get_interfaces(snat_namespaces[second])
        if qg:
            p = re.compile(r"qg-\w+-\w+")
            m = p.search(qg)
            if m:
                qg_interface = m.group()
            else:
                qg_interface = None

            if qg_interface:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
                    tcpdump_future = e.submit(self._start_tcpdump,
                             snat_namespaces[second],
                             qg_interface)
                    ssh_future = e.submit(self._ssh_and_ping_server,
                             server_ips[first],
                             server_ips[second],
                             qrouter_namespaces[first],
                             key_file_names[first])
                    assert(True == ssh_future.result()), "SSH/Ping failed"
                    lines = tcpdump_future.result().split('\n')
                    for line in lines:
                        if 'ESP' in line:
                            return True
        return False

    def _get_namespace(self):
        """Get namespaces

        :return: namespaces
        """
        LOG.debug("GET NAMESPACES USING 'ip netns'")
        try:
            cmd = ['ip', 'netns']
            cmd = ip_lib.add_namespace_to_cmd(cmd)
            namespaces = linux_utils.execute(cmd)
            LOG.debug("%s", namespaces)
            return namespaces
        except RuntimeError:
            return None

    def _wait_for_namespace_creation(self, namespace, rally_router):
        """Wait for namespace creation

        :param namespace: snat/qrouter namespace
        :param rally_router: rally_router
        :return:
        """
        start_time = time.time()
        while True:
            namespaces = self._get_namespace().split()
            for line in namespaces:
                if line == (namespace + rally_router["router"]["id"]):
                    namespace = line
                    return namespace
            time.sleep(1)
            if time.time() - start_time > 20:
                self._cleanup(called_from="_wait_for_namespace_creation")
                raise exceptions.Exception("Timeout while waiting for"
                                           " namespaces to be created")

    def _ping(self, namespace, ip):
        """Pings ip address from network namespace.

        In order to ping it uses following cli command:
        ip netns exec <namespace> ping -c 4 -q <ip>
        :param namespace: namespace
        :param ip: ip to ping to
        """
        LOG.debug("PING %s FROM THE NAMESPACE %s", ip, namespace)
        try:
            count = 4
            cmd = ['ping', '-w', 2 * count, '-c', count, ip]
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            ping_result = linux_utils.execute(cmd, run_as_root=True)
            LOG.debug("%s", ping_result)
            return True

        except RuntimeError:
            return False

    def _get_interfaces(self, namespace):
        """Do an "ip a".

        In order to do "ip a" it uses following cli command:
        ip netns exec <namespace> ip a | grep qg
        :param namespace: namespace
        """
        LOG.debug("GET THE INTERFACES BY USING 'ip a' FROM THE NAMESPACE %s",
                  namespace)
        try:
            cmd = ['ip', 'a']
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            interfaces = linux_utils.execute(cmd, run_as_root=True)
            LOG.debug("%s", interfaces)
            return interfaces

        except RuntimeError:
            return None

    def _start_tcpdump(self, namespace, interface):
        """Starts tcpdump at the given interface

        In order to start a "tcpdump" it uses the following command:
        ip netns exec <namespace> sudo tcpdump -i <interface>
        :param namespace: namespace
        :param interface: interface
        :return:
        """
        LOG.debug("START THE TCPDUMP USING 'tcpdump -i <%s> FROM THE NAMESPACE"
                  " %s", interface, namespace)
        try:
            cmd = ['timeout', '10', 'tcpdump', '-n',
                   '-i', interface]
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            tcpdump = linux_utils.execute(cmd, run_as_root=True,
                                         extra_ok_codes=[124])
            LOG.debug("%s", tcpdump)
            return tcpdump

        except RuntimeError:
            return None

    def _ssh_and_ping_server(self, ssh_server, ping_server,
                             namespace, key_file_name):
        """Ssh into the server from the namespace.

        In order to ssh it uses the following command:
        ip netns exec <namespace> ssh -i <path to keyfile> cirros@<server_ip>
        :param ssh_server: ip of the server to ssh into
        :param ping_server: ip of the server to ping to
        :param namespace: qrouter namespace
        :param key_file_name: path to private key file
        :return:
        """
        LOG.debug("SSH INTO SERVER %s AND PING THE PEER SERVER %s FROM THE"
                  " NAMESPACE %s", ssh_server, ping_server, namespace)
        try:
            # ssh instance
            host = "cirros@" + ssh_server
            count = 20
            cmd = ['ssh', '-o', 'StrictHostKeyChecking=no',
                   '-i', key_file_name, host,
                   'ping', '-w',
                   2 * count, '-c', count, ping_server]
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            ping_result = linux_utils.execute(cmd, run_as_root=True)
            LOG.debug("%s", ping_result)
            return True

        except RuntimeError:
            return False

    def _delete_server(self, nova_client, server):
        """Delete nova instance

        :param server: instance to delete
        :return:
        """
        # delete server
        sec_group_name = server.security_groups[0]['name']
        server_key_name = server.key_name

        LOG.debug("DELETING NOVA INSTANCE: %s", server.id)
        nova_client.servers.delete(server.id)

        LOG.debug("WAITING FOR INSTANCE TO GET DELETED")
        task_utils.wait_for_delete(server,
                            update_resource=task_utils.
                            get_from_manager())

        # delete sec-group
        for secgroup in nova_client.security_groups.list():
                if secgroup.name == sec_group_name:
                    LOG.debug("DELETING SEC_GROUP: %s", sec_group_name)
                    nova_client.security_groups.delete(secgroup.id)

        # delete key-pair
        for key_pair in nova_client.keypairs.list():
            if key_pair.name == server_key_name:
                LOG.debug("DELETING KEY_PAIR: %s", server_key_name)
                nova_client.keypairs.delete(key_pair.id)

    def _delete_ipsec_site_connection(self, neutron_client,
                                      ipsec_site_connection):
        """Deletes ipsec site connection

        :param neutron_client: neutron client
        :param ipsec_site_connection: ipsec_site_connection
        :return:
        """
        LOG.debug("DELETING IPSEC_SITE_CONNECTION %s",
                  ipsec_site_connection['id'])
        neutron_client.delete_ipsec_site_connection(
            ipsec_site_connection['id'])

    def _delete_vpn_service(self, neutron_client, vpn_service):
        """Deletes VPN service endpoints

        :param neutron_client: neutron client
        :param vpn_services: vpn_service
        :return:
        """
        LOG.debug("DELETING VPN_SERVICE %s", vpn_service['id'])
        neutron_client.delete_vpnservice(vpn_service['id'])

    def _delete_ipsec_policy(self, neutron_client, ipsec_policy):
        """Deletes IPSEC policy

        :param neutron_client: neutron client
        :param ipsec_policy: ipsec_policy
        :return:
        """
        LOG.debug("DELETING IPSEC POLICY")
        neutron_client.delete_ipsecpolicy(ipsec_policy['id'])

    def _delete_ike_policy(self, neutron_client, ike_policy):
        """Deletes IKE policy

        :param neutron_client: neutron client
        :param ike_policy: ike_policy
        :return:
        """
        LOG.debug("DELETING IKE POLICY")
        neutron_client.delete_ikepolicy(ike_policy['id'])

    def _delete_network(self, neutron_client):
        """Delete neutron network.

        :param network_tuple: tuple, router, network and subnet to delete
        :return
        """

        try:
            # delete interface subnet-router
            LOG.debug("DELETING RALLY ROUTER INTERFACES & GATEWAYS")
            routers = neutron_client.list_routers()
            subnets = neutron_client.list_subnets()
            subnet_id = None
            p = re.compile(r"\d")
            if routers:
                for router in routers['routers']:
                    if "rally" in router['name']:
                        neutron_client.remove_gateway_router(router['id'])
                        m = p.search(router['name'])
                        if m:
                            subnet_name = "rally_subnet_" + m.group()
                            if subnets:
                                for subnet in subnets['subnets']:
                                    if subnet_name == subnet['name']:
                                        subnet_id = subnet['id']
                        neutron_client.remove_interface_router(
                            router['id'],
                            {"subnet_id": subnet_id})

            # delete ports associated with interface
            LOG.debug("DELETING RALLY PORTS")
            ports = neutron_client.list_ports()
            if ports:
                for port in ports['ports']:
                    neutron_client.delete_port(port['id'])

            # delete router
            LOG.debug("DELETING RALLY ROUTERS")
            if routers:
                for router in routers['routers']:
                    if "rally" in router['name']:
                        neutron_client.delete_router(router['id'])

            # Delete external network & subnet:
            LOG.debug("DELETING RALLY PUBLIC NETWORK")
            networks = neutron_client.list_networks()
            if networks:
                for network in networks['networks']:
                    if network['router:external'] and (network['name']
                                == "rally_network_public"):
                        external_network = network
                        self.admin_clients("neutron").delete_network(
                            external_network["id"])

            # delete network
            LOG.debug("DELETING RALLY NETWORKS")
            networks = neutron_client.list_networks()
            if networks:
                for network in networks['networks']:
                    if "rally_network" in network['name']:
                        neutron_client.delete_network(network['id'])

        except Exception as err:
            LOG.exception(err)

    def _delete_key_file(self, key_files):
        """Delete ssh key file

        :param key_files:  list of paths to ssh key files
        :return:
        """
        LOG.debug("DELETING RALLY KEY FILES")
        for key_file in key_files:
            if os.path.exists(key_file):
                os.remove(key_file)

    def _delete_knownhosts_file(self):
        """Removes the knownhosts file

        :param server_ips: ips to be removed from /root/.ssh/knownhosts
        :return:
        """
        LOG.debug("DELETE THE KNOWNHOST FILE")
        try:
            cmd = ['rm', '-rf', "~/.ssh/known_hosts"]
            cmd = ip_lib.add_namespace_to_cmd(cmd)
            linux_utils.execute(cmd)
            return True

        except RuntimeError:
            return False

    def _cleanup(self,
                 key_file_names=None,
                 called_from=None):

        LOG.debug("CLEAN UP CALLED FROM %s", called_from)
        nova_client = self.clients("nova")
        neutron_client = self.clients("neutron")

        servers = nova_client.servers.list()
        if servers:
            for server in servers:
                if "rally" in server.name:
                    self._delete_server(nova_client, server)

        if key_file_names:
            self._delete_key_file(key_file_names)

        self._delete_knownhosts_file()

        vpn_connections = neutron_client.list_ipsec_site_connections()
        if vpn_connections:
            for vpn_connection in vpn_connections['ipsec_site_connections']:
                if "rally" in vpn_connection['name']:
                    self._delete_ipsec_site_connection(neutron_client,
                                                vpn_connection)

        vpn_services = neutron_client.list_vpnservices()
        if vpn_services:
            for vpn_service in vpn_services['vpnservices']:
                if "rally" in vpn_service['name']:
                    self._delete_vpn_service(neutron_client, vpn_service)

        ipsec_policies = neutron_client.list_ipsecpolicies()
        if ipsec_policies:
            for ipsec_policy in ipsec_policies['ipsecpolicies']:
                if "rally" in ipsec_policy['name']:
                    self._delete_ipsec_policy(neutron_client, ipsec_policy)

        ike_policies = neutron_client.list_ikepolicies()
        if ike_policies:
            for ike_policy in ike_policies['ikepolicies']:
                if "rally" in ike_policy['name']:
                    self._delete_ike_policy(neutron_client, ike_policy)

        # Deletes entire network
        self._delete_network(neutron_client)
