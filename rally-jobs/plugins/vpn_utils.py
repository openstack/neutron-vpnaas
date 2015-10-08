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

import exceptions
import os
from oslo_config import cfg
import stat
import time


def noop(*args, **kwargs):
    pass
cfg.CONF.register_cli_opts = noop

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from rally.common import log as logging
from rally.plugins.openstack.wrappers import network as network_wrapper
from rally.task import utils as task_utils

LOG = logging.getLogger(__name__)
SUBNET_IP_VERSION = 4
START_CIDR = "10.2.0.0/24"
EXT_NET_CIDR = "172.16.1.0/24"


def create_network(neutron_client, neutron_admin_client,
                   network_suffix, tenant_id=None):
    """Creates neutron network, subnet, router

    :param neutron_client: neutron client
    :param neutron_admin_client: neutron_admin_client
    :param network_suffix: str, suffix name of the new network
    :return: router, subnet, network, subnet_cidr
    """
    subnet_cidr = network_wrapper.generate_cidr(start_cidr=START_CIDR)

    def _create_network(neutron_client, network_suffix, is_external=False):
        """Creates neutron network"""

        network_name = "rally_network_" + network_suffix
        network_args = {"name": network_name,
                        "router:external": is_external
                        }
        LOG.debug("ADDING NEW NETWORK: %s", network_name)

        if tenant_id is not None:
            network_args["tenant_id"] = tenant_id

        return neutron_client.create_network({"network": network_args})

    def _create_subnet(neutron_client, rally_network, network_suffix, cidr):
        """Creates neutron subnet"""

        network_id = rally_network["network"]["id"]
        subnet_name = "rally_subnet_" + network_suffix
        subnet_args = {"name": subnet_name,
                       "cidr": cidr,
                       "network_id": network_id,
                       "ip_version": SUBNET_IP_VERSION
                       }
        LOG.debug("ADDING SUBNET: %s", subnet_name)

        if tenant_id is not None:
            subnet_args["tenant_id"] = tenant_id

        return neutron_client.create_subnet({"subnet": subnet_args})

    def _create_router(neutron_client, ext_network_id, rally_subnet):
        """Creates router, sets the external gateway and adds router interface

        :param neutron_client: neutron_client
        :param ext_network_id: uuid of the external network
        :param rally_subnet: subnet to add router interface
        :return: router
        """
        router_name = "rally_router_" + network_suffix
        gw_info = {"network_id": ext_network_id}
        router_args = {"name": router_name,
                       "external_gateway_info": gw_info
                       }
        LOG.debug("ADDING ROUTER: %s", router_name)
        LOG.debug("ADDING ROUTER INTERFACE")

        if tenant_id is not None:
            router_args["tenant_id"] = 'tenant_id'

        rally_router = neutron_client.create_router(
            {"router": router_args})
        neutron_client.add_interface_router(
            rally_router['router']["id"],
            {"subnet_id": rally_subnet["subnet"]["id"]})
        return rally_router

    def _get_external_network_id():
        """Fetches the external network id, if external network exists"""

        for network in neutron_client.list_networks()['networks']:
            if network['router:external']:
                ext_network_id = network['id']
                LOG.debug("EXTERNAL NETWORK ALREADY EXISTS")
                return ext_network_id

    def _create_external_network():
        """Creates external network and subnet"""

        ext_net = _create_network(neutron_admin_client, "public", True)
        _create_subnet(neutron_admin_client, ext_net, "public", EXT_NET_CIDR)
        return ext_net['network']['id']

    ext_network_id = _get_external_network_id()
    if not ext_network_id:
        ext_network_id = _create_external_network()
    rally_network = _create_network(neutron_client, network_suffix)
    rally_subnet = _create_subnet(neutron_client, rally_network,
                                  network_suffix, subnet_cidr)
    rally_router = _create_router(neutron_client, ext_network_id, rally_subnet)
    return rally_router, rally_network, rally_subnet, subnet_cidr


def create_tenant(keystone_client, tenant):
    """Creates keystone tenant with random name.
    :param tenant: create a tenant with random name
    :returns:
    """
    return keystone_client.tenants.create(tenant)


def delete_tenant(keystone_client, tenant):
    """Deletes keystone tenant

    :returns: delete keystone tenant instance
    """
    if tenant:
        for id in tenant:
            keystone_client.tenants.delete(id)


def create_keypair(nova_client, key_name, key_file_path):
    """Create keypair

    :param nova_client: nova_client
    :param key_name: key_name
    :param key_file_path: path to key_file
    :return: keypair
    """
    LOG.debug("ADDING NEW KEYPAIR")
    keypair = nova_client.keypairs.create(key_name)
    f = open(key_file_path, 'w')
    os.chmod(key_file_path, stat.S_IREAD | stat.S_IWRITE)
    f.write(keypair.private_key)
    f.close()
    return keypair


def create_nova_vm(nova_client, keypair, **kwargs):
    """Create nova instance

    :param nova_client: nova client
    :param keypair: key-pair to allow ssh
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

    LOG.debug("WAITING FOR INSTANCE TO BECOME ACTIVE")
    server = task_utils.wait_for(
        server,
        is_ready=task_utils.resource_is("ACTIVE"),
        update_resource=task_utils.get_from_manager(),
        timeout=kwargs["nova_server_boot_timeout"],
        check_interval=5)
    LOG.debug("SERVER STATUS: %s", server.status)

    assert('ACTIVE' == server.status), (
        "THE INSTANCE IS NOT IN ACTIVE STATE")
    return server


def get_server_ip(nova_client, server_id, network_suffix):
    """Get the ip associated with the nova instance

    :param nova_client: nova client
    :param server_id: uuid of the nova instance whose ip is required
    :param network_suffix: suffix name of the network
    :return: ip address of the instance
    """
    network_name = "rally_network_" + network_suffix
    server_details = nova_client.servers.get(server_id)
    server_ip = server_details.addresses[network_name][0]["addr"]
    return server_ip


def get_namespace():
    """Get namespaces

    :return: namespaces
    """
    LOG.debug("GET NAMESPACES USING 'ip netns'")
    cmd = ['ip', 'netns']
    cmd = ip_lib.add_namespace_to_cmd(cmd)
    try:
        namespaces = linux_utils.execute(cmd)
    except RuntimeError:
        return None
    LOG.debug("%s", namespaces)
    return namespaces


def wait_for_namespace_creation(namespace, rally_router, **kwargs):
    """Wait for namespace creation

    :param namespace: snat/qrouter namespace
    :param rally_router: rally_router
    :return:
    """
    start_time = time.time()
    while True:
        namespaces = get_namespace().split()
        for line in namespaces:
            if line == (namespace + rally_router["router"]["id"]):
                namespace = line
                return namespace
        time.sleep(1)
        if time.time() - start_time > kwargs['namespace_creation_timeout']:
            raise exceptions.Exception("Timeout while waiting for"
                                       " namespaces to be created")


def ping(namespace, ip):
    """Pings ip address from network namespace.

    In order to ping it uses following cli command:
    ip netns exec <namespace> ping -c 4 -q <ip>
    :param namespace: namespace
    :param ip: ip to ping to
    """
    LOG.debug("PING %s FROM THE NAMESPACE %s", ip, namespace)
    count = 4
    cmd = ['ping', '-w', 2 * count, '-c', count, ip]
    cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
    try:
        ping_result = linux_utils.execute(cmd, run_as_root=True)
    except RuntimeError:
        return False
    LOG.debug("%s", ping_result)
    return True


def get_interfaces(namespace):
    """Do an "ip a".

    In order to do "ip a" it uses following cli command:
    ip netns exec <namespace> ip a | grep qg
    :param namespace: namespace
    :return: interfaces
    """
    LOG.debug("GET THE INTERFACES BY USING 'ip a' FROM THE NAMESPACE %s",
              namespace)
    cmd = ['ip', 'a']
    cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
    try:
        interfaces = linux_utils.execute(cmd, run_as_root=True)
    except RuntimeError:
        return None
    LOG.debug("%s", interfaces)
    return interfaces


def start_tcpdump(namespace, interface):
    """Starts tcpdump at the given interface

    In order to start a "tcpdump" it uses the following command:
    ip netns exec <namespace> sudo tcpdump -i <interface>
    :param namespace: namespace
    :param interface: interface
    :return: tcpdump
    """
    LOG.debug("START THE TCPDUMP USING 'tcpdump -i <%s> FROM THE NAMESPACE"
              " %s", interface, namespace)
    cmd = ['timeout', '5', 'tcpdump', '-n', '-i', interface]
    cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
    try:
        tcpdump = linux_utils.execute(cmd, run_as_root=True,
                                      extra_ok_codes=[124])
    except RuntimeError:
        return None
    LOG.debug("%s", tcpdump)
    return tcpdump


def ssh_and_ping_server(ssh_server, ping_server, namespace, key_file_name):
    """SSH into the server from the namespace.

    In order to ssh it uses the following command:
    ip netns exec <namespace> ssh -i <path to keyfile> cirros@<server_ip>
    :param ssh_server: ip of the server to ssh into
    :param ping_server: ip of the server to ping to
    :param namespace: qrouter namespace
    :param key_file_name: path to private key file
    :return: True/False
    """
    LOG.debug("SSH INTO SERVER %s AND PING THE PEER SERVER %s FROM THE"
              " NAMESPACE %s", ssh_server, ping_server, namespace)
    host = "cirros@" + ssh_server
    count = 20
    cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'HashKnownHosts=no',
           '-i', key_file_name, host, 'ping', '-w', 2 * count, '-c', count,
           ping_server]
    cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
    try:
        ping_result = linux_utils.execute(cmd, run_as_root=True)
    except RuntimeError:
        return False
    LOG.debug("%s", ping_result)
    return True


def delete_servers(nova_client, servers):
    """Delete nova servers

    It deletes the nova servers, associated security groups and keypairs.

    :param nova_client: nova client
    :param servers: nova instances to be deleted
    :return:
    """
    if servers:
        for server in servers:
            if "rally" in server.name:
                sec_group_name = server.security_groups[0]['name']
                server_key_name = server.key_name

                LOG.debug("DELETING NOVA INSTANCE: %s", server.id)
                nova_client.servers.delete(server.id)

                LOG.debug("WAITING FOR INSTANCE TO GET DELETED")
                task_utils.wait_for_delete(
                    server, update_resource=task_utils.get_from_manager())

                for secgroup in nova_client.security_groups.list():
                    if secgroup.name == sec_group_name:
                        LOG.debug("DELETING SEC_GROUP: %s", sec_group_name)
                        nova_client.security_groups.delete(secgroup.id)

                for key_pair in nova_client.keypairs.list():
                    if key_pair.name == server_key_name:
                        LOG.debug("DELETING KEY_PAIR: %s", server_key_name)
                        nova_client.keypairs.delete(key_pair.id)


def delete_network(neutron_client, neutron_admin_client,
                   routers, networks, subnets):
    """Delete neutron network, subnets amd routers.

    :param neutron_client: neutron client
    :param neutron_admin_client: neutron_admin_client
    :param routers: list of routers to be deleted
    :param networks: list of networks to be deleted
    :param subnets: list of subnets to be deleted
    :return
    """
    LOG.debug("DELETING RALLY ROUTER INTERFACES & GATEWAYS")
    if routers:
        for router in routers:
            if "rally" in router['router']['name']:
                neutron_client.remove_gateway_router(router['router']['id'])
                router_name = router['router']['name']
                subnet_name = ("rally_subnet_" +
                               router_name[13:len(router_name)])
                if subnets:
                    for subnet in subnets:
                        if subnet_name == subnet['subnet']['name']:
                            neutron_client.remove_interface_router(
                                router['router']['id'],
                                {"subnet_id": subnet['subnet']['id']})

    LOG.debug("DELETING RALLY ROUTERS")
    if routers:
        for router in routers:
            if "rally" in router['router']['name']:
                neutron_client.delete_router(router['router']['id'])

    LOG.debug("DELETING RALLY NETWORKS")
    if networks:
        for network in networks:
            if (network['network']['router:external'] and
                network['network']['name'] == "rally_network_public"):
                external_network = network
                neutron_admin_client.delete_network(
                    external_network['network']["id"])
            if "rally_network" in network['network']['name']:
                neutron_client.delete_network(network['network']['id'])


def delete_key_files(key_file_paths):
    """Deletes ssh key files

    :param key_file_paths:  paths to ssh key files
    :return:
    """
    LOG.debug("DELETING RALLY KEY FILES")
    if key_file_paths:
        for path in key_file_paths:
            if os.path.exists(path):
                os.remove(path)


def delete_hosts_from_knownhosts_file(hosts):
    """Removes the hosts from the knownhosts file

    :param hosts: host ips to be removed from /root/.ssh/knownhosts
    :return:
    """
    LOG.debug("DELETES HOSTS FROM THE KNOWNHOSTS FILE")
    if hosts:
        for host in hosts:
            cmd = ['ssh-keygen', '-f', "/root/.ssh/known_hosts", '-R', host]
            cmd = ip_lib.add_namespace_to_cmd(cmd)
            try:
                linux_utils.execute(cmd, run_as_root=True)
            except RuntimeError:
                return False
            return True
