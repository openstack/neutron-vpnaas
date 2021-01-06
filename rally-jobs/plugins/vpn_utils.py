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

import os
import socket
import stat
import time

import paramiko
from rally.common import logging
from rally.plugins.openstack.wrappers import network as network_wrapper
from rally.task import utils as task_utils

LOG = logging.getLogger(__name__)
SUBNET_IP_VERSION = 4
START_CIDR = "10.2.0.0/24"
EXT_NET_CIDR = "172.16.1.0/24"


def execute_cmd_over_ssh(host, cmd, private_key):
    """Run the given command over ssh

    Using paramiko package, it creates a connection to the given host;
    executes the required command on it and returns the output.
    :param host: Dictionary of ip, username and password
    :param cmd: Command to be run over ssh
    :param private_key: path to private key file
    :return: Output of the executed command
    """
    LOG.debug('EXECUTE COMMAND <%s> OVER SSH', cmd)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    k = paramiko.RSAKey.from_private_key_file(private_key)

    try:

        client.connect(host["ip"], username=host["username"], pkey=k)
    except paramiko.BadHostKeyException as e:
        raise Exception(
            "BADHOSTKEY EXCEPTION WHEN CONNECTING TO %s", host["ip"], e)
    except paramiko.AuthenticationException as e:
        raise Exception(
            "AUTHENTICATION EXCEPTION WHEN CONNECTING TO %s", host["ip"], e)
    except paramiko.SSHException as e:
        raise Exception("SSH EXCEPTION WHEN CONNECTING TO %s", host["ip"], e)
    except socket.error as e:
        raise Exception("SOCKET ERROR WHEN CONNECTING TO %s", host["ip"], e)
    LOG.debug("CONNECTED TO HOST <%s>", host["ip"])
    try:
        stdin, stdout, stderr = client.exec_command(cmd)
        return stdout.read().splitlines()
    except paramiko.SSHException as e:
        raise Exception("SSHEXCEPTION WHEN CONNECTING TO %s", host["ip"], e)
    finally:
        client.close()


def create_tenant(keystone_client, tenant_suffix):
    """Creates keystone tenant with a random name.

    :param keystone_client: keystone client
    :param tenant_suffix: suffix name for the tenant
    :returns: uuid of the new tenant
    """
    tenant_name = "rally_tenant_" + tenant_suffix
    LOG.debug("CREATING NEW TENANT %s", tenant_name)
    return keystone_client.tenants.create(tenant_name).id


def create_network(neutron_client, neutron_admin_client, network_suffix,
                   tenant_id=None, DVR_flag=True, ext_net_name=None):
    """Create neutron network, subnet, router

    :param neutron_client: neutron client
    :param neutron_admin_client: neutron client with admin credentials
    :param network_suffix: str, suffix name of the new network
    :param tenant_id: uuid of the tenant
    :param DVR_flag: True - creates a DVR router
                     False - creates a non DVR router
    :param ext_net_name: external network that is to be used
    :return: router, subnet, network, subnet_cidr
    """
    subnet_cidr = network_wrapper.generate_cidr(start_cidr=START_CIDR)

    def _create_network(neutron_client, network_suffix, is_external=False):
        """Creates neutron network"""

        network_name = "rally_network_" + network_suffix
        network_args = {"name": network_name,
                        "router:external": is_external
                        }
        if tenant_id:
            network_args["tenant_id"] = tenant_id
        LOG.debug("ADDING NEW NETWORK %s", network_name)
        return neutron_client.create_network({"network": network_args})

    def _create_subnet(neutron_client, rally_network, network_suffix, cidr):
        """Create neutron subnet"""

        network_id = rally_network["network"]["id"]
        subnet_name = "rally_subnet_" + network_suffix
        subnet_args = {"name": subnet_name,
                       "cidr": cidr,
                       "network_id": network_id,
                       "ip_version": SUBNET_IP_VERSION
                       }
        if tenant_id:
            subnet_args["tenant_id"] = tenant_id
        LOG.debug("ADDING SUBNET %s", subnet_name)
        return neutron_client.create_subnet({"subnet": subnet_args})

    def _create_router(neutron_client, ext_network_id, rally_subnet, dvr_flag):
        """Create router, set the external gateway and add router interface

        :param neutron_client: neutron_client
        :param ext_network_id: uuid of the external network
        :param rally_subnet: subnet to add router interface
        :param dvr_flag: True - creates a DVR router
                         False - creates a non DVR router
        :return: router
        """
        router_name = "rally_router_" + network_suffix
        gw_info = {"network_id": ext_network_id}
        router_args = {"name": router_name,
                       "external_gateway_info": gw_info
                       }
        if not dvr_flag:
            router_args["distributed"] = dvr_flag
        if tenant_id:
            router_args["tenant_id"] = 'tenant_id'
        LOG.debug("ADDING ROUTER %s", router_name)
        rally_router = neutron_client.create_router({"router": router_args})

        LOG.debug("[%s]: ADDING ROUTER INTERFACE")
        neutron_client.add_interface_router(
            rally_router['router']["id"],
            {"subnet_id": rally_subnet["subnet"]["id"]})
        return rally_router

    def _get_external_network_id(ext_net_name):
        """Fetch the network id for the given external network, if it exists.
           Else fetch the first external network present.
        """

        ext_nets = neutron_client.list_networks(
            **{'router:external': True})['networks']

        ext_nets_searched = [n for n in ext_nets if n['name'] == ext_net_name]
        if ext_nets_searched:
            return ext_nets_searched[0]['id']
        elif ext_nets:
            return ext_nets[0]['id']
        else:
            return None

    def _create_external_network():
        """Creat external network and subnet"""

        ext_net = _create_network(neutron_admin_client, "public", True)
        _create_subnet(neutron_admin_client, ext_net, "public", EXT_NET_CIDR)
        return ext_net['network']['id']

    ext_network_id = _get_external_network_id(ext_net_name)
    if not ext_network_id:
        ext_network_id = _create_external_network()
    rally_network = _create_network(neutron_client, network_suffix)
    rally_subnet = _create_subnet(neutron_client, rally_network,
                                  network_suffix, subnet_cidr)
    rally_router = _create_router(neutron_client, ext_network_id,
                                  rally_subnet, DVR_flag)
    return rally_router, rally_network, rally_subnet, subnet_cidr


def create_keypair(nova_client, keypair_suffix):
    """Create keypair

    :param nova_client: nova_client
    :param keypair_suffix: sufix name for the keypair
    :return: keypair
    """
    keypair_name = "rally_keypair_" + keypair_suffix
    LOG.debug("CREATING A KEYPAIR %s", keypair_name)
    keypair = nova_client.keypairs.create(keypair_name)
    return keypair


def write_key_to_local_path(keypair, local_key_file):
    """Write the private key of the nova instance to a temp file

    :param keypair: nova keypair
    :param local_key_file: path to private key file
    :return:
    """

    with open(local_key_file, 'w') as f:
        os.chmod(local_key_file, stat.S_IREAD | stat.S_IWRITE)
        f.write(keypair.private_key)


def write_key_to_compute_node(keypair, local_path, remote_path, host,
                              private_key):
    """Write the private key of the nova instance to the compute node

    First fetches the private key from the keypair and writes it to a
    temporary file in the local machine. It then sftp's the file
    to the compute host.

    :param keypair: nova keypair
    :param local_path: path to private key file of the nova instance in the
                       local machine
    :param remote_path: path where the private key file has to be placed
                        in the remote machine
    :param host: compute host credentials
    :param private_key: path to your private key file
    :return:
    """

    LOG.debug("WRITING PRIVATE KEY TO COMPUTE NODE")
    k = paramiko.RSAKey.from_private_key_file(private_key)
    write_key_to_local_path(keypair, local_path)
    try:
        transport = paramiko.Transport(host['ip'], host['port'])
    except paramiko.SSHException as e:
        raise Exception(
            "PARAMIKO TRANSPORT FAILED. CHECK IF THE HOST IP %s AND PORT %s "
            "ARE CORRECT %s", host['ip'], host['port'], e)
    try:
        transport.connect(
                username=host['username'], pkey=k)
    except paramiko.BadHostKeyException as e:
        transport.close()
        raise Exception(
            "BADHOSTKEY EXCEPTION WHEN CONNECTING TO %s", host["ip"], e)
    except paramiko.AuthenticationException as e:
        transport.close()
        raise Exception("AUTHENTICATION EXCEPTION WHEN CONNECTING TO %s",
                        host["ip"], e)
    except paramiko.SSHException as e:
        transport.close()
        raise Exception("SSH EXCEPTION WHEN CONNECTING TO %s", host["ip"], e)
    LOG.debug("CONNECTED TO HOST <%s>", host["ip"])

    try:
        sftp_client = paramiko.SFTPClient.from_transport(transport)
        sftp_client.put(local_path, remote_path)
    except IOError as e:
        raise Exception("FILE PATH DOESN'T EXIST", e)
    finally:
        transport.close()


def create_server(nova_client, keypair, **kwargs):
    """Create nova instance

    :param nova_client: nova client
    :param keypair: key-pair to allow ssh
    :return: new nova instance
    """
    # add sec-group
    sec_group_name = "rally_secgroup_" + kwargs["sec_group_suffix"]
    LOG.debug("ADDING NEW SECURITY GROUP %s", sec_group_name)
    secgroup = nova_client.security_groups.create(sec_group_name,
                                                  sec_group_name)
    # add security rules for SSH and ICMP
    nova_client.security_group_rules.create(secgroup.id, from_port=22,
                to_port=22, ip_protocol="tcp", cidr="0.0.0.0/0")

    nova_client.security_group_rules.create(secgroup.id, from_port=-1,
                to_port=-1, ip_protocol="icmp", cidr="0.0.0.0/0")

    # boot new nova instance
    server_name = "rally_server_" + (kwargs["server_suffix"])
    LOG.debug("BOOTING NEW INSTANCE: %s", server_name)
    LOG.debug("%s", kwargs["image"])
    server = nova_client.servers.create(server_name,
                                        image=kwargs["image"],
                                        flavor=kwargs["flavor"],
                                        key_name=keypair.name,
                                        security_groups=[secgroup.id],
                                        nics=kwargs["nics"])
    return server


def assert_server_status(server, **kwargs):
    """Assert server status

    :param server: nova server
    """

    LOG.debug('WAITING FOR SERVER TO GO ACTIVE')
    server = task_utils.wait_for(
        server,
        is_ready=task_utils.resource_is("ACTIVE"),
        update_resource=task_utils.get_from_manager(),
        timeout=kwargs["nova_server_boot_timeout"],
        check_interval=5)
    LOG.debug("SERVER STATUS: %s", server.status)
    assert('ACTIVE' == server.status), ("THE INSTANCE IS NOT IN ACTIVE STATE")


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


def add_floating_ip(nova_client, server):
    """Associates floating-ip to a server

    :param nova_client: nova client
    :param server: nova instance
    :return: associated floating ip
    """

    fip_list = nova_client.floating_ips.list()
    for fip in fip_list:
        if fip.instance_id is None:
            floating_ip = fip
            break
    else:
        LOG.debug("CREATING NEW FLOATING IP")
        floating_ip = nova_client.floating_ips.create()
    LOG.debug("ASSOCIATING FLOATING IP %s", floating_ip.ip)
    nova_client.servers.add_floating_ip(server.id, floating_ip.ip)
    return floating_ip


def get_namespace(host, private_key):
    """SSH into the host and get the namespaces

    :param host : dictionary of controller/compute node credentials
     {ip:x.x.x.x, username:xxx, password:xxx}
    :param private_key: path to private key file
    :return: namespaces
    """
    LOG.debug("GET NAMESPACES")
    cmd = "sudo ip netns"
    namespaces = execute_cmd_over_ssh(host, cmd, private_key)
    LOG.debug("NAMESPACES %s", namespaces)
    return namespaces


def wait_for_namespace_creation(namespace_tag, router_id, hosts, private_key,
                                timeout=60):
    """Wait for the namespace creation

    Get into each of the controllers/compute nodes and check which one contains
    the snat/qrouter namespace corresponding to rally_router. Sleep for a sec
    and repeat until either the namespace is found or the namespace_creation_
    time exceeded.
    :param namespace_tag: which namespace ("snat_" or "qrouter_")
    :param router_id: uuid of the rally_router
    :param hosts: controllers or compute hosts
    :param private_key: path to private key file
    :param timeout: namespace creation time
    :return:
    """
    start_time = time.time()
    while True:
        for host in hosts:
            namespaces = get_namespace(host, private_key)
            for line in namespaces:
                if line == (namespace_tag + router_id):
                    namespace_tag = line
                    return namespace_tag, host
        time.sleep(1)
        if time.time() - start_time > timeout:
            raise Exception("TIMEOUT WHILE WAITING FOR"
                            " NAMESPACES TO BE CREATED")


def ping(host, cmd, private_key):
    """Execute ping command over ssh"""
    ping_result = execute_cmd_over_ssh(host, cmd, private_key)
    if ping_result:
        LOG.debug("PING RESULT %s", ping_result)
        return True
    else:
        return False


def ping_router_gateway(namespace_controller_tuple, router_gw_ip, private_key):
    """Ping the ip address from network namespace

    Get into controller's snat-namespaces and ping the peer router gateway ip.
    :param namespace_controller_tuple: namespace, controller tuple. (It's the
                                 controller that contains the namespace )
    :param router_gw_ip: ip address to be pinged
    :param private_key: path to private key file
    :return: True if ping succeeds
             False if ping fails
    """
    namespace, controller = namespace_controller_tuple
    LOG.debug("PING %s FROM THE NAMESPACE %s", router_gw_ip, namespace)
    count = 4
    cmd = "sudo ip netns exec {} ping -w {} -c {} {}".format(
        namespace, 2 * count, count, router_gw_ip)
    return ping(controller, cmd, private_key)


def get_interfaces(namespace_controller_tuple, private_key):
    """Get the interfaces

    Get into the controller's snat namespace and list the interfaces.
    :param namespace_controller_tuple: namespace, controller tuple(the
                                       controller that contains the namespace).
    :param private_key: path to private key file
    :return: interfaces
    """
    namespace, controller = namespace_controller_tuple
    LOG.debug("GET THE INTERFACES BY USING 'ip a' FROM THE NAMESPACE %s",
              namespace)
    cmd = "sudo ip netns exec {} ip a".format(namespace)
    interfaces = execute_cmd_over_ssh(controller, cmd, private_key)
    LOG.debug("INTERFACES %s", interfaces)
    return interfaces


def start_tcpdump(namespace_controller_tuple, interface, private_key):
    """Start the tcpdump at the given interface

    Get into the controller's snat namespace and start a tcp dump at the
    qg-interface.
    :param namespace_controller_tuple: namespace, controller tuple. (It's the
                                 controller that contains the namespace )
    :param interface: interface in which tcpdump has to be run
    :param private_key: path to private key file
    :return: tcpdump output
    """
    namespace, controller = namespace_controller_tuple
    LOG.debug("START THE TCPDUMP USING 'tcpdump -i %s FROM THE NAMESPACE"
              " %s", interface, namespace)
    cmd = ("sudo ip netns exec {} timeout 15 tcpdump -n -i {}"
           .format(namespace, interface))
    tcpdump = execute_cmd_over_ssh(controller, cmd, private_key)
    LOG.debug("TCPDUMP %s", tcpdump)
    return tcpdump


def ssh_and_ping_server(local_server, peer_server, ns_compute_tuple, keyfile,
                        private_key):
    """SSH and ping the nova instance from the namespace

     Get into the compute node's qrouter namespace and then ssh into the local
     nova instance & ping the peer nova instance.
    :param local_server: private ip of the server to ssh into
    :param peer_server: private ip of the server to ping to
    :param ns_compute_tuple: namespace, compute tuple. (It's the
                                 compute node that contains the namespace )
    :param keyfile: path to private key file of the nova instance
    :param private_key: path to private key file
    :return: True if ping succeeds
             False if ping fails
    """
    namespace, compute_host = ns_compute_tuple
    LOG.debug("SSH INTO SERVER %s AND PING THE PEER SERVER %s FROM THE"
              " NAMESPACE %s", local_server, peer_server, namespace)
    host = "cirros@" + local_server
    count = 20
    cmd = ("sudo ip netns exec {} ssh -v -o StrictHostKeyChecking=no -o"
           "HashKnownHosts=no -i {} {} ping -w {} -c {} {}"
           .format(namespace, keyfile, host, 2 * count, count, peer_server))
    return ping(compute_host, cmd, private_key)


def ssh_and_ping_server_with_fip(local_server, peer_server, keyfile,
                                 private_key):
    """SSH into the local nova instance and ping the peer instance using fips

    :param local_server: fip of the server to ssh into
    :param peer_server: private ip of the server to ping to
    :param keyfile: path to private key file of the nova instance
    :param private_key: path to private key file
    :return: True if ping succeeds
             False if ping fails
    """
    LOG.debug("SSH INTO LOCAL SERVER %s AND PING THE PEER SERVER %s",
              local_server.ip, peer_server)
    count = 20
    local_host = {"ip": "127.0.0.1", "username": None}
    host = "cirros@" + local_server.ip
    cmd = ("ssh -v -o StrictHostKeyChecking=no -o"
           "HashKnownHosts=no -i {} {} ping -w {} -c {} {}"
           .format(keyfile, host, 2 * count, count, peer_server))
    return ping(local_host, cmd, private_key)


def delete_servers(nova_client, servers):
    """Delete nova servers

    It deletes the nova servers, associated security groups.

    :param nova_client: nova client
    :param servers: nova instances to be deleted
    :return:
    """
    for server in servers:
        LOG.debug("DELETING NOVA INSTANCE: %s", server.id)
        sec_group_id = server.security_groups[0]['name']
        nova_client.servers.delete(server.id)

        LOG.debug("WAITING FOR INSTANCE TO GET DELETED")
        task_utils.wait_for_delete(
            server, update_resource=task_utils.get_from_manager())

        for secgroup in nova_client.security_groups.list():
            if secgroup.id == sec_group_id:
                LOG.debug("DELETING SEC_GROUP: %s", sec_group_id)
                nova_client.security_groups.delete(secgroup.id)


def delete_floating_ips(nova_client, fips):
    """Delete floating ips

    :param nova_client: nova client
    :param fips: list of floating ips
    :return:
    """
    for fip in fips:
        nova_client.floating_ips.delete(fip.id)


def delete_keypairs(nova_client, keypairs):
    """Delete key pairs

    :param nova_client: nova client
    :param keypairs: list of keypairs
    :return
    """
    for key_pair in keypairs:
        LOG.debug("DELETING KEY_PAIR %s", key_pair.name)
        nova_client.keypairs.delete(key_pair.id)


def delete_networks(neutron_client, neutron_admin_client,
                   routers, networks, subnets):
    """Delete neutron network, subnets amd routers

    :param neutron_client: neutron client
    :param neutron_admin_client: neutron_admin_client
    :param routers: list of routers to be deleted
    :param networks: list of networks to be deleted
    :param subnets: list of subnets to be deleted
    :return
    """
    LOG.debug("DELETING RALLY ROUTER INTERFACES & GATEWAYS")
    for router in routers:
        neutron_client.remove_gateway_router(router['router']['id'])
        router_name = router['router']['name']
        subnet_name = ("rally_subnet_" + router_name[13:len(router_name)])
        for subnet in subnets:
            if subnet_name == subnet['subnet']['name']:
                neutron_client.remove_interface_router(
                    router['router']['id'],
                    {"subnet_id": subnet['subnet']['id']})

    LOG.debug("DELETING RALLY ROUTERS")
    for router in routers:
        neutron_client.delete_router(router['router']['id'])

    LOG.debug("DELETING RALLY NETWORKS")
    for network in networks:
        if (network['network']['router:external'] and
            network['network']['name'] == "rally_network_public"):
            external_network = network
            neutron_admin_client.delete_network(
                external_network['network']["id"])
        elif network['network']['router:external']:
            pass
        else:
            neutron_client.delete_network(network['network']['id'])


def delete_tenants(keystone_client, tenant_ids):
    """Delete keystone tenant

    :param keystone_client: keystone client
    :param tenant_ids: list of tenants' uuids
    :returns: delete keystone tenant instance
    """
    LOG.debug('DELETE TENANTS')
    for id in tenant_ids:
        keystone_client.tenants.delete(id)


def delete_keyfiles(local_key_files, remote_key_files=None,
                    ns_compute_tuples=None, private_key=None):
    """Delete the SSH keyfiles from the compute and the local nodes

    :param local_key_files: paths to ssh key files in local node
    :param remote_key_files: paths to ssh key files in compute nodes
    :param ns_compute_tuples: namespace, compute tuple. (It's the
                              compute node that contains the namespace )
    :param private_key: path to private key file
    :return:
    """
    LOG.debug("DELETING RALLY KEY FILES FROM LOCAL MACHINE")
    for key in local_key_files:
        if os.path.exists(key):
            os.remove(key)

    if ns_compute_tuples:
        LOG.debug("DELETING RALLY KEY FILES FROM COMPUTE HOSTS")
        for key, ns_comp in zip(remote_key_files, ns_compute_tuples):
            cmd = "sudo rm -f {}".format(key)
            host = ns_comp[1]
            execute_cmd_over_ssh(host, cmd, private_key)


def delete_hosts_from_knownhosts_file(hosts, ns_compute_tuples=None,
                                      private_key=None):
    """Remove the hosts from the knownhosts file

    :param hosts: host ips to be removed from /root/.ssh/knownhosts
    :param ns_compute_tuples: namespace, compute tuple. (It's the
                              compute node that contains the namespace )
    :param private_key: path to private key file
    :return:
    """
    if ns_compute_tuples:
        LOG.debug("DELETES HOSTS FROM THE KNOWNHOSTS FILE")
        for host, ns_comp in zip(hosts, ns_compute_tuples):
            compute_host = ns_comp[1]
            cmd = ("sudo ssh-keygen -f /root/.ssh/known_hosts -R"
                   " {}".format(host))
            execute_cmd_over_ssh(compute_host, cmd, private_key)
    else:
        for host in hosts:
            os.system("sudo ssh-keygen -f /root/.ssh/known_hosts -R"
                      " {}".format(host))
