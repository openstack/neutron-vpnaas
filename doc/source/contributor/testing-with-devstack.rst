============================
Testing VPNaaS with devstack
============================

Installation
------------

In order to use Neutron-VPNaaS with `devstack <http://devstack.org>`_ a single node setup,
you'll need the following settings in your local.conf.

.. literalinclude:: ../../../devstack/local.conf.sample


You can find an example at `devstack/local.conf.sample
<https://git.openstack.org/cgit/openstack/neutron-vpnaas/tree/devstack/local.conf.sample>`_
in the source tree.

Quick Test Script
-----------------

This quick test script creates two sites with a router, a network and a subnet connected
with public network. Then, connect both sites via VPN.

You can find an example at `tools/test_script.sh
<https://git.openstack.org/cgit/openstack/neutron-vpnaas/tree/tools/test_script.sh>`_
in the source tree.

Using Two DevStack Nodes for Testing
------------------------------------

You can use two DevStack nodes connected by a common "public" network to test VPNaaS.
The second node can be set up with the same public network as the first node, except
it will use a different gateway IP (and hence router IP). In this example, we'll assume
we have two DevStack nodes (``East`` and ``West``), each running on hardware.

.. note::

   - You can do the same thing with multiple VM guests, if desired.
   - You can also create similar topology using two virtual routers with one devstack.

Example Topology
^^^^^^^^^^^^^^^^

.. code-block:: none

     (10.1.0.0/24 - DevStack East)
              |
              |  10.1.0.1
     [Neutron Router]
              |  172.24.4.226
              |
              |  172.24.4.225
     [Internet GW]
              |
              |
     [Internet GW]
              | 172.24.4.232
              |
              | 172.24.4.233
     [Neutron Router]
              |  10.2.0.1
              |
     (10.2.0.0/24 DevStack West)

DevStack Configuration
^^^^^^^^^^^^^^^^^^^^^^

For ``East`` you need to append the following lines to the local.conf, which will give you
a private net of 10.1.0.0/24 and public network of 172.24.4.0/24

.. code-block:: none

      PUBLIC_SUBNET_NAME=yoursubnet
      PRIVATE_SUBNET_NAME=mysubnet
      FIXED_RANGE=10.1.0.0/24
      NETWORK_GATEWAY=10.1.0.1
      PUBLIC_NETWORK_GATEWAY=172.24.4.225
      Q_FLOATING_ALLOCATION_POOL=start=172.24.4.226,end=172.24.4.231

For ``West`` you can add the following lines to local.conf to use a different local network,
public GW (and implicitly router) IP.

.. code-block:: none

      PUBLIC_SUBNET_NAME=yoursubnet
      PRIVATE_SUBNET_NAME=mysubnet
      FIXED_RANGE=10.2.0.0/24
      NETWORK_GATEWAY=10.2.0.1
      PUBLIC_NETWORK_GATEWAY=172.24.4.232
      Q_FLOATING_ALLOCATION_POOL=start=172.24.4.233,end=172.24.4.238

VPNaaS Configuration
^^^^^^^^^^^^^^^^^^^^

With DevStack running on ``East`` and ``West`` and connectivity confirmed (make sure
you can ping one router/GW from the other), you can perform these VPNaaS CLI commands.

On ``East``

.. code-block:: none

      neutron vpn-ikepolicy-create ikepolicy1
      neutron vpn-ipsecpolicy-create ipsecpolicy1
      neutron vpn-service-create --name myvpn --description "My vpn service" router1
      neutron vpn-endpoint-group-create --name my-locals --type subnet --value mysubnet
      neutron vpn-endpoint-group-create --name my-peers --type cidr --value 10.2.0.0/24
      neutron ipsec-site-connection-create --name vpnconnection1 --vpnservice-id myvpn \
      --ikepolicy-id ikepolicy1 --ipsecpolicy-id ipsecpolicy1 --peer-address 172.24.4.233 \
      --peer-id 172.24.4.233 --local-ep-group my-locals --peer-ep-group my-peers --psk secret

On ``West``

.. code-block:: none

      neutron vpn-ikepolicy-create ikepolicy1
      neutron vpn-ipsecpolicy-create ipsecpolicy1
      neutron vpn-service-create --name myvpn --description "My vpn service" router1
      neutron vpn-endpoint-group-create --name my-locals --type subnet --value mysubnet
      neutron vpn-endpoint-group-create --name my-peers --type cidr --value 10.1.0.0/24
      neutron ipsec-site-connection-create --name vpnconnection1 --vpnservice-id myvpn \
      --ikepolicy-id ikepolicy1 --ipsecpolicy-id ipsecpolicy1 --peer-address 172.24.4.226 \
      --peer-id 172.24.4.226 --local-ep-group my-locals --peer-ep-group my-peers --psk secret

.. note::

   Make sure setup security group (open icmp for vpn subnet etc)

Verification
^^^^^^^^^^^^

You can spin up VMs on each node, and then from the VM ping to the other one.
With tcpdump running on one of the nodes, you can see that pings appear
as encrypted packets (ESP). Note that BOOTP, IGMP, and the keepalive packets between
the two nodes are not encrypted (nor are pings between the two external IP addresses).

Once stacked, VMs were created for testing, VPN IPsec commands used to establish connections
between the nodes, and security group rules added to allow ICMP and SSH.

Using single DevStack and two routers for testing
-------------------------------------------------

Simple instructions on how to setup a test environment where a VPNaaS IPsec
connection can be established using the reference implementation (StrongSwan).
This example uses VirtualBox running on laptop to provide a VM for running
DevStack.

The idea here is to have a single OpenStack cloud created using DevStack,
two routers (one created automatically), two private networks (one created automatically)
10.1.0.0/24 and 10.2.0.0/24, a VM in each private network, and establish a VPN connection
between the two private nets, using the public network (172.24.4.0/24).

Preparation
^^^^^^^^^^^

Create a VM (e.g. 4 GB RAM, 2 CPUs) running Ubuntu 16.04, with NAT I/F for
access to the Internet. Clone a DevStack repo with latest.

DevStack Configuration
^^^^^^^^^^^^^^^^^^^^^^

For single DevStack and two routers case, You can find an example at `devstack/local_AIO.conf.sample
<https://git.openstack.org/cgit/openstack/neutron-vpnaas/tree/devstack/local_AIO.conf.sample>`_
in the source tree.

Start up the cloud using ``./stack.sh`` and ensure it completes successfully.
Once stacked, you can change ``RECLONE`` option in local.conf to No.

Cloud Configuration
^^^^^^^^^^^^^^^^^^^

Once stacking is completed, you'll have a private network (10.1.0.0/24), and a router (router1).
To prepare for establishing a VPN connection, a second network, subnet, and router needs
to be created, and a VM spun up in each private network.

.. code-block:: none

      # Create second net, subnet, router
      source ~/devstack/openrc admin demo
      neutron net-create privateB
      neutron subnet-create --name subB privateB 10.2.0.0/24 --gateway 10.2.0.1
      neutron router-create routerB
      neutron router-interface-add routerB subB
      neutron router-gateway-set routerB public

      # Start up a VM in the privateA subnet.
      PRIVATE_NET=`neutron net-list | grep 'private ' | cut -f 2 -d' '`
      nova boot --flavor 1 --image cirros-0.3.5-x86_64-uec --nic net-id=$PRIVATE_NET peter

      # Start up a VM in the privateB subnet
      PRIVATE_NETB=`neutron net-list | grep privateB | cut -f 2 -d' '`
      nova boot --flavor 1 --image cirros-0.3.5-x86_64-uec --nic net-id=$PRIVATE_NETB paul

At this point, you can verify that you have basic connectivity.

.. note::

   DevStack will create a static route that will allow you to ping the private interface IP of
   router1 from privateB network. You can remove the route, if desired.

IPsec Site-to-site Connection Creation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following commands will create the IPsec connection:

.. code-block:: none

      # Create VPN connections
      neutron vpn-ikepolicy-create ikepolicy
      neutron vpn-ipsecpolicy-create ipsecpolicy
      neutron vpn-service-create --name myvpn --description "My vpn service" router1
      neutron vpn-endpoint-group-create --name my-localsA --type subnet --value privateA
      neutron vpn-endpoint-group-create --name my-peersA --type cidr --value 10.2.0.0/24
      neutron ipsec-site-connection-create --name vpnconnection1 --vpnservice-id myvpn \
      --ikepolicy-id ikepolicy --ipsecpolicy-id ipsecpolicy --peer-address 172.24.4.13 \
      --peer-id 172.24.4.13 --local-ep-group my-localsA --peer-ep-group my-peersA --psk secret

      neutron vpn-service-create --name myvpnB --description "My vpn serviceB" routerB
      neutron vpn-endpoint-group-create --name my-localsB --type subnet --value subB
      neutron vpn-endpoint-group-create --name my-peersB --type cidr --value 10.1.0.0/24
      neutron ipsec-site-connection-create --name vpnconnection2 --vpnservice-id myvpnB \
      --ikepolicy-id ikepolicy --ipsecpolicy-id ipsecpolicy --peer-address 172.24.4.11 \
      --peer-id 172.24.4.11 --local-ep-group my-localsB --peer-ep-group my-peersB --psk secret

At this point (once the connections become active - which can take up to 30 seconds or so),
you should be able to ping from the VM in the privateA network, to the VM in the privateB
network. You'll see encrypted packets, if you tcpdump using the qg-# interface from one
of the router namespaces. If you delete one of the connections, you'll see that the pings
fail (if all works out correctly :)).

.. note::

   Because routerB is created manually, its public IP address may change (172.24.4.13
   in this case).


Multiple Local Subnets
^^^^^^^^^^^^^^^^^^^^^^

Early in Mitaka, IPsec site-to-site connections will support multiple local subnets,
in addition to the current multiple peer CIDRs. The multiple local subnet feature
is triggered by not specifying a local subnet, when creating a VPN service.
Backwards compatibility is maintained with single local subnets, by providing
the subnet in the VPN service creation.

To support multiple local subnets, a new capability has been provided (since Liberty),
called "Endpoint Groups". Each endpoint group will define one or more endpoints of
a specific type, and can be used to specify both local and peer endpoints for
IPsec connections. The Endpoint Groups separate the "what gets connected" from
the "how to connect" for a VPN service, and can be used for different flavors
of VPN, in the future. An example:

.. code-block:: none

      # Create VPN connections
      neutron vpn-ikepolicy-create ikepolicy
      neutron vpn-ipsecpolicy-create ipsecpolicy
      neutron vpn-service-create --name myvpnC --description "My vpn service" router1

To prepare for an IPsec site-to-site, one would create an endpoint group for
the local subnets, and an endpoint group for the peer CIDRs, like so:

.. code-block:: none

      neutron vpn-endpoint-group-create --name my-locals --type subnet --value privateA --value privateA2
      neutron vpn-endpoint-group-create --name my-peers --type cidr --value 10.2.0.0/24 --value 20.2.0.0/24

where privateA and privateA2 are two local (private) subnets, and 10.2.0.0/24 and 20.2.0.0/24
are two CIDRs representing peer (private) subnets that will be used by a connection.
Then, when creating the IPsec site-to-site connection, these endpoint group IDs would
be specified, instead of the peer-cidrs attribute:

.. code-block:: none

      neutron ipsec-site-connection-create --name vpnconnection3 --vpnservice-id myvpnC \
      --ikepolicy-id ikepolicy --ipsecpolicy-id ipsecpolicy --peer-address 172.24.4.11 \
      --peer-id 172.24.4.11 --local-ep-group my-locals --peer-ep-group my-peers --psk secret

.. note::
   - The validation logic makes sure that endpoint groups and peer CIDRs are not intermixed.
   - Endpoint group types are subnet, cidr, network, router, and vlan.
     However, only subnet and cidr are implemented (for IPsec use).
   - The endpoints in a group must be of the same type, although It can mix IP versions.
   - For IPsec connections, validation currently enforces that the local and peer
     endpoints all use the same IP version.
   - IPsec connection validation requires that local endpoints are subnets,
     and peer endpoints are CIDRs.
   - Migration will convert information for any existing VPN services and connections to endpoint groups.
   - The original APIs will work for backward compatibility.
