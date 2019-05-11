============================
Testing VPNaaS with devstack
============================

Installation
------------

In order to use Neutron-VPNaaS with `devstack <http://devstack.org>`_ a single node setup,
you'll need the following settings in your local.conf.

.. literalinclude:: ../../../devstack/local.conf.sample


You can find an example at `devstack/local.conf.sample
<https://opendev.org/openstack/neutron-vpnaas/src/branch/master/devstack/local.conf.sample>`_
in the source tree.

Quick Test Script
-----------------

This quick test script creates two sites with a router, a network and a subnet connected
with public network. Then, connect both sites via VPN.

You can find an example at `tools/test_script.sh
<https://opendev.org/openstack/neutron-vpnaas/src/branch/master/tools/test_script.sh>`_
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

      openstack vpn ike policy create ikepolicy1
      openstack vpn ipsec policy create ipsecpolicy1
      openstack vpn service create --description "My vpn service" \
          --router router1 myvpn
      openstack vpn endpoint group create --type subnet --value mysubnet my-locals
      openstack vpn endpoint group create --type cidr --value 10.2.0.0/24 my-peers
      openstack vpn ipsec site connection create --vpnservice myvpn \
          --ikepolicy ikepolicy1 --ipsecpolicy ipsecpolicy1 \
          --peer-address 172.24.4.233 --peer-id 172.24.4.233 \
          --local-endpoint-group my-locals --peer-endpoint-group my-peers \
          --psk secret vpnconnection1

On ``West``

.. code-block:: none

      openstack vpn ike policy create ikepolicy1
      openstack vpn ipsec policy create ipsecpolicy1
      openstack vpn service create --description "My vpn service" \
          --router router1 myvpn
      openstack vpn endpoint group create --type subnet --value mysubnet my-locals
      openstack vpn endpoint group create --type cidr --value 10.1.0.0/24 my-peers
      openstack vpn ipsec site connection create --vpnservice myvpn \
          --ikepolicy ikepolicy1 --ipsecpolicy ipsecpolicy1 \
          --peer-address 172.24.4.226 --peer-id 172.24.4.226 \
          --local-endpoint-group my-locals --peer-endpoint-group my-peers \
          --psk secret vpnconnection1

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
<https://opendev.org/openstack/neutron-vpnaas/src/branch/master/devstack/local_AIO.conf.sample>`_
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
      openstack network create privateB
      openstack subnet create --network privateB --subnet-range 10.2.0.0/24 --gateway 10.2.0.1 subB
      openstack router create routerB
      openstack router add subnet routerB subB
      openstack router set --external-gateway public routerB

      # Start up a VM in the privateA subnet.
      PRIVATE_NET=`openstack network show private -c id -f value`
      openstack server create --flavor 1 --image cirros-0.3.5-x86_64-uec \
          --nic net-id=$PRIVATE_NET peter

      # Start up a VM in the privateB subnet
      PRIVATE_NETB=`openstack network show privateB -c id -f value`
      openstack server create --flavor 1 --image cirros-0.3.5-x86_64-uec \
          --nic net-id=$PRIVATE_NETB paul

At this point, you can verify that you have basic connectivity.

.. note::

   DevStack will create a static route that will allow you to ping the private interface IP of
   router1 from privateB network. You can remove the route, if desired.

IPsec Site-to-site Connection Creation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following commands will create the IPsec connection:

.. code-block:: none

      # Create VPN connections
      openstack vpn ike policy create ikepolicy
      openstack vpn ipsec policy create ipsecpolicy
      openstack vpn service create --router router1 \
          --description "My vpn service" myvpn
      openstack vpn endpoint group create --type subnet --value privateA my-localsA
      openstack vpn endpoint group create --type cidr --value 10.2.0.0/24 my-peersA
      openstack vpn ipsec site connection create --vpnservice myvpn \
          --ikepolicy ikepolicy --ipsecpolicy ipsecpolicy \
          --peer-address 172.24.4.13 --peer-id 172.24.4.13 \
          --local-endpoint-group my-localsA --peer-endpoint-group my-peersA \
          --psk secret vpnconnection1

      openstack vpn service create --router routerB \
          --description "My vpn serviceB" myvpnB
      openstack vpn endpoint group create --type subnet --value subB my-localsB
      openstack vpn endpoint group create --type cidr --value 10.1.0.0/24 my-peersB
      openstack vpn ipsec site connection create --vpnservice myvpnB \
          --ikepolicy ikepolicy --ipsecpolicy ipsecpolicy \
          --peer-address 172.24.4.11 --peer-id 172.24.4.11 \
          --local-endpoint-group my-localsB --peer-endpoint-group my-peersB \
          --psk secret vpnconnection2

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
      openstack vpn ike policy create ikepolicy
      openstack vpn ipsec policy create ipsecpolicy
      openstack vpn service create --router router1 \
          --description "My vpn service" myvpnC

To prepare for an IPsec site-to-site, one would create an endpoint group for
the local subnets, and an endpoint group for the peer CIDRs, like so:

.. code-block:: none

      openstack vpn endpoint group create --type subnet --value privateA --value privateA2 my-locals
      openstack vpn endpoint group create --type cidr --value 10.2.0.0/24 --value 20.2.0.0/24 my-peers

where privateA and privateA2 are two local (private) subnets, and 10.2.0.0/24 and 20.2.0.0/24
are two CIDRs representing peer (private) subnets that will be used by a connection.
Then, when creating the IPsec site-to-site connection, these endpoint group IDs would
be specified, instead of the peer-cidrs attribute:

.. code-block:: none

      openstack vpn ipsec site connection create --vpnservice myvpnC \
          --ikepolicy ikepolicy --ipsecpolicy ipsecpolicy \
          --peer-address 172.24.4.11 --peer-id 172.24.4.11 \
          --local-endpoint-group my-locals --peer-endpoint-group my-peers \
          --psk secret vpnconnection3

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
