=================================
Multiple Local Subnets for VPNaaS
=================================

As originally implemented, an VPN IPSec connection could have one or more
peer subnets specified, but only **one** local subnet. To support multiple
local subnets, multiple IPSec connections would be needed.

With the multiple local subnet support, three goals are addressed. First,
there can be multiple local and peer endpoints for a single IPSec connection.

Second, validation enforces that the same IP version is used for all
endpoints (to reduce complexity and ease testing).

Third, the "what is connected" is separated from the "how to connect",
so that other flavors of VPN (as they are developed) can use some of this
mechanism.


Design Notes
------------

There were three proposals considered, to support multiple local subnets.

Proposal A was to just add the local subnets to the IPSec connection API.
That would be the quickest way, and addresses the first two goals, but
not the third.

Proposal B was to create a new API that specifies of the local subnets
and peer CIDRs, and reference those in the connection API. This would
separate the "what is connected" from the "how to connect", and again
addresses the first two goals (only).

Proposal C, which was the *selected proposal*, creates a new API
that represents the "endpoint groups" for VPN connections, in the same
manner as proposal B. The added flexibility here, though, which meets
goal three, is to also include the endpoint group "type", thus allowing
subnets (local) and CIDRs (peer) to be used for IPSec, but routers,
networks, and VLANs to be used for other VPN types (BGP, L2, direct
connection). Additional types can be added in the future as needed.


Client CLI API
--------------

The originally implemented client CLI APIs (which are still available
for backward compatibility) for an IPsec connection are:

.. code-block:: none

    openstack vpn service create --router ROUTER --subnet SUBNET NAME
    openstack vpn ipsec site connection create
        --vpnservice VPNSERVICE
        --ikepolicy IKEPOLICY
        --ipsecpolicy IPSECPOLICY
        --peer-address PEER_ADDRESS
        --peer-id PEER_ID
        --peer-cidr PEER_CIDRS
        --dpd action=ACTION,interval=INTERVAL,timeout=TIMEOUT
        --initiator {bi-directional | response-only}
        --mtu MTU
        --psk PSK
        VPN_IPSEC_SITE_CONNECTION_NAME

Changes to the API, to support multiple local subnets, are shown in
**highlighted** text:

.. code-block:: none
   :emphasize-lines: 2-6,17-18

    openstack vpn service create --router ROUTER NAME
    openstack vpn endpoint group create
        --description OPTIONAL-DESCRIPTION
        --type={subnet,cidr,network,vlan,router}
        --value=ENDPOINT-OF-TYPE[,--value=ENDPOINT-OF-TYPE,...]
        ENDPOINT-GROUP-NAME
    openstack vpn ipsec site connection create
        --vpnservice VPNSERVICE
        --ikepolicy IKEPOLICY
        --ipsecpolicy IPSECPOLICY
        --peer-address PEER_ADDRESS
        --peer-id PEER_ID
        --dpd action=ACTION,interval=INTERVAL,timeout=TIMEOUT
        --initiator {bi-directional | response-only}
        --mtu MTU
        --psk PSK
        --local-endpoint-group ENDPOINT-GROUP-UUID
        --peer-endpoint-group ENDPOINT-GROUP-UUID
        VPN_IPSEC_SITE_CONNECTION_NAME

The SUBNET in the original service API is optional, and will be used as an
indicator of whether or not the multiple local subnets feature is active.
See the 'Backward Compatibility' section, below, for details.

For the endpoint groups, the ``--type`` value is a string, so that other
types can be supported in the future.

The endpoint groups API would enforce that the endpoint values are all of
the same type, and match the endpoint type specified.

The connection APIs, would then provide additional validation. For example,
with IPSec, the endpoint type must be 'subnet' for local, and 'cidr' for
peer, all the endpoints should be of the same IP version, and for the local
endpoint, all subnets would be on the same router.

For BGP VPN with dynamic routing, only a local endpoint group would be
specified, and the type would be 'network'.

The ROUTER may also be able to be removed, in the future, and can be
determined, when the connections are created.


Examples
--------

The original APIs to create one side of an IPSec connection with
only one local and peer subnet:

.. code-block:: none

    openstack vpn ike policy create ikepolicy
    openstack vpn ipsec policy create ipsecpolicy
    openstack vpn service create --router router1 --subnet privateA myvpn
    openstack vpn ipsec site connection create
        --vpnservice myvpn
        --ikepolicy ikepolicy
        --ipsecpolicy ipsecpolicy
        --peer-address 172.24.4.13
        --peer-id 172.24.4.13
        --peer-cidr 10.3.0.0/24
        --psk secret
        vpnconnection1

The local CIDR is obtained from the subnet, privateA. In this example,
that would be 10.1.0.0/24 (because that's how privateA was created).

Using the multiple local subnet feature, the APIs (with changes shown
in **highlighted** below:

.. code-block:: none
   :emphasize-lines: 4-12,20-21

    openstack vpn ike policy create ikepolicy
    openstack vpn ipsec policy create ipsecpolicy
    openstack vpn service create --router router1 myvpn
    openstack vpn endpoint group create
        --type=subnet
        --value=privateA
        --value=privateB
        local-eps
    openstack vpn endpoint group create
        --type=cidr
        --value=10.3.0.0/24
        peer-eps
    openstack vpn ipsec site connection create
        --vpnservice myvpn
        --ikepolicy ikepolicy
        --ipsecpolicy ipsecpolicy
        --peer-address 172.24.4.13
        --peer-id 172.24.4.13
        --psk secret
        --local-endpoint-group local-eps
        --peer-endpoint-group peer-eps
        vpnconnection1

The subnets privateA and privateB are used for local endpoints and the
10.3.0.0/24 CIDR is used for the peer endpoint.


Database
--------

The vpn_endpoints table contains single endpoint entries and a reference
to the containing endpoint group. The vpn_endpoint_groups table defines
the group, specifying the endpoint type.


Database Migration
------------------

For an older database, the first subnet, in the subnet entry of the
service table can be placed in an endpoint group that will be used
for the local endpoints of the connection. The CIDRs from the connection
can be placed into another endpoint group for the peer endpoints.


Backwards Compatibility
-----------------------

Operators would like to see this new capability provided, with backward
compatibility support. The implication, as I see it, is to provide the
ability for end users to be able to switch to the new API at any time,
versus being forced to use the new API immediately, upon upgrade to the
new release containing this feature. This would apply to both manual
API use, and client apps/scripting-tools that would be used to configure
VPNaaS.

There are several attributes that are involve here. One is the subnet ID
attribute in the VPN service API. The other is the peer CIDR attribute in
the IPSec connection API. Both would be specified by endpoint groups in
the new API, and these groups would be called out in the IPSec connection
API.

A plan to meet the backward compatibility goal of allowing both APIs to
be used at once involves taking the following steps.

For VPN service:

- Make the subnet ID attribute optional.
- If subnet ID is specified for create, consider old API mode.
- If subnet ID specified for create, create endpoint group and store ID.
- For delete, if subnet ID exists, delete corresponding endpoint group.
- For show/list, if subnet ID exists, show the ID in output.
- Subnet ID is not mutable, so no change for update API.


For IPSec site to site connection:

- For create, if old API mode, only allow peer-cidr attribute.
- For create, if not old API mode, require local/peer endpoint group IDs attributes.
- For create, if peer-cidr specified, create endpoint group and store ID.
- For create, reject endpoint group ID attributes, if old API mode.
- For create, reject peer-cidr attribute, if not old API mode.
- For create, if old API mode, lookup subnet in service, find containing endpoint group ID and store.
- For delete, if old API mode, delete endpoint group for peer.
- For update of CIDRs (old mode), will delete endpoint group and create new one. (note 1)
- For update of endpoint-group IDs (new mode), will allow different groups to be specified. (note 1,2)
- For show/list, if old API mode, only display the peer CIDR values from peer endpoint group.
- For show/list, if not old API mode, also show local subnets from local endpoint group.

Note 1: Implication is that connection is torn down and re-created (as is
done currently).

Note 2: Users would create a new endpoint group, and then select that group,
when modifying the IPSec connection.


For endpoint groups:

- For delete, if subnet, and (sole) subnet ID is used in a VPN service (old mode), reject request.
- Updates are not supported, so no action required. (note 2)

Note 2: Allowing updates would require deletion/recreation of connection
using endpoint group. Avoiding that complexity.


The thought here is to use endpoint groups under the hood, but if the old
API was being used, treat the endpoint groups as if they never existed.
Deleting connections and services would remove any endpoint groups, unlike
with the new API, where they are independent.

Migration can be used to move any VPNaaS configurations using the old
schema to the new schema. This would look at VPN services and for any
with a subnet ID, an endpoint group would be created and the group ID
stored in any existing IPSec connections for that service. Likewise,
any peer CIDRs in a connection would be copied into a new endpoint group
and the group ID stored in the connection.

The subnet ID field would then be removed from the VPN service table,
and the peer CIDRs table would be removed.

This migration could be done at the time of the new API release, in which
case all tenants with existing VPNaaS configurations would use the new
API to manage them (but could use old for new configurations).

Alternatively, the migration could be deferred until the old API is
removed, to ensure all existing configurations conform to the new schema.
Migration tools can then be created to manually migrate individual
tenants, as desired.


Stories
-------

For the endpoint groups, stories can cover:

- CRUD API for the endpoint groups.
- Database support for new tables.
- Migration creation of new tables.
- Validation of endpoints for a group (same type).
- Neutron client support for new API.
- Horizon support for new API.
- API documentation update.

For the multiple local subnets, stories can cover:

- create IPsec connection with one local subnet, but using new API.
- create IPSec connection with multiple local subnets.
- Show IPSec connection to display endpoint group IDs (or endpoints?).
- Ensure previous API still works, but uses new tables.
- Validation to ensure old and new APIs are not mixed.
- Modify CLI client.
- Validate multiple local subnets on same router.
- Validate local and peer endpoints are of same IP version.
- Functional tests with multiple local subnets
- API and How-To documentation update

Note: The intent here is to have the initial stories take slices
vertically through the process so that we can demonstrate the
capability early.

Note: Horizon work to support the changes is not expected to be part
of this effort and would be handled by the Horizon team separately,
if support is desired.
