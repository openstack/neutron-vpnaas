# Copyright 2015 Cisco Systems, Inc.
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

from neutron_lib import constants

# Endpoint group types
SUBNET_ENDPOINT = 'subnet'
CIDR_ENDPOINT = 'cidr'
VLAN_ENDPOINT = 'vlan'
NETWORK_ENDPOINT = 'network'
ROUTER_ENDPOINT = 'router'

# NOTE: Type usage...
# IPSec local endpoints - subnet, IPSec peer endpoints - cidr
# BGP VPN local endpoints - network
# Direct connect style endpoints - vlan
# IMPORTANT: The ordering of these is important, as it is used in an enum
# for the database (and migration script). Only add to this list.
VPN_SUPPORTED_ENDPOINT_TYPES = [
    SUBNET_ENDPOINT, CIDR_ENDPOINT, VLAN_ENDPOINT,
    NETWORK_ENDPOINT, ROUTER_ENDPOINT,
]

AGENT_TYPE_VPN = "VPN Agent"

DEVICE_OWNER_VPN_ROUTER_GW = constants.DEVICE_OWNER_NETWORK_PREFIX + \
                             "vpn_router_gateway"

DEVICE_OWNER_TRANSIT_NETWORK = constants.DEVICE_OWNER_NETWORK_PREFIX + \
                               "vpn_namespace"

OVN_AGENT_VPN_SB_CFG_KEY = 'neutron:ovn-vpnagent-sb-cfg'
OVN_AGENT_VPN_DESC_KEY = 'neutron:description-vpnagent'
OVN_AGENT_VPN_ID_KEY = 'neutron:ovn-vpnagent-id'
