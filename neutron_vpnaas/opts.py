#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services import provider_configuration

from neutron_vpnaas.db.vpn import vpn_agentschedulers_db
from neutron_vpnaas.services.vpn import agent as vpn_agent
from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import libreswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec
from neutron_vpnaas.services.vpn import ovn_agent


def list_agent_opts():
    return [
        ('vpnagent', vpn_agent.vpn_agent_opts),
        ('ipsec', ipsec.ipsec_opts),
        ('libreswan', libreswan_ipsec.libreswan_opts),
        ('strongswan', strongswan_ipsec.strongswan_opts),
        ('pluto', ipsec.pluto_opts)
    ]


def list_ovn_agent_opts():
    return [
        ('vpnagent', vpn_agent.vpn_agent_opts),
        ('ovs', ovn_agent.OVS_OPTS),
        ('ovn', ovn_conf.ovn_opts),
        ('ipsec', ipsec.ipsec_opts),
        ('libreswan', libreswan_ipsec.libreswan_opts),
        ('strongswan', strongswan_ipsec.strongswan_opts),
        ('pluto', ipsec.pluto_opts)
    ]


def list_opts():
    return [
        ('service_providers', provider_configuration.serviceprovider_opts),
        ('', vpn_agentschedulers_db.VPN_AGENTS_SCHEDULER_OPTS)
    ]
