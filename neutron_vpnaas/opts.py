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

import neutron.conf.plugins.ml2.drivers.ovn.ovn_conf
import neutron.services.provider_configuration

import neutron_vpnaas.services.vpn.agent
import neutron_vpnaas.services.vpn.device_drivers.ipsec
import neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec
import neutron_vpnaas.services.vpn.ovn_agent


def list_agent_opts():
    return [
        ('vpnagent',
         neutron_vpnaas.services.vpn.agent.vpn_agent_opts),
        ('ipsec',
         neutron_vpnaas.services.vpn.device_drivers.ipsec.ipsec_opts),
        ('strongswan',
         neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec.
         strongswan_opts),
        ('pluto',
         neutron_vpnaas.services.vpn.device_drivers.ipsec.pluto_opts)
    ]


def list_ovn_agent_opts():
    return [
        ('vpnagent',
         neutron_vpnaas.services.vpn.ovn_agent.VPN_AGENT_OPTS),
        ('ovs',
         neutron_vpnaas.services.vpn.ovn_agent.OVS_OPTS),
        ('ovn',
         neutron.conf.plugins.ml2.drivers.ovn.ovn_conf.ovn_opts),
        ('ipsec',
         neutron_vpnaas.services.vpn.device_drivers.ipsec.ipsec_opts),
        ('strongswan',
         neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec.
         strongswan_opts),
        ('pluto',
         neutron_vpnaas.services.vpn.device_drivers.ipsec.pluto_opts)
    ]


def list_opts():
    return [
        ('service_providers',
         neutron.services.provider_configuration.serviceprovider_opts)
    ]
