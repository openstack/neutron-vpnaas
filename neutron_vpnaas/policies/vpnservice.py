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

from oslo_policy import policy

from neutron_vpnaas.policies import base


rules = [
    policy.DocumentedRuleDefault(
        'create_vpnservice',
        base.RULE_ANY,
        'Create a VPN service',
        [
            {
                'method': 'POST',
                'path': '/vpn/vpnservices',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_vpnservice',
        base.RULE_ADMIN_OR_OWNER,
        'Update a VPN service',
        [
            {
                'method': 'PUT',
                'path': '/vpn/vpnservices/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_vpnservice',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a VPN service',
        [
            {
                'method': 'DELETE',
                'path': '/vpn/vpnservices/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_vpnservice',
        base.RULE_ADMIN_OR_OWNER,
        'Get VPN services',
        [
            {
                'method': 'GET',
                'path': '/vpn/vpnservices',
            },
            {
                'method': 'GET',
                'path': '/vpn/vpnservices/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
