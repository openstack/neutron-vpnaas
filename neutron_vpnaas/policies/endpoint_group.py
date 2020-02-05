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

from neutron_lib import policy as base


rules = [
    policy.DocumentedRuleDefault(
        'create_endpoint_group',
        base.RULE_ANY,
        'Create a VPN endpoint group',
        [
            {
                'method': 'POST',
                'path': '/vpn/endpoint-groups',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_endpoint_group',
        base.RULE_ADMIN_OR_OWNER,
        'Update a VPN endpoint group',
        [
            {
                'method': 'PUT',
                'path': '/vpn/endpoint-groups/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_endpoint_group',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a VPN endpoint group',
        [
            {
                'method': 'DELETE',
                'path': '/vpn/endpoint-groups/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_endpoint_group',
        base.RULE_ADMIN_OR_OWNER,
        'Get VPN endpoint groups',
        [
            {
                'method': 'GET',
                'path': '/vpn/endpoint-groups',
            },
            {
                'method': 'GET',
                'path': '/vpn/endpoint-groups/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
