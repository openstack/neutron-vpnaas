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
        'create_ipsec_site_connection',
        base.RULE_ANY,
        'Create an IPsec site connection',
        [
            {
                'method': 'POST',
                'path': '/vpn/ipsec-site-connections',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_ipsec_site_connection',
        base.RULE_ADMIN_OR_OWNER,
        'Update an IPsec site connection',
        [
            {
                'method': 'PUT',
                'path': '/vpn/ipsec-site-connections/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_ipsec_site_connection',
        base.RULE_ADMIN_OR_OWNER,
        'Delete an IPsec site connection',
        [
            {
                'method': 'DELETE',
                'path': '/vpn/ipsec-site-connections/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_ipsec_site_connection',
        base.RULE_ADMIN_OR_OWNER,
        'Get IPsec site connections',
        [
            {
                'method': 'GET',
                'path': '/vpn/ipsec-site-connections',
            },
            {
                'method': 'GET',
                'path': '/vpn/ipsec-site-connections/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
