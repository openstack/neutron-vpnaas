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

from neutron.conf.policies import base as neutron_base
from neutron_lib import policy as base
from oslo_policy import policy

DEPRECATED_REASON = """
The VPaaS API now supports Secure RBAC default roles for endpoint groups.
"""

rules = [
    policy.DocumentedRuleDefault(
        name='create_endpoint_group',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Create a VPN endpoint group',
        operations=[
            {
                'method': 'POST',
                'path': '/vpn/endpoint-groups',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='create_endpoint_group',
            check_str=base.RULE_ANY,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    policy.DocumentedRuleDefault(
        name='update_endpoint_group',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Update a VPN endpoint group',
        operations=[
            {
                'method': 'PUT',
                'path': '/vpn/endpoint-groups/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='update_endpoint_group',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    policy.DocumentedRuleDefault(
        name='delete_endpoint_group',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Delete a VPN endpoint group',
        operations=[
            {
                'method': 'DELETE',
                'path': '/vpn/endpoint-groups/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='delete_endpoint_group',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
    policy.DocumentedRuleDefault(
        name='get_endpoint_group',
        check_str=neutron_base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description='Get VPN endpoint groups',
        operations=[
            {
                'method': 'GET',
                'path': '/vpn/endpoint-groups',
            },
            {
                'method': 'GET',
                'path': '/vpn/endpoint-groups/{id}',
            },
        ],
        deprecated_rule=policy.DeprecatedRule(
            name='get_endpoint_group',
            check_str=base.RULE_ADMIN_OR_OWNER,
            deprecated_reason=DEPRECATED_REASON,
            deprecated_since='2025.2')
    ),
]


def list_rules():
    return rules
