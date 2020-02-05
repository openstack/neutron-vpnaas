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
        'create_ikepolicy',
        base.RULE_ANY,
        'Create an IKE policy',
        [
            {
                'method': 'POST',
                'path': '/vpn/ikepolicies',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_ikepolicy',
        base.RULE_ADMIN_OR_OWNER,
        'Update an IKE policy',
        [
            {
                'method': 'PUT',
                'path': '/vpn/ikepolicies/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_ikepolicy',
        base.RULE_ADMIN_OR_OWNER,
        'Delete an IKE policy',
        [
            {
                'method': 'DELETE',
                'path': '/vpn/ikepolicies/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_ikepolicy',
        base.RULE_ADMIN_OR_OWNER,
        'Get IKE policyies',
        [
            {
                'method': 'GET',
                'path': '/vpn/ikepolicies',
            },
            {
                'method': 'GET',
                'path': '/vpn/ikepolicies/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
