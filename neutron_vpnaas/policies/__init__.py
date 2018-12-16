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

import itertools

from neutron_vpnaas.policies import endpoint_group
from neutron_vpnaas.policies import ike_policy
from neutron_vpnaas.policies import ipsec_policy
from neutron_vpnaas.policies import ipsec_site_connection
from neutron_vpnaas.policies import vpnservice


def list_rules():
    return itertools.chain(
        endpoint_group.list_rules(),
        ike_policy.list_rules(),
        ipsec_policy.list_rules(),
        ipsec_site_connection.list_rules(),
        vpnservice.list_rules(),
    )
