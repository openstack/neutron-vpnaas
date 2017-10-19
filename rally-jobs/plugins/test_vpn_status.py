# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from rally.common import logging
from rally.task import scenario
from rally.task import types

import vpn_base

LOG = logging.getLogger(__name__)


class TestVpnStatusScenario(vpn_base.VpnBase):
    @types.convert(image={"type": "glance_image"},
                   flavor={"type": "nova_flavor"})
    @scenario.configure()
    def check_vpn_status(self, **kwargs):
        """Test VPN's status correctly after bringing router's status to
         DOWN and back to ACTIVE state

        1. Create 2 private networks, subnets and routers
        2. Create public network, subnets and GW IPs on routers, if not present
        3. Execute ip netns command and get the snat and qrouter namespaces
           (assuming we use DVR)
        4. Verify that there is a route between the router gateways by pinging
           each other from their snat namespaces
        5. Add security group rules for SSH and ICMP
        6. Start a nova instance in each of the private networks
        7. Create IKE and IPSEC policies
        8. Create VPN service at each of the routers
        9. Create IPSEC site connections at both endpoints
        10. Bring both the private router's status to DOWN state
        11. Verify that vpn-service and ipsec-site-connection is DOWN
        12. Bring back the router's status to ACTIVE state
        13. Verify the vpn-service and ipsec-site-connection is back to ACTIVE
        14. Perform resource cleanup
        """

        try:
            self.setup(**kwargs)
            self.create_networks(**kwargs)
            self.check_route()
            self.ike_policy = self._create_ike_policy(**kwargs)
            self.ipsec_policy = self._create_ipsec_policy(**kwargs)
            self.create_vpn_services()
            self.create_ipsec_site_connections(**kwargs)
            self.assert_statuses(final_status='ACTIVE', **kwargs)
            self.update_router(self.router_ids[0], admin_state_up=False)
            self.update_router(self.router_ids[1], admin_state_up=False)
            self.assert_statuses(final_status='DOWN', **kwargs)
            self.update_router(self.router_ids[0], admin_state_up=True)
            self.update_router(self.router_ids[1], admin_state_up=True)
            self.assert_statuses(final_status='ACTIVE', **kwargs)
            LOG.info("VPN STATUS TEST PASSED!")

        finally:
            self.cleanup()
