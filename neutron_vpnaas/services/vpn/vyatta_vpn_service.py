# Copyright 2015 Brocade Communications System, Inc.
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


from neutron_vpnaas.services.vpn import vpn_service


class VyattaVPNService(vpn_service.VPNService):
    """Vyatta VPN Service handler."""

    def __init__(self, l3_agent):
        """Creates a Vyatta VPN Service instance.

        NOTE: Directly accessing l3_agent here is an interim solution
        until we move to have a router object given down to device drivers
        to access router related methods
        """
        super(VyattaVPNService, self).__init__(l3_agent)
        self.l3_agent = l3_agent

    def get_router_client(self, router_id):
        """
        Get Router RESTapi client
        """
        return self.l3_agent.get_router_client(router_id)

    def get_router(self, router_id):
        """
        Get Router Object
        """
        return self.l3_agent.get_router(router_id)
