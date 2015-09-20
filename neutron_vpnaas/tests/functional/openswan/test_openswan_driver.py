# Copyright (c) 2015 Cisco Systems, Inc.
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

# NOTE: The purpose of this module is to provide nop tests to verify that
# the functional gate is working.

# TODO(pcm): In the future, repurpose this module for use in a "real"
# functional test for the OpenSwan reference implementation. For now, just
# ignore the test cases herein.

import mock
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils

from neutron_vpnaas.tests.functional.common import test_scenario


class TestOpenSwanDeviceDriver(test_scenario.TestIPSecBase):

    """Test the OpenSwan reference implementation of the device driver."""

    # NOTE: Tests may be added/removed/changed, when this is fleshed out
    # in future commits.

    def _ping_mtu(self, namespace, ip, size):
        """Pings ip address using packets of given size and with DF=1.

        In order to ping it uses following cli command:
            ip netns exec <namespace> ping -c 4 -M do -s <size> <ip>
        """
        try:
            cmd = ['ping', '-c', 4, '-M', 'do', '-s', size, ip]
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            linux_utils.execute(cmd, run_as_root=True)
            return True
        except RuntimeError:
            return False

    def test_config_files_created_on_ipsec_connection_create(self):
        """Verify that directory and config files are correct on create."""
        pass

    def test_config_files_removed_on_ipsec_connection_delete(self):
        """Verify that directory and config files removed on delete."""
        pass

    def test_process_created_on_ipsec_connection_create(self):
        """Check that pluto process is running."""
        pass

    def test_connection_status_with_one_side_of_ipsec_connection(self):
        """Check status of connection, with only one end created.

        Expect that the status will indicate that the connection is down.
        """
        pass

    def test_process_gone_on_ipsec_connection_delete(self):
        """Verify that there is no longer a process, upon deletion."""
        pass

    def test_nat_rule_update(self):
        """Check NAT rule when create and then delete connection."""
        pass

    def test_cached_status_on_create_and_delete(self):
        """Test that the status is cached."""
        pass

    def test_status_reporting(self):
        """Test status reported correctly to agent."""
        pass

    def test_ipsec_site_connections_mtu_enforcement(self):
        """Test that mtu of ipsec site connections is enforced."""

        # Set up non-default mtu value
        self.fake_ipsec_connection['mtu'] = 1200

        # Establish an ipsec connection between two sites
        site1, site2 = self._create_ipsec_site_connection()

        self.driver.sync(mock.Mock(), [{'id': site1['router'].router_id},
                                       {'id': site2['router'].router_id}])
        self.addCleanup(
            self.driver._delete_vpn_processes,
            [site1['router'].router_id, site2['router'].router_id], [])

        # Validate that ip packets with 1172 (1200) bytes of data pass
        self.assertTrue(self._ping_mtu(site1['port_namespace'],
                                       site2['port_ip'], 1172))
        self.assertTrue(self._ping_mtu(site2['port_namespace'],
                                       site1['port_ip'], 1172))

        # Validate that ip packets with 1173 (1201) bytes of data are dropped
        self.assertFalse(self._ping_mtu(site1['port_namespace'],
                                        site2['port_ip'], 1173))
        self.assertFalse(self._ping_mtu(site2['port_namespace'],
                                        site1['port_ip'], 1173))
