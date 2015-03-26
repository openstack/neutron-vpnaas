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

from neutron.tests.functional import base


class TestOpenSwanDeviceDriver(base.BaseSudoTestCase):

    """Test the OpenSwan reference implmentation of the device driver."""

    # NOTE: Tests may be added/removed/changed, when this is fleshed out
    # in future commits.

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
