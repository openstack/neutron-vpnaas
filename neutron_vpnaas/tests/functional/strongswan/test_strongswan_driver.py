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

# NOTE: The purpose of this module is to provide a nop test to verify that
# the functional gate is working for the StrongSwan device driver.

# TODO(pcm): In the future, this module will be replace, in whole, with
# actual StrongSwan driver test cases.


from neutron.tests.functional.agent.linux import base


class TestStrongSwanDeviceDriver(base.BaseLinuxTestCase):

    """Test the StrongSwan reference implmentation of the device driver."""

    def test_dummy(self):
        """Placeholder test for verifying the functional job."""
        pass
