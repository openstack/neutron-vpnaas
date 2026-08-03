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

from unittest import mock

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from oslo_config import cfg

from neutron_vpnaas.services.vpn import agent as vpn_agent
from neutron_vpnaas.services.vpn.device_drivers import libreswan_ipsec
from neutron_vpnaas.tests.functional.common import test_scenario

VPNAAS_LIBRESWAN_DEVICE = ('neutron_vpnaas.services.vpn.'
                           'device_drivers.libreswan_ipsec.'
                           'LibreSwanDriver')


class TestLibreSwanDeviceDriver(test_scenario.TestIPSecBase):

    """Test the LibreSwan implementation of the device driver."""

    def setUp(self):
        super().setUp()
        self.conf.set_override('vpn_device_driver',
                               [VPNAAS_LIBRESWAN_DEVICE],
                               'vpnagent')
        self.vpn_agent = vpn_agent.L3WithVPNaaS(self.conf)
        self.driver = self.vpn_agent.device_drivers[0]
        self.driver.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[])
        self.driver.report_status = mock.Mock()

    def _ping_mtu(self, from_site, to_site, size, instance=0):
        """Pings ip address using packets of given size and with DF=1.

        In order to ping it uses following cli command:
            ip netns exec <namespace> ping -c 4 -M do -s <size> <ip>
        """
        namespace = from_site.vm[instance].namespace
        ip = to_site.vm[instance].port_ip
        try:
            cmd = ['ping', '-c', 4, '-M', 'do', '-s', size, ip]
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            linux_utils.execute(cmd, run_as_root=True)
            return True
        except RuntimeError:
            return False

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

    def test_cached_status_on_create_and_delete(self):
        """Test that the status is cached."""
        pass

    def test_status_reporting(self):
        """Test status reported correctly to agent."""
        pass

    def _override_mtu_for_site(self, site, mtu):
        ipsec_connection = site.vpn_service['ipsec_site_connections'][0]
        ipsec_connection['mtu'] = mtu

    def test_ipsec_site_connections_mtu_enforcement(self):
        """Test that mtu of ipsec site connections is enforced."""
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                                 [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                                 [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._override_mtu_for_site(site1, 1200)
        self._override_mtu_for_site(site2, 1200)

        self.sync_to_create_ipsec_connections(site1, site2)

        self.assertTrue(self._ping_mtu(site1, site2, 1172))
        self.assertTrue(self._ping_mtu(site2, site1, 1172))

        self.assertFalse(self._ping_mtu(site1, site2, 1173))
        self.assertFalse(self._ping_mtu(site2, site1, 1173))

    def test_no_config_change_skip_restart(self):
        """Test when config is not changed, then restart should be skipped"""
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                                 [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                                 [self.private_nets[2]])

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

        with mock.patch.object(
                libreswan_ipsec.LibreSwanProcess, 'start') as my_start:

            libreswan_ipsec.LibreSwanProcess.active = mock.patch.object(
                libreswan_ipsec.LibreSwanProcess,
                'active', return_value=True).start()
            libreswan_ipsec.LibreSwanProcess._config_changed = (
                mock.patch.object(
                    libreswan_ipsec.LibreSwanProcess,
                    '_config_changed', return_value=False).start())

            self.sync_to_create_ipsec_connections(site1, site2)
            self.assertEqual(1, my_start.call_count)
            my_start.reset_mock()

            cfg.CONF.set_override('restart_check_config', True,
                                  group='pluto')
            self.sync_to_create_ipsec_connections(site1, site2)
            my_start.assert_not_called()

            libreswan_ipsec.LibreSwanProcess.active.stop()
            libreswan_ipsec.LibreSwanProcess._config_changed.stop()
            cfg.CONF.set_override('restart_check_config', False,
                                  group='pluto')

    def test_libreswan_connection_with_non_ascii_vpnservice_name(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                                 [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                                 [self.private_nets[2]])
        site1.vpn_service.update(
            {'name': test_scenario.NON_ASCII_VPNSERVICE_NAME})

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    def test_libreswan_connection_with_non_ascii_psk(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                                 [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                                 [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._update_ipsec_connection(site1, psk=test_scenario.NON_ASCII_PSK)
        self._update_ipsec_connection(site2, psk=test_scenario.NON_ASCII_PSK)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    def test_libreswan_connection_with_wrong_non_ascii_psk(self):
        site1 = self.create_site(test_scenario.PUBLIC_NET[4],
                                 [self.private_nets[1]])
        site2 = self.create_site(test_scenario.PUBLIC_NET[5],
                                 [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self._update_ipsec_connection(site1, psk=test_scenario.NON_ASCII_PSK)
        self._update_ipsec_connection(site2,
                                      psk=test_scenario.NON_ASCII_PSK[:-1])
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)
