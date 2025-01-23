# Copyright 2025 SysEleven GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import maintenance


class VPNOVNMaintenancePeriodics:
    """Periodics to be run in the maintenance worker."""

    def __init__(self, plugin, ovn_client):
        self._plugin = plugin
        self._idl = ovn_client._nb_idl.idl

    @property
    def has_lock(self):
        return self._idl.has_lock

    @maintenance.has_lock_periodic(
            spacing=max(cfg.CONF.agent_down_time // 2, 1),
            run_immediately=False)
    def check_vpn_agents(self):
        self._plugin.reschedule_vpnservices_from_down_agents()
