# Copyright 2014 OpenStack Foundation.
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

from neutron.services import provider_configuration as provconfig
from neutron_lib.exceptions import vpn as vpn_exception
from oslo_log import log as logging
from oslo_utils import importutils

LOG = logging.getLogger(__name__)

DEVICE_DRIVERS = 'device_drivers'


class VPNService(object):
    """VPN Service observer."""

    def __init__(self, l3_agent):
        self.conf = l3_agent.conf

    def load_device_drivers(self, host):
        """Loads one or more device drivers for VPNaaS."""
        drivers = []
        for device_driver in self.conf.vpnagent.vpn_device_driver:
            device_driver = provconfig.get_provider_driver_class(
                device_driver, DEVICE_DRIVERS)
            try:
                drivers.append(importutils.import_object(device_driver,
                                                         self,
                                                         host))
                LOG.debug('Loaded VPNaaS device driver: %s', device_driver)
            except ImportError:
                raise vpn_exception.DeviceDriverImportError(
                    device_driver=device_driver)
        return drivers
