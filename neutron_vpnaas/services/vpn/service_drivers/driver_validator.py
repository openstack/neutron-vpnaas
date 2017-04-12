# Copyright 2017 Eayun, Inc.
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
#


class VpnDriverValidator(object):
    """Driver-specific validation routines for VPN resources."""

    def __init__(self, driver):
        self.driver = driver

    @property
    def l3_plugin(self):
        return self.driver.l3_plugin

    def validate_ipsec_site_connection(self, context, ipsec_sitecon):
        """Driver can override this for its additional validations."""
        pass
