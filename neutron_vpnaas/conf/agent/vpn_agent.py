# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# Copyright 2017, Fujitsu Limited
# Copyright 2026 OpenStack Foundation
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

from oslo_config import cfg

from neutron_vpnaas._i18n import _


vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron_vpnaas.services.vpn.device_drivers.'
                 'libreswan_ipsec.LibreSwanDriver'],
        sample_default=['neutron_vpnaas.services.vpn.device_drivers.'
                        'libreswan_ipsec.LibreSwanDriver, '
                        'neutron_vpnaas.services.vpn.device_drivers.'
                        'strongswan_ipsec.StrongSwanDriver'],
        help=_("The vpn device drivers Neutron will use")),
]


def register_vpn_agent_opts(conf=cfg.CONF):
    conf.register_opts(vpn_agent_opts, 'vpnagent')
