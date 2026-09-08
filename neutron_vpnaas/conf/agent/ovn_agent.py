# Copyright 2023, SysEleven GmbH
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


VPN_AGENT_OPTS = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron_vpnaas.services.vpn.device_drivers.'
                 'ovn_ipsec.OvnStrongSwanDriver'],
        sample_default=['neutron_vpnaas.services.vpn.device_drivers.'
                        'ovn_ipsec.OvnStrongSwanDriver'],
        help=_("The OVN VPN device drivers Neutron will use")),
]

OVS_OPTS = [
    cfg.StrOpt('ovsdb_connection',
               default='unix:/usr/local/var/run/openvswitch/db.sock',
               regex=r'^(tcp|ssl|unix):.+',
               help=_('The connection string for the native OVSDB backend.\n'
                      'Use tcp:IP:PORT for TCP connection.\n'
                      'Use unix:FILE for unix domain socket connection.')),
    cfg.IntOpt('ovsdb_connection_timeout',
               default=180,
               help=_('Timeout in seconds for the OVSDB '
                      'connection transaction'))
]


def register_ovn_vpn_agent_opts(conf=cfg.CONF):
    conf.register_opts(VPN_AGENT_OPTS, 'vpnagent')
    conf.register_opts(OVS_OPTS, 'ovs')
