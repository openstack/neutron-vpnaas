# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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


ipsec_opts = [
    cfg.StrOpt(
        'config_base_dir',
        default='$state_path/ipsec',
        help=_('Location to store ipsec server config files')),
    cfg.IntOpt('ipsec_status_check_interval',
               default=60,
               help=_("Interval for checking ipsec status")),
    cfg.BoolOpt('enable_detailed_logging',
                default=False,
                help=_("Enable detail logging for ipsec pluto process. "
                       "If the flag set to True, the detailed logging will "
                       "be written into config_base_dir/<pid>/log. "
                       "Note: This setting applies to LibreSwan "
                       "only. StrongSwan logs to syslog.")),
]

pluto_opts = [
    cfg.IntOpt('shutdown_check_timeout',
               default=1,
               help=_('Initial interval in seconds for checking if pluto '
                      'daemon is shutdown'),
               deprecated_group='libreswan'),
    cfg.IntOpt('shutdown_check_retries',
               default=5,
               help=_('The maximum number of retries for checking for '
                      'pluto daemon shutdown'),
               deprecated_group='libreswan'),
    cfg.FloatOpt('shutdown_check_back_off',
                 default=1.5,
                 help=_('A factor to increase the retry interval for '
                        'each retry'),
                 deprecated_group='libreswan'),
    cfg.BoolOpt('restart_check_config',
                default=False,
                help=_('Enable this flag to avoid from unnecessary restart'),
                deprecated_group='libreswan')
]


def register_ipsec_opts(conf=cfg.CONF):
    conf.register_opts(ipsec_opts, 'ipsec')


def register_pluto_opts(conf=cfg.CONF):
    conf.register_opts(pluto_opts, 'pluto')
