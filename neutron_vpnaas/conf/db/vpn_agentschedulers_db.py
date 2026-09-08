# Copyright (c) 2013 OpenStack Foundation.
# Copyright (c) 2023 SysEleven GmbH.
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


VPN_AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('vpn_scheduler_driver',
               default='neutron_vpnaas.scheduler.vpn_agent_scheduler'
                       '.LeastRoutersScheduler',
               help=_('Driver to use for scheduling '
                      'router to a VPN agent')),
    cfg.BoolOpt('vpn_auto_schedule', default=True,
                help=_('Allow auto scheduling of routers to VPN agent.')),
    cfg.BoolOpt('allow_automatic_vpnagent_failover', default=False,
                help=_('Automatically reschedule routers from offline VPN '
                       'agents to online VPN agents.')),
]


def register_db_vpn_agentschedulers_opts(conf=cfg.CONF):
    conf.register_opts(VPN_AGENTS_SCHEDULER_OPTS)
