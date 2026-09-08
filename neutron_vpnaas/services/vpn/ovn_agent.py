# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# Copyright 2023, SysEleven GmbH
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
import sys

from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from neutron_vpnaas.agent.ovn.vpn import agent
from neutron_vpnaas.conf.agent import ovn_agent as ovn_agent_conf

LOG = logging.getLogger(__name__)

VPN_AGENT_OPTS = ovn_agent_conf.VPN_AGENT_OPTS
OVS_OPTS = ovn_agent_conf.OVS_OPTS


def register_opts(conf):
    common_config.register_common_config_options()
    agent_config.register_interface_driver_opts_helper(conf)
    agent_config.register_interface_opts(conf)
    agent_config.register_availability_zone_opts_helper(conf)
    ovn_conf.register_opts()
    ovn_agent_conf.register_ovn_vpn_agent_opts(conf)


def main():
    register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    agent_config.setup_logging()
    agent_config.setup_privsep()

    agt = agent.OvnVpnAgent(cfg.CONF)
    service.launch(cfg.CONF, agt, restart_method='mutate').wait()
