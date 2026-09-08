# Copyright (c) 2015 Canonical, Inc.
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

import os

from oslo_config import cfg

from neutron_vpnaas._i18n import _


_TEMPLATE_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    '../../../services/vpn/device_drivers'))

strongswan_opts = [
    cfg.StrOpt(
        'ipsec_config_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/strongswan/ipsec.conf.template'),
        help=_('Template file for ipsec configuration.')),
    cfg.StrOpt(
        'strongswan_config_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/strongswan/strongswan.conf.template'),
        help=_('Template file for strongswan configuration.')),
    cfg.StrOpt(
        'ipsec_secret_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/strongswan/ipsec.secret.template'),
        help=_('Template file for ipsec secret configuration.')),
    cfg.StrOpt(
        'default_config_area',
        default='/etc/strongswan.d',
        help=_('The area where default StrongSwan configuration '
               'files are located.')),
    cfg.BoolOpt(
        'use_swanctl',
        default=True,
        deprecated_since='2027.1',
        deprecated_reason=_('The use_swanctl option is deprecated and will be '
                            'removed in the 2027.2 release. ``swanctl`` mode '
                            'is the default behavior.'),
        help=_('Use ``swanctl`` (VICI protocol) instead of legacy stroke '
               'interface. When True, configuration files are generated in '
               '/etc/swanctl/ and charon is managed via systemd.')),
    cfg.StrOpt(
        'swanctl_config_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/swanctl/swanctl.conf.template'),
        help=_('Template file for swanctl configuration.')),
    cfg.StrOpt(
        'swanctl_secrets_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/swanctl/ipsec.secrets.template'),
        help=_('Template file for swanctl secrets configuration.')),
    cfg.StrOpt(
        'swanctl_config_dir',
        default='/etc/swanctl',
        help=_('Directory where swanctl loads its configuration from. '
               'This directory must contain swanctl.conf, connections/, '
               'secrets/.'))
]


def register_strongswan_opts(conf=cfg.CONF):
    conf.register_opts(strongswan_opts, 'strongswan')
