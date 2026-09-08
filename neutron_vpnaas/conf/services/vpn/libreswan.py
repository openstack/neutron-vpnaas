# Copyright (c) 2015 Red Hat, Inc.
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

libreswan_opts = [
    cfg.StrOpt(
        'ipsec_config_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/libreswan/ipsec.conf.template'),
        help=_('Template file for ipsec configuration')),
    cfg.StrOpt(
        'ipsec_secret_template',
        default=os.path.join(
            _TEMPLATE_PATH,
            'template/libreswan/ipsec.secret.template'),
        help=_('Template file for ipsec secret configuration'))
]


def register_libreswan_opts(conf=cfg.CONF):
    conf.register_opts(libreswan_opts, 'libreswan')
