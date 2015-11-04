# Copyright (c) 2015 IBM, Inc.
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

from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec

TEMPLATE_PATH = os.path.dirname(os.path.abspath(__file__))

cfg.CONF.set_default(name='default_config_area',
                     default=os.path.join(
                         TEMPLATE_PATH,
                         '/usr/share/strongswan/templates/'
                         'config/strongswan.d'),
                     group='strongswan')


class FedoraStrongSwanProcess(strongswan_ipsec.StrongSwanProcess):

    binary = 'strongswan'
    CONFIG_DIRS = [
        'var/run',
        'log',
        'etc',
        'etc/strongswan/ipsec.d/aacerts',
        'etc/strongswan/ipsec.d/acerts',
        'etc/strongswan/ipsec.d/cacerts',
        'etc/strongswan/ipsec.d/certs',
        'etc/strongswan/ipsec.d/crls',
        'etc/strongswan/ipsec.d/ocspcerts',
        'etc/strongswan/ipsec.d/policies',
        'etc/strongswan/ipsec.d/private',
        'etc/strongswan/ipsec.d/reqs',
        'etc/pki/nssdb/'
    ]
    STATUS_NOT_RUNNING_RE = ('Command:.*[ipsec|strongswan].*status.*'
                             'Exit code: [1|3] ')

    def __init__(self, conf, process_id, vpnservice, namespace):
        super(FedoraStrongSwanProcess, self).__init__(conf, process_id,
                                                      vpnservice, namespace)

    def ensure_configs(self):
        """Generate config files which are needed for StrongSwan.

        If there is no directory, this function will create
        dirs.
        """
        self.ensure_config_dir(self.vpnservice)
        self.ensure_config_file(
            'ipsec.conf',
            cfg.CONF.strongswan.ipsec_config_template,
            self.vpnservice)
        self.ensure_config_file(
            'strongswan.conf',
            cfg.CONF.strongswan.strongswan_config_template,
            self.vpnservice)
        self.ensure_config_file(
            'ipsec.secrets',
            cfg.CONF.strongswan.ipsec_secret_template,
            self.vpnservice,
            0o600)
        self.copy_and_overwrite(cfg.CONF.strongswan.default_config_area,
                                self._get_config_filename('strongswan.d'))
        # Fedora uses /usr/share/strongswan/templates/config/ as strongswan
        # template directory. But /usr/share/strongswan/templates/config/
        # strongswan.d does not include charon. Those configuration files
        # are in /usr/share/strongswan/templates/config/plugins directory.
        charon_dir = os.path.join(
            cfg.CONF.strongswan.default_config_area,
            'charon')
        if not os.path.exists(charon_dir):
            plugins_dir = os.path.join(
                cfg.CONF.strongswan.default_config_area, '../plugins')
            self.copy_and_overwrite(
                plugins_dir,
                self._get_config_filename('strongswan.d/charon'))

    def _get_config_filename(self, kind):
        config_dir = '%s/strongswan' % self.etc_dir
        return os.path.join(config_dir, kind)


class FedoraStrongSwanDriver(ipsec.IPsecDriver):

    def create_process(self, process_id, vpnservice, namespace):
        return FedoraStrongSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
