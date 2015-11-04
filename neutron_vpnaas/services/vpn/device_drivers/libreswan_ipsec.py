# Copyright (c) 2015 Red Hat, Inc.
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
import os.path

from neutron_vpnaas.services.vpn.device_drivers import ipsec


class LibreSwanProcess(ipsec.OpenSwanProcess):
    """Libreswan Process manager class.

    Libreswan needs nssdb initialised before running pluto daemon.
    """
    def __init__(self, conf, process_id, vpnservice, namespace):
        super(LibreSwanProcess, self).__init__(conf, process_id,
                                              vpnservice, namespace)

    def ensure_configs(self):
        """Generate config files which are needed for Libreswan.

        Initialise the nssdb, otherwise pluto daemon will fail to run.
        """

        # Since we set ipsec.secrets to be owned by root, the standard
        # mechanisms for setting up the config files will get a permission
        # problem when attempting to overwrite the file, so we need to
        # remove it first.
        secrets_file = self._get_config_filename('ipsec.secrets')
        if os.path.exists(secrets_file):
            os.remove(secrets_file)

        super(LibreSwanProcess, self).ensure_configs()

        # LibreSwan uses the capabilities library to restrict access to
        # ipsec.secrets to users that have explicit access. Since pluto is
        # running as root and the file has 0600 perms, we must set the
        # owner of the file to root.
        self._execute(['chown', '--from=%s' % os.getuid(), 'root:root',
                       secrets_file])

        # Load the ipsec kernel module if not loaded
        self._execute([self.binary, '_stackmanager', 'start'])
        # checknss creates nssdb only if it is missing
        # It is added in Libreswan version v3.10
        # For prior versions use initnss
        try:
            self._execute([self.binary, 'checknss', self.etc_dir])
        except RuntimeError:
            self._execute([self.binary, 'initnss', self.etc_dir])


class LibreSwanDriver(ipsec.IPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return LibreSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
