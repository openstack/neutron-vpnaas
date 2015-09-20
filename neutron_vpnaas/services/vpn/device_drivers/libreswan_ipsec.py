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

import eventlet

from neutron.i18n import _LE, _LW
from oslo_config import cfg
from oslo_log import log as logging

from neutron_vpnaas.services.vpn.device_drivers import ipsec

LOG = logging.getLogger(__name__)

libreswan_opts = [
    cfg.IntOpt('shutdown_check_timeout',
               default=1,
               help=_('Initial interval in seconds for checking if pluto '
                      'daemon is shutdown')),
    cfg.IntOpt('shutdown_check_retries',
               default=5,
               help=_('The maximum number of retries for checking for '
                      'pluto daemon shutdown')),
    cfg.FloatOpt('shutdown_check_back_off',
                 default=1.5,
                 help=_('A factor to increase the retry interval for '
                        'each retry'))
]

cfg.CONF.register_opts(libreswan_opts, 'libreswan')


class LibreSwanProcess(ipsec.OpenSwanProcess):
    """Libreswan Process manager class.

    Libreswan needs nssdb initialised before running pluto daemon.
    """
    def __init__(self, conf, process_id, vpnservice, namespace):
        super(LibreSwanProcess, self).__init__(conf, process_id,
                                              vpnservice, namespace)
        self.pid_file = '%s.pid' % self.pid_path

    def ensure_configs(self):
        """Generate config files which are needed for Libreswan.

        Initialise the nssdb, otherwise pluto daemon will fail to run.
        """
        super(LibreSwanProcess, self).ensure_configs()

        # LibreSwan uses the capabilities library to restrict access to
        # ipsec.secrets to users that have explicit access. Since pluto is
        # running as root and the file has 0600 perms, we must set the
        # owner of the file to root.
        secrets_file = self._get_config_filename('ipsec.secrets')
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

    def _process_running(self):
        """Checks if process is still running."""

        # If no PID file, we assume the process is not running.
        if not os.path.exists(self.pid_file):
            return False

        try:
            # We take an ask-forgiveness-not-permission approach and rely
            # on throwing to tell us something. If the pid file exists,
            # delve into the process information and check if it matches
            # our expected command line.
            with open(self.pid_file, 'r') as f:
                pid = f.readline().strip()
                with open('/proc/%s/cmdline' % pid) as cmd_line_file:
                    cmd_line = cmd_line_file.readline()
                    if self.pid_path in cmd_line and 'pluto' in cmd_line:
                        # Okay the process is probably a libreswan process
                        # and it contains the pid_path in the command
                        # line... could be a race. Log to error and return
                        # that it is *NOT* okay to clean up files. We are
                        # logging to error instead of debug because it
                        # indicates something bad has happened and this is
                        # valuable information for figuring it out.
                        LOG.error(_LE('Process %(pid)s exists with command '
                                  'line %(cmd_line)s.') %
                                  {'pid': pid, 'cmd_line': cmd_line})
                        return True

        except IOError as e:
            LOG.error(_LE('Unable to check control files on startup for '
                          'router %(router)s: %(msg)s'),
                      {'router': self.id, 'msg': e})
        return False

    def _cleanup_control_files(self):
        try:
            ctl_file = '%s.ctl' % self.pid_path
            LOG.debug('Removing %(pidfile)s and %(ctlfile)s',
                      {'pidfile': self.pid_file,
                       'ctlfile': '%s.ctl' % ctl_file})

            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)

            if os.path.exists(ctl_file):
                os.remove(ctl_file)

        except OSError as e:
            LOG.error(_LE('Unable to remove libreswan control '
                          'files for router %(router)s. %(msg)s'),
                      {'router': self.id, 'msg': e})

    def start(self):
        # NOTE: The restart operation calls the parent's start() instead of
        # this one to avoid having to special case the startup file check.
        # If anything is added to this method that needs to run whenever
        # a restart occurs, it should be either added to the restart()
        # override or things refactored to special-case start() when
        # called from restart().

        # LibreSwan's use of the capablities library may prevent the ctl
        # and pid files from being cleaned up, so we check to see if the
        # process is running and if not, attempt a cleanup. In either case
        # we fall through to allow the LibreSwan process to start or fail
        # in the usual way.
        if not self._process_running():
            self._cleanup_control_files()

        super(LibreSwanProcess, self).start()

    def restart(self):
        # stop() followed immediately by a start() runs the risk that the
        # current pluto daemon has not had a chance to shutdown. We check
        # the current process information to see if the daemon is still
        # running and if so, wait a short interval and retry.
        self.stop()
        wait_interval = cfg.CONF.libreswan.shutdown_check_timeout
        for i in range(cfg.CONF.libreswan.shutdown_check_retries):
            if not self._process_running():
                self._cleanup_control_files()
                break
            eventlet.sleep(wait_interval)
            wait_interval *= cfg.CONF.libreswan.shutdown_check_back_off
        else:
            LOG.warning(_LW('Server appears to still be running, restart '
                            'of router %s may fail'), self.id)

        super(LibreSwanProcess, self).start()


class LibreSwanDriver(ipsec.IPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return LibreSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
