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
import filecmp
import os
import shutil
import socket
import time

import netaddr
from neutron.agent.linux import ip_lib
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.exceptions import vpn as vpn_exception
from oslo_config import cfg
from oslo_log import log as logging

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn.device_drivers import ipsec

LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(os.path.abspath(__file__))

libreswan_opts = [
    cfg.StrOpt(
        'ipsec_config_template',
        default=os.path.join(
            TEMPLATE_PATH,
            'template/libreswan/ipsec.conf.template'),
        help=_('Template file for ipsec configuration')),
    cfg.StrOpt(
        'ipsec_secret_template',
        default=os.path.join(
            TEMPLATE_PATH,
            'template/libreswan/ipsec.secret.template'),
        help=_('Template file for ipsec secret configuration'))
]

cfg.CONF.register_opts(libreswan_opts, 'libreswan')


class LibreSwanProcess(ipsec.BaseSwanProcess):
    """Libreswan Process manager class.

    Libreswan needs nssdb initialised before running pluto daemon.
    """

    DIALECT_MAP = dict(ipsec.BaseSwanProcess.DIALECT_MAP)

    def __init__(self, conf, process_id, vpnservice, namespace):
        dialect_map_update = {
            # ENCR_AES_CTR
            'aes-128-ctr': 'aes_ctr128',
            'aes-192-ctr': 'aes_ctr192',
            'aes-256-ctr': 'aes_ctr256',
            # ENCR_AES_CCM_8
            'aes-128-ccm-8': 'aes_ccm_a128',
            'aes-192-ccm-8': 'aes_ccm_a192',
            'aes-256-ccm-8': 'aes_ccm_a256',
            # ENCR_AES_CCM_12
            'aes-128-ccm-12': 'aes_ccm_b128',
            'aes-192-ccm-12': 'aes_ccm_b192',
            'aes-256-ccm-12': 'aes_ccm_b256',
            # ENCR_AES_CCM_16
            'aes-128-ccm-16': 'aes_ccm_c128',
            'aes-192-ccm-16': 'aes_ccm_c192',
            'aes-256-ccm-16': 'aes_ccm_c256',
            # ENCR_AES_GCM_8
            'aes-128-gcm-8': 'aes_gcm_a128',
            'aes-192-gcm-8': 'aes_gcm_a192',
            'aes-256-gcm-8': 'aes_gcm_a256',
            # ENCR_AES_GCM_12
            'aes-128-gcm-12': 'aes_gcm_b128',
            'aes-192-gcm-12': 'aes_gcm_b192',
            'aes-256-gcm-12': 'aes_gcm_b256',
            # ENCR_AES_GCM_16
            'aes-128-gcm-16': 'aes_gcm_c128',
            'aes-192-gcm-16': 'aes_gcm_c192',
            'aes-256-gcm-16': 'aes_gcm_c256'
        }
        self.DIALECT_MAP.update(dialect_map_update)
        self._rootwrap_cfg = self._get_rootwrap_config()
        super().__init__(conf, process_id, vpnservice, namespace)
        self.secrets_file = os.path.join(self.etc_dir, 'ipsec.secrets')
        self.config_file = os.path.join(self.etc_dir, 'ipsec.conf')
        self.pid_path = os.path.join(
            self.config_dir, 'var', 'run', 'pluto')
        self.pid_file = '%s.pid' % self.pid_path

    def _execute(self, cmd, check_exit_code=True, extra_ok_codes=None):
        """Execute command on namespace."""
        ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        return ip_wrapper.netns.execute(cmd, check_exit_code=check_exit_code,
                                        extra_ok_codes=extra_ok_codes)

    def _ipsec_execute(self, cmd, check_exit_code=True, extra_ok_codes=None):
        """Execute ipsec command on namespace.

        This execute is wrapped by namespace wrapper.
        The namespace wrapper will bind /etc and /var/run
        """
        ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        mount_paths = {'/etc': '%s/etc' % self.config_dir,
                       '/run': '%s/var/run' % self.config_dir}
        mount_paths_str = ','.join(
            "{}:{}".format(source, target)
            for source, target in mount_paths.items())
        ns_wrapper = self.get_ns_wrapper()
        return ip_wrapper.netns.execute(
            [ns_wrapper,
             '--mount_paths=%s' % mount_paths_str,
             ('--rootwrap_config=%s' % self._rootwrap_cfg
                 if self._rootwrap_cfg else ''),
             '--cmd={},{}'.format(self.binary, ','.join(cmd))],
            check_exit_code=check_exit_code,
            extra_ok_codes=extra_ok_codes)

    def _ensure_needed_files(self):
        with open('%s/etc/hosts' % self.config_dir, 'a'):
            pass
        with open('%s/etc/resolv.conf' % self.config_dir, 'a'):
            pass

    def ensure_configs(self):
        """Generate config files which are needed for Libreswan.

        Initialise the nssdb, otherwise pluto daemon will fail to run.
        """
        secrets_file = self._get_config_filename('ipsec.secrets')
        if os.path.exists(secrets_file):
            self._execute(['rm', '-f', secrets_file])

        self.ensure_config_dir(self.vpnservice)
        self.ensure_config_file(
            'ipsec.conf',
            self.conf.libreswan.ipsec_config_template,
            self.vpnservice)
        self.ensure_config_file(
            'ipsec.secrets',
            self.conf.libreswan.ipsec_secret_template,
            self.vpnservice,
            0o600)

        self._execute(['chown', '--from=%s' % os.getuid(), 'root:root',
                       secrets_file])
        self._execute(['chown', '--from=%s' % os.getuid(), 'root:root',
                       self.log_dir])

        self._ensure_needed_files()

        # Load the ipsec kernel module if not loaded
        # NOTE(ralonsoh): _stackmanager is no longer available since libreswan
        # v5.3. Remove this fallback when we drop support for libreswan<v5.3
        try:
            self._ipsec_execute(['_stackmanager', 'start'])
        except RuntimeError:
            self._ipsec_execute(['start'])
        # checknss creates nssdb only if it is missing
        self._ipsec_execute(['checknss'])

    def _copy_configs(self):
        if not cfg.CONF.pluto.restart_check_config:
            return
        config_file_name = self._get_config_filename('ipsec.conf')
        if os.path.isfile(config_file_name):
            shutil.copyfile(config_file_name, config_file_name + '.old')
        config_file_name = self._get_config_filename('ipsec.secrets')
        if os.path.isfile(config_file_name):
            shutil.copyfile(config_file_name, config_file_name + '.old')
        os.chmod(config_file_name + '.old', 0o600)

    def _process_running(self):
        """Checks if process is still running."""
        if not os.path.exists(self.pid_file):
            return False

        try:
            with open(self.pid_file) as f:
                pid = f.readline().strip()
                with open('/proc/%s/cmdline' % pid) as cmd_line_file:
                    cmd_line = cmd_line_file.readline()
                    if self.pid_path in cmd_line and 'pluto' in cmd_line:
                        LOG.error('Process %(pid)s exists with command '
                                  'line %(cmd_line)s.',
                                  {'pid': pid, 'cmd_line': cmd_line})
                        return True

        except OSError as e:
            LOG.info('Unable to find control files on startup for '
                     'router %(router)s: %(msg)s',
                     {'router': self.id, 'msg': e})
        return False

    def _cleanup_control_files(self):
        try:
            ctl_file = '%s.ctl' % self.pid_path
            LOG.debug('Removing %(pidfile)s and %(ctlfile)s',
                      {'pidfile': self.pid_file,
                       'ctlfile': ctl_file})

            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)

            if os.path.exists(ctl_file):
                os.remove(ctl_file)

        except OSError as e:
            LOG.error('Unable to remove pluto control '
                      'files for router %(router)s. %(msg)s',
                      {'router': self.id, 'msg': e})

    def _config_changed(self):
        secrets_file = os.path.join(self.etc_dir, 'ipsec.secrets')
        config_file = os.path.join(self.etc_dir, 'ipsec.conf')

        if not os.path.isfile(secrets_file + '.old'):
            return True
        if not os.path.isfile(config_file + '.old'):
            return True

        if not filecmp.cmp(secrets_file, secrets_file + '.old'):
            return True
        if not filecmp.cmp(config_file, config_file + '.old'):
            return True

        return False

    def get_status(self):
        return self._ipsec_execute(['whack', '--status'],
                                   extra_ok_codes=[1, 3])

    def restart(self):
        """Restart the process."""
        if cfg.CONF.pluto.restart_check_config and not self._config_changed():
            return
        self.stop()
        wait_interval = cfg.CONF.pluto.shutdown_check_timeout
        for i in range(cfg.CONF.pluto.shutdown_check_retries):
            if not self._process_running():
                self._cleanup_control_files()
                break
            time.sleep(wait_interval)
            wait_interval *= cfg.CONF.pluto.shutdown_check_back_off
        else:
            LOG.warning('Server appears to still be running, restart '
                        'of router %s may fail', self.id)
        self.start()

    def _resolve_fqdn(self, fqdn):
        try:
            addrinfo = socket.getaddrinfo(fqdn, None)[0]
            return addrinfo[-1][0]
        except socket.gaierror:
            LOG.exception("Peer address %s cannot be resolved", fqdn)

    def _get_nexthop(self, address, connection_id):
        invalid_ip_address = validators.validate_ip_address(address)
        if invalid_ip_address:
            ip_addr = self._resolve_fqdn(address)
            if not ip_addr:
                self._record_connection_status(connection_id, constants.ERROR,
                                               force_status_update=True)
                raise vpn_exception.VPNPeerAddressNotResolved(
                    peer_address=address)
        else:
            ip_addr = address
        routes = self._execute(['ip', 'route', 'get', ip_addr])
        if routes.find('via') >= 0:
            return routes.split(' ')[2]
        return address

    def _virtual_privates(self, vpnservice):
        """Returns line of virtual_privates.

        virtual_private contains the networks
        that are allowed as subnet for the remote client.
        """
        virtual_privates = []
        nets = []
        for ipsec_site_conn in vpnservice['ipsec_site_connections']:
            nets += ipsec_site_conn['local_cidrs']
            nets += ipsec_site_conn['peer_cidrs']
        for net in nets:
            version = netaddr.IPNetwork(net).version
            virtual_privates.append('%v{}:{}'.format(version, net))
        virtual_privates.sort()
        return ','.join(virtual_privates)

    def _gen_config_content(self, template_file, vpnservice):
        template = ipsec._get_template(template_file)
        virtual_privates = self._virtual_privates(vpnservice)
        return template.render(
            {'vpnservice': vpnservice,
             'virtual_privates': virtual_privates})

    def start_pluto(self):
        cmd = ['pluto',
               '--use-xfrm',
               '--uniqueids']

        if self.conf.ipsec.enable_detailed_logging:
            cmd += ['--perpeerlog', '--perpeerlogbase', self.log_dir]
        self._ipsec_execute(cmd)

    def add_ipsec_connection(self, nexthop, conn_id):
        pass

    def start_whack_listening(self):
        # NOTE(huntxu): This is a workaround for with a weak (len<8) secret,
        # "ipsec whack --listen" will exit with 3.
        self._ipsec_execute(['whack', '--listen'], extra_ok_codes=[3])

    def shutdown_whack(self):
        self._ipsec_execute(['whack', '--shutdown'])

    def initiate_connection(self, conn_name):
        self._ipsec_execute(
            ['whack', '--name', conn_name, '--asynchronous', '--initiate'])

    def terminate_connection(self, conn_name):
        self._ipsec_execute(['whack', '--name', conn_name, '--terminate'])

    def start(self):
        """Start the process.

        Note: if there is not namespace yet,
        just do nothing, and wait next event.
        """
        if not self.namespace:
            return

        if not self._process_running():
            self._cleanup_control_files()

        self.start_pluto()

        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            if not ipsec_site_conn['admin_state_up']:
                continue
            nexthop = self._get_nexthop(ipsec_site_conn['peer_address'],
                                        ipsec_site_conn['id'])
            self.add_ipsec_connection(nexthop, ipsec_site_conn['id'])

        self.start_whack_listening()

        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            if (not ipsec_site_conn['initiator'] == 'start' or
                    not ipsec_site_conn['admin_state_up']):
                continue
            self.initiate_connection(ipsec_site_conn['id'])
        self._copy_configs()

    def get_established_connections(self):
        connections = []
        status_output = self.get_status()

        if not status_output:
            return connections

        for line in status_output.split('\n'):
            if self.STATUS_NOT_RUNNING_PATTERN.search(line):
                return connections
            m = self.STATUS_IPSEC_SA_ESTABLISHED_PATTERN2.search(line)
            if m:
                connection = m.group(1)
                if connection in connections:
                    continue
                connections.append(connection)
        return connections

    def disconnect(self):
        if not self.namespace:
            return
        if not self.vpnservice:
            return

        connections = self.get_established_connections()
        for conn_name in connections:
            self.terminate_connection(conn_name)

    def stop(self):
        self.disconnect()
        self.shutdown_whack()
        self.connection_status = {}


class LibreSwanDriver(ipsec.IPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return LibreSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
