# Copyright (c) 2015 Canonical, Inc.
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
import time
import warnings

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron_lib import constants
from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils

from neutron_vpnaas._i18n import _
from neutron_vpnaas.conf.services.vpn import strongswan as strongswan_conf
from neutron_vpnaas.services.vpn.device_drivers import ipsec

LOG = logging.getLogger(__name__)


strongswan_opts = strongswan_conf.strongswan_opts
strongswan_conf.register_strongswan_opts()


class StrongSwanProcess(ipsec.BaseSwanProcess):

    # ROUTED means route created. (only for auto=route mode)
    # CONNECTING means route created, connection tunnel is negotiating.
    # INSTALLED means route created,
    #           also connection tunnel installed. (traffic can pass)

    DIALECT_MAP = dict(ipsec.BaseSwanProcess.DIALECT_MAP)

    STATUS_DICT = {
        'ROUTED': constants.DOWN,
        'CONNECTING': constants.DOWN,
        'INSTALLED': constants.ACTIVE
    }
    STATUS_RE = r'([a-f0-9\-]+).* (ROUTED|CONNECTING|INSTALLED)'
    STATUS_NOT_RUNNING_RE = 'Command:.*ipsec.*status.*Exit code: [1|3] '

    def __init__(self, conf, process_id, vpnservice, namespace):
        warnings.warn(
            "StrongSwanProcess is deprecated and will be removed in a future "
            "release. Use SwanctlProcess with use_swanctl=True instead.",
            DeprecationWarning,
            stacklevel=2)
        dialect_map_update = {
            'v1': 'ikev1',
            'v2': 'ikev2',
            # ENCR_AES_CTR
            'aes-128-ctr': 'aes128ctr',
            'aes-192-ctr': 'aes192ctr',
            'aes-256-ctr': 'aes256ctr',
            # ENCR_AES_CCM_8
            'aes-128-ccm-8': 'aes128ccm8',
            'aes-192-ccm-8': 'aes192ccm8',
            'aes-256-ccm-8': 'aes256ccm8',
            # ENCR_AES_CCM_12
            'aes-128-ccm-12': 'aes128ccm12',
            'aes-192-ccm-12': 'aes192ccm12',
            'aes-256-ccm-12': 'aes256ccm12',
            # ENCR_AES_CCM_16
            'aes-128-ccm-16': 'aes128ccm16',
            'aes-192-ccm-16': 'aes192ccm16',
            'aes-256-ccm-16': 'aes256ccm16',
            # ENCR_AES_GCM_8
            'aes-128-gcm-8': 'aes128gcm8',
            'aes-192-gcm-8': 'aes192gcm8',
            'aes-256-gcm-8': 'aes256gcm8',
            # ENCR_AES_GCM_12
            'aes-128-gcm-12': 'aes128gcm12',
            'aes-192-gcm-12': 'aes192gcm12',
            'aes-256-gcm-12': 'aes256gcm12',
            # ENCR_AES_GCM_16
            'aes-128-gcm-16': 'aes128gcm16',
            'aes-192-gcm-16': 'aes192gcm16',
            'aes-256-gcm-16': 'aes256gcm16',
            # AUTH
            'sha256': 'sha256',
            'aes-xcbc': 'aesxcbc',
            'aes-cmac': 'aescmac',
            # PFS
            'group22': 'modp1024s160',
            'group23': 'modp2048s224',
            'group24': 'modp2048s256',
            'group25': 'ecp192',
            'group26': 'ecp224',
            'group27': 'ecp224bp',
            'group28': 'ecp256bp',
            'group29': 'ecp384bp',
            'group30': 'ecp512bp',
        }
        self.DIALECT_MAP.update(dialect_map_update)
        self._strongswan_piddir = self._get_strongswan_piddir()
        self._rootwrap_cfg = self._get_rootwrap_config()
        LOG.debug("strongswan piddir is '%s'", (self._strongswan_piddir))
        super().__init__(conf, process_id, vpnservice, namespace)

    def _get_strongswan_piddir(self):
        return utils.execute(
            cmd=[self.binary, "--piddir"], run_as_root=True).strip()

    def _check_status_line(self, line):
        """Parse a line and search for status information.

        If a given line contains status information for a connection,
        extract the status and mark the connection as ACTIVE or DOWN
        according to the STATUS_MAP.
        """
        m = self.STATUS_PATTERN.search(line)
        if m:
            connection_id = m.group(1)
            status = self.STATUS_MAP[m.group(2)]
            return connection_id, status
        return None, None

    def _execute(self, cmd, check_exit_code=True, extra_ok_codes=None):
        """Execute command on namespace.

        This execute is wrapped by namespace wrapper.
        The namespace wrapper will bind /etc/ and /var/run
        """
        ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        ns_wrapper = self.get_ns_wrapper()
        return ip_wrapper.netns.execute(
            [ns_wrapper,
             '--mount_paths=/etc:{}/etc,{}:{}/var/run'.format(
                 self.config_dir, self._strongswan_piddir, self.config_dir),
             ('--rootwrap_config=%s' % self._rootwrap_cfg
                 if self._rootwrap_cfg else ''),
             '--cmd=%s' % ','.join(cmd)],
            check_exit_code=check_exit_code,
            extra_ok_codes=extra_ok_codes)

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

    def get_status(self):
        return self._execute([self.binary, 'status'],
                             extra_ok_codes=[1, 3])

    def restart(self):
        """Restart the process."""
        self.reload_secrets()
        self.reload()

    def reload_secrets(self):
        """Reload the ipsec.secrets file.

        Flushes and rereads all secrets defined in ipsec.secrets. This needs
        to be done each time when a new site connection is associated with
        a VPN service which already hosts a site connection - 'ipsec reload'
        does not reload the secrets and new connections will not authenticate
        properly.
        """
        self._execute([self.binary, 'rereadsecrets'])

    def reload(self):
        """Reload the process.

        Sends a USR1 signal to ipsec starter which in turn reloads the whole
        configuration on the running IKE daemon charon based on the actual
        ipsec.conf. Currently established connections are not affected by
        configuration changes.
        """
        self._execute([self.binary, 'reload'])

    def start(self):
        """Start the process for only auto=route mode now.

        Note: if there is no namespace yet,
        just do nothing, and wait next event.
        """
        if not self.namespace:
            return
        self._execute([self.binary, 'start'])
        # initiate ipsec connection
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            self._execute([self.binary, 'stroke', 'up-nb',
                           ipsec_site_conn['id']])

    def stop(self):
        self._execute([self.binary, 'stop'])
        self.connection_status = {}


class SwanctlProcess(ipsec.BaseSwanProcess):
    """swanctl-based strongSwan process using VICI protocol.

    This class manages strongSwan via the swanctl CLI frontend which
    uses the modern VICI protocol instead of the deprecated stroke
    interface. Connections and secrets are rendered in swanctl.conf
    format [1] and loaded into charon with 'swanctl --load-all'.

    The charon daemon is still managed with the 'ipsec' starter
    command, which only needs a minimal ipsec.conf ("config setup")
    to start charon; connections are not defined there.

    [1] https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html

    .. versionadded:: 25.1.0
    """

    binary = 'swanctl'
    IPSEC_BINARY = 'ipsec'
    DEFAULT_PIDDIR = '/var/run'

    # 'swanctl --list-sas' reports one block per IKE_SA with one line
    # per CHILD_SA. Both the IKE_SA and the CHILD_SA names are the
    # IPsec site connection id, as rendered by the swanctl.conf
    # template; only the CHILD_SA lines have a reqid:
    #   <conn>: #1, ESTABLISHED, IKEv2, <spi_i> <spi_r>*
    #     <conn>: #2, reqid 1, INSTALLED, TUNNEL, esp:aes128-sha256
    # A connection is considered ACTIVE only when its CHILD_SA is
    # INSTALLED (or being rekeyed): an ESTABLISHED IKE_SA alone does
    # not mean that traffic can flow. Any IKE_SA/CHILD_SA being set up
    # or torn down is reported as DOWN. The pattern is not anchored to
    # the beginning of the line because the namespace wrapper prefixes
    # the command output with command information.
    STATUS_RE = (r'(\S+): #\d+, (?:reqid \d+, )?'
                 r'(CONNECTING|CREATED|DELETING|DESTROYING|'
                 r'INSTALLED|REKEYING|REKEYED)\b')
    STATUS_DICT = {
        'INSTALLED': constants.ACTIVE,
        'REKEYING': constants.ACTIVE,
        'REKEYED': constants.ACTIVE,
        'CONNECTING': constants.DOWN,
        'CREATED': constants.DOWN,
        'DELETING': constants.DOWN,
        'DESTROYING': constants.DOWN,
    }
    # The namespace wrapper reports command failures as
    # "Command: [...] Exit code: N ..." on stdout; 'swanctl
    # --list-sas' exits with a non-zero code if charon is not running
    # ("connecting to socket failed").
    STATUS_NOT_RUNNING_RE = (
        r'Command:.*swanctl.*--list-sas.*Exit code: [1-9]')

    # The base DIALECT_MAP translates these API values to stroke
    # keywords; swanctl needs the VICI ones instead (see the action
    # parsing rules of the vici plugin: clear, none, trap, start,
    # restart). Algorithm names and DH groups use the strongSwan
    # keywords (without dashes) for all the values the generic base
    # DIALECT_MAP does not cover.
    SWANCTL_DIALECT_MAP = {
        'v1': '1',
        'v2': '2',
        'bi-directional': 'start',
        'response-only': 'none',
        'hold': 'trap',
        'clear': 'clear',
        'disabled': 'none',
        'restart': 'restart',
        'restart-by-peer': 'restart',
        # ENCR_AES_CTR
        'aes-128-ctr': 'aes128ctr',
        'aes-192-ctr': 'aes192ctr',
        'aes-256-ctr': 'aes256ctr',
        # ENCR_AES_CCM_8
        'aes-128-ccm-8': 'aes128ccm8',
        'aes-192-ccm-8': 'aes192ccm8',
        'aes-256-ccm-8': 'aes256ccm8',
        # ENCR_AES_CCM_12
        'aes-128-ccm-12': 'aes128ccm12',
        'aes-192-ccm-12': 'aes192ccm12',
        'aes-256-ccm-12': 'aes256ccm12',
        # ENCR_AES_CCM_16
        'aes-128-ccm-16': 'aes128ccm16',
        'aes-192-ccm-16': 'aes192ccm16',
        'aes-256-ccm-16': 'aes256ccm16',
        # ENCR_AES_GCM_8
        'aes-128-gcm-8': 'aes128gcm8',
        'aes-192-gcm-8': 'aes192gcm8',
        'aes-256-gcm-8': 'aes256gcm8',
        # ENCR_AES_GCM_12
        'aes-128-gcm-12': 'aes128gcm12',
        'aes-192-gcm-12': 'aes192gcm12',
        'aes-256-gcm-12': 'aes256gcm12',
        # ENCR_AES_GCM_16
        'aes-128-gcm-16': 'aes128gcm16',
        'aes-192-gcm-16': 'aes192gcm16',
        'aes-256-gcm-16': 'aes256gcm16',
        # AUTH
        'sha256': 'sha256',
        'aes-xcbc': 'aesxcbc',
        'aes-cmac': 'aescmac',
        # PFS
        'group22': 'modp1024s160',
        'group23': 'modp2048s224',
        'group24': 'modp2048s256',
        'group25': 'ecp192',
        'group26': 'ecp224',
        'group27': 'ecp224bp',
        'group28': 'ecp256bp',
        'group29': 'ecp384bp',
        'group30': 'ecp512bp',
    }

    def __init__(self, conf, process_id, vpnservice, namespace):
        super().__init__(conf, process_id, vpnservice, namespace)
        self._swanctl_config_dir = os.path.join(self.etc_dir, 'swanctl')
        self._strongswan_piddir = self._get_strongswan_piddir()
        self._rootwrap_cfg = self._get_rootwrap_config()
        LOG.debug("swanctl config dir is '%s'", self._swanctl_config_dir)

    def _get_strongswan_piddir(self):
        # The ipsec command is only shipped with the legacy strongswan-starter
        # package, which is not always installed when using swanctl.
        try:
            return utils.execute(
                cmd=[self.IPSEC_BINARY, '--piddir'],
                run_as_root=True).strip()
        except Exception:
            LOG.warning("Unable to run '%s --piddir', using '%s'",
                        self.IPSEC_BINARY, self.DEFAULT_PIDDIR)
            return self.DEFAULT_PIDDIR

    def translate_dialect(self):
        """Map API values to swanctl/VICI keywords.

        Extends the generic algorithm and DH-group translations of the
        base class with the swanctl specific keyword mapping for the
        IKE version, the initiator mode and the DPD action, which the
        base DIALECT_MAP translates to stroke keywords instead.
        """
        if not self.vpnservice:
            return
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            self._dialect(ipsec_site_conn, 'initiator')
            self._dialect(ipsec_site_conn, 'dpd_action')
            self._dialect(ipsec_site_conn['ikepolicy'], 'ike_version')
            for key in ['encryption_algorithm',
                        'auth_algorithm',
                        'pfs']:
                self._dialect(ipsec_site_conn['ikepolicy'], key)
                self._dialect(ipsec_site_conn['ipsecpolicy'], key)
            if (('local_id' not in ipsec_site_conn.keys()) or
                    (not ipsec_site_conn['local_id'])):
                ipsec_site_conn['local_id'] = ipsec_site_conn['external_ip']
        # Drop any ipsec_site_connections with an invalid local_id/peer_id
        # before they can reach a template.
        self.vpnservice['ipsec_site_connections'] = [
            conn for conn in self.vpnservice['ipsec_site_connections']
            if self._validate_id_field(conn, 'local_id') and
            self._validate_id_field(conn, 'peer_id')]

    def _dialect(self, obj, key):
        obj[key] = self.SWANCTL_DIALECT_MAP.get(
            obj[key],
            ipsec.BaseSwanProcess.DIALECT_MAP.get(obj[key], obj[key]))

    def _execute(self, cmd, check_exit_code=True, extra_ok_codes=None):
        """Execute command on namespace.

        This execute is wrapped by namespace wrapper.
        The namespace wrapper will bind /etc/ and /var/run
        """
        ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        ns_wrapper = self.get_ns_wrapper()
        return ip_wrapper.netns.execute(
            [ns_wrapper,
             '--mount_paths=/etc:{}/etc,{}:{}/var/run'.format(
                 self.config_dir, self._strongswan_piddir, self.config_dir),
             ('--rootwrap_config=%s' % self._rootwrap_cfg
                 if self._rootwrap_cfg else ''),
             '--cmd=%s' % ','.join(cmd)],
            check_exit_code=check_exit_code,
            extra_ok_codes=extra_ok_codes)

    def ensure_configs(self):
        """Generate config files which are needed for strongSwan.

        Renders the swanctl configuration (connections and secrets)
        and the minimal starter configuration. 'swanctl --load-all'
        reads <swanctl dir>/swanctl.conf, which includes the secrets
        file generated next to it.
        """
        self.ensure_config_dir(self.vpnservice)
        fileutils.ensure_tree(self._swanctl_config_dir, 0o755)

        # swanctl.conf, the entry point read by 'swanctl --load-all'.
        # It contains all the connections and includes the secrets
        # file rendered below.
        self.ensure_config_file(
            'swanctl/swanctl.conf',
            cfg.CONF.strongswan.swanctl_config_template,
            self.vpnservice)

        # PSK secrets, included from swanctl.conf, with restricted
        # file permissions.
        self.ensure_config_file(
            'swanctl/secrets.conf',
            cfg.CONF.strongswan.swanctl_secrets_template,
            self.vpnservice,
            0o600)

        # Minimal ipsec.conf for the starter: it only manages the
        # charon daemon lifecycle; the connections are loaded through
        # swanctl/VICI and must not be defined here.
        ipsec_conf = self._get_config_filename('ipsec.conf')
        file_utils.replace_file(
            ipsec_conf,
            '# Configuration for %s\nconfig setup\n' % self.vpnservice['id'])

        # strongswan.conf, including the distribution defaults from
        # strongswan.d (which enable the vici plugin for charon).
        self.ensure_config_file(
            'strongswan.conf',
            cfg.CONF.strongswan.strongswan_config_template,
            self.vpnservice)
        self.copy_and_overwrite(cfg.CONF.strongswan.default_config_area,
                                self._get_config_filename('strongswan.d'))

    def _extract_and_record_connection_status(self, status_output):
        """Parse 'swanctl --list-sas' output and record the status.

        Only CHILD_SA lines are taken into account: a connection is
        ACTIVE only when its CHILD_SA is INSTALLED. If charon is not
        running, or no CHILD_SA is reported at all, any previous
        status is cleared so the connections are reported as DOWN.
        """
        if not status_output:
            self.connection_status = {}
            return
        if self.STATUS_NOT_RUNNING_PATTERN.search(status_output):
            self.connection_status = {}
            return
        # Reset any status recorded in previous iterations so only the
        # connections reported by charon in this run are kept.
        self.connection_status = {}
        for line in status_output.split('\n'):
            m = self.STATUS_PATTERN.search(line)
            if m:
                self._record_connection_status(
                    m.group(1),
                    self.STATUS_MAP.get(m.group(2), constants.DOWN))

    def _wait_for_charon_ready(self, timeout=10):
        """Wait for the charon daemon to accept VICI connections.

        Polls 'swanctl --list-sas' until it succeeds, which means the
        charon VICI socket is up and accepting commands.

        :param timeout: Maximum seconds to wait.
        :raises RuntimeError: If charon does not become ready within
            timeout.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                self._execute([self.binary, '--list-sas'])
                return
            except RuntimeError:
                time.sleep(0.5)
        raise RuntimeError(
            _('charon did not become ready within %ds') % timeout)

    def get_status(self):
        return self._execute([self.binary, '--list-sas'],
                             extra_ok_codes=[1])

    def restart(self):
        """Reload all swanctl configuration.

        Replaces the whole connection and secret configuration in
        charon; established connections that are unchanged keep
        running.
        """
        self._execute([self.binary, '--load-all'])

    def reload_secrets(self):
        """Reload secrets via swanctl --load-creds."""
        self._execute([self.binary, '--load-creds'])

    def reload(self):
        """Reload configuration via swanctl --load-all."""
        self._execute([self.binary, '--load-all'])

    def start(self):
        """Start the charon daemon and load the swanctl configuration.

        Note: if there is no namespace yet,
        just do nothing, and wait next event.
        """
        if not self.namespace:
            return
        self._execute([self.IPSEC_BINARY, 'start'])
        # Wait for the charon VICI socket to be ready before loading
        # the configuration. Loading the configuration also runs the
        # start actions: 'start' connections are initiated immediately
        # and 'trap' ones install a policy for on-demand establishment.
        self._wait_for_charon_ready()
        self._execute([self.binary, '--load-all'])

    def stop(self):
        self._execute([self.IPSEC_BINARY, 'stop'])
        self.connection_status = {}


class SwanctlDriver(ipsec.IPsecDriver):
    """IPsec driver that uses SwanctlProcess.

    .. versionadded:: 25.1.0
    """

    def create_process(self, process_id, vpnservice, namespace):
        return SwanctlProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)


class StrongSwanDriver(ipsec.IPsecDriver):

    def create_process(self, process_id, vpnservice, namespace):
        return StrongSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
