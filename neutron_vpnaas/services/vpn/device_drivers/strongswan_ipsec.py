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
import re
import time
import warnings

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron_lib import constants
from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils

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

    def copy_and_overwrite(self, from_path, to_path):
        # NOTE(toabctl): the agent may run as non-root user, so rm/copy as root
        if os.path.exists(to_path):
            utils.execute(
                cmd=["rm", "-rf", to_path], run_as_root=True)
        utils.execute(
            cmd=["cp", "-a", from_path, to_path], run_as_root=True)

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

    This class manages strongSwan via the swanctl CLI frontend which uses
    the modern VICI protocol instead of the deprecated stroke/starter
    interface.

    .. versionadded:: 25.1.0
    """

    # States from swanctl --list-sas output
    STATUS_DICT = {
        'INSTALLED': constants.ACTIVE,
        'CONNECTING': constants.DOWN,
        'REKEYING': constants.ACTIVE,
        'DELETING': constants.DOWN,
    }
    # Match lines like: "child_sa:  VPN_abc123_child_1" followed by state on
    # next line
    STATUS_RE = r'(INSTALLED|CONNECTING|REKEYING|DELETING)'
    # Match connection name + state: "CONN_NAME:  STATE"
    STATUS_CONN_RE = r'^([^\s:]+):\s+(INSTALLED|CONNECTING|REKEYING|DELETING)'
    STATUS_NOT_RUNNING_RE = (
        r'No active Security Associations found\.?$')
    # Match established SA lines like: "child_sa.*INSTALLED.*established"
    STATUS_IPSEC_SA_ESTABLISHED_RE = (
        r'(?:IKE|CHILD)_SA[^\n]*\n[^\n]*(?:ESTABLISHED|INSTALLED)')

    binary = 'swanctl'
    IPSEC_BINARY = 'ipsec'

    def __init__(self, conf, process_id, vpnservice, namespace):
        super().__init__(conf, process_id, vpnservice, namespace)
        self._swanctl_config_dir = os.path.join(self.etc_dir, 'swanctl')
        self._strongswan_piddir = self._get_strongswan_piddir()
        self._rootwrap_cfg = self._get_rootwrap_config()
        self.STATUS_CONN_PATTERN = re.compile(self.STATUS_CONN_RE)
        LOG.debug("swanctl config dir is '%s'", self._swanctl_config_dir)

    def _get_strongswan_piddir(self):
        return utils.execute(
            cmd=[self.IPSEC_BINARY, '--piddir'], run_as_root=True).strip()

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

    # ------------------------------------------------------------------ #
    # Section 1: Configuration format
    # ------------------------------------------------------------------ #

    def _get_swanctl_connections_dir(self):
        """Return path to swanctl connections directory."""
        return os.path.join(
            self._swanctl_config_dir, 'connections')

    def _get_swanctl_secrets_dir(self):
        """Return path to swanctl secrets directory."""
        return os.path.join(
            self._swanctl_config_dir, 'secrets')

    def ensure_configs(self):
        """Generate swanctl configuration files.

        Creates the connections/ and secrets/ subdirectories under
        the per-router etc/swanctl directory and renders the Jinja2
        templates into those directories.
        """
        self.ensure_config_dir(self.vpnservice)
        fileutils.ensure_tree(
            self._get_swanctl_connections_dir(), 0o755)
        fileutils.ensure_tree(self._get_swanctl_secrets_dir(), 0o755)

        # Render swanctl.conf into connections/ directory
        for ipsec_site_conn in (
                self.vpnservice['ipsec_site_connections']):
            conn_id = ipsec_site_conn['id']
            config_str = self._gen_config_content(
                cfg.CONF.strongswan.swanctl_config_template,
                self.vpnservice)
            # Write per-connection file for easier reload
            conn_file = os.path.join(
                self._get_swanctl_connections_dir(),
                '%s.conf' % conn_id)
            file_utils.replace_file(conn_file, config_str)

        # Render secrets into secrets/ directory
        secrets_str = self._gen_config_content(
            cfg.CONF.strongswan.swanctl_secrets_template,
            self.vpnservice)
        secrets_file = os.path.join(self._get_swanctl_secrets_dir(),
                                    'secrets.conf')
        file_utils.replace_file(secrets_file, secrets_str, 0o600)

    # ------------------------------------------------------------------ #
    # Section 2: Daemon management (charon lifecycle in namespace)
    # ------------------------------------------------------------------ #

    def _start_daemon(self):
        """Start strongSwan charon in the router namespace."""
        self._execute([self.IPSEC_BINARY, 'start'],
                      check_exit_code=False)

    def _stop_daemon(self):
        """Stop strongSwan charon in the router namespace."""
        self._execute([self.IPSEC_BINARY, 'stop'],
                      check_exit_code=False)

    def _wait_for_charon_ready(self, timeout=10):
        """Wait for charon to be ready by polling swanctl --list-sas.

        :param timeout: Maximum seconds to wait.
        :raises RuntimeError: If charon does not become ready within timeout.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                self._execute([self.binary, '--list-sas'],
                              check_exit_code=False)
                return
            except RuntimeError:
                time.sleep(0.5)
        raise RuntimeError(
            _('charon did not become ready within %ds' % timeout))

    # ------------------------------------------------------------------ #
    # Section 3: Connection control (stroke CLI → swanctl equivalents)
    # ------------------------------------------------------------------ #

    def _initiate_connection_swanctl(self, child_sa_id):
        """Initiate an IPsec child SA via swanctl.

        Equivalent to: ipsec stroke up-nb <id>
        :param child_sa_id: The IPSec site connection ID.
        """
        self._execute([self.binary, '--initiate', '--child', child_sa_id])

    def _reload_config_swanctl(self):
        """Reload all swanctl configuration.

        Equivalent to: ipsec reload
        """
        self._execute([self.binary, '--load-all'])

    def _reload_secrets_swanctl(self):
        """Reload credentials/secrets via swanctl.

        Equivalent to: ipsec rereadsecrets
        """
        self._execute([self.binary, '--load-creds'])

    # ------------------------------------------------------------------ #
    # Section 4: Status parsing (swanctl --list-sas output format)
    # ------------------------------------------------------------------ #

    def _check_swanctl_status_line(self, line):
        """Parse a swanctl --list-sas output line.

        swanctl --list-sas produces indented blocks like::

            VPN_abc123:  INSTALLED, ESTABLISHED, current (IPv4)
                child_sa:  VPN_abc123_child_1
                    INSTALLED, ESTABLISHED, current (IPv4)

        This method extracts the connection/child SA name and state.

        :param line: A single line from swanctl --list-sas output.
        :returns: Tuple of (connection_id, status) or (None, None).
        """
        # Check for established CHILD_SA lines
        m = self.STATUS_IPSEC_SA_ESTABLISHED_PATTERN.search(line)
        if m:
            # Extract the child_sa name from preceding context
            return None, constants.ACTIVE

        m = self.STATUS_PATTERN.search(line)
        if m:
            state_str = m.group(1)
            status = self.STATUS_MAP.get(state_str, constants.DOWN)
            # For lines like "child_sa:  NAME" followed by state on next line
            return None, status

        return None, None

    def _extract_and_swanctl_connection_status(self, output):
        """Parse swanctl --list-sas output and record connection statuses.

        :param output: Full text output from swanctl --list-sas.
        """
        if not output:
            self.connection_status = {}
            return

        # Parse the structured output line by line
        lines = output.split('\n')
        current_conn = None
        for i, line in enumerate(lines):
            # Match connection name at start of line: "CONN_NAME:  STATE"
            conn_match = self.STATUS_CONN_PATTERN.match(line)
            if conn_match:
                current_conn = conn_match.group(1)
                state = conn_match.group(2)
                status = self.STATUS_MAP.get(state, constants.DOWN)
                self._record_connection_status(current_conn, status)

            # Match child_sa lines
            child_match = re.match(
                r'^\s+child_sa:\s+(\S+)', line)
            if child_match and current_conn:
                child_id = child_match.group(1)
                # Check next line for state
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    state_match = self.STATUS_PATTERN.search(next_line)
                    if state_match:
                        state = state_match.group(1)
                        status = self.STATUS_MAP.get(state, constants.DOWN)
                        # Use child_sa name as connection_id for finer
                        # granularity
                        self._record_connection_status(child_id, status)

    def get_status(self):
        """Get status via swanctl --list-sas."""
        return self._execute([self.binary, '--list-sas'],
                             check_exit_code=False)

    # ------------------------------------------------------------------ #
    # Lifecycle methods (start/stop/reload)
    # ------------------------------------------------------------------ #

    def disable(self):
        """Disable the swanctl process."""
        try:
            if self.active:
                self.stop()
            self.remove_config()
        except RuntimeError:
            LOG.exception(
                "Failed to disable swanctl vpn process on router %s",
                self.id)

    def restart(self):
        """Restart the swanctl process."""
        self.reload_secrets()
        self.reload()

    def start(self):
        """Start the swanctl process."""
        if not self.namespace:
            return
        self._start_daemon()
        self._wait_for_charon_ready()
        self._reload_config_swanctl()
        self._reload_secrets_swanctl()
        for ipsec_site_conn in (
                self.vpnservice['ipsec_site_connections']):
            self._initiate_connection_swanctl(
                ipsec_site_conn['id'])

    def stop(self):
        """Stop the swanctl process."""
        self._stop_daemon()
        self.connection_status = {}

    def reload_secrets(self):
        """Reload secrets via swanctl --load-creds."""
        self._reload_secrets_swanctl()

    def reload(self):
        """Reload configuration via swanctl --load-all."""
        self._reload_config_swanctl()

    @property
    def active(self):
        """Check if the process is active or not."""
        try:
            status = self.get_status()
            self._extract_and_swanctl_connection_status(status)
            if not self.connection_status:
                return False
        except RuntimeError:
            return False
        return True


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
