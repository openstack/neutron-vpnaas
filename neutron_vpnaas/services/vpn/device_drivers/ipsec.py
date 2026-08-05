# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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
import abc
import base64
import copy
import os
import re
import sys
import typing as ty

import jinja2
import netaddr
from neutron.agent.l3.router_info import RouterInfo
from neutron.agent.linux import utils as agent_utils
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import utils as plugin_utils
from neutron_lib import rpc as n_rpc
from neutron_lib.utils import file as file_utils
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_utils import encodeutils
from oslo_utils import fileutils

from neutron_vpnaas._i18n import _
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn import device_drivers

LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(os.path.abspath(__file__))

ipsec_opts = [
    cfg.StrOpt(
        'config_base_dir',
        default='$state_path/ipsec',
        help=_('Location to store ipsec server config files')),
    cfg.IntOpt('ipsec_status_check_interval',
               default=60,
               help=_("Interval for checking ipsec status")),
    cfg.BoolOpt('enable_detailed_logging',
                default=False,
                help=_("Enable detail logging for ipsec pluto process. "
                       "If the flag set to True, the detailed logging will "
                       "be written into config_base_dir/<pid>/log. "
                       "Note: This setting applies to LibreSwan "
                       "only. StrongSwan logs to syslog.")),
]
cfg.CONF.register_opts(ipsec_opts, 'ipsec')


pluto_opts = [
    cfg.IntOpt('shutdown_check_timeout',
               default=1,
               help=_('Initial interval in seconds for checking if pluto '
                      'daemon is shutdown'),
               deprecated_group='libreswan'),
    cfg.IntOpt('shutdown_check_retries',
               default=5,
               help=_('The maximum number of retries for checking for '
                      'pluto daemon shutdown'),
               deprecated_group='libreswan'),
    cfg.FloatOpt('shutdown_check_back_off',
                 default=1.5,
                 help=_('A factor to increase the retry interval for '
                        'each retry'),
                 deprecated_group='libreswan'),
    cfg.BoolOpt('restart_check_config',
                default=False,
                help=_('Enable this flag to avoid from unnecessary restart'),
                deprecated_group='libreswan')
]

cfg.CONF.register_opts(pluto_opts, 'pluto')

JINJA_ENV = None

IPSEC_CONNS = 'ipsec_site_connections'

# *Swan supports Base64 encoded binary values as PSKs. In such cases,
# a character sequence beginning with 0s is interpreted as Base64
# encoded binary data.
#   - StrongSwan
#     - https://wiki.strongswan.org/projects/strongswan/wiki/PskSecret
#   - LibreSwan
#     - https://libreswan.org/man/ipsec.secrets.5.html
#     - https://libreswan.org/man/ipsec_ttodata.3.html
PSK_BASE64_PREFIX = '0s'


def _get_template(template_file):
    global JINJA_ENV
    if not JINJA_ENV:
        templateLoader = jinja2.FileSystemLoader(searchpath="/")
        JINJA_ENV = jinja2.Environment(loader=templateLoader, autoescape=True)
    return JINJA_ENV.get_template(template_file)


class BaseSwanProcess(metaclass=abc.ABCMeta):
    """Swan Family Process Manager

    This class manages start/restart/stop ipsec process.
    This class create/delete config template
    """

    binary = "ipsec"
    CONFIG_DIRS = [
        'var/run',
        'log',
        'etc',
        'etc/ipsec.d/aacerts',
        'etc/ipsec.d/acerts',
        'etc/ipsec.d/cacerts',
        'etc/ipsec.d/certs',
        'etc/ipsec.d/crls',
        'etc/ipsec.d/ocspcerts',
        'etc/ipsec.d/policies',
        'etc/ipsec.d/private',
        'etc/ipsec.d/reqs',
        'etc/pki/nssdb/'
    ]

    DIALECT_MAP = {
        "aes-128": "aes128",
        "aes-192": "aes192",
        "aes-256": "aes256",
        "aes-ctr-128": "aesctr128",
        "aes-ctr-192": "aesctr192",
        "aes-ctr-256": "aesctr256",
        "aes-xcbc": "aes_xcbc",
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
        "group2": "modp1024",
        "group5": "modp1536",
        "group14": "modp2048",
        "group15": "modp3072",
        "group16": "modp4096",
        "group17": "modp6144",
        "group18": "modp8192",
        "group19": "ecp256",
        "group20": "ecp384",
        "group21": "ecp521",
        "group22": "dh22",
        "group23": "dh23",
        "group24": "dh24",
        "group31": "curve25519",
        "bi-directional": "start",
        "response-only": "add",
        "v2": "insist",
        "v1": "never"
    }

    NS_WRAPPER = 'neutron-vpn-netns-wrapper'

    STATUS_DICT = {
        'erouted': constants.ACTIVE,
        'unrouted': constants.DOWN
    }
    STATUS_RE = r'\d\d\d "([a-f0-9\-]+).* (unrouted|erouted);'
    STATUS_NOT_RUNNING_RE = 'Command:.*ipsec.*status.*Exit code: [1|3]$'
    STATUS_IPSEC_SA_ESTABLISHED_RE = (
        r'\d{3} #\d+: "([a-f0-9\-]+).*established.*newest')
    STATUS_IPSEC_SA_ESTABLISHED_RE2 = (
        r'\d{3} #\d+: "([a-f0-9\-\/x]+).*established.*newest')

    def __init__(self, conf, process_id, vpnservice, namespace):
        self.conf = conf
        self.id = process_id
        self.updated_pending_status = False
        self.namespace = namespace
        self.connection_status = {}
        self.config_dir = os.path.join(
            self.conf.ipsec.config_base_dir, self.id)
        self.etc_dir = os.path.join(self.config_dir, 'etc')
        self.log_dir = os.path.join(self.config_dir, 'log')
        self.update_vpnservice(vpnservice)
        self.STATUS_PATTERN = re.compile(self.STATUS_RE)
        self.STATUS_NOT_RUNNING_PATTERN = re.compile(
            self.STATUS_NOT_RUNNING_RE)
        self.STATUS_IPSEC_SA_ESTABLISHED_PATTERN = re.compile(
            self.STATUS_IPSEC_SA_ESTABLISHED_RE)
        self.STATUS_IPSEC_SA_ESTABLISHED_PATTERN2 = re.compile(
            self.STATUS_IPSEC_SA_ESTABLISHED_RE2)
        self.STATUS_MAP = self.STATUS_DICT

    def translate_dialect(self):
        if not self.vpnservice:
            return
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            self._dialect(ipsec_site_conn, 'initiator')
            self._dialect(ipsec_site_conn['ikepolicy'], 'ike_version')
            for key in ['encryption_algorithm',
                        'auth_algorithm',
                        'pfs']:
                self._dialect(ipsec_site_conn['ikepolicy'], key)
                self._dialect(ipsec_site_conn['ipsecpolicy'], key)
            if (('local_id' not in ipsec_site_conn.keys()) or
                (not ipsec_site_conn['local_id'])):
                ipsec_site_conn['local_id'] = ipsec_site_conn['external_ip']

    def base64_encode_psk(self):
        if not self.vpnservice:
            return
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            psk = ipsec_site_conn['psk']
            encoded_psk = base64.b64encode(encodeutils.safe_encode(psk))
            # NOTE(huntxu): base64.b64encode returns an instance of 'bytes'
            # in Python 3, convert it to a str. For Python 2, after calling
            # safe_decode, psk is converted into a unicode not containing any
            # non-ASCII characters so it doesn't matter.
            psk = encodeutils.safe_decode(encoded_psk, incoming='utf_8')
            ipsec_site_conn['psk'] = PSK_BASE64_PREFIX + psk

    def get_ns_wrapper(self):
        """
        Check if we're inside a virtualenv. If we are, then we should
        respect this and launch wrapper from venv as well.
        """
        if (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)):
            ns_wrapper = os.path.join(sys.prefix, "bin/", self.NS_WRAPPER)
        else:
            ns_wrapper = self.NS_WRAPPER
        return ns_wrapper

    def update_vpnservice(self, vpnservice):
        self.vpnservice = vpnservice
        self.translate_dialect()
        self.base64_encode_psk()

    def _dialect(self, obj, key):
        obj[key] = self.DIALECT_MAP.get(obj[key], obj[key])

    @abc.abstractmethod
    def ensure_configs(self):
        pass

    def ensure_config_file(self, kind, template, vpnservice, file_mode=None):
        """Update config file,  based on current settings for service."""
        config_str = self._gen_config_content(template, vpnservice)
        config_file_name = self._get_config_filename(kind)
        if file_mode is None:
            file_utils.replace_file(config_file_name, config_str)
        else:
            file_utils.replace_file(config_file_name, config_str, file_mode)

    def remove_config(self):
        """Remove whole config file."""
        agent_utils.execute(
            cmd=["rm", "-rf", self.config_dir], run_as_root=True)

    def _get_config_filename(self, kind):
        config_dir = self.etc_dir
        return os.path.join(config_dir, kind)

    def ensure_config_dir(self, vpnservice):
        """Create config directory if it does not exist."""
        fileutils.ensure_tree(self.config_dir, 0o755)
        for subdir in self.CONFIG_DIRS:
            dir_path = os.path.join(self.config_dir, subdir)
            fileutils.ensure_tree(dir_path, 0o755)

    def _gen_config_content(self, template_file, vpnservice):
        template = _get_template(template_file)
        return template.render(
            {'vpnservice': vpnservice,
             'state_path': self.conf.state_path})

    def _get_rootwrap_config(self):
        if 'neutron-rootwrap' in cfg.CONF.AGENT.root_helper:
            rh_tokens = cfg.CONF.AGENT.root_helper.split(' ')
            if len(rh_tokens) == 3 and os.path.exists(rh_tokens[2]):
                return rh_tokens[2]
        return None

    @abc.abstractmethod
    def get_status(self):
        pass

    @property
    def status(self):
        if self.active:
            return constants.ACTIVE
        return constants.DOWN

    @property
    def active(self):
        """Check if the process is active or not."""
        if not self.namespace:
            return False
        try:
            status = self.get_status()
            self._extract_and_record_connection_status(status)
            if not self.connection_status:
                return False
        except RuntimeError:
            return False
        return True

    def update(self):
        """Update Status based on vpnservice configuration."""

        # Disable the process if a vpnservice is disabled or it has no
        # enabled IPSec site connections.
        vpnservice_has_active_ipsec_site_conns = any(
            ipsec_site_conn['admin_state_up']
            for ipsec_site_conn in self.vpnservice['ipsec_site_connections'])
        if (not self.vpnservice['admin_state_up'] or
                not vpnservice_has_active_ipsec_site_conns):
            self.disable()
        else:
            self.enable()

        if plugin_utils.in_pending_status(self.vpnservice['status']):
            self.updated_pending_status = True

        self.vpnservice['status'] = self.status
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            if plugin_utils.in_pending_status(ipsec_site_conn['status']):
                conn_id = ipsec_site_conn['id']
                conn_status = self.connection_status.get(conn_id)
                if not conn_status:
                    continue
                conn_status['updated_pending_status'] = True
                ipsec_site_conn['status'] = conn_status['status']

    def enable(self):
        """Enabling the process."""
        try:
            self.ensure_configs()
            if self.active:
                self.restart()
            else:
                self.start()
        except RuntimeError:
            LOG.exception(
                "Failed to enable vpn process on router %s",
                self.id)

    def disable(self):
        """Disabling the process."""
        try:
            if self.active:
                self.stop()
            self.remove_config()
        except RuntimeError:
            LOG.exception(
                "Failed to disable vpn process on router %s",
                self.id)

    @abc.abstractmethod
    def restart(self):
        """Restart process."""

    @abc.abstractmethod
    def start(self):
        """Start process."""

    @abc.abstractmethod
    def stop(self):
        """Stop process."""

    def _check_status_line(self, line):
        """Parse a line and search for status information.

        If a connection has an established Security Association,
        it will be considered ACTIVE. Otherwise, even if a status
        line shows that a connection is active, it will be marked
        as DOWN-ed.
        """

        # pluto is not running so just exit
        if self.STATUS_NOT_RUNNING_PATTERN.search(line):
            self.connection_status = {}
            raise StopIteration()

        m = self.STATUS_IPSEC_SA_ESTABLISHED_PATTERN.search(line)
        if m:
            connection_id = m.group(1)
            return connection_id, constants.ACTIVE
        else:
            m = self.STATUS_PATTERN.search(line)
            if m:
                connection_id = m.group(1)
                return connection_id, constants.DOWN
        return None, None

    def _extract_and_record_connection_status(self, status_output):
        if not status_output:
            self.connection_status = {}
            return
        for line in status_output.split('\n'):
            try:
                conn_id, conn_status = self._check_status_line(line)
            except StopIteration:
                break
            if conn_id:
                self._record_connection_status(conn_id, conn_status)

    def _record_connection_status(self, connection_id, status,
                                  force_status_update=False):
        conn_info = self.connection_status.get(connection_id)
        if not conn_info:
            self.connection_status[connection_id] = {
                'status': status,
                'updated_pending_status': force_status_update
            }
        else:
            conn_info['status'] = status
            if force_status_update:
                conn_info['updated_pending_status'] = True


class IPsecVpnDriverApi:
    """IPSecVpnDriver RPC api."""

    @log_helpers.log_method_call
    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    @log_helpers.log_method_call
    def get_vpn_services_on_host(self, context, host):
        """Get list of vpnservices.

        The vpnservices including related ipsec_site_connection,
        ikepolicy and ipsecpolicy on this host
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vpn_services_on_host', host=host)

    @log_helpers.log_method_call
    def update_status(self, context, status):
        """Update local status.

        This method call updates status attribute of
        VPNServices.
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_status', status=status)


class IPsecDriver(device_drivers.DeviceDriver, metaclass=abc.ABCMeta):
    """VPN Device Driver for IPSec.

    This class is designed for use with L3-agent now.
    However this driver will be used with another agent in future
    so the use of "Router" is kept minimal now.
    Instead of router_id, we are using process_id in this code.
    """

    # history
    #   1.0 Initial version
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, vpn_service, host):
        # TODO(pc_m) Replace vpn_service with config arg, once all driver
        # implementations no longer need vpn_service.
        self.conf = vpn_service.conf
        self.host = host
        self.conn = n_rpc.Connection()
        self.context = context.get_admin_context_without_session()
        self.topic = topics.IPSEC_AGENT_TOPIC
        node_topic = '{}.{}'.format(self.topic, self.host)

        self.processes = {}
        self.routers: ty.Dict[str, ty.Any] = {}
        self.process_status_cache = {}

        self.endpoints = [self]
        self.conn.create_consumer(node_topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = IPsecVpnDriverApi(topics.IPSEC_DRIVER_TOPIC)
        self.process_status_cache_check = loopingcall.FixedIntervalLoopingCall(
            self.report_status, self.context)
        self.process_status_cache_check.start(
            interval=self.conf.ipsec.ipsec_status_check_interval)

    def get_namespace(self, router_id):
        """Get namespace of router.

        :router_id: router_id
        :returns: namespace string.
            Note: If the router is a DVR, then the SNAT namespace will be
                  provided. If the router does not exist, return None.
        """
        router_info = self.routers.get(router_id)
        if not router_info:
            return
        # For DVR, use SNAT namespace
        # TODO(pcm): Use router object method to tell if DVR, when available
        if router_info.router['distributed']:
            return router_info.snat_namespace.name
        return router_info.ns_name

    def get_router_based_iptables_manager(self, ri):
        """Returns router based iptables manager

        In DVR routers the IPsec VPN service should run inside
        the snat namespace. So the iptables manager used for
        snat namespace is different from the iptables manager
        used for the qr namespace in a non dvr based router.

        This function will check the router type and then will
        return the right iptables manager. If DVR enabled router
        it will return the snat_iptables_manager otherwise it will
        return the legacy iptables_manager.
        """
        # TODO(pcm): Use router object method to tell if DVR, when available
        if ri.router['distributed']:
            return ri.snat_iptables_manager
        return ri.iptables_manager

    def ensure_nat_rules(self, vpnservice):
        """Ensure the required nat rules for ipsec exist in iptables.

        :param vpnservice: vpnservices
        """
        LOG.debug("ensure_nat_rules called for router %s",
                  vpnservice['router_id'])
        ri = self.routers.get(vpnservice['router_id'])
        if not ri:
            LOG.debug("No router info for router %s", vpnservice['router_id'])
            return

        iptables_manager = self.get_router_based_iptables_manager(ri)
        # clear all existing rules first
        LOG.debug("Clearing vpnaas tagged NAT rules for router %s",
                  ri.router_id)
        iptables_manager.ipv4['nat'].clear_rules_by_tag('vpnaas')

        for ipsec_site_connection in vpnservice['ipsec_site_connections']:
            for local_cidr in ipsec_site_connection['local_cidrs']:
                # This ipsec rule is not needed for ipv6.
                if netaddr.IPNetwork(local_cidr).version == 6:
                    continue

                for peer_cidr in ipsec_site_connection['peer_cidrs']:
                    LOG.debug("Adding an ipsec policy NAT rule"
                              "%s <-> %s to router id %s",
                              peer_cidr, local_cidr, vpnservice['router_id'])

                    iptables_manager.ipv4['nat'].add_rule(
                        'POSTROUTING',
                        '-s %s -d %s -m policy '
                        '--dir out --pol ipsec '
                        '-j ACCEPT ' % (local_cidr, peer_cidr),
                        top=True, tag='vpnaas')

        LOG.debug("Applying iptables for router id %s",
                  vpnservice['router_id'])
        iptables_manager.apply()

    @log_helpers.log_method_call
    def remove_nat_rules(self, router_id):
        """Remove all our iptables rules in namespace.

        :param router_id: router_id
        """
        router = self.routers.get(router_id)
        if not router:
            return
        iptables_manager = self.get_router_based_iptables_manager(router)
        iptables_manager.ipv4['nat'].clear_rules_by_tag('vpnaas')
        iptables_manager.apply()

    @log_helpers.log_method_call
    def vpnservice_updated(self, context, **kwargs):
        """Vpnservice updated rpc handler

        VPN Service Driver will call this method
        when vpnservices updated.
        Then this method start sync with server.
        """
        router = kwargs.get('router', None)
        self.sync(context, [router] if router else [])

    @abc.abstractmethod
    def create_process(self, process_id, vpnservice, namespace):
        pass

    def ensure_process(self, process_id, vpnservice=None):
        """Ensuring process.

        If the process doesn't exist, it will create process
        and store it in self.process
        """
        process = self.processes.get(process_id)
        if not process or not process.namespace:
            namespace = self.get_namespace(process_id)
            process = self.create_process(
                process_id,
                vpnservice,
                namespace)
            self.processes[process_id] = process
        elif vpnservice:
            process.update_vpnservice(vpnservice)
        return process

    def create_router(self, router_info: RouterInfo):
        """Handling create router event.

        Agent calls this method, when the process namespace is ready.
        Note: process_id == router_id == vpnservice_id
        """
        process_id = router_info.router_id
        self.routers[process_id] = router_info
        if process_id in self.processes:
            # In case of vpnservice is created
            # before router's namespace
            process = self.processes[process_id]
            self.ensure_nat_rules(process.vpnservice)
            # Don't run ipsec process for backup HA router
            if router_info.router['ha'] and router_info.ha_state == 'backup':
                return
            process.enable()

    def destroy_process(self, process_id):
        """Destroy process.

        Disable the process, remove the iptables rules, and remove the process
        manager for the processes that no longer are running vpn service.
        """
        if process_id in self.processes:
            process = self.processes[process_id]
            process.disable()
            vpnservice = process.vpnservice
            if vpnservice:
                self.remove_nat_rules(process_id)
            del self.processes[process_id]

    def destroy_router(self, process_id):
        """Handling destroy_router event.

        Agent calls this method, when the process namespace
        is deleted.
        """
        self.destroy_process(process_id)
        if process_id in self.routers:
            del self.routers[process_id]

    def get_process_status_cache(self, process):
        if not self.process_status_cache.get(process.id):
            self.process_status_cache[process.id] = {
                'status': None,
                'id': process.vpnservice['id'],
                'updated_pending_status': False,
                'ipsec_site_connections': {}}
        return self.process_status_cache[process.id]

    def is_status_updated(self, process, previous_status):
        if process.updated_pending_status:
            return True
        if process.status != previous_status['status']:
            return True
        if (process.connection_status !=
            previous_status['ipsec_site_connections']):
            return True

    def unset_updated_pending_status(self, process):
        process.updated_pending_status = False
        for connection_status in process.connection_status.values():
            connection_status['updated_pending_status'] = False

    def copy_process_status(self, process):
        return {
            'id': process.vpnservice['id'],
            'status': process.status,
            'updated_pending_status': process.updated_pending_status,
            'ipsec_site_connections': copy.deepcopy(process.connection_status)
        }

    def update_downed_connections(self, process_id, new_status):
        """Update info to be reported, if connections just went down.

        If there is no longer any information for a connection, because it
        has been removed (e.g. due to an admin down of VPN service or IPSec
        connection), but there was previous status information for the
        connection, mark the connection as down for reporting purposes.
        """
        if process_id in self.process_status_cache:
            for conn in self.process_status_cache[process_id][IPSEC_CONNS]:
                if conn not in new_status[IPSEC_CONNS]:
                    new_status[IPSEC_CONNS][conn] = {
                        'status': constants.DOWN,
                        'updated_pending_status': True
                    }

    def should_be_reported(self, context, process):
        if (context.is_admin or
            process.vpnservice["project_id"] == context.project_id):
            return True

    @log_helpers.log_method_call
    def report_status(self, context):
        status_changed_vpn_services = []
        for process_id, process in list(self.processes.items()):
            # NOTE(mnaser): It's not necessary to check status for processes
            #               of a backup L3 agent
            router = self.routers.get(process_id)
            if (router and
                isinstance(router, RouterInfo) and
                router.router['ha'] and
                router.ha_state == 'backup'
                ):
                LOG.debug("%s router in backup state, skipping", process_id)
                continue
            if not self.should_be_reported(context, process):
                continue
            previous_status = self.get_process_status_cache(process)
            if self.is_status_updated(process, previous_status):
                new_status = self.copy_process_status(process)
                self.update_downed_connections(process.id, new_status)
                status_changed_vpn_services.append(new_status)
                self.process_status_cache[process.id] = (
                    self.copy_process_status(process))
                # We need unset updated_pending status after it
                # is reported to the server side
                self.unset_updated_pending_status(process)

        if status_changed_vpn_services:
            self.agent_rpc.update_status(
                context,
                status_changed_vpn_services)

    @log_helpers.log_method_call
    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, router_information: ty.List):
        """Sync status with server side.

        :param context: context object for RPC call
        :param router_information: RouterInfo objects with updated state

        There could be many failure cases should be
        considered including the followings.
        1) Agent class restarted
        2) Failure on process creation
        3) VpnService is deleted during agent down
        4) RPC failure

        In order to handle these failure cases,
        This driver takes simple sync strategies.
        """
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host)
        router_ids = [vpnservice['router_id'] for vpnservice in vpnservices]
        sync_router_ids = []

        for ri in router_information:
            # Update our router_info with the updated one
            router_id = None
            if isinstance(ri, RouterInfo):
                if ri.router_id:
                    router_id = ri.router_id
                    self.routers[router_id] = ri
            elif isinstance(ri, dict):
                router_id = ri.get("id")

            if router_id:
                sync_router_ids.append(router_id)

        self._sync_vpn_processes(vpnservices, sync_router_ids)
        self._delete_vpn_processes(sync_router_ids, router_ids)
        self._cleanup_stale_vpn_processes(router_ids)

        self.report_status(context)

    def _sync_vpn_processes(self, vpnservices, sync_router_ids):
        # Ensure the ipsec process is enabled only for
        # - the vpn services which are not yet in self.processes
        # - vpn services whose router id is in 'sync_router_ids'
        for vpnservice in vpnservices:
            if vpnservice['router_id'] not in self.processes or (
                    vpnservice['router_id'] in sync_router_ids):
                process = self.ensure_process(vpnservice['router_id'],
                                              vpnservice=vpnservice)
                self.ensure_nat_rules(vpnservice)
                ri = self.routers.get(vpnservice['router_id'])
                if not ri:
                    continue
                # For HA router, spawn vpn process on master router
                # and terminate vpn process on backup router
                if ri.router['ha'] and ri.ha_state == 'backup':
                    process.disable()
                else:
                    process.update()

    def _delete_vpn_processes(self, sync_router_ids, vpn_router_ids):
        # Delete any IPSec processes that are
        # associated with routers, but are not running the VPN service.
        for process_id in sync_router_ids:
            if process_id not in vpn_router_ids:
                self.destroy_process(process_id)

    def _cleanup_stale_vpn_processes(self, vpn_router_ids):
        # Delete any IPSec processes running
        # VPN that do not have an associated router.
        process_ids = [pid for pid in self.processes
                       if pid not in vpn_router_ids]
        for process_id in process_ids:
            self.destroy_process(process_id)
