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

import collections
import copy
import functools
from unittest import mock

import netaddr
from neutron.agent.common import ovs_lib
from neutron.agent.l3 import l3_agent_extensions_manager as ext_manager
from neutron.agent.l3 import namespaces as n_namespaces
from neutron.agent.l3 import router_info
from neutron.agent import l3_agent as l3_agent_main
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import config as common_config
from neutron.common import utils as common_utils
from neutron.conf.agent import common as agent_config
from neutron.conf import common as conf_common
from neutron.services.provider_configuration import serviceprovider_opts
from neutron.tests.common import l3_test_common
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework
from neutron_lib import constants
from neutron_lib.utils import net as n_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import testtools

from neutron_vpnaas.services.vpn import agent as vpn_agent
from neutron_vpnaas.services.vpn.agent import vpn_agent_opts
from neutron_vpnaas.services.vpn.device_drivers import ipsec


_uuid = uuidutils.generate_uuid
FAKE_IKE_POLICY = {
    'auth_algorithm': 'sha1',
    "ike_version": "v1",
    'encryption_algorithm': 'aes-128',
    'pfs': 'group5',
    'phase1_negotiation_mode': 'main',
    'lifetime_units': 'seconds',
    'lifetime_value': 3600
}

FAKE_IPSEC_POLICY = {
    "encapsulation_mode": "tunnel",
    "encryption_algorithm": "aes-128",
    "pfs": "group5",
    "lifetime_units": "seconds",
    "lifetime_value": 3600,
    "transform_protocol": "esp",
    "auth_algorithm": "sha1",
}

FAKE_VPN_SERVICE = {
    "id": _uuid(),
    "router_id": _uuid(),
    "status": constants.PENDING_CREATE,
    "admin_state_up": True,
    'external_ip': "172.24.4.8"
}

FAKE_IPSEC_CONNECTION = {
    "vpnservice_id": _uuid(),
    "status": "PENDING_CREATE",
    "psk": "969022489",
    "initiator": "bi-directional",
    "admin_state_up": True,
    "auth_mode": "psk",
    'external_ip': "172.24.4.8",
    "peer_cidrs": ["10.100.255.224/28"],
    "mtu": 1500,
    "dpd_action": "hold",
    "dpd_interval": 30,
    "dpd_timeout": 120,
    "route_mode": "static",
    "ikepolicy": FAKE_IKE_POLICY,
    "ipsecpolicy": FAKE_IPSEC_POLICY,
    "peer_address": "172.24.4.8",
    "peer_id": "172.24.4.8",
    "id": _uuid()
}


FAKE_IKE_POLICY_SHA256 = {
    'auth_algorithm': 'sha256',
    "ike_version": "v1",
    'encryption_algorithm': 'aes-128',
    'pfs': 'group5',
    'phase1_negotiation_mode': 'main',
    'lifetime_units': 'seconds',
    'lifetime_value': 3600
}

FAKE_IPSEC_POLICY_SHA256 = {
    "encapsulation_mode": "tunnel",
    "encryption_algorithm": "aes-128",
    "pfs": "group5",
    "lifetime_units": "seconds",
    "lifetime_value": 3600,
    "transform_protocol": "esp",
    "auth_algorithm": "sha256",
}

FAKE_IPSEC_CONNECTION_SHA256 = {
    "vpnservice_id": _uuid(),
    "status": "PENDING_CREATE",
    "psk": "969022489",
    "initiator": "bi-directional",
    "admin_state_up": True,
    "auth_mode": "psk",
    'external_ip': "172.24.4.8",
    "peer_cidrs": ["10.100.255.224/28"],
    "mtu": 1500,
    "dpd_action": "hold",
    "dpd_interval": 30,
    "dpd_timeout": 120,
    "route_mode": "static",
    "ikepolicy": FAKE_IKE_POLICY_SHA256,
    "ipsecpolicy": FAKE_IPSEC_POLICY_SHA256,
    "peer_address": "172.24.4.8",
    "peer_id": "172.24.4.8",
    "id": _uuid()
}

PUBLIC_NET = netaddr.IPNetwork('19.4.4.0/24')
PRIVATE_NET = netaddr.IPNetwork('35.4.0.0/16')
FAKE_PUBLIC_SUBNET_ID = _uuid()
FAKE_PRIVATE_SUBNET_ID = _uuid()

FAKE_ROUTER = {
    'enable_snat': True,
    'gw_port': {
        'network_id': _uuid(),
        'subnets': [
            {
                'cidr': str(PUBLIC_NET),
                'gateway_ip': str(PUBLIC_NET[1]),
                'id': FAKE_PUBLIC_SUBNET_ID
            }
        ],
        'fixed_ips': [
            {
                'subnet_id': FAKE_PUBLIC_SUBNET_ID,
                'prefixlen': PUBLIC_NET.prefixlen,
            }
        ],
    },
    'distributed': False,
    '_floatingips': [],
    'routes': []
}

# It's a long name.
NON_ASCII_VPNSERVICE_NAME = u'\u9577\u3044\u540d\u524d\u3067\u3059'
# I'm doing very well.
NON_ASCII_PSK = u'\u00e7a va tr\u00e9s bien'


def get_ovs_bridge(br_name):
    return ovs_lib.OVSBridge(br_name)


Vm = collections.namedtuple('Vm', ['namespace', 'port_ip'])


class SiteInfo(object):

    """Holds info on the router, ports, service, and connection."""

    def __init__(self, public_net, private_nets):
        self.public_net = public_net
        self.private_nets = private_nets
        self.generate_router_info()
        self._prepare_vpn_service_info()

    def _get_random_mac(self):
        mac_base = cfg.CONF.base_mac.split(':')
        return n_utils.get_random_mac(mac_base)

    def _generate_private_interface_for_router(self, subnet):
        subnet_id = _uuid()
        return {
            'id': _uuid(),
            'admin_state_up': True,
            'network_id': _uuid(),
            'mtu': 1500,
            'mac_address': self._get_random_mac(),
            'subnets': [
                {
                    'ipv6_ra_mode': None,
                    'cidr': str(subnet),
                    'gateway_ip': str(subnet[1]),
                    'id': subnet_id,
                    'ipv6_address_mode': None
                }
            ],
            'fixed_ips': [
                {
                    'subnet_id': subnet_id,
                    'prefixlen': 24,
                    'ip_address': str(subnet[4])
                }
            ]
        }

    def generate_router_info(self):
        self.info = copy.deepcopy(FAKE_ROUTER)
        self.info['id'] = _uuid()
        self.info['project_id'] = _uuid()
        self.info['_interfaces'] = [
            self._generate_private_interface_for_router(subnet)
            for subnet in self.private_nets]
        self.info['gw_port']['id'] = _uuid()
        self.info['gw_port']['fixed_ips'][0]['ip_address'] = str(
            self.public_net)
        self.info['gw_port']['mac_address'] = self._get_random_mac()
        self.info['ha'] = False

    def _prepare_vpn_service_info(self):
        self.vpn_service = copy.deepcopy(FAKE_VPN_SERVICE)
        self.vpn_service.update({'id': _uuid(),
                                 'router_id': self.info['id'],
                                 'external_ip': str(self.public_net)})

    def prepare_ipsec_conn_info(self, peer, connection=FAKE_IPSEC_CONNECTION,
                                local_id=None, peer_id=None):
        ipsec_connection = copy.deepcopy(connection)
        local_cidrs = [str(s) for s in self.private_nets]
        peer_cidrs = [str(s) for s in peer.private_nets]
        ipsec_connection.update({
            'id': _uuid(),
            'vpnservice_id': self.vpn_service['id'],
            'external_ip': self.vpn_service['external_ip'],
            'peer_cidrs': peer_cidrs,
            'peer_address': peer.vpn_service['external_ip'],
            'peer_id': peer.vpn_service['external_ip'],
            'local_cidrs': local_cidrs,
            'local_ip_vers': 4
        })
        if local_id:
            ipsec_connection['local_id'] = local_id
        if peer_id:
            ipsec_connection['peer_id'] = peer_id
        self.vpn_service['ipsec_site_connections'] = [ipsec_connection]


class SiteInfoWithHaRouter(SiteInfo):

    def __init__(self, public_net, private_nets, host, failover_host):
        self.host = host
        self.failover_host = failover_host
        self.get_ns_name = mock.patch.object(n_namespaces.RouterNamespace,
                                             '_get_ns_name').start()
        super(SiteInfoWithHaRouter, self).__init__(public_net, private_nets)

    def generate_router_info(self):
        super(SiteInfoWithHaRouter, self).generate_router_info()
        self.info['ha'] = True
        self.info['ha_vr_id'] = 1
        self.info[constants.HA_INTERFACE_KEY] = (
            l3_test_common.get_ha_interface())
        # Mock router namespace name, for when router is created
        self.get_ns_name.return_value = "qrouter-{0}-{1}".format(
            self.info['id'], self.host)

    def generate_backup_router_info(self):
        # Clone router info, using different HA interface (using same ID)
        info = copy.deepcopy(self.info)
        info[constants.HA_INTERFACE_KEY] = (
            l3_test_common.get_ha_interface(ip='169.254.192.2',
                                            mac='22:22:22:22:22:22'))
        # Mock router namespace name, for when router is created
        self.get_ns_name.return_value = "qrouter-{0}-{1}".format(
            info['id'], self.failover_host)
        return info


class TestIPSecBase(framework.L3AgentTestFramework):
    NESTED_NAMESPACE_SEPARATOR = '@'

    def setUp(self):
        super(TestIPSecBase, self).setUp()
        common_config.register_common_config_options()
        mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.'
            'IPsecVpnDriverApi').start()
        # avoid report_status running periodically
        mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall').start()
        # Both the vpn agents try to use execute_rootwrap_daemon's socket
        # simultaneously during test cleanup, but execute_rootwrap_daemon has
        # limitations with simultaneous reads. So avoid using
        # root_helper_daemon and instead use root_helper
        # https://bugs.launchpad.net/neutron/+bug/1482622
        cfg.CONF.set_override('root_helper_daemon', None, group='AGENT')

        # Mock the method below because it causes Exception:
        #   RuntimeError: Second simultaneous read on fileno 5 detected.
        #   Unless you really know what you're doing, make sure that only
        #   one greenthread can read any particular socket.  Consider using
        #   a pools.Pool. If you do know what you're doing and want to disable
        #   this error, call eventlet.debug.hub_prevent_multiple_readers(False)
        # Can reproduce the exception in the test only
        ip_lib.send_ip_addr_adv_notif = mock.Mock()

        self.vpn_agent = vpn_agent.L3WithVPNaaS(self.conf)
        self.driver = self.vpn_agent.device_drivers[0]
        self.driver.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[])
        self.driver.report_status = mock.Mock()

        self.private_nets = list(PRIVATE_NET.subnet(24))

    def _connect_agents(self, agent1, agent2):
        """Simulate both agents in the same host.

         For packet flow between resources connected to these two agents,
         agent's ovs bridges are connected through patch ports.
        """
        br_int_1 = get_ovs_bridge(agent1.conf.OVS.integration_bridge)
        br_int_2 = get_ovs_bridge(agent2.conf.OVS.integration_bridge)
        net_helpers.create_patch_ports(br_int_1, br_int_2)

    def _get_config_opts(self):
        """Register default config options"""
        config = cfg.ConfigOpts()
        config.register_opts(conf_common.core_opts)
        config.register_opts(conf_common.core_cli_opts)
        config.register_opts(serviceprovider_opts, 'service_providers')
        config.register_opts(vpn_agent_opts, 'vpnagent')
        config.register_opts(ipsec.ipsec_opts, 'ipsec')
        config.register_opts(ipsec.openswan_opts, 'openswan')

        logging.register_options(config)
        agent_config.register_process_monitor_opts(config)
        ext_manager.register_opts(config)
        return config

    def _configure_agent(self, host):
        """Override specific config options"""
        config = self._get_config_opts()
        l3_agent_main.register_opts(config)
        cfg.CONF.set_override('debug', True)
        agent_config.setup_logging()
        config.set_override('extensions', ['vpnaas'], 'agent')
        config.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')

        br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        config.set_override('integration_bridge', br_int.br_name, 'OVS')

        temp_dir = self.get_new_temp_dir()
        get_temp_file_path = functools.partial(self.get_temp_file_path,
                                               root=temp_dir)
        config.set_override('state_path', temp_dir.path)
        config.set_override('metadata_proxy_socket',
                          get_temp_file_path('metadata_proxy'))
        config.set_override('ha_confs_path',
                          get_temp_file_path('ha_confs'))
        config.set_override('external_pids',
                          get_temp_file_path('external/pids'))
        config.set_override('host', host)
        ipsec_config_base_dir = '%s/%s' % (temp_dir.path, 'ipsec')
        config.set_override('config_base_dir',
                          ipsec_config_base_dir, group='ipsec')

        # Assign ip address to br-int port because it is a gateway
        ex_port = ip_lib.IPDevice(br_int.br_name)
        ex_port.addr.add(str(PUBLIC_NET[1]))

        return config

    def _setup_failover_agent(self):
        self.failover_agent = self._configure_agent('agent2')
        self._connect_agents(self.vpn_agent, self.failover_agent)
        self.failover_driver = self.failover_agent.device_drivers[0]
        self.failover_driver.agent_rpc.get_vpn_services_on_host = (
            mock.Mock(return_value=[]))
        self.failover_driver.report_status = mock.Mock()

    def create_router(self, agent, info):
        """Create router for agent from router info."""
        self.addCleanup(agent._safe_router_removed, info['id'])

        # Generate unique internal and external router device names using the
        # agent's hostname. This is to allow multiple HA router replicas to
        # co-exist on the same machine, otherwise they'd all use the same
        # device names and OVS would freak out(OVS won't allow a port with
        # same name connected to two bridges).
        def _append_suffix(dev_name):
            # If dev_name = 'xyz123' and the suffix is 'agent2' then the result
            # will be 'xy-nt2'
            return "{0}-{1}".format(dev_name[:-4], agent.host[-3:])

        def get_internal_device_name(port_id):
            return _append_suffix(
                (n_namespaces.INTERNAL_DEV_PREFIX + port_id)
                [:interface.LinuxInterfaceDriver.DEV_NAME_LEN])

        def get_external_device_name(port_id):
            return _append_suffix(
                (n_namespaces.EXTERNAL_DEV_PREFIX + port_id)
                [:interface.LinuxInterfaceDriver.DEV_NAME_LEN])

        mock_get_internal_device_name = mock.patch.object(
            router_info.RouterInfo, 'get_internal_device_name').start()
        mock_get_internal_device_name.side_effect = get_internal_device_name
        mock_get_external_device_name = mock.patch.object(
            router_info.RouterInfo, 'get_external_device_name').start()
        mock_get_external_device_name.side_effect = get_external_device_name

        # NOTE(huntxu): with commit 88f5e11d8bf, neutron plugs new ports as
        # dead vlan(4095). During functional tests, all the ports are untagged.
        # So need to remove such tag during functional testing.
        original_plug_new = interface.OVSInterfaceDriver.plug_new

        def plug_new(self, *args, **kwargs):
            original_plug_new(self, *args, **kwargs)
            bridge = (kwargs.get('bridge') or args[4] or
                      self.conf.OVS.integration_bridge)
            device_name = kwargs.get('device_name') or args[2]
            ovsbr = ovs_lib.OVSBridge(bridge)
            ovsbr.clear_db_attribute('Port', device_name, 'tag')

        with mock.patch(
            'neutron.agent.linux.interface.OVSInterfaceDriver.plug_new',
            autospec=True
        ) as ovs_plug_new:
            ovs_plug_new.side_effect = plug_new
            agent._process_added_router(info)

        return agent.router_info[info['id']]

    def _port_first_ip_cidr(self, port):
        fixed_ip = port['fixed_ips'][0]
        return common_utils.ip_to_cidr(fixed_ip['ip_address'],
                                       fixed_ip['prefixlen'])

    def create_ports_for(self, site):
        """Creates namespaces and ports for simulated VM.

        There will be a unique namespace for each port, which is representing
        a VM for the test.
        """
        bridge = get_ovs_bridge(self.vpn_agent.conf.OVS.integration_bridge)
        site.vm = []
        for internal_port in site.router.internal_ports:
            router_ip_cidr = self._port_first_ip_cidr(internal_port)
            port_ip_cidr = net_helpers.increment_ip_cidr(router_ip_cidr, 1)
            client_ns = self.useFixture(
                net_helpers.NamespaceFixture()).ip_wrapper
            namespace = client_ns.namespace
            port = self.useFixture(
                net_helpers.OVSPortFixture(bridge, namespace)).port
            port.addr.add(port_ip_cidr)
            port.route.add_gateway(router_ip_cidr.partition('/')[0])
            site.vm.append(Vm(namespace, port_ip_cidr.partition('/')[0]))

    def create_site(self, public_net, private_nets, l3ha=False):
        """Build router(s), namespaces, and ports for a site.

        For HA, we'll create a backup router and wait for both routers
        to be ready, so that we can test pings after failover.
        """
        if l3ha:
            site = SiteInfoWithHaRouter(public_net, private_nets,
                                        self.agent.host,
                                        self.failover_agent.host)
        else:
            site = SiteInfo(public_net, private_nets)

        site.router = self.create_router(self.agent, site.info)
        if l3ha:
            backup_info = site.generate_backup_router_info()
            site.backup_router = self.create_router(self.failover_agent,
                                                    backup_info)
            linux_utils.wait_until_true(
                lambda: site.router.ha_state in ('master', 'primary'))
            linux_utils.wait_until_true(
                lambda: site.backup_router.ha_state == 'backup')

        self.create_ports_for(site)
        return site

    def prepare_ipsec_site_connections(self, site1, site2):
        """Builds info for connections in both directions in prep for sync."""
        site1.prepare_ipsec_conn_info(site2)
        site2.prepare_ipsec_conn_info(site1)

    def prepare_ipsec_site_connections_sha256(self, site1, site2):
        """Builds info for connections in both directions in prep for sync."""
        site1.prepare_ipsec_conn_info(site2,
                                    FAKE_IPSEC_CONNECTION_SHA256)
        site2.prepare_ipsec_conn_info(site1,
                                    FAKE_IPSEC_CONNECTION_SHA256)

    def prepare_ipsec_site_connections_local_id(self, site1, site2):
        """Builds info for connections in both directions in prep for sync."""
        site1.prepare_ipsec_conn_info(site2, local_id='@site1.com',
                                    peer_id='@site2.com')
        site2.prepare_ipsec_conn_info(site1, local_id='@site2.com',
                                    peer_id='@site1.com')

    def sync_to_create_ipsec_connections(self, site1, site2):
        """Perform a sync, so that connections are created."""
        # Provide service info to sync
        self.driver.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[site1.vpn_service, site2.vpn_service])

        local_router_id = site1.router.router_id
        peer_router_id = site2.router.router_id
        self.driver.sync(mock.Mock(), [{'id': local_router_id},
                                       {'id': peer_router_id}])
        self.agent._process_updated_router(site1.router.router)
        self.agent._process_updated_router(site2.router.router)
        self.addCleanup(self.driver._delete_vpn_processes,
                        [local_router_id, peer_router_id], [])

    def sync_failover_agent(self, site):
        """Perform a sync on failover agent associated w/backup router."""
        self.failover_driver.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[site.vpn_service])
        self.failover_driver.sync(mock.Mock(),
                                  [{'id': site.backup_router.router_id}])

    def check_ping(self, from_site, to_site, instance=0, success=True):
        if success:
            net_helpers.assert_ping(from_site.vm[instance].namespace,
                                    to_site.vm[instance].port_ip,
                                    timeout=8, count=4)
        else:
            net_helpers.assert_no_ping(from_site.vm[instance].namespace,
                                       to_site.vm[instance].port_ip,
                                       timeout=8, count=4)

    def _failover_ha_router(self, router1, router2):
        """Cause a failover of HA router.

        Fail the agent1's HA router. Agent1's HA router will transition
        to backup and agent2's HA router will become master. Wait for
        the failover to complete.
        """
        device_name = router1.get_ha_device_name()
        ha_device = ip_lib.IPDevice(device_name, router1.ns_name)
        ha_device.link.set_down()
        linux_utils.wait_until_true(
            lambda: router2.ha_state in ('master', 'primary'))
        linux_utils.wait_until_true(lambda: router1.ha_state == 'backup')

    def _ipsec_process_exists(self, conf, router, pid_files):
        """Check if *Swan process has started up."""
        for pid_file in pid_files:
            pm = external_process.ProcessManager(
                conf,
                "ipsec",
                router.ns_name, pid_file=pid_file)
            if pm.active:
                break
        return pm.active

    def _wait_for_ipsec_startup(self, router, driver, conf, should_run=True):
        """Wait for new IPSec process on failover agent to start up."""
        # check for both strongswan and openswan processes
        path = driver.processes[router.router_id].config_dir
        pid_files = ['%s/var/run/charon.pid' % path,
                     '%s/var/run/pluto.pid' % path]
        linux_utils.wait_until_true(
            lambda: should_run == self._ipsec_process_exists(
                conf, router, pid_files))

    @staticmethod
    def _update_vpnservice(site, **kwargs):
        site.vpn_service.update(kwargs)

    @staticmethod
    def _update_ipsec_connection(site, **kwargs):
        ipsec_connection = site.vpn_service['ipsec_site_connections'][0]
        ipsec_connection.update(kwargs)


class TestIPSecScenario(TestIPSecBase):

    @testtools.skip('bug/1598466')
    def test_single_ipsec_connection(self):
        site1 = self.create_site(PUBLIC_NET[4], [self.private_nets[1]])
        site2 = self.create_site(PUBLIC_NET[5], [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    @testtools.skip('bug/1598466')
    def test_single_ipsec_connection_sha256(self):
        site1 = self.create_site(PUBLIC_NET[4], [self.private_nets[1]])
        site2 = self.create_site(PUBLIC_NET[5], [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections_sha256(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    @testtools.skip('bug/1598466')
    def test_single_ipsec_connection_local_id(self):
        site1 = self.create_site(PUBLIC_NET[4], [self.private_nets[1]])
        site2 = self.create_site(PUBLIC_NET[5], [self.private_nets[2]])

        self.check_ping(site1, site2, success=False)
        self.check_ping(site2, site1, success=False)

        self.prepare_ipsec_site_connections_local_id(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    @testtools.skip('bug/1598466')
    def test_ipsec_site_connections_with_mulitple_subnets(self):
        """Check with a pair of subnets on each end of connection."""
        site1 = self.create_site(PUBLIC_NET[4], self.private_nets[1:3])
        site2 = self.create_site(PUBLIC_NET[5], self.private_nets[3:5])

        # Just check from each VM, not every combination
        for i in [0, 1]:
            self.check_ping(site1, site2, instance=i, success=False)
            self.check_ping(site2, site1, instance=i, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        for i in [0, 1]:
            self.check_ping(site1, site2, instance=i)
            self.check_ping(site2, site1, instance=i)

    @testtools.skip('bug/1598466')
    def test_ipsec_site_connections_with_l3ha_routers(self):
        """Test ipsec site connection with HA routers.
        This test creates two agents. First agent will have Legacy and HA
        routers. Second agent will host only HA router. We setup ipsec
        connection between legacy and HA router.

        When HA router is created, agent1 will have master router and
        agent2 will have backup router. Ipsec connection will be established
        between legacy router and agent1's master HA router.

        Then we fail the agent1's master HA router. Agent1's HA router will
        transition to backup and agent2's HA router will become master.
        Now ipsec connection will be established between legacy router and
        agent2's master HA router
        """

        self._setup_failover_agent()

        site1 = self.create_site(PUBLIC_NET[4], [self.private_nets[1]])
        site2 = self.create_site(PUBLIC_NET[5], [self.private_nets[2]],
                                 l3ha=True)

        # No ipsec connection between legacy router and HA routers
        self.check_ping(site1, site2, 0, success=False)
        self.check_ping(site2, site1, 0, success=False)

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)
        self.sync_failover_agent(site2)

        # Test ipsec connection between legacy router and agent2's HA router
        self.check_ping(site1, site2, 0)
        self.check_ping(site2, site1, 0)

        self._failover_ha_router(site2.router, site2.backup_router)
        self._wait_for_ipsec_startup(site2.backup_router,
                                     self.failover_driver,
                                     self.failover_agent.conf)

        # Test ipsec connection between legacy router and agent2's HA router
        self.check_ping(site1, site2, 0)
        self.check_ping(site2, site1, 0)

    @testtools.skip('bug/1598466')
    def _test_admin_state_up(self, update_method):
        # Create ipsec connection between two sites
        site1 = self.create_site(PUBLIC_NET[4], [self.private_nets[1]])
        site2 = self.create_site(PUBLIC_NET[5], [self.private_nets[2]])

        self.prepare_ipsec_site_connections(site1, site2)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

        # Disable resource on one of the sites and check that
        # ping no longer passes.
        update_method(site1, admin_state_up=False)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2, 0, success=False)
        self.check_ping(site2, site1, 0, success=False)

        # Validate that ipsec process for the disabled site was terminated.
        self._wait_for_ipsec_startup(site1.router, self.driver,
                                     self.vpn_agent.conf,
                                     should_run=False)

        # Change admin_state_up of the disabled resource back to True and
        # check that everything works again.
        update_method(site1, admin_state_up=True)
        self.sync_to_create_ipsec_connections(site1, site2)

        self.check_ping(site1, site2)
        self.check_ping(site2, site1)

    @testtools.skip('bug/1598466')
    def test_ipsec_site_connections_update_admin_state_up(self):
        """Test updating admin_state_up of ipsec site connections."""

        self._test_admin_state_up(self._update_ipsec_connection)

    @testtools.skip('bug/1598466')
    def test_vpnservice_update_admin_state_up(self):
        """Test updating admin_state_up of a vpn service."""

        self._test_admin_state_up(self._update_vpnservice)
