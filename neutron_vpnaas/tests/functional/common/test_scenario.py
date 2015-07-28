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

import copy
import functools
import mock
import netaddr
import os

from neutron.agent.common import config as agent_config
from neutron.agent.common import ovs_lib
from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_info
from neutron.agent import l3_agent as l3_agent_main
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.plugins.common import constants
from neutron.services.provider_configuration import serviceprovider_opts
from neutron.tests.common import l3_test_common
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils

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
    'external_ip': "172.24.4.8",
    'subnet': {'cidr': "10.100.255.224/28"}
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

PUBLIC_NET = netaddr.IPNetwork('19.4.4.0/24')
PRIVATE_NET = netaddr.IPNetwork('35.4.0.0/16')
FAKE_PUBLIC_SUBNET_ID = _uuid()
FAKE_PRIVATE_SUBNET_ID = _uuid()

MAC_BASE = cfg.CONF.base_mac.split(':')
FAKE_ROUTER = {
    'id': _uuid(),
    '_interfaces': [
        {
            'id': _uuid(),
            'admin_state_up': True,
            'network_id': _uuid(),
            'mac_address': common_utils.get_random_mac(MAC_BASE),
            'subnets': [
                {
                    'ipv6_ra_mode': None,
                    'cidr': str(PRIVATE_NET),
                    'gateway_ip': str(PRIVATE_NET[1]),
                    'id': FAKE_PRIVATE_SUBNET_ID,
                    'ipv6_address_mode': None
                }
            ],
            'fixed_ips': [
                {
                    'subnet_id': FAKE_PRIVATE_SUBNET_ID,
                    'prefixlen': 24,
                    'ip_address': PRIVATE_NET[4]
                }
            ]
        }
    ],
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
                'ip_address': str(PUBLIC_NET[4])
            }
        ],
        'id': _uuid(),
        'mac_address': common_utils.get_random_mac(MAC_BASE)
    },
    'distributed': False,
    '_floatingips': [],
    'routes': []
}


def get_ovs_bridge(br_name):
    return ovs_lib.OVSBridge(br_name)


class TestIPSecBase(base.BaseSudoTestCase):
    vpn_agent_ini = os.environ.get('VPN_AGENT_INI',
                                   '/etc/neutron/vpn_agent.ini')
    NESTED_NAMESPACE_SEPARATOR = '@'

    def setUp(self):
        super(TestIPSecBase, self).setUp()
        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()
        # avoid report_status running periodically
        mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall').start()
        # Both the vpn agents try to use execute_rootwrap_daemon's socket
        # simultaneously during test cleanup, but execute_rootwrap_daemon has
        # limitations with simultaneous reads. So avoid using
        # root_helper_daemon and instead use root_helper
        # https://bugs.launchpad.net/neutron/+bug/1482622
        cfg.CONF.set_override('root_helper_daemon', None, group='AGENT')

        self.fake_vpn_service = copy.deepcopy(FAKE_VPN_SERVICE)
        self.fake_ipsec_connection = copy.deepcopy(FAKE_IPSEC_CONNECTION)

        self.vpn_agent = self._configure_agent('agent1')
        self.driver = self.vpn_agent.device_drivers[0]

    def connect_agents(self, agent1, agent2):
        """Simulate both agents in the same host.

         For packet flow between resources connected to these two agents,
         agent's ovs bridges are connected through patch ports.
        """
        br_int_1 = get_ovs_bridge(agent1.conf.ovs_integration_bridge)
        br_int_2 = get_ovs_bridge(agent2.conf.ovs_integration_bridge)
        net_helpers.create_patch_ports(br_int_1, br_int_2)

        br_ex_1 = get_ovs_bridge(agent1.conf.external_network_bridge)
        br_ex_2 = get_ovs_bridge(agent2.conf.external_network_bridge)
        net_helpers.create_patch_ports(br_ex_1, br_ex_2)

    def _get_config_opts(self):
        """Register default config options"""
        config = cfg.ConfigOpts()
        config.register_opts(common_config.core_opts)
        config.register_opts(common_config.core_cli_opts)
        config.register_opts(serviceprovider_opts, 'service_providers')
        config.register_opts(vpn_agent_opts, 'vpnagent')
        config.register_opts(ipsec.ipsec_opts, 'ipsec')
        config.register_opts(ipsec.openswan_opts, 'openswan')

        logging.register_options(config)
        agent_config.register_process_monitor_opts(config)
        return config

    def _configure_agent(self, host):
        """Override specific config options"""
        config = self._get_config_opts()
        l3_agent_main.register_opts(config)
        cfg.CONF.set_override('debug', True)
        agent_config.setup_logging()
        config.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        config.set_override('router_delete_namespaces', True)

        br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        br_ex = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        config.set_override('ovs_integration_bridge', br_int.br_name)
        config.set_override('external_network_bridge', br_ex.br_name)

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

        config(['--config-file', self.vpn_agent_ini])

        # Assign ip address to br-ex port because it is a gateway
        ex_port = ip_lib.IPDevice(br_ex.br_name)
        ex_port.addr.add(str(PUBLIC_NET[1]))

        return vpn_agent.VPNAgent(host, config)

    def _generate_info(self, public_ip, private_cidr, enable_ha=False):
        """Generate router info"""
        info = copy.deepcopy(FAKE_ROUTER)
        info['id'] = _uuid()
        info['_interfaces'][0]['id'] = _uuid()
        (info['_interfaces'][0]
         ['mac_address']) = common_utils.get_random_mac(MAC_BASE)
        (info['_interfaces'][0]['fixed_ips'][0]
         ['ip_address']) = str(private_cidr[4])
        info['_interfaces'][0]['subnets'][0].update({
            'cidr': str(private_cidr),
            'gateway_ip': str(private_cidr[1])})
        info['gw_port']['id'] = _uuid()
        info['gw_port']['fixed_ips'][0]['ip_address'] = str(public_ip)
        info['gw_port']['mac_address'] = common_utils.get_random_mac(MAC_BASE)
        if enable_ha:
            info['ha'] = True
            info['ha_vr_id'] = 1
            info[l3_constants.HA_INTERFACE_KEY] = (
                l3_test_common.get_ha_interface())
        else:
            info['ha'] = False
        return info

    def manage_router(self, agent, router):
        """Create router from router_info"""
        self.addCleanup(agent._safe_router_removed, router['id'])

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
                (namespaces.INTERNAL_DEV_PREFIX + port_id)
                [:interface.LinuxInterfaceDriver.DEV_NAME_LEN])

        def get_external_device_name(port_id):
            return _append_suffix(
                (namespaces.EXTERNAL_DEV_PREFIX + port_id)
                [:interface.LinuxInterfaceDriver.DEV_NAME_LEN])

        mock_get_internal_device_name = mock.patch.object(
            router_info.RouterInfo, 'get_internal_device_name').start()
        mock_get_internal_device_name.side_effect = get_internal_device_name
        mock_get_external_device_name = mock.patch.object(
            router_info.RouterInfo, 'get_external_device_name').start()
        mock_get_external_device_name.side_effect = get_external_device_name

        agent._process_added_router(router)

        return agent.router_info[router['id']]

    def prepare_vpn_service_info(self, router_id, external_ip, subnet_cidr):
        service = copy.deepcopy(self.fake_vpn_service)
        service.update({
            'id': _uuid(),
            'router_id': router_id,
            'external_ip': str(external_ip),
            'subnet': {'cidr': str(subnet_cidr)}})
        return service

    def prepare_ipsec_conn_info(self, vpn_service, peer_vpn_service):
        ipsec_conn = copy.deepcopy(self.fake_ipsec_connection)
        ipsec_conn.update({
            'id': _uuid(),
            'vpnservice_id': vpn_service['id'],
            'external_ip': vpn_service['external_ip'],
            'peer_cidrs': [peer_vpn_service['subnet']['cidr']],
            'peer_address': peer_vpn_service['external_ip'],
            'peer_id': peer_vpn_service['external_ip']
        })
        vpn_service['ipsec_site_connections'] = [ipsec_conn]

    def port_setup(self, router, bridge=None, offset=1, namespace=None):
        """Creates namespace and a port inside it on a client site."""
        if not namespace:
            client_ns = self.useFixture(
                net_helpers.NamespaceFixture()).ip_wrapper
            namespace = client_ns.namespace
        router_ip_cidr = self._port_first_ip_cidr(router.internal_ports[0])

        port_ip_cidr = net_helpers.increment_ip_cidr(router_ip_cidr, offset)

        if not bridge:
            bridge = get_ovs_bridge(self.vpn_agent.conf.ovs_integration_bridge)

        port = self.useFixture(
            net_helpers.OVSPortFixture(bridge, namespace)).port
        port.addr.add(port_ip_cidr)
        port.route.add_gateway(router_ip_cidr.partition('/')[0])
        return namespace, port_ip_cidr.partition('/')[0]

    def _port_first_ip_cidr(self, port):
        fixed_ip = port['fixed_ips'][0]
        return common_utils.ip_to_cidr(fixed_ip['ip_address'],
                                       fixed_ip['prefixlen'])

    def site_setup(self, router_public_ip, private_net_cidr):
        router_info = self._generate_info(router_public_ip, private_net_cidr)
        router = self.manage_router(self.vpn_agent, router_info)
        port_namespace, port_ip = self.port_setup(router)

        vpn_service = self.prepare_vpn_service_info(
            router.router_id, router_public_ip, private_net_cidr)
        return {"router": router, "port_namespace": port_namespace,
                "port_ip": port_ip, "vpn_service": vpn_service}

    def setup_ha_routers(self, router_public_ip, private_net_cidr):
        """Setup HA master router on agent1 and backup router on agent2"""
        router_info = self._generate_info(router_public_ip,
            private_net_cidr, enable_ha=True)
        get_ns_name = mock.patch.object(
            namespaces.RouterNamespace, '_get_ns_name').start()
        get_ns_name.return_value = "qrouter-{0}-{1}".format(
            router_info['id'], self.vpn_agent.host)

        router1 = self.manage_router(self.vpn_agent, router_info)

        router_info_2 = copy.deepcopy(router_info)
        router_info_2[l3_constants.HA_INTERFACE_KEY] = (
            l3_test_common.get_ha_interface(ip='169.254.192.2',
                                            mac='22:22:22:22:22:22'))
        get_ns_name.return_value = "qrouter-{0}-{1}".format(
            router_info['id'], self.failover_agent.host)
        router2 = self.manage_router(self.failover_agent, router_info_2)

        linux_utils.wait_until_true(lambda: router1.ha_state == 'master')
        linux_utils.wait_until_true(lambda: router2.ha_state == 'backup')

        port_namespace, port_ip = self.port_setup(router1)

        vpn_service = self.prepare_vpn_service_info(
            router1.router_id, router_public_ip, private_net_cidr)
        return {"router1": router1, "router2": router2,
                "port_namespace": port_namespace, "port_ip": port_ip,
                "vpn_service": vpn_service}

    def _fail_ha_router(self, router):
        """Down the HA router."""
        device_name = router.get_ha_device_name()
        ha_device = ip_lib.IPDevice(device_name, router.ns_name)
        ha_device.link.set_down()

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

    def _create_ipsec_site_connection(self, l3ha=False):
        # Mock the method below because it causes Exception:
        #   RuntimeError: Second simultaneous read on fileno 5 detected.
        #   Unless you really know what you're doing, make sure that only
        #   one greenthread can read any particular socket.  Consider using
        #   a pools.Pool. If you do know what you're doing and want to disable
        #   this error, call eventlet.debug.hub_prevent_multiple_readers(False)
        # Can reproduce the exception in the test only
        ip_lib.send_ip_addr_adv_notif = mock.Mock()
        # There are no vpn services yet. get_vpn_services_on_host returns
        # empty list
        self.driver.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[])
        # instantiate network resources "router", "private network"
        private_nets = list(PRIVATE_NET.subnet(24))
        site1 = self.site_setup(PUBLIC_NET[4], private_nets[1])
        if l3ha:
            site2 = self.setup_ha_routers(PUBLIC_NET[5], private_nets[2])
        else:
            site2 = self.site_setup(PUBLIC_NET[5], private_nets[2])
        # build vpn resources
        self.prepare_ipsec_conn_info(site1['vpn_service'],
                                     site2['vpn_service'])
        self.prepare_ipsec_conn_info(site2['vpn_service'],
                                     site1['vpn_service'])

        self.driver.report_status = mock.Mock()
        self.driver.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[site1['vpn_service'],
                          site2['vpn_service']])
        if l3ha:
            self.failover_agent_driver.agent_rpc.get_vpn_services_on_host = (
                mock.Mock(return_value=[]))
            self.failover_agent_driver.report_status = mock.Mock()
            self.failover_agent_driver.agent_rpc.get_vpn_services_on_host = (
                mock.Mock(return_value=[site2['vpn_service']]))

        return site1, site2


class TestIPSecScenario(TestIPSecBase):

    def test_ipsec_site_connections(self):
        site1, site2 = self._create_ipsec_site_connection()

        net_helpers.assert_no_ping(site1['port_namespace'], site2['port_ip'],
                                   timeout=8, count=4)
        net_helpers.assert_no_ping(site2['port_namespace'], site1['port_ip'],
                                   timeout=8, count=4)

        self.driver.sync(mock.Mock(), [{'id': site1['router'].router_id},
                                       {'id': site2['router'].router_id}])
        self.addCleanup(
            self.driver._delete_vpn_processes,
            [site1['router'].router_id, site2['router'].router_id], [])

        net_helpers.assert_ping(site1['port_namespace'], site2['port_ip'],
                                timeout=8, count=4)
        net_helpers.assert_ping(site2['port_namespace'], site1['port_ip'],
                                timeout=8, count=4)

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
        self.failover_agent = self._configure_agent('agent2')
        self.connect_agents(self.vpn_agent, self.failover_agent)

        vpn_agent_driver = self.vpn_agent.device_drivers[0]
        self.failover_agent_driver = self.failover_agent.device_drivers[0]

        site1, site2 = self._create_ipsec_site_connection(l3ha=True)

        router = site1['router']
        router1 = site2['router1']
        router2 = site2['router2']

        # No ipsec connection between legacy router and HA routers
        net_helpers.assert_no_ping(site1['port_namespace'], site2['port_ip'],
                                   timeout=8, count=4)
        net_helpers.assert_no_ping(site2['port_namespace'], site1['port_ip'],
                                   timeout=8, count=4)

        # sync the routers
        vpn_agent_driver.sync(mock.Mock(), [{'id': router.router_id},
                                  {'id': router1.router_id}])
        self.failover_agent_driver.sync(mock.Mock(),
                                        [{'id': router1.router_id}])

        self.addCleanup(
            vpn_agent_driver._delete_vpn_processes,
            [router.router_id, router1.router_id], [])

        # Test ipsec connection between legacy router and agent2's HA router
        net_helpers.assert_ping(site1['port_namespace'], site2['port_ip'],
                                timeout=8, count=4)
        net_helpers.assert_ping(site2['port_namespace'], site1['port_ip'],
                                timeout=8, count=4)

        # Fail the agent1's HA router. Agent1's HA router will transition
        # to backup and agent2's HA router will become master.
        self._fail_ha_router(router1)

        linux_utils.wait_until_true(lambda: router2.ha_state == 'master')
        linux_utils.wait_until_true(lambda: router1.ha_state == 'backup')

        # wait until ipsec process running in failover agent's HA router
        # check for both strongswan and openswan processes
        path = self.failover_agent_driver.processes[
            router2.router_id].config_dir
        pid_files = ['%s/var/run/charon.pid' % path,
                     '%s/var/run/pluto.pid' % path]
        linux_utils.wait_until_true(
            lambda: self._ipsec_process_exists(
                self.failover_agent.conf, router2, pid_files))

        # Test ipsec connection between legacy router and agent2's HA router
        net_helpers.assert_ping(site1['port_namespace'], site2['port_ip'],
                                timeout=8, count=4)
        net_helpers.assert_ping(site2['port_namespace'], site1['port_ip'],
                                timeout=8, count=4)
