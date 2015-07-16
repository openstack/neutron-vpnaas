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
import os

import fixtures
import mock
import netaddr
from neutron.agent.common import config as agent_config
from neutron.agent import l3_agent as l3_agent_main
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import config as common_config
from neutron.common import utils as common_utils
from neutron.plugins.common import constants
from neutron.services.provider_configuration import serviceprovider_opts
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


class RouterFixture(fixtures.Fixture):

    def __init__(self, l3_agent, public_ip, private_cidr):
        self.l3_agent = l3_agent
        self.router_info = self._generate_info(public_ip, private_cidr)
        self.router_id = self.router_info['id']

    def setUp(self):
        super(RouterFixture, self).setUp()
        self.l3_agent._process_added_router(self.router_info)
        self.router = self.l3_agent.router_info[self.router_id]
        self.addCleanup(self.l3_agent._router_removed, self.router_id)

    def _generate_info(self, public_ip, private_cidr):
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
        return info


class TestIPSecScenario(base.BaseSudoTestCase):

    vpn_agent_ini = os.environ.get('VPN_AGENT_INI',
                                   '/etc/neutron/vpn_agent.ini')

    def setUp(self):
        super(TestIPSecScenario, self).setUp()

        mock.patch('neutron.agent.l3.agent.L3PluginApi').start()

        cfg.CONF.set_override('debug', True)
        agent_config.setup_logging()
        config = cfg.ConfigOpts()
        config.register_opts(common_config.core_opts)
        config.register_opts(common_config.core_cli_opts)
        logging.register_options(config)
        agent_config.register_process_monitor_opts(config)
        l3_agent_main.register_opts(config)
        config.set_override(
            'interface_driver',
            'neutron.agent.linux.interface.OVSInterfaceDriver')
        config.set_override('router_delete_namespaces', True)
        config.register_opts(serviceprovider_opts, 'service_providers')
        config.register_opts(vpn_agent_opts, 'vpnagent')
        config.register_opts(ipsec.ipsec_opts, 'ipsec')
        config.register_opts(ipsec.openswan_opts, 'openswan')
        config.set_override('state_path', self.get_new_temp_dir().path)

        self.br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.br_ex = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        config.set_override('ovs_integration_bridge', self.br_int.br_name)
        config.set_override('external_network_bridge', self.br_ex.br_name)

        config(['--config-file', self.vpn_agent_ini])
        self.vpn_agent = vpn_agent.VPNAgent('agent1', config)

        # Assign ip address to br-ex port because it is a gateway
        ex_port = ip_lib.IPDevice(self.br_ex.br_name)
        ex_port.addr.add(str(PUBLIC_NET[1]))

    def prepare_vpn_service_info(self, router_id, external_ip, subnet_cidr):
        service = copy.deepcopy(FAKE_VPN_SERVICE)
        service.update({
            'id': _uuid(),
            'router_id': router_id,
            'external_ip': str(external_ip),
            'subnet': {'cidr': str(subnet_cidr)}})
        return service

    def prepare_ipsec_conn_info(self, vpn_service, peer_vpn_service):
        ipsec_conn = copy.deepcopy(FAKE_IPSEC_CONNECTION)
        ipsec_conn.update({
            'id': _uuid(),
            'vpnservice_id': vpn_service['id'],
            'external_ip': vpn_service['external_ip'],
            'peer_cidrs': [peer_vpn_service['subnet']['cidr']],
            'peer_address': peer_vpn_service['external_ip'],
            'peer_id': peer_vpn_service['external_ip']
        })
        vpn_service['ipsec_site_connections'] = [ipsec_conn]

    def port_setup(self, router):
        """Creates namespace and a port inside it on a client site."""
        client_ns = self.useFixture(net_helpers.NamespaceFixture()).ip_wrapper
        router_ip_cidr = self._port_first_ip_cidr(router.internal_ports[0])

        port_ip_cidr = net_helpers.increment_ip_cidr(router_ip_cidr)
        port = self.useFixture(
            net_helpers.OVSPortFixture(self.br_int, client_ns.namespace)).port
        port.addr.add(port_ip_cidr)
        port.route.add_gateway(router_ip_cidr.partition('/')[0])
        return client_ns.namespace, port_ip_cidr.partition('/')[0]

    def _port_first_ip_cidr(self, port):
        fixed_ip = port['fixed_ips'][0]
        return common_utils.ip_to_cidr(fixed_ip['ip_address'],
                                       fixed_ip['prefixlen'])

    def site_setup(self, router_public_ip, private_net_cidr):
        router = self.useFixture(
            RouterFixture(self.vpn_agent, router_public_ip,
                          private_net_cidr)).router
        port_namespace, port_ip = self.port_setup(router)

        vpn_service = self.prepare_vpn_service_info(
            router.router_id, router_public_ip, private_net_cidr)
        return {"router": router, "port_namespace": port_namespace,
                "port_ip": port_ip, "vpn_service": vpn_service}

    def _ping(self, namespace, ip):
        """Pings ip address from network namespace.

        In order to ping it uses following cli command:
            ip netns exec <namespace> ping -c 4 -q <ip>
        """
        try:
            count = 4
            cmd = ['ping', '-w', 2 * count, '-c', count, ip]
            cmd = ip_lib.add_namespace_to_cmd(cmd, namespace)
            linux_utils.execute(cmd, run_as_root=True)
            return True
        except RuntimeError:
            return False

    def test_ipsec_site_connections(self):
        device = self.vpn_agent.device_drivers[0]
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
        device.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[])
        # instantiate network resources "router", "private network"
        private_nets = list(PRIVATE_NET.subnet(24))
        site1 = self.site_setup(PUBLIC_NET[4], private_nets[1])
        site2 = self.site_setup(PUBLIC_NET[5], private_nets[2])
        # build vpn resources
        self.prepare_ipsec_conn_info(site1['vpn_service'],
                                     site2['vpn_service'])
        self.prepare_ipsec_conn_info(site2['vpn_service'],
                                     site1['vpn_service'])

        device.report_status = mock.Mock()
        device.agent_rpc.get_vpn_services_on_host = mock.Mock(
            return_value=[site1['vpn_service'],
                          site2['vpn_service']])

        self.assertFalse(self._ping(site1['port_namespace'], site2['port_ip']))
        self.assertFalse(self._ping(site2['port_namespace'], site1['port_ip']))

        device.sync(mock.Mock(), [{'id': site1['router'].router_id},
                                  {'id': site2['router'].router_id}])
        self.addCleanup(
            device._delete_vpn_processes,
            [site1['router'].router_id, site2['router'].router_id], [])

        self.assertTrue(self._ping(site1['port_namespace'], site2['port_ip']))
        self.assertTrue(self._ping(site2['port_namespace'], site1['port_ip']))
