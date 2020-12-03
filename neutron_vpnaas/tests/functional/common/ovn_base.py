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

from unittest import mock

import netaddr
from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.common.ovn import constants as ovn_const
from neutron.conf.agent import common as agent_conf
from neutron.conf import common as common_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron_lib import constants as lib_constants
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.utils import helpers
from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import event

from neutron_vpnaas.agent.ovn.vpn import agent
from neutron_vpnaas.agent.ovn.vpn import ovsdb
from neutron_vpnaas.services.vpn.common import constants as vpn_const
from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn import ovn_agent
from neutron_vpnaas.services.vpn.service_drivers import ovn_ipsec


OVS_INTERFACE_DRIVER = 'neutron.agent.linux.interface.OVSInterfaceDriver'
IPSEC_SERVICE_PROVIDER = ('VPN:ovn:neutron_vpnaas.services.vpn.'
                          'service_drivers.ovn_ipsec.IPsecOvnVPNDriver:'
                          'default')
VPN_PLUGIN = 'neutron_vpnaas.services.vpn.ovn_plugin.VPNOVNDriverPlugin'

PUBLIC_NET = netaddr.IPNetwork('19.4.4.0/24')
LOCAL_NETS = list(netaddr.IPNetwork('10.0.0.0/16').subnet(24))
PEER_NET = netaddr.IPNetwork('10.1.0.0/16')
PEER_ADDR = '19.4.5.6'


class VPNAgentHealthEvent(event.WaitEvent):
    event_name = 'VPNAgentHealthEvent'

    def __init__(self, chassis, sb_cfg, table, timeout=5):
        self.chassis = chassis
        self.sb_cfg = sb_cfg
        super().__init__(
            (self.ROW_UPDATE,), table, (('name', '=', self.chassis),),
            timeout=timeout)

    def matches(self, event, row, old=None):
        if not super().matches(event, row, old):
            return False
        return int(row.external_ids.get(
            vpn_const.OVN_AGENT_VPN_SB_CFG_KEY, 0)) >= self.sb_cfg


class OvnSiteInfo:
    def __init__(self, parent, index, ext_net, ext_sub):
        self.ext_net = ext_net
        self.ext_sub = ext_sub
        self.parent = parent
        self.context = parent.context
        self.fmt = parent.fmt
        self.index = index

    def create_base(self):
        router_data = {
            'name': 'r%d' % self.index,
            'admin_state_up': True,
            'tenant_id': self.parent._tenant_id,
            'external_gateway_info': {
                'enable_snat': True,
                'network_id': self.ext_net['id'],
                'external_fixed_ips': [
                    {'ip_address': str(PUBLIC_NET[4 + 2 * self.index]),
                     'subnet_id': self.ext_sub['id']}
                ]
            }
        }
        self.router = self.parent.l3_plugin.create_router(
            self.context, {'router': router_data})

        # local subnet
        private_net = LOCAL_NETS[self.index]
        self.local_cidr = str(private_net)

        net = self.parent._make_network(self.fmt, 'local%d' % self.index, True)
        self.local_net = net['network']
        sub = self.parent._make_subnet(self.fmt, net, private_net[1],
                                       self.local_cidr, enable_dhcp=False)
        self.local_sub = sub['subnet']
        interface_info = {'subnet_id': self.local_sub['id']}
        self.parent.l3_plugin.add_router_interface(
            self.context, self.router['id'], interface_info)

    def create_vpnservice(self):
        plugin = self.parent.vpn_plugin
        data = {
            'tenant_id': self.parent._tenant_id,
            'name': 'my-service',
            'description': 'new service',
            'subnet_id': self.local_sub['id'],
            'router_id': self.router['id'],
            'flavor_id': None,
            'admin_state_up': True,
        }
        self.vpnservice = plugin.create_vpnservice(self.context,
                                                   {'vpnservice': data})
        self.local_addr = self.vpnservice['external_v4_ip']

        data = {
            'tenant_id': self.parent._tenant_id,
            'name': 'ikepolicy%d' % self.index,
            'description': '',
            'auth_algorithm': 'sha1',
            'encryption_algorithm': 'aes-128',
            'phase1_negotiation_mode': 'main',
            'ike_version': 'v1',
            'pfs': 'group5',
            'lifetime': {'units': 'seconds', 'value': 3600},
        }
        self.ikepolicy = plugin.create_ikepolicy(self.context,
                                                 {'ikepolicy': data})

        data = {
            'tenant_id': self.parent._tenant_id,
            'name': 'ipsecpolicy%d' % self.index,
            'description': '',
            'transform_protocol': 'esp',
            'auth_algorithm': 'sha1',
            'encryption_algorithm': 'aes-128',
            'encapsulation_mode': 'tunnel',
            'pfs': 'group5',
            'lifetime': {'units': 'seconds', 'value': 3600},
        }
        self.ipsecpolicy = plugin.create_ipsecpolicy(self.context,
                                                     {'ipsecpolicy': data})

    def create_site_connection(self, peer_addr, peer_cidr):
        data = {
            'tenant_id': self.parent._tenant_id,
            'name': 'conn%d' % self.index,
            'description': '',
            'local_id': self.local_addr,
            'peer_address': peer_addr,
            'peer_id': peer_addr,
            'peer_cidrs': [peer_cidr],
            'mtu': 1500,
            'initiator': 'bi-directional',
            'auth_mode': 'psk',
            'psk': 'secret',
            'dpd': {
                'action': 'hold',
                'interval': 30,
                'timeout': 120,
            },
            'admin_state_up': True,
            'vpnservice_id': self.vpnservice['id'],
            'ikepolicy_id': self.ikepolicy['id'],
            'ipsecpolicy_id': self.ipsecpolicy['id'],
            'local_ep_group_id': None,
            'peer_ep_group_id': None,
        }
        self.siteconn = self.parent.vpn_plugin.create_ipsec_site_connection(
            self.context, {'ipsec_site_connection': data})


class TestOvnVPNAgentBase(base.TestOVNFunctionalBase):
    FAKE_CHASSIS_HOST = 'ovn-host-fake'

    def setUp(self):
        cfg.CONF.set_override('service_provider', [IPSEC_SERVICE_PROVIDER],
                              group='service_providers')
        service_plugins = {'vpnaas_plugin': VPN_PLUGIN}
        super().setUp(service_plugins=service_plugins)
        common_config.register_common_config_options()

        self.mock_ovsdb_idl = mock.Mock()
        mock_instance = mock.Mock()
        mock_instance.start.return_value = self.mock_ovsdb_idl
        mock_ovs_idl = mock.patch.object(ovsdb, 'VPNAgentOvsIdl').start()
        mock_ovs_idl.return_value = mock_instance

        self.vpn_plugin = directory.get_plugin(plugin_constants.VPN)
        # normally called in post_for_initialize
        self.vpn_plugin.watch_agent_events()
        self.vpn_service_driver = self.vpn_plugin.drivers['ovn']

        self.handler = self.sb_api.idl.notify_handler
        self.agent = self._start_vpn_agent()
        self.agent_driver = self.agent.device_drivers[0]

    def _start_vpn_agent(self):
        # Set up a ConfigOpts separate to cfg.CONF in order to avoid conflicts
        # with other tests.
        # The OVN VPN agent registers a different variant of
        # vpnagent.vpn_device_drivers than the L3 agent extension.
        conf = agent_conf.setup_conf()
        conf.register_opts(ovn_conf.ovn_opts, group='ovn')
        conf.register_opts(ipsec.ipsec_opts, 'ipsec')
        common_conf.register_core_common_config_opts(conf)
        ovs_conf.register_ovs_opts(conf)
        ovn_agent.register_opts(conf)
        agent_conf.register_process_monitor_opts(conf)
        agent_conf.setup_privsep()

        conf.set_override('state_path', self.get_default_temp_dir().path)
        conf.set_override('interface_driver', OVS_INTERFACE_DRIVER)
        conf.set_override('vpn_device_driver', [self.VPN_DEVICE_DRIVER],
                          group='vpnagent')

        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        conf.set_override('ovn_sb_connection', ovn_sb_db, group='ovn')

        self.chassis_name = self.add_fake_chassis(self.FAKE_CHASSIS_HOST)
        mock.patch.object(agent.OvnVpnAgent,
                          '_get_own_chassis_name',
                          return_value=self.chassis_name).start()
        conf.set_override('host', self.FAKE_CHASSIS_HOST)

        self.br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        conf.set_override('integration_bridge', self.br_int.br_name, 'OVS')

        # name prefix for namespaces managed by vpn agent
        # will be patched into device driver to make sure concurrent
        # tests don't interfere with each other
        # (a vpn agent will normally remove all unknown qvpn- namespaces)
        self.ns_prefix = 'qvpn-test-%s-' % helpers.get_random_string(8)

        agt = agent.OvnVpnAgent(conf)
        driver = agt.device_drivers[0]
        driver.agent_rpc = mock.Mock()
        # let initial sync get an empty list of vpnservices
        driver.agent_rpc.get_vpn_services_on_host.return_value = []
        driver.devmgr.plugin = driver.agent_rpc
        driver.devmgr.OVN_NS_PREFIX = self.ns_prefix

        agt.start()
        self.addCleanup(agt.ovs_idl.ovsdb_connection.stop)
        self.addCleanup(agt.sb_idl.ovsdb_connection.stop)
        # let agent remove remaining vpn namespaces in cleanup
        self.addCleanup(driver._cleanup_stale_vpn_processes, [])

        return agt

    @property
    def agent_chassis_table(self):
        if self.agent.has_chassis_private:
            return 'Chassis_Private'
        return 'Chassis'

    def _make_ext_network(self):
        network = self._make_network(
            self.fmt, 'external-net', True, as_admin=True,
            arg_list=('router:external',
                      'provider:network_type',
                      'provider:physical_network'),
            **{'router:external': True,
                'provider:network_type': 'flat',
                'provider:physical_network': 'public'})

        pools = [{'start': PUBLIC_NET[2], 'end': PUBLIC_NET[253]}]
        gateway = PUBLIC_NET[1]
        cidr = str(PUBLIC_NET)
        subnet = self._make_subnet(self.fmt, network, gateway, cidr,
                                   allocation_pools=pools,
                                   enable_dhcp=False)
        return network['network'], subnet['subnet']

    def _find_lswitch_by_neutron_name(self, name):
        for row in self.nb_api._tables['Logical_Switch'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY) == name):
                return row

    def _find_transit_lswitch(self, router_id):
        name = ovn_ipsec.TRANSIT_NETWORK_PREFIX + router_id
        return self._find_lswitch_by_neutron_name(name)

    def _match_extids(self, row, expected):
        for key, value in expected.items():
            if row.external_ids.get(key) != value:
                return False
        return True

    def _find_transit_ns_port(self, router_id, ports):
        name = ovn_ipsec.TRANSIT_PORT_PREFIX + router_id
        extids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: name}

        for row in ports:
            if self._match_extids(row, extids):
                return row

    def _find_transit_router_port(self, router_id, network_name, ports):
        extids = {
            ovn_const.OVN_DEVID_EXT_ID_KEY: router_id,
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: 'network:router_interface',
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network_name,
        }
        for row in ports:
            if self._match_extids(row, extids):
                return row

    def _find_vpn_gw_port(self, router_id, ports):
        name = ovn_ipsec.VPN_GW_PORT_PREFIX + router_id
        extids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: name}

        for row in ports:
            if self._match_extids(row, extids):
                return row

    def _find_lrouter_by_neutron_id(self, router_id):
        for row in self.nb_api._tables['Logical_Router'].rows.values():
            if row.name == "neutron-" + router_id:
                return row

    def test_agent(self):
        chassis_row = self.sb_api.db_find(
            self.agent_chassis_table,
            ('name', '=', self.chassis_name)).execute(
            check_error=True)[0]

        # Assert that, prior to creating a resource the VPN agent
        # didn't populate the external_ids from the Chassis
        self.assertNotIn(vpn_const.OVN_AGENT_VPN_SB_CFG_KEY,
                         chassis_row['external_ids'])

        # Let's list the agents to force the nb_cfg to be bumped on NB
        # db, which will automatically increment the nb_cfg counter on
        # NB_Global and make ovn-controller copy it over to SB_Global. Upon
        # this event, VPN agent will update the external_ids on its
        # Chassis row to signal that it's healthy.

        row_event = VPNAgentHealthEvent(self.chassis_name, 1,
                                        self.agent_chassis_table)
        self.handler.watch_event(row_event)
        self.new_list_request('agents').get_response(self.api)

        # If we do not time out waiting for the event, then we are assured
        # that the VPN agent has populated the external_ids from the
        # chassis with the nb_cfg, 1 revisions when listing the agents.
        self.assertTrue(row_event.wait())

    def test_service(self):
        r = self.new_list_request('agents').get_response(self.api)
        ext_net, ext_sub = self._make_ext_network()

        server = ovn_ipsec.IPsecVpnOvnDriverCallBack(self.vpn_service_driver)

        # Mock the controller side RPC client (prepare and cast)
        # to be able to check that "vpnservice_updated" will be called
        prepare_mock = mock.Mock()
        prepared_mock = mock.Mock()
        self.vpn_service_driver.agent_rpc.client.prepare = prepare_mock
        prepare_mock.return_value = prepared_mock

        # Create a site (router, network, subnet, vpnservice, site conn)
        site = OvnSiteInfo(self, 1, ext_net, ext_sub)
        site.create_base()
        site.create_vpnservice()
        site.create_site_connection(PEER_ADDR, str(PEER_NET))

        # Check that the vpnservice_updated RPC was triggered towards
        # the agent
        prepare_mock.assert_called_once_with(
            server=self.FAKE_CHASSIS_HOST,
            version=self.vpn_service_driver.agent_rpc.target.version)
        prepared_mock.cast.assert_called_once_with(
            self.context, 'vpnservice_updated',
            router={'id': site.router['id']})

        # Mock the agent->controller RPCs. Let them return data from the
        # actual VPN plugin
        def get_vpn_services_on_host(ctx, host):
            r = server.get_vpn_services_on_host(self.context, host)
            return r

        def get_vpn_transit_network_details(router_id):
            return server.get_vpn_transit_network_details(
                self.context, router_id)

        def get_subnet_info(subnet_id):
            return server.get_subnet_info(self.context, subnet_id)

        r = self.agent_driver.agent_rpc
        r.get_vpn_services_on_host.side_effect = get_vpn_services_on_host
        r.get_vpn_transit_network_details.side_effect = \
            get_vpn_transit_network_details
        r.get_subnet_info.side_effect = get_subnet_info

        # Call the agent's vpnservice_updated as if it was coming from
        # the controller.
        for driver in self.agent.device_drivers:
            driver.vpnservice_updated(driver.context,
                                      router={'id': site.router['id']})

        # Check that transit network and VPN gateway port are set up correctly
        # - transit network exists
        # - router port in transit network exists
        # - transit network port to be bound to chassis exists and
        #   host is assigned
        # - VPN gateway port exists and host is assigned
        # - static route exists towards peer CIDR

        # expect transit network in NB
        transit_row = self._find_transit_lswitch(site.router['id'])
        self.assertIsNotNone(transit_row)

        # check the transit network router port exists
        transit_router_port = self._find_transit_router_port(
            site.router['id'], transit_row.name, transit_row.ports)
        self.assertIsNotNone(transit_router_port)

        # check that the namespace port in the transit network exists
        transit_ns_port = self._find_transit_ns_port(site.router['id'],
                                                     transit_row.ports)
        self.assertIsNotNone(transit_ns_port)

        # check that the port has the requested-host option
        requested_host = transit_ns_port.options.get(
            ovn_const.LSP_OPTIONS_REQUESTED_CHASSIS_KEY)
        self.assertEqual(requested_host, self.FAKE_CHASSIS_HOST)

        # get vpn gateway port via external network lswitch
        ext_row = self._find_lswitch_by_neutron_name("external-net")
        self.assertIsNotNone(ext_row)

        vpn_gw_port = self._find_vpn_gw_port(site.router['id'], ext_row.ports)
        self.assertIsNotNone(vpn_gw_port)
        # check that vpn gateway port has the requested-host option
        requested_host = vpn_gw_port.options.get(
            ovn_const.LSP_OPTIONS_REQUESTED_CHASSIS_KEY)
        self.assertEqual(requested_host, self.FAKE_CHASSIS_HOST)

        # check that static route towards peer cidr is set
        router_row = self._find_lrouter_by_neutron_id(site.router['id'])
        self.assertIsNotNone(router_row)
        for r in router_row.static_routes:
            if r.ip_prefix == str(PEER_NET):
                route = r
                break
        else:
            route = None

        self.assertIsNotNone(route)
        self.assertEqual(route.nexthop, ovn_ipsec.VPN_TRANSIT_RIP)

        # Check agent side
        # - network namespace
        # - routes towards transit network's gateway IP
        # - devices and their IP addresses in the namespace
        ns_name = self.ns_prefix + site.router['id']
        devlen = lib_constants.LINUX_DEV_LEN
        transit_dev = ('vr' + transit_ns_port.name)[:devlen]
        gw_dev = ('vg' + vpn_gw_port.name)[:devlen]
        self.assertTrue(ip_lib.network_namespace_exists(ns_name))
        device = ip_lib.IPDevice(None, namespace=ns_name)
        routes = device.route.list_routes(lib_constants.IP_VERSION_4,
                                          proto='static',
                                          via=ovn_ipsec.VPN_TRANSIT_LIP)
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]['via'], ovn_ipsec.VPN_TRANSIT_LIP)
        self.assertEqual(routes[0]['cidr'], site.local_cidr)
        self.assertEqual(routes[0]['device'], transit_dev)

        # check addresses in namespace
        addrs = device.addr.list(ip_version=lib_constants.IP_VERSION_4)
        addrs_dict = {a['name']: a for a in addrs}
        self.assertIn(transit_dev, addrs_dict)
        self.assertEqual(
            addrs_dict[transit_dev]['cidr'],
            transit_ns_port.external_ids[ovn_const.OVN_CIDRS_EXT_ID_KEY])

        self.assertIn(gw_dev, addrs_dict)
        self.assertEqual(
            addrs_dict[gw_dev]['cidr'],
            vpn_gw_port.external_ids[ovn_const.OVN_CIDRS_EXT_ID_KEY])
