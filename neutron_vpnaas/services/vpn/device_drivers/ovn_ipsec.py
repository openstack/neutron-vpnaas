# Copyright (c) 2016 Yi Jing Zhu, IBM.
# Copyright (c) 2023 SysEleven GmbH
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

import netaddr

from neutron.agent.common import utils as agent_common_utils
from neutron.agent.linux import ip_lib
from neutron_lib import constants as lib_constants
from neutron_lib import context as nctx
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import libreswan_ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec

PORT_PREFIX_INTERNAL = 'vr'
PORT_PREFIX_EXTERNAL = 'vg'
PORT_PREFIXES = {
    'internal': PORT_PREFIX_INTERNAL,
    'external': PORT_PREFIX_EXTERNAL,
}

LOG = logging.getLogger(__name__)


class DeviceManager(object):
    """Device Manager for ports in qvpn-xx namespace.
    It is a veth pair, one side in qvpn and the other
    side is attached to ovs.
    """

    OVN_NS_PREFIX = "qvpn-"

    def __init__(self, conf, host, plugin, context):
        self.conf = conf
        self.host = host
        self.plugin = plugin
        self.context = context
        self.driver = agent_common_utils.load_interface_driver(conf)

    def get_interface_name(self, port, ptype):
        suffix = port['id']
        return (PORT_PREFIXES[ptype] + suffix)[:self.driver.DEV_NAME_LEN]

    def get_namespace_name(self, process_id):
        return self.OVN_NS_PREFIX + process_id

    def get_existing_process_ids(self):
        """Return the process IDs derived from the existing VPN namespaces."""
        return [ns[len(self.OVN_NS_PREFIX):]
                for ns in ip_lib.list_network_namespaces()
                if ns.startswith(self.OVN_NS_PREFIX)]

    def set_default_route(self, namespace, subnet, device_name):
        device = ip_lib.IPDevice(device_name, namespace=namespace)
        gateway = device.route.get_gateway(ip_version=subnet['ip_version'])
        if gateway:
            gateway = gateway.get('gateway')
        new_gateway = subnet['gateway_ip']
        if gateway == new_gateway:
            return
        device.route.add_gateway(subnet['gateway_ip'])

    def add_routes(self, namespace, cidrs, via):
        device = ip_lib.IPDevice(None, namespace=namespace)
        for cidr in cidrs:
            device.route.add_route(cidr, via=via, metric=100, proto='static')

    def delete_routes(self, namespace, cidrs, via):
        device = ip_lib.IPDevice(None, namespace=namespace)
        for cidr in cidrs:
            device.route.delete_route(cidr, via=via, metric=100,
                                      proto='static')

    def list_routes(self, namespace, via=None):
        device = ip_lib.IPDevice(None, namespace=namespace)
        return device.route.list_routes(
            lib_constants.IP_VERSION_4, proto='static', via=via)

    def del_static_routes(self, namespace):
        device = ip_lib.IPDevice(None, namespace=namespace)
        routes = device.route.list_routes(
            lib_constants.IP_VERSION_4, proto='static')

        for r in routes:
            device.route.delete_route(r['cidr'], via=r['via'])

    def _del_port(self, process_id, ptype):
        namespace = self.get_namespace_name(process_id)
        prefix = PORT_PREFIXES[ptype]
        device = ip_lib.IPDevice(None, namespace=namespace)
        ports = device.addr.list()
        for p in ports:
            if not p['name'].startswith(prefix):
                continue
            interface_name = p['name']
            self.driver.unplug(interface_name, namespace=namespace)

    def del_internal_port(self, process_id):
        self._del_port(process_id, 'internal')

    def del_external_port(self, process_id):
        self._del_port(process_id, 'external')

    def setup_external(self, process_id, network_details):
        network = network_details["external_network"]
        vpn_port = network_details['gw_port']
        ns_name = self.get_namespace_name(process_id)
        interface_name = self.get_interface_name(vpn_port, 'external')

        if not ip_lib.ensure_device_is_ready(interface_name,
                                             namespace=ns_name):
            try:
                self.driver.plug(network['id'],
                                 vpn_port['id'],
                                 interface_name,
                                 vpn_port['mac_address'],
                                 namespace=ns_name,
                                 mtu=network.get('mtu'),
                                 prefix=PORT_PREFIX_EXTERNAL)
            except Exception:
                LOG.exception('plug external port %s failed', vpn_port)
                return None

        ip_cidrs = []
        subnets = []
        for fixed_ip in vpn_port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet = self.plugin.get_subnet_info(subnet_id)
            net = netaddr.IPNetwork(subnet['cidr'])
            ip_cidr = '%s/%s' % (fixed_ip['ip_address'], net.prefixlen)
            ip_cidrs.append(ip_cidr)
            subnets.append(subnet)
        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=ns_name)
        for subnet in subnets:
            self.set_default_route(ns_name, subnet, interface_name)
        return interface_name

    def setup_internal(self, process_id, network_details):
        vpn_port = network_details["transit_port"]
        ns_name = self.get_namespace_name(process_id)
        interface_name = self.get_interface_name(vpn_port, 'internal')

        if not ip_lib.ensure_device_is_ready(interface_name,
                                             namespace=ns_name):
            try:
                self.driver.plug('',
                                 vpn_port['id'],
                                 interface_name,
                                 vpn_port['mac_address'],
                                 namespace=ns_name,
                                 prefix=PORT_PREFIX_INTERNAL)
            except Exception:
                LOG.exception('plug internal port %s failed', vpn_port['id'])
                return None

        ip_cidrs = []
        for fixed_ip in vpn_port['fixed_ips']:
            ip_cidr = '%s/%s' % (fixed_ip['ip_address'], 28)
            ip_cidrs.append(ip_cidr)
        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=ns_name)
        return interface_name


class NamespaceManager(object):
    def __init__(self, use_ipv6=False):
        self.ip_wrapper_root = ip_lib.IPWrapper()
        self.use_ipv6 = use_ipv6

    def exists(self, name):
        return ip_lib.network_namespace_exists(name)

    def create(self, name):
        ip_wrapper = self.ip_wrapper_root.ensure_namespace(name)
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
        ip_wrapper.netns.execute(cmd)
        if self.use_ipv6:
            cmd = ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1']
            ip_wrapper.netns.execute(cmd)

    def delete(self, name):
        try:
            self.ip_wrapper_root.netns.delete(name)
        except RuntimeError:
            msg = 'Failed trying to delete namespace: %s'
            LOG.exception(msg, name)


class OvnOpenSwanProcess(ipsec.OpenSwanProcess):
    pass


class OvnStrongSwanProcess(strongswan_ipsec.StrongSwanProcess):
    pass


class OvnLibreSwanProcess(libreswan_ipsec.LibreSwanProcess):
    pass


class IPsecOvnDriverApi(ipsec.IPsecVpnDriverApi):
    def __init__(self, topic):
        super().__init__(topic)
        self.admin_ctx = nctx.get_admin_context_without_session()

    def get_vpn_transit_network_details(self, router_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.admin_ctx, 'get_vpn_transit_network_details',
                          router_id=router_id)

    def get_subnet_info(self, subnet_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.admin_ctx, 'get_subnet_info',
                          subnet_id=subnet_id)


class OvnIPsecDriver(ipsec.IPsecDriver):

    def __init__(self, vpn_service, host):
        self.nsmgr = NamespaceManager()
        super().__init__(vpn_service, host)
        self.agent_rpc = IPsecOvnDriverApi(topics.IPSEC_DRIVER_TOPIC)
        self.devmgr = DeviceManager(self.conf, self.host,
                                    self.agent_rpc, self.context)

    get_router_based_iptables_manager = None

    def get_namespace(self, router_id):
        """Get namespace for VPN services of router.

        :router_id: router_id
        :returns: namespace string.
        """
        return self.devmgr.get_namespace_name(router_id)

    def _cleanup_namespace(self, router_id):
        ns_name = self.devmgr.get_namespace_name(router_id)
        if not self.nsmgr.exists(ns_name):
            return

        self.devmgr.del_internal_port(router_id)
        self.devmgr.del_external_port(router_id)
        self.nsmgr.delete(ns_name)

    def _ensure_namespace(self, router_id, network_details):
        ns_name = self.get_namespace(router_id)
        if not self.nsmgr.exists(ns_name):
            self.nsmgr.create(ns_name)

        # set up vpn external port on provider net
        self.devmgr.setup_external(router_id, network_details)

        # set up vpn internal port on transit net
        self.devmgr.setup_internal(router_id, network_details)

        return ns_name

    def destroy_process(self, process_id):
        LOG.info('process %s is destroyed', process_id)
        namespace = self.devmgr.get_namespace_name(process_id)

        # If the namespace exists but the process_id is not in the table
        # there may be an active swan process from a previous run of the agent
        # which does not have a process object in memory.
        # To be able to clean it up we need to create a dummy process object
        # here (without a vpnservice), so that destroy_process will stop
        # the swan.
        if self.nsmgr.exists(namespace) and process_id not in self.processes:
            self.ensure_process(process_id)
        super().destroy_process(process_id)
        self._cleanup_namespace(process_id)

    def create_router(self, router):
        pass

    def destroy_router(self, process_id):
        pass

    def _update_nat(self, vpnservice, func):
        pass

    def _update_route(self, vpnservice, network_details):
        router_id = vpnservice['router_id']
        gateway_ip = network_details['transit_gateway_ip']
        namespace = self.devmgr.get_namespace_name(router_id)

        old_local_cidrs = set()
        for route in self.devmgr.list_routes(namespace, via=gateway_ip):
            old_local_cidrs.add(route['cidr'])

        new_local_cidrs = set()
        for ipsec_site_conn in vpnservice['ipsec_site_connections']:
            new_local_cidrs.update(ipsec_site_conn['local_cidrs'])

        self.devmgr.delete_routes(namespace,
                                  old_local_cidrs - new_local_cidrs,
                                  gateway_ip)
        self.devmgr.add_routes(namespace,
                               new_local_cidrs - old_local_cidrs,
                               gateway_ip)

    def _sync_vpn_processes(self, vpnservices, sync_router_ids):
        # Ensure the ipsec process is enabled only for
        # - the vpn services which are not yet in self.processes
        # - vpn services whose router id is in 'sync_router_ids'
        for vpnservice in vpnservices:
            router_id = vpnservice['router_id']
            if router_id not in self.processes or router_id in sync_router_ids:
                net_details = self.agent_rpc.get_vpn_transit_network_details(
                    router_id)

                self._ensure_namespace(router_id, net_details)
                self._update_route(vpnservice, net_details)
                process = self.ensure_process(router_id, vpnservice=vpnservice)
                process.update()

    def _cleanup_stale_vpn_processes(self, vpn_router_ids):
        super()._cleanup_stale_vpn_processes(vpn_router_ids)
        # Look for additional namespaces on this node that we don't know
        # and that should be deleted
        for router_id in self.devmgr.get_existing_process_ids():
            if router_id not in vpn_router_ids:
                self.destroy_process(router_id)

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def vpnservice_removed_from_agent(self, context, router_id):
        # must run under the same lock as sync()
        self.destroy_process(router_id)

    def vpnservice_added_to_agent(self, context, router_ids):
        routers = [{'id': router_id} for router_id in router_ids]
        self.sync(context, routers)


class OvnStrongSwanDriver(OvnIPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return OvnStrongSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)


class OvnOpenSwanDriver(OvnIPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return OvnOpenSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)


class OvnLibreSwanDriver(OvnIPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return OvnLibreSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
