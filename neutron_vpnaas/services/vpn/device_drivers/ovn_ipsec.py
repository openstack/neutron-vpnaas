# Copyright (c) 2016 Yi Jing Zhu, IBM.
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

from oslo_log import log as logging

from neutron.agent.common import utils as agent_common_utils
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron import context as nctx
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas._i18n import _LE, _LI

from neutron_vpnaas.services.vpn.device_drivers import ipsec
from neutron_vpnaas.services.vpn.device_drivers import strongswan_ipsec

OVN_NS_PREFIX = 'qvpn-'

port_prefix = {'external': 'vg', 'internal': 'vr'}

LOG = logging.getLogger(__name__)


class DeviceManager(object):
    """Device Manager for ports in qvpn-xx namespace.
    It is a veth pair, one side in qvpn and the other
    side is attached to ovs.
    """

    def __init__(self, conf, host, plugin, context):
        self.conf = conf
        self.host = host
        self.plugin = plugin
        self.context = context
        self.driver = agent_common_utils.load_interface_driver(conf)

    def get_interface_name(self, port, ptype):
        suffix = port['id'] if ptype == 'external' else port['name']
        return (port_prefix[ptype] + suffix)[:self.driver.DEV_NAME_LEN]

    def get_namespace_name(self, process_id):
        return OVN_NS_PREFIX + process_id

    def get_vpn_internal_port(self, process_id):
        return self.plugin.find_vpn_port('internal', process_id, self.host)

    def get_vpn_external_port(self, process_id):
        return self.plugin.find_vpn_port('external', process_id, self.host)

    def set_default_route(self, subnet, device_name, namespace):
        device = ip_lib.IPDevice(device_name, namespace=namespace)
        gateway = device.route.get_gateway()
        if gateway:
            gateway = gateway.get('gateway')
        new_gateway = subnet['gateway_ip']
        if gateway == new_gateway:
            return
        device.route.add_gateway(subnet['gateway_ip'])

    def add_router_entry(self, cidr, via, namespace):
        device = ip_lib.IPDevice(None, namespace=namespace)
        device.route.add_route(cidr, via=via, metric=100, proto='static')

    def del_static_routes(self, namespace):
        device = ip_lib.IPDevice(None, namespace=namespace)
        routes = device.route.list_routes(4, proto='static')

        for r in routes:
            device.route.delete_route(r['cidr'], via=r['via'])

    def del_internal_port(self, process_id):
        namespace = self.get_namespace_name(process_id)
        device = ip_lib.IPDevice(None, namespace=namespace)
        ports = device.addr.list()
        for p in ports:
            if port_prefix['internal'] not in p['name']:
                continue
            interface_name = p['name']
            self.driver.unplug(interface_name, namespace=namespace)

    def del_external_port(self, gateway_ip, process_id):
        namespace = self.get_namespace_name(process_id)
        device = ip_lib.IPDevice(None, namespace=namespace)
        ports = device.addr.list()
        for p in ports:
            if port_prefix['external'] not in p['name']:
                continue
            interface_name = p['name']
            self.driver.unplug(interface_name, namespace=namespace)

    def setup_external(self, network, subnet, process_id):
        vpn_port = self.get_vpn_external_port(process_id)
        LOG.info('external vpn port find is %s' % vpn_port)
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
                                 prefix=port_prefix['external'])
            except Exception:
                LOG.exception(_LE('plug external port %s failed') % vpn_port)
                return None

        ip_cidrs = []
        net = netaddr.IPNetwork(subnet['cidr'])
        for fixed_ip in vpn_port['fixed_ips']:
            ip_cidr = '%s/%s' % (fixed_ip['ip_address'], net.prefixlen)
            ip_cidrs.append(ip_cidr)
        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=ns_name)
        self.set_default_route(subnet, interface_name, ns_name)
        return interface_name

    def setup_internal(self, process_id):
        vpn_port = self.get_vpn_internal_port(process_id)
        LOG.info('internal vpn port find is %s' % vpn_port)
        ns_name = self.get_namespace_name(process_id)
        interface_name = self.get_interface_name(vpn_port, 'internal')

        if not ip_lib.ensure_device_is_ready(interface_name,
                                         namespace=ns_name):
            try:
                self.driver.plug('',
                                 vpn_port['name'],
                                 interface_name,
                                 vpn_port['mac_address'],
                                 namespace=ns_name,
                                 prefix=port_prefix['internal'])
            except Exception:
                LOG.exception(_LE('plug internal port %s failed') % vpn_port)
                return None

        ip_cidrs = []
        for fixed_ip in vpn_port['fixed_ips']:
            ip_cidr = '%s/%s' % (fixed_ip, 28)
            ip_cidrs.append(ip_cidr)
        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=ns_name)
        return interface_name


class NamespaceManager(object):
    def __init__(self, use_ipv6=False):
        self.ip_wrapper_root = ip_lib.IPWrapper()
        self.use_ipv6 = use_ipv6

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
            msg = _LE('Failed trying to delete namespace: %s')
            LOG.exception(msg, name)


class OvnOpenSwanProcess(ipsec.OpenSwanProcess):
    pass


class OvnStrongSwanProcess(strongswan_ipsec.StrongSwanProcess):
    pass


class IPsecOvnDriverApi(ipsec.IPsecVpnDriverApi):
    def __init__(self, topic):
        super(IPsecOvnDriverApi, self).__init__(topic)
        self.admin_ctx = nctx.get_admin_context_without_session()

    def get_provider_network4vpn(self, router_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.admin_ctx, 'get_provider_network4vpn',
                          router_id=router_id)

    def get_subnet_info(self, subnet_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.admin_ctx, 'get_subnet_info',
                          subnet_id=subnet_id)

    def find_vpn_port(self, ptype, router_id, host):
        cctxt = self.client.prepare()
        return cctxt.call(self.admin_ctx, 'find_vpn_port',
                          ptype=ptype, router_id=router_id, host=host)


class OvnSwanDriver(ipsec.IPsecDriver):

    def __init__(self, vpn_service, host):
        self.nsmgr = NamespaceManager()
        self.iptables_managers = {}
        super(OvnSwanDriver, self).__init__(vpn_service, host)
        self.agent_rpc = IPsecOvnDriverApi(topics.IPSEC_DRIVER_TOPIC)
        self.devmgr = DeviceManager(self.conf, self.host,
                        self.agent_rpc, self.context)

    def prepare_namespace(self, context, **kwargs):
        router = kwargs.get('router', None)
        router_id = router['id']
        self.get_namespace(router_id)

    def cleanup_namespace(self, context, **kwargs):
        router = kwargs.get('router', None)
        process_id = router['id']

        self.devmgr.del_internal_port(process_id)
        self.devmgr.del_external_port(None, process_id)

    def get_namespace(self, router_id):
        """Get namespace of router.

        :router_id: router_id
        :returns: namespace string.
        """
        ns_name = self.devmgr.get_namespace_name(router_id)
        if ns_name not in ip_lib.IPWrapper.get_namespaces():
            self.nsmgr.create(ns_name)
        if not self.iptables_managers.get(router_id):
            imgr = iptables_manager.IptablesManager(use_ipv6=False,
                   namespace=ns_name)
            self.iptables_managers[router_id] = imgr
        self.routers[router_id] = router_id

        #setUp vpn external port on provider net
        net = self.agent_rpc.get_provider_network4vpn(router_id)
        subnet = self.agent_rpc.get_subnet_info(net['subnets'][0])
        self.devmgr.setup_external(net, subnet, router_id)

        #setUp vpn internal port on transit net
        self.devmgr.setup_internal(router_id)

        return ns_name

    def get_router_based_iptables_manager(self, router):
        #router here is actually an id
        return self.iptables_managers[router]

    def destroy_process(self, process_id):
        LOG.info(_LI('process %s is destroyed') % process_id)
        super(OvnSwanDriver, self).destroy_process(process_id)

        namespace = self.devmgr.get_namespace_name(process_id)
        self.devmgr.del_static_routes(namespace)

    def create_router(self, router):
        pass

    def destroy_router(self, process_id):
        pass

    def _update_route(self, vpnservice):
        gateway_ip = '169.254.0.1'

        namespace = self.devmgr.get_namespace_name(vpnservice['router_id'])
        for ipsec_site_conn in vpnservice['ipsec_site_connections']:
            for local_cidr in ipsec_site_conn['local_cidrs']:
                self.devmgr.add_router_entry(local_cidr, gateway_ip, namespace)

    def _sync_vpn_processes(self, vpnservices, sync_router_ids):
        for vpnservice in vpnservices:
            router_id = vpnservice['router_id']
            vpn_port = self.devmgr.get_vpn_external_port(router_id)
            ip_addr = vpn_port['fixed_ips'][0]['ip_address']
            for ipsec_site_conn in vpnservice['ipsec_site_connections']:
                ipsec_site_conn['external_ip'] = ip_addr

        # Ensure the ipsec process is enabled only for
        # - the vpn services which are not yet in self.processes
        # - vpn services whose router id is in 'sync_router_ids'
        for vpnservice in vpnservices:
            if vpnservice['router_id'] not in self.processes or (
                    vpnservice['router_id'] in sync_router_ids):
                process = self.ensure_process(vpnservice['router_id'],
                                              vpnservice=vpnservice)
                self._update_route(vpnservice)
                self._update_nat(vpnservice, self.add_nat_rule)
                router = self.routers.get(vpnservice['router_id'])
                if not router:
                    continue
                # If HA is enabled and ha state is backup, then disable
                # If HA is enabled and ha state is matser, then update
                # If HA is enabled but not formed, then do nothing here
                # If HA is not enabled, then update
                if False:
                    process.disable()
                else:
                    process.update()

    def create_process(self, process_id, vpnservice, namespace):
        return OvnStrongSwanProcess(
            self.conf,
            process_id,
            vpnservice,
            namespace)
