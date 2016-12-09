# Copyright 2015 Brocade Communications System, Inc.
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

import collections
import pprint

from networking_brocade.vyatta.common import exceptions as v_exc
from networking_brocade.vyatta.common import vrouter_config
from networking_brocade.vyatta.vpn import config as vyatta_vpn_config
from neutron.common import rpc as n_rpc
from neutron import context as n_ctx
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_service import loopingcall
from oslo_service import periodic_task

from neutron_vpnaas._i18n import _, _LE, _LW
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn import device_drivers

LOG = logging.getLogger(__name__)

_KEY_CONNECTIONS = 'ipsec_site_connections'
_KEY_IKEPOLICY = 'ikepolicy'
_KEY_ESPPOLICY = 'ipsecpolicy'


class _DriverRPCEndpoint(object):
    """
    VPN device driver RPC endpoint (server > agent)

    history
      1.0 Initial version
    """

    target = messaging.Target(version='1.0')

    def __init__(self, driver):
        self.driver = driver

    def vpnservice_updated(self, context, **kwargs):
        self.driver.sync(context, [])


class NeutronServerAPI(object):
    """
    VPN service driver RPC endpoint (agent > server)
    """

    def __init__(self, topic):
        target = messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_vpn_services_on_host(self, context, host):
        # make RPC call to neutron server
        cctxt = self.client.prepare()
        data = cctxt.call(context, 'get_vpn_services_on_host', host=host)

        vpn_services = list()
        for svc in data:
            try:
                for conn in svc[_KEY_CONNECTIONS]:
                    vyatta_vpn_config.validate_svc_connection(conn)
            except v_exc.InvalidVPNServiceError:
                LOG.error(_LE('Invalid or incomplete VPN service data: '
                              'id={id}').format(id=svc.get('id')))
                continue
            vpn_services.append(svc)

        # return transformed data to caller
        return vpn_services

    def update_status(self, context, status):
        cctxt = self.client.prepare()
        cctxt.cast(context, 'update_status', status=status)


class VyattaIPSecDriver(device_drivers.DeviceDriver):
    """
    Vyatta VPN device driver
    """
    rpc_endpoint_factory = _DriverRPCEndpoint

    def __init__(self, vpn_service, host):
        super(VyattaIPSecDriver, self).__init__(vpn_service, host)
        self.vpn_service = vpn_service
        self.host = host

        # register RPC endpoint
        conn = n_rpc.create_connection()
        node_topic = '%s.%s' % (topics.BROCADE_IPSEC_AGENT_TOPIC,
                                self.host)

        endpoints = [self.rpc_endpoint_factory(self)]
        conn.create_consumer(node_topic, endpoints, fanout=False)
        conn.consume_in_threads()

        # initialize agent to server RPC link
        self.server_api = NeutronServerAPI(
            topics.BROCADE_IPSEC_DRIVER_TOPIC)

        # initialize VPN service cache (to keep service state)
        self._svc_cache = list()
        self._router_resources_cache = dict()

        # setup periodic task. All periodic task require fully configured
        # device driver. It will be called asynchronously, and soon, so it
        # should be last, when all configuration is done.
        self._periodic_tasks = periodic = _VyattaPeriodicTasks(self)
        loop = loopingcall.DynamicLoopingCall(periodic)
        loop.start(initial_delay=5)

    def sync(self, context, processes):
        """
        Called by _DriverRPCEndpoint instance.
        """
        svc_update = self.server_api.get_vpn_services_on_host(
            context, self.host)
        to_del, to_change, to_add = self._svc_diff(
            self._svc_cache, svc_update)

        for svc in to_del:
            resources = self.get_router_resources(svc['router_id'])
            self._svc_delete(svc, resources)

        for old, new in to_change:
            resources = self.get_router_resources(old['router_id'])
            self._svc_delete(old, resources)
            self._svc_add(new, resources)

        for svc in to_add:
            resources = self.get_router_resources(svc['router_id'])
            self._svc_add(svc, resources)

        self._svc_cache = svc_update

    def create_router(self, router):
        router_id = router.router_id
        vrouter = self.vpn_service.get_router_client(router_id)
        config_raw = vrouter.get_vrouter_configuration()

        resources = self.get_router_resources(router_id)
        with resources.make_patch() as patch:
            vrouter_svc = vyatta_vpn_config.parse_vrouter_config(
                vrouter_config.parse_config(config_raw), patch)
            for svc in vrouter_svc:
                svc['router_id'] = router_id

        self._svc_cache.extend(vrouter_svc)

    def destroy_router(self, router_id):
        to_del = list()
        for idx, svc in enumerate(self._svc_cache):
            if svc['router_id'] != router_id:
                continue
            resources = self.get_router_resources(svc['router_id'])
            self._svc_delete(svc, resources)
            to_del.insert(0, idx)

        for idx in to_del:
            del self._svc_cache[idx]

    def _svc_add(self, svc, resources):
        vrouter = self.vpn_service.get_router_client(svc['router_id'])

        for conn in svc[_KEY_CONNECTIONS]:
            with resources.make_patch() as patch:
                iface = self._get_router_gw_iface(vrouter, svc['router_id'])
                batch = vyatta_vpn_config.connect_setup_commands(
                    vrouter, iface, svc, conn, patch)
                vrouter.exec_cmd_batch(batch)

    def _svc_delete(self, svc, resources):
        vrouter = self.vpn_service.get_router_client(svc['router_id'])

        for conn in svc[_KEY_CONNECTIONS]:
            with resources.make_patch() as patch:
                iface = self._get_router_gw_iface(vrouter, svc['router_id'])
                batch = vyatta_vpn_config.connect_remove_commands(
                    vrouter, iface, svc, conn, patch)
                vrouter.exec_cmd_batch(batch)

    def _svc_diff(self, svc_old, svc_new):
        state_key = 'admin_state_up'

        old_idnr = set(x['id'] for x in svc_old)
        new_idnr = set(x['id'] for x in svc_new if x[state_key])
        to_del = old_idnr - new_idnr
        to_add = new_idnr - old_idnr
        possible_change = old_idnr & new_idnr

        svc_old = dict((x['id'], x) for x in svc_old)
        svc_new = dict((x['id'], x) for x in svc_new)

        to_del = [svc_old[x] for x in to_del]
        to_add = [svc_new[x] for x in to_add]
        to_change = list()

        for idnr in possible_change:
            old = svc_old[idnr]
            new = svc_new[idnr]

            assert old['router_id'] == new['router_id']

            vrouter = self.vpn_service.get_router_client(old['router_id'])
            gw_iface = self._get_router_gw_iface(vrouter, old['router_id'])

            if vyatta_vpn_config.compare_vpn_services(
                    vrouter, gw_iface, old, new):
                continue

            to_change.append((old, new))

        return to_del, to_change, to_add

    def get_active_services(self):
        return tuple(self._svc_cache)

    def get_router_resources(self, router_id):
        try:
            res = self._router_resources_cache[router_id]
        except KeyError:
            res = vyatta_vpn_config.RouterResources(router_id)
            self._router_resources_cache[router_id] = res

        return res

    def update_status(self, ctx, stat):
        LOG.debug('STAT: %s', pprint.pformat(stat))
        self.server_api.update_status(ctx, stat)

    def _get_router_gw_iface(self, vrouter, router_id):
        router = self.vpn_service.get_router(router_id)
        try:
            gw_interface = vrouter.get_ethernet_if_id(
                router['gw_port']['mac_address'])
        except KeyError:
            raise v_exc.InvalidL3AgentStateError(description=_(
                'Router id={0} have no external gateway.').format(
                    router['id']))
        return gw_interface


class _VyattaPeriodicTasks(periodic_task.PeriodicTasks):
    def __init__(self, driver):
        super(_VyattaPeriodicTasks, self).__init__(cfg.CONF)
        self.driver = driver

    def __call__(self):
        ctx_admin = n_ctx.get_admin_context()
        return self.run_periodic_tasks(ctx_admin)

    @periodic_task.periodic_task(spacing=5)
    def grab_vpn_status(self, ctx):
        LOG.debug('VPN device driver periodic task: grab_vpn_status.')

        svc_by_vrouter = collections.defaultdict(list)
        for svc in self.driver.get_active_services():
            svc_by_vrouter[svc['router_id']].append(svc)

        status = list()

        for router_id, svc_set in svc_by_vrouter.items():
            vrouter = self.driver.vpn_service.get_router_client(router_id)
            resources = self.driver.get_router_resources(router_id)

            try:
                ipsec_sa = vrouter.get_vpn_ipsec_sa()
            except v_exc.VRouterOperationError as e:
                LOG.warning(_LW('Failed to fetch tunnel stats from router '
                                '{0}: {1}').format(router_id, unicode(e)))
                continue

            conn_ok = vyatta_vpn_config.parse_vpn_connections(
                ipsec_sa, resources)

            for svc in svc_set:
                svc_ok = True
                conn_stat = dict()
                for conn in svc[_KEY_CONNECTIONS]:
                    ok = conn['id'] in conn_ok
                    svc_ok = svc_ok and ok
                    conn_stat[conn['id']] = {
                        'status': 'ACTIVE' if ok else 'DOWN',
                        'updated_pending_status': True
                    }

                status.append({
                    'id': svc['id'],
                    'status': 'ACTIVE' if svc_ok else 'DOWN',
                    'updated_pending_status': True,
                    'ipsec_site_connections': conn_stat
                })

        self.driver.update_status(ctx, status)
