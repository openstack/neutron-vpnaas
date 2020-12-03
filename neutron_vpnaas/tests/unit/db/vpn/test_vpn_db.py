#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    (c) Copyright 2015 Cisco Systems Inc.
#    All Rights Reserved.
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

import contextlib
import copy
import os
from unittest import mock

from neutron.api import extensions as api_extensions
from neutron.common import config
from neutron.db import agentschedulers_db
from neutron.db import l3_agentschedulers_db
from neutron.db import servicetype_db as sdb
from neutron import extensions as nextensions
from neutron.scheduler import l3_agent_scheduler
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron_lib.api.definitions import vpn
from neutron_lib.callbacks import events
from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import l3 as l3_exception
from neutron_lib.exceptions import vpn as vpn_exception
from neutron_lib.plugins import constants as nconstants
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from oslo_utils import uuidutils
import webob.exc

from neutron_vpnaas.db.vpn import vpn_db
from neutron_vpnaas.db.vpn import vpn_models
from neutron_vpnaas.services.vpn.common import constants
from neutron_vpnaas.services.vpn import plugin as vpn_plugin
from neutron_vpnaas.tests import base

from neutron_vpnaas import extensions

DB_CORE_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
DB_VPN_PLUGIN_KLASS = "neutron_vpnaas.services.vpn.plugin.VPNPlugin"
FLAVOR_PLUGIN_KLASS = "neutron.services.flavors.flavors_plugin.FlavorsPlugin"
ROOTDIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__),
    '..', '..', '..', '..'))

extensions_path = ':'.join(extensions.__path__ + nextensions.__path__)

_uuid = uuidutils.generate_uuid


class TestVpnCorePlugin(test_l3_plugin.TestL3NatIntPlugin,
                        l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                        agentschedulers_db.DhcpAgentSchedulerDbMixin):
    def __init__(self, configfile=None):
        super(TestVpnCorePlugin, self).__init__()
        self.router_scheduler = l3_agent_scheduler.ChanceScheduler()


class VPNTestMixin(object):
    resource_prefix_map = dict(
        (k.replace('_', '-'),
         "/vpn")
        for k in vpn.RESOURCE_ATTRIBUTE_MAP
    )

    def _create_ikepolicy(self, fmt,
                          name='ikepolicy1',
                          auth_algorithm='sha1',
                          encryption_algorithm='aes-128',
                          phase1_negotiation_mode='main',
                          lifetime_units='seconds',
                          lifetime_value=3600,
                          ike_version='v1',
                          pfs='group5',
                          expected_res_status=None, **kwargs):

        data = {'ikepolicy': {
                'name': name,
                'auth_algorithm': auth_algorithm,
                'encryption_algorithm': encryption_algorithm,
                'phase1_negotiation_mode': phase1_negotiation_mode,
                'lifetime': {
                    'units': lifetime_units,
                    'value': lifetime_value},
                'ike_version': ike_version,
                'pfs': pfs,
                'tenant_id': self._tenant_id
                }}
        if kwargs.get('description') is not None:
            data['ikepolicy']['description'] = kwargs['description']

        ikepolicy_req = self.new_create_request('ikepolicies', data, fmt)
        ikepolicy_res = ikepolicy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(ikepolicy_res.status_int, expected_res_status)

        return ikepolicy_res

    @contextlib.contextmanager
    def ikepolicy(self, fmt=None,
                  name='ikepolicy1',
                  auth_algorithm='sha1',
                  encryption_algorithm='aes-128',
                  phase1_negotiation_mode='main',
                  lifetime_units='seconds',
                  lifetime_value=3600,
                  ike_version='v1',
                  pfs='group5',
                  do_delete=True,
                  **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_ikepolicy(fmt,
                                     name,
                                     auth_algorithm,
                                     encryption_algorithm,
                                     phase1_negotiation_mode,
                                     lifetime_units,
                                     lifetime_value,
                                     ike_version,
                                     pfs,
                                     **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        ikepolicy = self.deserialize(fmt or self.fmt, res)
        yield ikepolicy
        if do_delete:
            self._delete('ikepolicies', ikepolicy['ikepolicy']['id'])

    def _create_ipsecpolicy(self, fmt,
                            name='ipsecpolicy1',
                            auth_algorithm='sha1',
                            encryption_algorithm='aes-128',
                            encapsulation_mode='tunnel',
                            transform_protocol='esp',
                            lifetime_units='seconds',
                            lifetime_value=3600,
                            pfs='group5',
                            expected_res_status=None,
                            **kwargs):

        data = {'ipsecpolicy': {'name': name,
                                'auth_algorithm': auth_algorithm,
                                'encryption_algorithm': encryption_algorithm,
                                'encapsulation_mode': encapsulation_mode,
                                'transform_protocol': transform_protocol,
                                'lifetime': {'units': lifetime_units,
                                             'value': lifetime_value},
                                'pfs': pfs,
                                'tenant_id': self._tenant_id}}
        if kwargs.get('description') is not None:
            data['ipsecpolicy']['description'] = kwargs['description']
        ipsecpolicy_req = self.new_create_request('ipsecpolicies', data, fmt)
        ipsecpolicy_res = ipsecpolicy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(ipsecpolicy_res.status_int, expected_res_status)

        return ipsecpolicy_res

    @contextlib.contextmanager
    def ipsecpolicy(self, fmt=None,
                    name='ipsecpolicy1',
                    auth_algorithm='sha1',
                    encryption_algorithm='aes-128',
                    encapsulation_mode='tunnel',
                    transform_protocol='esp',
                    lifetime_units='seconds',
                    lifetime_value=3600,
                    pfs='group5',
                    do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_ipsecpolicy(fmt,
                                       name,
                                       auth_algorithm,
                                       encryption_algorithm,
                                       encapsulation_mode,
                                       transform_protocol,
                                       lifetime_units,
                                       lifetime_value,
                                       pfs,
                                       **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        ipsecpolicy = self.deserialize(fmt or self.fmt, res)
        yield ipsecpolicy
        if do_delete:
            self._delete('ipsecpolicies', ipsecpolicy['ipsecpolicy']['id'])

    def _create_vpnservice(self, fmt, name,
                           admin_state_up,
                           router_id, subnet_id,
                           expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'vpnservice': {'name': name,
                               'subnet_id': subnet_id,
                               'router_id': router_id,
                               'admin_state_up': admin_state_up,
                               'tenant_id': tenant_id}}
        if kwargs.get('description') is not None:
            data['vpnservice']['description'] = kwargs['description']
        if kwargs.get('flavor_id') is not None:
            data['vpnservice']['flavor_id'] = kwargs['flavor_id']
        vpnservice_req = self.new_create_request('vpnservices', data, fmt)
        if (kwargs.get('set_context') and
                'tenant_id' in kwargs):
            # create a specific auth context for this request
            vpnservice_req.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])
        vpnservice_res = vpnservice_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(vpnservice_res.status_int, expected_res_status)
        return vpnservice_res

    @contextlib.contextmanager
    def vpnservice(self, fmt=None, name='vpnservice1',
                   subnet=None,
                   router=None,
                   admin_state_up=True,
                   do_delete=True,
                   plug_subnet=True,
                   external_subnet_cidr='192.168.100.0/24',
                   external_router=True,
                   **kwargs):
        if not fmt:
            fmt = self.fmt
        with test_db_plugin.optional_ctx(subnet, self.subnet) as tmp_subnet, \
                test_db_plugin.optional_ctx(router,
                                            self.router) as tmp_router, \
                self.subnet(cidr=external_subnet_cidr) as public_sub:
            if external_router:
                self._set_net_external(
                    public_sub['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    tmp_router['router']['id'],
                    public_sub['subnet']['network_id'])
                tmp_router['router']['external_gateway_info'] = {
                    'network_id': public_sub['subnet']['network_id']}
            if plug_subnet:
                self._router_interface_action(
                    'add',
                    tmp_router['router']['id'],
                    tmp_subnet['subnet']['id'], None)

            res = self._create_vpnservice(fmt,
                                          name,
                                          admin_state_up,
                                          router_id=(tmp_router['router']
                                                     ['id']),
                                          subnet_id=(tmp_subnet['subnet']
                                                     ['id']),
                                          **kwargs)
            vpnservice = self.deserialize(fmt or self.fmt, res)
            if res.status_int < 400:
                yield vpnservice

            if do_delete and vpnservice.get('vpnservice'):
                self._delete('vpnservices',
                             vpnservice['vpnservice']['id'])
            if plug_subnet:
                self._router_interface_action(
                    'remove',
                    tmp_router['router']['id'],
                    tmp_subnet['subnet']['id'], None)
            if external_router:
                external_gateway = tmp_router['router'].get(
                    'external_gateway_info')
                if external_gateway:
                    network_id = external_gateway['network_id']
                    self._remove_external_gateway_from_router(
                        tmp_router['router']['id'], network_id)
            if res.status_int >= 400:
                raise webob.exc.HTTPClientError(
                    code=res.status_int, detail=vpnservice)
            self._delete('subnets', public_sub['subnet']['id'])
        if not subnet:
            self._delete('subnets', tmp_subnet['subnet']['id'])

    def _create_ipsec_site_connection(self, fmt, name='test',
                                      peer_address='192.168.1.10',
                                      peer_id='192.168.1.10',
                                      peer_cidrs=None,
                                      mtu=1500,
                                      psk='abcdefg',
                                      initiator='bi-directional',
                                      dpd_action='hold',
                                      dpd_interval=30,
                                      dpd_timeout=120,
                                      vpnservice_id='fake_id',
                                      ikepolicy_id='fake_id',
                                      ipsecpolicy_id='fake_id',
                                      admin_state_up=True,
                                      local_ep_group_id=None,
                                      peer_ep_group_id=None,
                                      expected_res_status=None, **kwargs):
        data = {
            'ipsec_site_connection': {'name': name,
                                      'peer_address': peer_address,
                                      'peer_id': peer_id,
                                      'peer_cidrs': peer_cidrs,
                                      'mtu': mtu,
                                      'psk': psk,
                                      'initiator': initiator,
                                      'dpd': {
                                          'action': dpd_action,
                                          'interval': dpd_interval,
                                          'timeout': dpd_timeout,
                                      },
                                      'vpnservice_id': vpnservice_id,
                                      'ikepolicy_id': ikepolicy_id,
                                      'ipsecpolicy_id': ipsecpolicy_id,
                                      'admin_state_up': admin_state_up,
                                      'tenant_id': self._tenant_id,
                                      'local_ep_group_id': local_ep_group_id,
                                      'peer_ep_group_id': peer_ep_group_id}
        }
        if kwargs.get('description') is not None:
            data['ipsec_site_connection'][
                'description'] = kwargs['description']

        ipsec_site_connection_req = self.new_create_request(
            'ipsec-site-connections', data, fmt
        )
        ipsec_site_connection_res = ipsec_site_connection_req.get_response(
            self.ext_api
        )
        if expected_res_status:
            self.assertEqual(
                ipsec_site_connection_res.status_int, expected_res_status
            )

        return ipsec_site_connection_res

    @contextlib.contextmanager
    def ipsec_site_connection(self, fmt=None, name='ipsec_site_connection1',
                              peer_address='192.168.1.10',
                              peer_id='192.168.1.10',
                              peer_cidrs=None,
                              mtu=1500,
                              psk='abcdefg',
                              initiator='bi-directional',
                              dpd_action='hold',
                              dpd_interval=30,
                              dpd_timeout=120,
                              vpnservice=None,
                              ikepolicy=None,
                              ipsecpolicy=None,
                              admin_state_up=True, do_delete=True,
                              local_ep_group_id=None,
                              peer_ep_group_id=None,
                              **kwargs):
        if not fmt:
            fmt = self.fmt
        with test_db_plugin.optional_ctx(vpnservice, self.vpnservice
                                         ) as tmp_vpnservice, \
                test_db_plugin.optional_ctx(ikepolicy, self.ikepolicy
                                            ) as tmp_ikepolicy, \
                test_db_plugin.optional_ctx(ipsecpolicy, self.ipsecpolicy
                                            ) as tmp_ipsecpolicy:
            vpnservice_id = tmp_vpnservice['vpnservice']['id']
            ikepolicy_id = tmp_ikepolicy['ikepolicy']['id']
            ipsecpolicy_id = tmp_ipsecpolicy['ipsecpolicy']['id']
            if not peer_cidrs and not local_ep_group_id:
                # Must be legacy usage - pick default to use
                peer_cidrs = ['10.0.0.0/24']
            res = self._create_ipsec_site_connection(fmt,
                                                     name,
                                                     peer_address,
                                                     peer_id,
                                                     peer_cidrs,
                                                     mtu,
                                                     psk,
                                                     initiator,
                                                     dpd_action,
                                                     dpd_interval,
                                                     dpd_timeout,
                                                     vpnservice_id,
                                                     ikepolicy_id,
                                                     ipsecpolicy_id,
                                                     admin_state_up,
                                                     local_ep_group_id,
                                                     peer_ep_group_id,
                                                     **kwargs)
            if res.status_int >= 400:
                raise webob.exc.HTTPClientError(code=res.status_int)

            ipsec_site_connection = self.deserialize(
                fmt or self.fmt, res
            )
            yield ipsec_site_connection

            if do_delete:
                self._delete(
                    'ipsec-site-connections',
                    ipsec_site_connection[
                        'ipsec_site_connection']['id']
                )

    def _check_ipsec_site_connection(self, ipsec_site_connection, keys, dpd):
        self.assertEqual(
            keys,
            dict((k, v) for k, v
                 in ipsec_site_connection.items()
                 if k in keys))
        self.assertEqual(
            dpd,
            dict((k, v) for k, v
                 in ipsec_site_connection['dpd'].items()
                 if k in dpd))

    def _set_active(self, model, resource_id):
        service_plugin = directory.get_plugin(nconstants.VPN)
        adminContext = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(adminContext):
            resource_db = service_plugin._get_resource(
                adminContext,
                model,
                resource_id)
            resource_db.status = lib_constants.ACTIVE


class VPNPluginDbTestCase(VPNTestMixin,
                          test_l3_plugin.L3NatTestCaseMixin,
                          base.NeutronDbPluginV2TestCase):
    def setUp(self, core_plugin=None, vpnaas_plugin=DB_VPN_PLUGIN_KLASS,
              vpnaas_provider=None):
        if not vpnaas_provider:
            vpnaas_provider = (
                nconstants.VPN +
                ':vpnaas:neutron_vpnaas.services.vpn.'
                'service_drivers.ipsec.IPsecVPNDriver:default')
        bits = vpnaas_provider.split(':')
        vpnaas_provider = {
            'service_type': bits[0],
            'name': bits[1],
            'driver': bits[2]
        }
        if len(bits) == 4:
            vpnaas_provider['default'] = True
        # override the default service provider
        self.service_providers = (
            mock.patch.object(sdb.ServiceTypeManager,
                              'get_service_providers').start())
        self.service_providers.return_value = [vpnaas_provider]
        # force service type manager to reload configuration:
        sdb.ServiceTypeManager._instance = None
        service_plugins = {
            'vpnaas_plugin': vpnaas_plugin,
            'flavors_plugin': FLAVOR_PLUGIN_KLASS}
        plugin_str = ('neutron_vpnaas.tests.unit.db.vpn.'
                      'test_vpn_db.TestVpnCorePlugin')

        super(VPNPluginDbTestCase, self).setUp(
            plugin_str,
            service_plugins=service_plugins
        )
        self._subnet_id = _uuid()
        self.core_plugin = TestVpnCorePlugin()
        self.plugin = vpn_plugin.VPNPlugin()
        ext_mgr = api_extensions.PluginAwareExtensionManager(
            extensions_path,
            {nconstants.CORE: self.core_plugin,
             nconstants.VPN: self.plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)


class TestVpnaas(VPNPluginDbTestCase):

    def setUp(self, **kwargs):
        # TODO(armax): this is far from being a unit test case, as it tests
        # that multiple parties (core + vpn) are integrated properly and
        # should be replaced by API test that do not rely on so much mocking.
        # NOTE(armax): make sure that the callbacks needed by this test are
        # registered, as they may get wiped out depending by the order in
        # which imports, subscriptions and mocks occur.
        super(TestVpnaas, self).setUp(**kwargs)
        vpn_db.subscribe()

    def _check_policy(self, policy, keys, lifetime):
        for k, v in keys:
            self.assertEqual(policy[k], v)
        for k, v in lifetime.items():
            self.assertEqual(policy['lifetime'][k], v)

    def test_create_ikepolicy(self):
        """Test case to create an ikepolicy."""
        name = "ikepolicy1"
        description = 'ipsec-ikepolicy'
        keys = [('name', name),
                ('description', 'ipsec-ikepolicy'),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name, description=description) as ikepolicy:
            self._check_policy(ikepolicy['ikepolicy'], keys, lifetime)

    def test_create_ikepolicy_with_aggressive_mode(self):
        """Test case to create an ikepolicy with aggressive mode."""
        name = "ikepolicy1"
        description = 'ipsec-ikepolicy'
        mode = 'aggressive'
        keys = [('name', name),
                ('description', 'ipsec-ikepolicy'),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'aggressive'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name, description=description,
                            phase1_negotiation_mode=mode) as ikepolicy:
            self._check_policy(ikepolicy['ikepolicy'], keys, lifetime)

    def test_delete_ikepolicy(self):
        """Test case to delete an ikepolicy."""
        with self.ikepolicy(do_delete=False) as ikepolicy:
            req = self.new_delete_request('ikepolicies',
                                          ikepolicy['ikepolicy']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_ikepolicy(self):
        """Test case to show or get an ikepolicy."""
        name = "ikepolicy1"
        description = 'ipsec-ikepolicy'
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name, description=description) as ikepolicy:
            req = self.new_show_request('ikepolicies',
                                        ikepolicy['ikepolicy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self._check_policy(res['ikepolicy'], keys, lifetime)

    def test_list_ikepolicies(self):
        """Test case to list all ikepolicies."""
        name = "ikepolicy_list"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name) as ikepolicy:
            keys.append(('id', ikepolicy['ikepolicy']['id']))
            req = self.new_list_request('ikepolicies')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            for k, v in keys:
                self.assertEqual(res['ikepolicies'][0][k], v)
            for k, v in lifetime.items():
                self.assertEqual(res['ikepolicies'][0]['lifetime'][k], v)

    def test_list_ikepolicies_with_sort_emulated(self):
        """Test case to list all ikepolicies."""
        with self.ikepolicy(name='ikepolicy1') as ikepolicy1, \
                self.ikepolicy(name='ikepolicy2') as ikepolicy2, \
                self.ikepolicy(name='ikepolicy3') as ikepolicy3:
            self._test_list_with_sort('ikepolicy', (ikepolicy3,
                                                    ikepolicy2,
                                                    ikepolicy1),
                                      [('name', 'desc')],
                                      'ikepolicies')

    def test_list_ikepolicies_with_pagination_emulated(self):
        """Test case to list all ikepolicies with pagination."""
        with self.ikepolicy(name='ikepolicy1') as ikepolicy1, \
                self.ikepolicy(name='ikepolicy2') as ikepolicy2, \
                self.ikepolicy(name='ikepolicy3') as ikepolicy3:
            self._test_list_with_pagination('ikepolicy',
                                            (ikepolicy1,
                                             ikepolicy2,
                                             ikepolicy3),
                                            ('name', 'asc'), 2, 2,
                                            'ikepolicies')

    def test_list_ikepolicies_with_pagination_reverse_emulated(self):
        """Test case to list all ikepolicies with reverse pagination."""
        with self.ikepolicy(name='ikepolicy1') as ikepolicy1, \
                self.ikepolicy(name='ikepolicy2') as ikepolicy2, \
                self.ikepolicy(name='ikepolicy3') as ikepolicy3:
            self._test_list_with_pagination_reverse('ikepolicy',
                                                    (ikepolicy1,
                                                     ikepolicy2,
                                                     ikepolicy3),
                                                    ('name', 'asc'), 2, 2,
                                                    'ikepolicies')

    def test_update_ikepolicy(self):
        """Test case to update an ikepolicy."""
        name = "new_ikepolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id),
                ('lifetime', {'units': 'seconds',
                              'value': 60})]
        with self.ikepolicy(name=name) as ikepolicy:
            data = {'ikepolicy': {'name': name,
                                  'lifetime': {'units': 'seconds',
                                               'value': 60}}}
            req = self.new_update_request("ikepolicies",
                                          data,
                                          ikepolicy['ikepolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['ikepolicy'][k], v)

    def test_update_ikepolicy_with_aggressive_mode(self):
        """Test case to update an ikepolicy with aggressive mode."""
        name = "new_ikepolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'aggressive'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id),
                ('lifetime', {'units': 'seconds',
                              'value': 60})]
        with self.ikepolicy(name=name) as ikepolicy:
            data = {'ikepolicy': {'name': name,
                                  'phase1_negotiation_mode': 'aggressive',
                                  'lifetime': {'units': 'seconds',
                                               'value': 60}}}
            req = self.new_update_request("ikepolicies",
                                          data,
                                          ikepolicy['ikepolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['ikepolicy'][k], v)

    def test_create_ikepolicy_with_invalid_values(self):
        """Test case to test invalid values."""
        name = 'ikepolicy1'
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               auth_algorithm='md5',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               auth_algorithm=200,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               encryption_algorithm='des',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               encryption_algorithm=100,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               phase1_negotiation_mode='unsupported',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               phase1_negotiation_mode=-100,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               ike_version='v6',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               ike_version=500,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               pfs='group1',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               pfs=120,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_units='Megabytes',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_units=20000,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_value=-20,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_value='Megabytes',
                               expected_res_status=400)

    def test_create_ipsecpolicy(self):
        """Test case to create an ipsecpolicy."""
        name = "ipsecpolicy1"
        description = 'my-ipsecpolicy'
        keys = [('name', name),
                ('description', 'my-ipsecpolicy'),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ipsecpolicy(name=name,
                              description=description) as ipsecpolicy:
            self._check_policy(ipsecpolicy['ipsecpolicy'], keys, lifetime)

    def test_delete_ipsecpolicy(self):
        """Test case to delete an ipsecpolicy."""
        with self.ipsecpolicy(do_delete=False) as ipsecpolicy:
            req = self.new_delete_request('ipsecpolicies',
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_ipsecpolicy(self):
        """Test case to show or get an ipsecpolicy."""
        name = "ipsecpolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ipsecpolicy(name=name) as ipsecpolicy:
            req = self.new_show_request('ipsecpolicies',
                                        ipsecpolicy['ipsecpolicy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self._check_policy(res['ipsecpolicy'], keys, lifetime)

    def test_list_ipsecpolicies(self):
        """Test case to list all ipsecpolicies."""
        name = "ipsecpolicy_list"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ipsecpolicy(name=name) as ipsecpolicy:
            keys.append(('id', ipsecpolicy['ipsecpolicy']['id']))
            req = self.new_list_request('ipsecpolicies')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            self._check_policy(res['ipsecpolicies'][0], keys, lifetime)

    def test_list_ipsecpolicies_with_sort_emulated(self):
        """Test case to list all ipsecpolicies."""
        with self.ipsecpolicy(name='ipsecpolicy1') as ipsecpolicy1, \
                self.ipsecpolicy(name='ipsecpolicy2') as ipsecpolicy2, \
                self.ipsecpolicy(name='ipsecpolicy3') as ipsecpolicy3:
            self._test_list_with_sort('ipsecpolicy', (ipsecpolicy3,
                                                      ipsecpolicy2,
                                                      ipsecpolicy1),
                                      [('name', 'desc')],
                                      'ipsecpolicies')

    def test_list_ipsecpolicies_with_pagination_emulated(self):
        """Test case to list all ipsecpolicies with pagination."""
        with self.ipsecpolicy(name='ipsecpolicy1') as ipsecpolicy1, \
                self.ipsecpolicy(name='ipsecpolicy2') as ipsecpolicy2, \
                self.ipsecpolicy(name='ipsecpolicy3') as ipsecpolicy3:
            self._test_list_with_pagination('ipsecpolicy',
                                            (ipsecpolicy1,
                                             ipsecpolicy2,
                                             ipsecpolicy3),
                                            ('name', 'asc'), 2, 2,
                                            'ipsecpolicies')

    def test_list_ipsecpolicies_with_pagination_reverse_emulated(self):
        """Test case to list all ipsecpolicies with reverse pagination."""
        with self.ipsecpolicy(name='ipsecpolicy1') as ipsecpolicy1, \
                self.ipsecpolicy(name='ipsecpolicy2') as ipsecpolicy2, \
                self.ipsecpolicy(name='ipsecpolicy3') as ipsecpolicy3:
            self._test_list_with_pagination_reverse('ipsecpolicy',
                                                    (ipsecpolicy1,
                                                     ipsecpolicy2,
                                                     ipsecpolicy3),
                                                    ('name', 'asc'), 2, 2,
                                                    'ipsecpolicies')

    def test_update_ipsecpolicy(self):
        """Test case to update an ipsecpolicy."""
        name = "new_ipsecpolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id),
                ('lifetime', {'units': 'seconds',
                              'value': 60})]
        with self.ipsecpolicy(name=name) as ipsecpolicy:
            data = {'ipsecpolicy': {'name': name,
                                    'lifetime': {'units': 'seconds',
                                                 'value': 60}}}
            req = self.new_update_request("ipsecpolicies",
                                          data,
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['ipsecpolicy'][k], v)

    def test_update_ipsecpolicy_lifetime(self):
        with self.ipsecpolicy() as ipsecpolicy:
            data = {'ipsecpolicy': {'lifetime': {'units': 'seconds'}}}
            req = self.new_update_request("ipsecpolicies",
                                          data,
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['ipsecpolicy']['lifetime']['units'],
                             'seconds')

            data = {'ipsecpolicy': {'lifetime': {'value': 60}}}
            req = self.new_update_request("ipsecpolicies",
                                          data,
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['ipsecpolicy']['lifetime']['value'], 60)

    def test_create_ipsecpolicy_with_invalid_values(self):
        """Test case to test invalid values."""
        name = 'ipsecpolicy1'

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, auth_algorithm='md5', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, auth_algorithm=100, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, encryption_algorithm='des', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, encryption_algorithm=200, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, transform_protocol='abcd', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, transform_protocol=500, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name,
            encapsulation_mode='unsupported', expected_res_status=400)
        self._create_ipsecpolicy(name=name,
                                 fmt=self.fmt,
                                 encapsulation_mode=100,
                                 expected_res_status=400)

        self._create_ipsecpolicy(name=name,
                                 fmt=self.fmt,
                                 pfs='group9', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt, name=name, pfs=-1, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt, name=name, lifetime_units='minutes',
            expected_res_status=400)

        self._create_ipsecpolicy(fmt=self.fmt, name=name, lifetime_units=100,
                                 expected_res_status=400)

        self._create_ipsecpolicy(fmt=self.fmt, name=name,
                                 lifetime_value=-800, expected_res_status=400)
        self._create_ipsecpolicy(fmt=self.fmt, name=name,
                                 lifetime_value='Megabytes',
                                 expected_res_status=400)

    def test_create_vpnservice(self, **extras):
        """Test case to create a vpnservice."""
        description = 'my-vpn-service'
        expected = {'name': 'vpnservice1',
                    'description': 'my-vpn-service',
                    'admin_state_up': True,
                    'status': 'PENDING_CREATE',
                    'tenant_id': self._tenant_id, }

        expected.update(extras)
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                expected['router_id'] = router['router']['id']
                expected['subnet_id'] = subnet['subnet']['id']
                name = expected['name']
                with self.vpnservice(name=name,
                                     subnet=subnet,
                                     router=router,
                                     description=description,
                                     **extras) as vpnservice:
                    self.assertEqual(dict((k, v) for k, v in
                                          vpnservice['vpnservice'].items()
                                          if k in expected),
                                     expected)

    def test_delete_router_interface_in_use_by_vpnservice(self):
        """Test delete router interface in use by vpn service."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router):
                    self._router_interface_action('remove',
                                                  router['router']['id'],
                                                  subnet['subnet']['id'],
                                                  None,
                                                  expected_code=webob.exc.
                                                  HTTPConflict.code)

    def test_delete_router_interface_not_in_use_by_vpnservice(self):
        """Test delete router interface not in use by vpn service."""
        with self.subnet(cidr='10.2.0.0/24') as subnet, \
                self.router() as router1, self.router() as router2, \
                self.vpnservice(subnet=subnet, router=router1), \
                self.port(subnet=subnet) as port:
            self._router_interface_action('add',
                                          router2['router']['id'],
                                          None,
                                          port['port']['id'],
                                          expected_code=webob.exc.
                                          HTTPOk.code)
            self._router_interface_action('remove',
                                          router1['router']['id'],
                                          subnet['subnet']['id'],
                                          None,
                                          expected_code=webob.exc.
                                          HTTPConflict.code)
            self._router_interface_action('remove',
                                          router2['router']['id'],
                                          None,
                                          port['port']['id'],
                                          expected_code=webob.exc.
                                          HTTPOk.code)

    def test_delete_external_gateway_interface_in_use_by_vpnservice(self):
        """Test delete external gateway interface in use by vpn service."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.subnet(cidr='11.0.0.0/24') as public_sub:
                    self._set_net_external(
                        public_sub['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        router['router']['id'],
                        public_sub['subnet']['network_id'])
                    with self.vpnservice(subnet=subnet,
                                         router=router):
                        self._remove_external_gateway_from_router(
                            router['router']['id'],
                            public_sub['subnet']['network_id'],
                            expected_code=webob.exc.HTTPConflict.code)

    def test_router_update_after_ipsec_site_connection(self):
        """Test case to update router after vpn connection."""
        rname1 = "router_one"
        rname2 = "router_two"
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router(name=rname1) as r:
                with self.vpnservice(subnet=subnet,
                                     router=r
                                     ) as vpnservice:
                    self.ipsec_site_connection(
                        name='connection1', vpnservice=vpnservice
                    )
                    body = self._show('routers', r['router']['id'])
                    self.assertEqual(body['router']['name'], rname1)
                    body = self._update('routers', r['router']['id'],
                                        {'router': {'name': rname2}})
                    body = self._show('routers', r['router']['id'])
                    self.assertEqual(body['router']['name'], rname2)

    def test_update_vpnservice(self):
        """Test case to update a vpnservice."""
        name = 'new_vpnservice1'
        keys = [('name', name)]
        with self.subnet(cidr='10.2.0.0/24') as subnet, \
                self.router() as router:
            with self.vpnservice(name=name,
                                 subnet=subnet,
                                 router=router) as vpnservice:
                keys.append(('subnet_id',
                             vpnservice['vpnservice']['subnet_id']))
                keys.append(('router_id',
                             vpnservice['vpnservice']['router_id']))
                data = {'vpnservice': {'name': name}}
                self._set_active(vpn_models.VPNService,
                                 vpnservice['vpnservice']['id'])
                req = self.new_update_request(
                    'vpnservices',
                    data,
                    vpnservice['vpnservice']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['vpnservice'][k], v)

    def test_update_vpnservice_with_invalid_state(self):
        """Test case to update a vpnservice in invalid state ."""
        name = 'new_vpnservice1'
        keys = [('name', name)]
        with self.subnet(cidr='10.2.0.0/24') as subnet, \
                self.router() as router:
            with self.vpnservice(name=name,
                                 subnet=subnet,
                                 router=router) as vpnservice:
                keys.append(('subnet_id',
                             vpnservice['vpnservice']['subnet_id']))
                keys.append(('router_id',
                             vpnservice['vpnservice']['router_id']))
                data = {'vpnservice': {'name': name}}
                req = self.new_update_request(
                    'vpnservices',
                    data,
                    vpnservice['vpnservice']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(400, res.status_int)
                res = self.deserialize(self.fmt, res)
                self.assertIn(vpnservice['vpnservice']['id'],
                              res['NeutronError']['message'])

    def test_delete_vpnservice(self):
        """Test case to delete a vpnservice."""
        with self.vpnservice(name='vpnserver',
                             do_delete=False) as vpnservice:
            req = self.new_delete_request('vpnservices',
                                          vpnservice['vpnservice']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_vpnservice(self):
        """Test case to show or get a vpnservice."""
        name = "vpnservice1"
        keys = [('name', name),
                ('description', ''),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vpnservice(name=name) as vpnservice:
            req = self.new_show_request('vpnservices',
                                        vpnservice['vpnservice']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vpnservice'][k], v)

    def test_list_vpnservices(self):
        """Test case to list all vpnservices."""
        name = "vpnservice_list"
        keys = [('name', name),
                ('description', ''),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vpnservice(name=name) as vpnservice:
            keys.append(('subnet_id', vpnservice['vpnservice']['subnet_id']))
            keys.append(('router_id', vpnservice['vpnservice']['router_id']))
            req = self.new_list_request('vpnservices')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            for k, v in keys:
                self.assertEqual(res['vpnservices'][0][k], v)

    def test_list_vpnservices_with_sort_emulated(self):
        """Test case to list all vpnservices with sorting."""
        with self.subnet() as subnet:
            with self.router() as router:
                with self.vpnservice(name='vpnservice1',
                                     subnet=subnet,
                                     router=router,
                                     external_subnet_cidr='192.168.10.0/24'
                                     ) as vpnservice1, \
                        self.vpnservice(name='vpnservice2',
                                        subnet=subnet,
                                        router=router,
                                        plug_subnet=False,
                                        external_router=False,
                                        external_subnet_cidr='192.168.11.0/24'
                                        ) as vpnservice2, \
                        self.vpnservice(name='vpnservice3',
                                        subnet=subnet,
                                        router=router,
                                        plug_subnet=False,
                                        external_router=False,
                                        external_subnet_cidr='192.168.13.0/24'
                                        ) as vpnservice3:
                    self._test_list_with_sort('vpnservice', (vpnservice3,
                                                             vpnservice2,
                                                             vpnservice1),
                                              [('name', 'desc')])

    def test_list_vpnservice_with_pagination_emulated(self):
        """Test case to list all vpnservices with pagination."""
        with self.subnet() as subnet:
            with self.router() as router:
                with self.vpnservice(name='vpnservice1',
                                     subnet=subnet,
                                     router=router,
                                     external_subnet_cidr='192.168.10.0/24'
                                     ) as vpnservice1, \
                        self.vpnservice(name='vpnservice2',
                                        subnet=subnet,
                                        router=router,
                                        plug_subnet=False,
                                        external_subnet_cidr='192.168.20.0/24',
                                        external_router=False
                                        ) as vpnservice2, \
                        self.vpnservice(name='vpnservice3',
                                        subnet=subnet,
                                        router=router,
                                        plug_subnet=False,
                                        external_subnet_cidr='192.168.30.0/24',
                                        external_router=False
                                        ) as vpnservice3:
                    self._test_list_with_pagination('vpnservice',
                                                    (vpnservice1,
                                                     vpnservice2,
                                                     vpnservice3),
                                                    ('name', 'asc'), 2, 2)

    def test_list_vpnservice_with_pagination_reverse_emulated(self):
        """Test case to list all vpnservices with reverse pagination."""
        with self.subnet() as subnet:
            with self.router() as router:
                with self.vpnservice(name='vpnservice1',
                                     subnet=subnet,
                                     router=router,
                                     external_subnet_cidr='192.168.10.0/24'
                                     ) as vpnservice1, \
                        self.vpnservice(name='vpnservice2',
                                        subnet=subnet,
                                        router=router,
                                        plug_subnet=False,
                                        external_subnet_cidr='192.168.11.0/24',
                                        external_router=False
                                        ) as vpnservice2, \
                        self.vpnservice(name='vpnservice3',
                                        subnet=subnet,
                                        router=router,
                                        plug_subnet=False,
                                        external_subnet_cidr='192.168.12.0/24',
                                        external_router=False
                                        ) as vpnservice3:
                    self._test_list_with_pagination_reverse('vpnservice',
                                                            (vpnservice1,
                                                             vpnservice2,
                                                             vpnservice3),
                                                            ('name', 'asc'),
                                                            2, 2)

    def test_create_ipsec_site_connection_with_invalid_values(self):
        """Test case to create an ipsec_site_connection with invalid values."""
        name = 'connection1'
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, peer_cidrs='myname', expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, mtu=-100, expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, dpd_action='unsupported', expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, dpd_interval=-1, expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, dpd_timeout=-200, expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, initiator='unsupported', expected_status_int=400)

    def _test_create_ipsec_site_connection(self, key_overrides=None,
                                           setup_overrides=None,
                                           expected_status_int=200):
        """Create ipsec_site_connection and check results."""
        params = {'ikename': 'ikepolicy1',
                  'ipsecname': 'ipsecpolicy1',
                  'vpnsname': 'vpnservice1',
                  'subnet_cidr': '10.2.0.0/24',
                  'subnet_version': 4}
        if setup_overrides is not None:
            params.update(setup_overrides)
        keys = {'name': 'connection1',
                'description': 'my-ipsec-connection',
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
        if key_overrides is not None:
            keys.update(key_overrides)
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        with self.ikepolicy(name=params['ikename']) as ikepolicy, \
                self.ipsecpolicy(name=params['ipsecname']) as ipsecpolicy, \
                self.subnet(cidr=params['subnet_cidr'],
                            ip_version=params['subnet_version']) as subnet, \
                self.router() as router:
            with self.vpnservice(name=params['vpnsname'], subnet=subnet,
                                 router=router) as vpnservice1:
                keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                keys['ipsecpolicy_id'] = ipsecpolicy['ipsecpolicy']['id']
                keys['vpnservice_id'] = vpnservice1['vpnservice']['id']
                try:
                    with self.ipsec_site_connection(
                            self.fmt,
                            keys['name'],
                            keys['peer_address'],
                            keys['peer_id'],
                            keys['peer_cidrs'],
                            keys['mtu'],
                            keys['psk'],
                            keys['initiator'],
                            dpd['action'],
                            dpd['interval'],
                            dpd['timeout'],
                            vpnservice1,
                            ikepolicy,
                            ipsecpolicy,
                            keys['admin_state_up'],
                            description=keys['description']
                    ) as ipsec_site_connection:
                        if expected_status_int != 200:
                            self.fail("Expected failure on create")
                        self._check_ipsec_site_connection(
                                ipsec_site_connection['ipsec_site_connection'],
                                keys,
                                dpd)
                except webob.exc.HTTPClientError as ce:
                    self.assertEqual(ce.code, expected_status_int)
        self._delete('subnets', subnet['subnet']['id'])

    def test_create_ipsec_site_connection(self, **extras):
        """Test case to create an ipsec_site_connection."""
        self._test_create_ipsec_site_connection(key_overrides=extras)

    def test_delete_ipsec_site_connection(self):
        """Test case to delete a ipsec_site_connection."""
        with self.ipsec_site_connection(
                do_delete=False) as ipsec_site_connection:
            req = self.new_delete_request(
                'ipsec-site-connections',
                ipsec_site_connection['ipsec_site_connection']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_update_ipsec_site_connection(self):
        """Test case for valid updates to IPSec site connection."""
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        self._test_update_ipsec_site_connection(update={'dpd': dpd})
        self._test_update_ipsec_site_connection(update={'mtu': 2000})
        ipv6_settings = {
            'peer_address': 'fe80::c0a8:10a',
            'peer_id': 'fe80::c0a8:10a',
            'peer_cidrs': ['fe80::c0a8:200/120', 'fe80::c0a8:300/120'],
            'subnet_cidr': 'fe80::a02:0/120',
            'subnet_version': 6}
        self._test_update_ipsec_site_connection(update={'mtu': 2000},
                                                overrides=ipv6_settings)

    def test_update_ipsec_site_connection_with_invalid_state(self):
        """Test updating an ipsec_site_connection in invalid state."""
        self._test_update_ipsec_site_connection(
            overrides={'make_active': False},
            expected_status_int=400)

    def test_update_ipsec_site_connection_peer_cidrs(self):
        """Test updating an ipsec_site_connection for peer_cidrs."""
        new_peers = {'peer_cidrs': ['192.168.4.0/24',
                                    '192.168.5.0/24']}
        self._test_update_ipsec_site_connection(
            update=new_peers)

    def _test_update_ipsec_site_connection(self,
                                           update={'name': 'new name'},
                                           overrides=None,
                                           expected_status_int=200):
        """Creates and then updates ipsec_site_connection."""
        keys = {'name': 'new_ipsec_site_connection',
                'ikename': 'ikepolicy1',
                'ipsecname': 'ipsecpolicy1',
                'vpnsname': 'vpnservice1',
                'description': 'my-ipsec-connection',
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'ACTIVE',
                'admin_state_up': True,
                'action': 'hold',
                'interval': 40,
                'timeout': 120,
                'subnet_cidr': '10.2.0.0/24',
                'subnet_version': 4,
                'make_active': True}
        if overrides is not None:
            keys.update(overrides)

        with self.ikepolicy(name=keys['ikename']) as ikepolicy, \
                self.ipsecpolicy(name=keys['ipsecname']) as ipsecpolicy, \
                self.subnet(cidr=keys['subnet_cidr'],
                            ip_version=keys['subnet_version']) as subnet, \
                self.router() as router:
            with self.vpnservice(name=keys['vpnsname'], subnet=subnet,
                                 router=router) as vpnservice1:
                ext_gw = router['router']['external_gateway_info']
                if ext_gw:
                    self._create_subnet(self.fmt,
                        net_id=ext_gw['network_id'],
                        ip_version=6, cidr='2001:db8::/32')
                keys['vpnservice_id'] = vpnservice1['vpnservice']['id']
                keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                keys['ipsecpolicy_id'] = ipsecpolicy['ipsecpolicy']['id']
                with self.ipsec_site_connection(
                    self.fmt,
                    keys['name'],
                    keys['peer_address'],
                    keys['peer_id'],
                    keys['peer_cidrs'],
                    keys['mtu'],
                    keys['psk'],
                    keys['initiator'],
                    keys['action'],
                    keys['interval'],
                    keys['timeout'],
                    vpnservice1,
                    ikepolicy,
                    ipsecpolicy,
                    keys['admin_state_up'],
                    description=keys['description']
                ) as ipsec_site_connection:
                    data = {'ipsec_site_connection': update}
                    if keys.get('make_active', None):
                        self._set_active(
                            vpn_models.IPsecSiteConnection,
                            (ipsec_site_connection['ipsec_site_connection']
                             ['id']))
                    req = self.new_update_request(
                        'ipsec-site-connections',
                        data,
                        ipsec_site_connection['ipsec_site_connection']['id'])
                    res = req.get_response(self.ext_api)
                    self.assertEqual(expected_status_int, res.status_int)
                    if expected_status_int == 200:
                        res_dict = self.deserialize(self.fmt, res)
                        actual = res_dict['ipsec_site_connection']
                        for k, v in update.items():
                            # Sort lists before checking equality
                            if isinstance(actual[k], list):
                                self.assertEqual(v, sorted(actual[k]))
                            else:
                                self.assertEqual(v, actual[k])
        self._delete('networks', subnet['subnet']['network_id'])

    def test_show_ipsec_site_connection(self):
        """Test case to show a ipsec_site_connection."""
        ikename = "ikepolicy1"
        ipsecname = "ipsecpolicy1"
        vpnsname = "vpnservice1"
        name = "connection1"
        description = "my-ipsec-connection"
        keys = {'name': name,
                'description': "my-ipsec-connection",
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        with self.ikepolicy(name=ikename) as ikepolicy, \
                self.ipsecpolicy(name=ipsecname) as ipsecpolicy, \
                self.subnet() as subnet, \
                self.router() as router:
            with self.vpnservice(name=vpnsname, subnet=subnet,
                                 router=router) as vpnservice1:
                keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                keys['ipsecpolicy_id'] = ipsecpolicy['ipsecpolicy']['id']
                keys['vpnservice_id'] = vpnservice1['vpnservice']['id']
                with self.ipsec_site_connection(
                    self.fmt,
                    name,
                    keys['peer_address'],
                    keys['peer_id'],
                    keys['peer_cidrs'],
                    keys['mtu'],
                    keys['psk'],
                    keys['initiator'],
                    dpd['action'],
                    dpd['interval'],
                    dpd['timeout'],
                    vpnservice1,
                    ikepolicy,
                    ipsecpolicy,
                    keys['admin_state_up'],
                    description=description,
                ) as ipsec_site_connection:

                    req = self.new_show_request(
                        'ipsec-site-connections',
                        ipsec_site_connection[
                            'ipsec_site_connection']['id'],
                        fmt=self.fmt
                    )
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )

                    self._check_ipsec_site_connection(
                        res['ipsec_site_connection'],
                        keys,
                        dpd)

    def test_list_ipsec_site_connections_with_sort_emulated(self):
        """Test case to list all ipsec_site_connections with sort."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router
                                     ) as vpnservice:
                    with self.ipsec_site_connection(name='connection1',
                                                    vpnservice=vpnservice
                                                    ) as conn1, \
                            self.ipsec_site_connection(name='connection2',
                                                       vpnservice=vpnservice
                                                       ) as conn2, \
                            self.ipsec_site_connection(name='connection3',
                                                       vpnservice=vpnservice
                                                       ) as conn3:
                        self._test_list_with_sort('ipsec-site-connection',
                                                  (conn3, conn2, conn1),
                                                  [('name', 'desc')])

    def test_list_ipsec_site_connections_with_pagination_emulated(self):
        """Test case to list all ipsec_site_connections with pagination."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router
                                     ) as vpnservice:
                    with self.ipsec_site_connection(
                            name='ipsec_site_connection1',
                            vpnservice=vpnservice) as conn1, \
                            self.ipsec_site_connection(
                                name='ipsec_site_connection1',
                                vpnservice=vpnservice) as conn2, \
                            self.ipsec_site_connection(
                                name='ipsec_site_connection1',
                                vpnservice=vpnservice) as conn3:
                        self._test_list_with_pagination(
                            'ipsec-site-connection',
                            (conn1, conn2, conn3),
                            ('name', 'asc'), 2, 2)

    def test_list_ipsec_site_conns_with_pagination_reverse_emulated(self):
        """Test to list all ipsec_site_connections with reverse pagination."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router
                                     ) as vpnservice:
                    with self.ipsec_site_connection(name='connection1',
                                                    vpnservice=vpnservice
                                                    ) as conn1, \
                            self.ipsec_site_connection(name='connection2',
                                                       vpnservice=vpnservice
                                                       ) as conn2, \
                            self.ipsec_site_connection(name='connection3',
                                                       vpnservice=vpnservice
                                                       ) as conn3:
                        self._test_list_with_pagination_reverse(
                            'ipsec-site-connection',
                            (conn1, conn2, conn3),
                            ('name', 'asc'), 2, 2
                        )

    def test_create_vpn(self):
        """Test case to create a vpn."""
        vpns_name = "vpnservice1"
        ike_name = "ikepolicy1"
        ipsec_name = "ipsecpolicy1"
        name1 = "ipsec_site_connection1"
        with self.ikepolicy(name=ike_name) as ikepolicy, \
                self.ipsecpolicy(name=ipsec_name) as ipsecpolicy, \
                self.vpnservice(name=vpns_name) as vpnservice:
            vpnservice_id = vpnservice['vpnservice']['id']
            ikepolicy_id = ikepolicy['ikepolicy']['id']
            ipsecpolicy_id = ipsecpolicy['ipsecpolicy']['id']
            with self.ipsec_site_connection(
                self.fmt,
                name1,
                '192.168.1.10',
                '192.168.1.10',
                ['192.168.2.0/24',
                 '192.168.3.0/24'],
                1500,
                'abcdef',
                'bi-directional',
                'hold',
                30,
                120,
                vpnservice,
                ikepolicy,
                ipsecpolicy,
                True
            ) as vpnconn1:

                vpnservice_req = self.new_show_request(
                    'vpnservices',
                    vpnservice_id,
                    fmt=self.fmt)
                vpnservice_updated = self.deserialize(
                    self.fmt,
                    vpnservice_req.get_response(self.ext_api)
                )
                self.assertEqual(
                    vpnservice_updated['vpnservice']['id'],
                    vpnconn1['ipsec_site_connection']['vpnservice_id']
                )
                ikepolicy_req = self.new_show_request('ikepolicies',
                                                      ikepolicy_id,
                                                      fmt=self.fmt)
                ikepolicy_res = self.deserialize(
                    self.fmt,
                    ikepolicy_req.get_response(self.ext_api)
                )
                self.assertEqual(
                    ikepolicy_res['ikepolicy']['id'],
                    vpnconn1['ipsec_site_connection']['ikepolicy_id'])
                ipsecpolicy_req = self.new_show_request(
                    'ipsecpolicies',
                    ipsecpolicy_id,
                    fmt=self.fmt)
                ipsecpolicy_res = self.deserialize(
                    self.fmt,
                    ipsecpolicy_req.get_response(self.ext_api)
                )
                self.assertEqual(
                    ipsecpolicy_res['ipsecpolicy']['id'],
                    vpnconn1['ipsec_site_connection']['ipsecpolicy_id']
                )

    def test_delete_ikepolicy_inuse(self):
        """Test case to delete an ikepolicy, that is in use."""
        vpns_name = "vpnservice1"
        ike_name = "ikepolicy1"
        ipsec_name = "ipsecpolicy1"
        name1 = "ipsec_site_connection1"
        with self.ikepolicy(name=ike_name) as ikepolicy:
            with self.ipsecpolicy(name=ipsec_name) as ipsecpolicy:
                with self.vpnservice(name=vpns_name) as vpnservice:
                    with self.ipsec_site_connection(
                        self.fmt,
                        name1,
                        '192.168.1.10',
                        '192.168.1.10',
                        ['192.168.2.0/24',
                         '192.168.3.0/24'],
                        1500,
                        'abcdef',
                        'bi-directional',
                        'hold',
                        30,
                        120,
                        vpnservice,
                        ikepolicy,
                        ipsecpolicy,
                        True
                    ):
                        delete_req = self.new_delete_request(
                            'ikepolicies',
                            ikepolicy['ikepolicy']['id']
                        )
                        delete_res = delete_req.get_response(self.ext_api)
                        self.assertEqual(409, delete_res.status_int)

    def test_delete_ipsecpolicy_inuse(self):
        """Test case to delete an ipsecpolicy, that is in use."""
        vpns_name = "vpnservice1"
        ike_name = "ikepolicy1"
        ipsec_name = "ipsecpolicy1"
        name1 = "ipsec_site_connection1"
        with self.ikepolicy(name=ike_name) as ikepolicy:
            with self.ipsecpolicy(name=ipsec_name) as ipsecpolicy:
                with self.vpnservice(name=vpns_name) as vpnservice:
                    with self.ipsec_site_connection(
                        self.fmt,
                        name1,
                        '192.168.1.10',
                        '192.168.1.10',
                        ['192.168.2.0/24',
                         '192.168.3.0/24'],
                        1500,
                        'abcdef',
                        'bi-directional',
                        'hold',
                        30,
                        120,
                        vpnservice,
                        ikepolicy,
                        ipsecpolicy,
                        True
                    ):

                        delete_req = self.new_delete_request(
                            'ipsecpolicies',
                            ipsecpolicy['ipsecpolicy']['id']
                        )
                        delete_res = delete_req.get_response(self.ext_api)
                        self.assertEqual(409, delete_res.status_int)

    def test_router_in_use_by_vpnaas(self):
        """Check that exception raised, if router in use by VPNaaS."""
        with self.subnet(cidr='10.2.0.0/24') as subnet, \
                self.router() as router:
            with self.vpnservice(subnet=subnet,
                                 router=router):
                self.assertRaises(l3_exception.RouterInUse,
                                  self.plugin.check_router_in_use,
                                  context.get_admin_context(),
                                  router['router']['id'])

    def test_subnet_in_use_by_vpnaas(self):
        """Check that exception raised, if subnet in use by VPNaaS."""
        with self.subnet(cidr='10.2.0.0/24') as subnet, \
                self.router() as router:
            with self.vpnservice(subnet=subnet,
                                 router=router):
                self.assertRaises(vpn_exception.SubnetInUseByVPNService,
                                  self.plugin.check_subnet_in_use,
                                  context.get_admin_context(),
                                  subnet['subnet']['id'],
                                  router['router']['id'])

    def test_check_router_has_no_vpn(self):
        vpn_plugin = mock.Mock()
        directory.add_plugin('VPN', vpn_plugin)
        payload = events.DBEventPayload(
            context=mock.ANY,
            states=({'id': 'foo_id'},))
        self.assertTrue(vpn_db.migration_callback(
            mock.ANY, mock.ANY, mock.ANY, payload))
        vpn_plugin.check_router_in_use.assert_called_once_with(
            mock.ANY, 'foo_id')


# Note: Below are new database related tests that only exercise the database
# instead of going through the client API. The intent here is to (eventually)
# convert all the database tests to this method, for faster, more granular
# tests.

# TODO(pcm): Put helpers in another module for sharing
class NeutronResourcesMixin(object):

    def create_network(self, overrides=None):
        """Create database entry for network."""
        network_info = {'network': {'name': 'my-net',
                                    'tenant_id': self.tenant_id,
                                    'admin_state_up': True,
                                    'shared': False}}
        if overrides:
            network_info['network'].update(overrides)
        return self.core_plugin.create_network(self.context, network_info)

    def create_subnet(self, overrides=None):
        """Create database entry for subnet."""
        subnet_info = {'subnet': {'name': 'my-subnet',
                                  'tenant_id': self.tenant_id,
                                  'ip_version': 4,
                                  'enable_dhcp': True,
                                  'dns_nameservers': None,
                                  'host_routes': None,
                                  'allocation_pools': None}}
        if overrides:
            subnet_info['subnet'].update(overrides)
        return self.core_plugin.create_subnet(self.context, subnet_info)

    def create_router(self, overrides=None, gw=None):
        """Create database entry for router with optional gateway."""
        router_info = {
            'router': {
                'name': 'my-router',
                'tenant_id': self.tenant_id,
                'admin_state_up': True,
            }
        }
        if overrides:
            router_info['router'].update(overrides)
        if gw:
            gw_info = {
                'external_gateway_info': {
                    'network_id': gw['net_id'],
                    'external_fixed_ips': [{'subnet_id': gw['subnet_id'],
                                            'ip_address': gw['ip']}],
                }
            }
            router_info['router'].update(gw_info)
        return self.l3_plugin.create_router(self.context, router_info)

    def create_router_port_for_subnet(self, router, subnet):
        """Creates port on router for subnet specified."""
        port = {'port': {
            'tenant_id': self.tenant_id,
            'network_id': subnet['network_id'],
            'fixed_ips': [
                {'ip_address': subnet['gateway_ip'],
                 'subnet_id': subnet['id']}
            ],
            'mac_address': lib_constants.ATTR_NOT_SPECIFIED,
            'admin_state_up': True,
            'device_id': router['id'],
            'device_owner': lib_constants.DEVICE_OWNER_ROUTER_INTF,
            'name': ''
        }}
        return self.core_plugin.create_port(self.context, port)

    def create_basic_topology(self, create_router_port=True):
        """Setup networks, subnets, and a router for testing VPN."""

        public_net = self.create_network(overrides={'name': 'public',
                                                    'router:external': True})
        private_net = self.create_network(overrides={'name': 'private'})
        overrides = {'name': 'private-subnet',
                     'cidr': '10.2.0.0/24',
                     'gateway_ip': '10.2.0.1',
                     'network_id': private_net['id']}
        private_subnet = self.create_subnet(overrides=overrides)
        overrides = {'name': 'public-subnet',
                     'cidr': '192.168.100.0/24',
                     'gateway_ip': '192.168.100.1',
                     'allocation_pools': [{'start': '192.168.100.2',
                                           'end': '192.168.100.254'}],
                     'network_id': public_net['id']}
        public_subnet = self.create_subnet(overrides=overrides)
        gw_info = {'net_id': public_net['id'],
                   'subnet_id': public_subnet['id'],
                   'ip': '192.168.100.5'}
        router = self.create_router(gw=gw_info)
        if create_router_port:
            self.create_router_port_for_subnet(router, private_subnet)
        return (private_subnet, router)


class TestVpnDatabase(base.NeutronDbPluginV2TestCase, NeutronResourcesMixin):

    def setUp(self):
        # Setup the core plugin
        self.plugin_str = ('neutron_vpnaas.tests.unit.db.vpn.'
                           'test_vpn_db.TestVpnCorePlugin')
        super(TestVpnDatabase, self).setUp(self.plugin_str)
        # Get the plugins
        self.core_plugin = directory.get_plugin()
        self.l3_plugin = directory.get_plugin(nconstants.L3)

        # Create VPN database instance
        self.plugin = vpn_db.VPNPluginDb()
        self.tenant_id = _uuid()
        self.context = context.get_admin_context()

    def prepare_service_info(self, private_subnet, router):
        subnet_id = private_subnet['id'] if private_subnet else None
        return {'vpnservice': {'tenant_id': self.tenant_id,
                               'name': 'my-service',
                               'description': 'new service',
                               'subnet_id': subnet_id,
                               'router_id': router['id'],
                               'flavor_id': None,
                               'admin_state_up': True}}

    def test_create_vpnservice(self):
        private_subnet, router = self.create_basic_topology()
        info = self.prepare_service_info(private_subnet, router)
        expected = {'admin_state_up': True,
                    'external_v4_ip': None,
                    'external_v6_ip': None,
                    'status': 'PENDING_CREATE'}
        expected.update(info['vpnservice'])
        new_service = self.plugin.create_vpnservice(self.context, info)
        self.assertDictSupersetOf(expected, new_service)

    def test_create_vpn_service_without_subnet(self):
        """Create service w/o subnet (will use endpoint groups for conn)."""
        private_subnet, router = self.create_basic_topology()
        info = self.prepare_service_info(private_subnet=None, router=router)
        expected = {'admin_state_up': True,
                    'external_v4_ip': None,
                    'external_v6_ip': None,
                    'status': 'PENDING_CREATE'}
        expected.update(info['vpnservice'])

        new_service = self.plugin.create_vpnservice(self.context, info)
        self.assertDictSupersetOf(expected, new_service)

    def test_update_external_tunnel_ips(self):
        """Verify that external tunnel IPs can be set."""
        private_subnet, router = self.create_basic_topology()
        info = self.prepare_service_info(private_subnet, router)
        expected = {'admin_state_up': True,
                    'external_v4_ip': None,
                    'external_v6_ip': None,
                    'status': 'PENDING_CREATE'}
        expected.update(info['vpnservice'])
        new_service = self.plugin.create_vpnservice(self.context, info)
        self.assertDictSupersetOf(expected, new_service)

        external_v4_ip = '192.168.100.5'
        external_v6_ip = 'fd00:1000::4'
        expected.update({'external_v4_ip': external_v4_ip,
                         'external_v6_ip': external_v6_ip})
        mod_service = self.plugin.set_external_tunnel_ips(self.context,
                                                          new_service['id'],
                                                          v4_ip=external_v4_ip,
                                                          v6_ip=external_v6_ip)
        self.assertDictSupersetOf(expected, mod_service)

    def prepare_endpoint_info(self, group_type, endpoints):
        return {'endpoint_group': {'tenant_id': self.tenant_id,
                                   'name': 'my endpoint group',
                                   'description': 'my description',
                                   'type': group_type,
                                   'endpoints': endpoints}}

    def test_endpoint_group_create_with_cidrs(self):
        """Verify create endpoint group using CIDRs."""
        info = self.prepare_endpoint_info(constants.CIDR_ENDPOINT,
                                          ['10.10.10.0/24', '20.20.20.0/24'])
        expected = info['endpoint_group']
        new_endpoint_group = self.plugin.create_endpoint_group(self.context,
                                                               info)
        self._compare_groups(expected, new_endpoint_group)

    def test_endpoint_group_create_with_subnets(self):
        """Verify create endpoint group using subnets."""
        # Skip validation for subnets, as validation is checked in other tests
        mock.patch.object(self.l3_plugin, "get_subnet").start()
        private_subnet, router = self.create_basic_topology()
        private_net2 = self.create_network(overrides={'name': 'private2'})
        overrides = {'name': 'private-subnet2',
                     'cidr': '10.1.0.0/24',
                     'gateway_ip': '10.1.0.1',
                     'network_id': private_net2['id']}
        private_subnet2 = self.create_subnet(overrides=overrides)
        self.create_router_port_for_subnet(router, private_subnet2)

        info = self.prepare_endpoint_info(constants.SUBNET_ENDPOINT,
                                          [private_subnet['id'],
                                           private_subnet2['id']])
        expected = info['endpoint_group']
        new_endpoint_group = self.plugin.create_endpoint_group(self.context,
                                                               info)
        self._compare_groups(expected, new_endpoint_group)

    def test_endpoint_group_create_with_vlans(self):
        """Verify endpoint group using VLANs."""
        info = self.prepare_endpoint_info(constants.VLAN_ENDPOINT,
                                          ['100', '200', '300'])
        expected = info['endpoint_group']
        new_endpoint_group = self.plugin.create_endpoint_group(self.context,
                                                               info)
        self._compare_groups(expected, new_endpoint_group)

    def _compare_groups(self, expected_group, actual_group):
        # Callers may want to reuse passed dicts later
        expected_group = copy.deepcopy(expected_group)
        actual_group = copy.deepcopy(actual_group)

        # We need to compare endpoints separately because their order is
        # not defined
        check_endpoints = 'endpoints' in expected_group
        expected_endpoints = set(expected_group.pop('endpoints', []))
        actual_endpoints = set(actual_group.pop('endpoints', []))

        self.assertDictSupersetOf(expected_group, actual_group)
        if check_endpoints:
            self.assertEqual(expected_endpoints, actual_endpoints)

    def helper_create_endpoint_group(self, info):
        """Create endpoint group database entry and verify OK."""
        group = info['endpoint_group']
        try:
            actual = self.plugin.create_endpoint_group(self.context, info)
        except db_exc.DBError as e:
            self.fail("Endpoint create in prep for test failed: %s" % e)
        self._compare_groups(group, actual)
        self.assertIn('id', actual)
        return actual['id']

    def check_endpoint_group_entry(self, endpoint_group_id, expected_info,
                                   should_exist=True):
        try:
            endpoint_group = self.plugin.get_endpoint_group(self.context,
                                                            endpoint_group_id)
            is_found = True
        except vpn_exception.VPNEndpointGroupNotFound:
            is_found = False
        except Exception as e:
            self.fail("Unexpected exception getting endpoint group: %s" % e)

        if should_exist != is_found:
            self.fail("Endpoint group should%(expected)s exist, but "
                      "did%(actual)s exist" %
                      {'expected': '' if should_exist else ' not',
                       'actual': '' if is_found else ' not'})
        if is_found:
            self._compare_groups(expected_info, endpoint_group)

    def test_delete_endpoint_group(self):
        """Test that endpoint group is deleted."""
        info = self.prepare_endpoint_info(constants.CIDR_ENDPOINT,
                                          ['10.10.10.0/24', '20.20.20.0/24'])
        expected = info['endpoint_group']
        group_id = self.helper_create_endpoint_group(info)
        self.check_endpoint_group_entry(group_id, expected, should_exist=True)

        self.plugin.delete_endpoint_group(self.context, group_id)
        self.check_endpoint_group_entry(group_id, expected, should_exist=False)

        self.assertRaises(vpn_exception.VPNEndpointGroupNotFound,
                          self.plugin.delete_endpoint_group,
                          self.context, group_id)

    def test_show_endpoint_group(self):
        """Test showing a single endpoint group."""
        info = self.prepare_endpoint_info(constants.CIDR_ENDPOINT,
                                          ['10.10.10.0/24', '20.20.20.0/24'])
        expected = info['endpoint_group']
        group_id = self.helper_create_endpoint_group(info)
        self.check_endpoint_group_entry(group_id, expected, should_exist=True)

        actual = self.plugin.get_endpoint_group(self.context, group_id)
        self._compare_groups(expected, actual)

    def test_fail_showing_non_existent_endpoint_group(self):
        """Test failure to show non-existent endpoint group."""
        self.assertRaises(vpn_exception.VPNEndpointGroupNotFound,
                          self.plugin.get_endpoint_group,
                          self.context, uuidutils.generate_uuid())

    def test_list_endpoint_groups(self):
        """Test listing multiple endpoint groups."""
        # Skip validation for subnets, as validation is checked in other tests
        mock.patch.object(self.l3_plugin, "get_subnet").start()
        info1 = self.prepare_endpoint_info(constants.CIDR_ENDPOINT,
                                           ['10.10.10.0/24', '20.20.20.0/24'])
        expected1 = info1['endpoint_group']
        group_id1 = self.helper_create_endpoint_group(info1)
        self.check_endpoint_group_entry(group_id1, expected1,
                                        should_exist=True)

        info2 = self.prepare_endpoint_info(constants.SUBNET_ENDPOINT,
                                           [uuidutils.generate_uuid(),
                                            uuidutils.generate_uuid()])
        expected2 = info2['endpoint_group']
        group_id2 = self.helper_create_endpoint_group(info2)
        self.check_endpoint_group_entry(group_id2, expected2,
                                        should_exist=True)
        expected1.update({'id': group_id1})
        expected2.update({'id': group_id2})
        expected_groups = [expected1, expected2]
        actual_groups = self.plugin.get_endpoint_groups(self.context,
            fields=('type', 'tenant_id', 'endpoints',
                    'name', 'description', 'id'))
        for expected_group, actual_group in zip(expected_groups,
                                                actual_groups):
            self._compare_groups(expected_group, actual_group)

    def test_update_endpoint_group(self):
        """Test updating endpoint group information."""
        info = self.prepare_endpoint_info(constants.CIDR_ENDPOINT,
                                          ['10.10.10.0/24', '20.20.20.0/24'])
        expected = info['endpoint_group']
        group_id = self.helper_create_endpoint_group(info)
        self.check_endpoint_group_entry(group_id, expected, should_exist=True)

        group_updates = {'endpoint_group': {'name': 'new name',
                                            'description': 'new description'}}
        updated_group = self.plugin.update_endpoint_group(self.context,
                                                          group_id,
                                                          group_updates)

        # Check what was returned, and what is stored in database
        self._compare_groups(group_updates['endpoint_group'], updated_group)
        expected.update(group_updates['endpoint_group'])
        self.check_endpoint_group_entry(group_id, expected,
                                        should_exist=True)

    def test_fail_updating_non_existent_group(self):
        """Test fail updating a non-existent group."""
        group_updates = {'endpoint_group': {'name': 'new name'}}
        self.assertRaises(
            vpn_exception.VPNEndpointGroupNotFound,
            self.plugin.update_endpoint_group,
            self.context, _uuid(), group_updates)

    def prepare_ike_policy_info(self):
        return {'ikepolicy': {'tenant_id': self.tenant_id,
                              'name': 'ike policy',
                              'description': 'my ike policy',
                              'auth_algorithm': 'sha1',
                              'encryption_algorithm': 'aes-128',
                              'phase1_negotiation_mode': 'main',
                              'lifetime': {'units': 'seconds', 'value': 3600},
                              'ike_version': 'v1',
                              'pfs': 'group5'}}

    def test_create_ike_policy(self):
        """Create IKE policy with all settings specified."""
        info = self.prepare_ike_policy_info()
        expected = info['ikepolicy']
        new_ike_policy = self.plugin.create_ikepolicy(self.context, info)
        self.assertDictSupersetOf(expected, new_ike_policy)

    def prepare_ipsec_policy_info(self):
        return {'ipsecpolicy': {'tenant_id': self.tenant_id,
                                'name': 'ipsec policy',
                                'description': 'my ipsec policy',
                                'auth_algorithm': 'sha1',
                                'encryption_algorithm': 'aes-128',
                                'encapsulation_mode': 'tunnel',
                                'transform_protocol': 'esp',
                                'lifetime': {'units': 'seconds',
                                             'value': 3600},
                                'pfs': 'group5'}}

    def test_create_ipsec_policy(self):
        """Create IPsec policy with all settings specified."""
        info = self.prepare_ipsec_policy_info()
        expected = info['ipsecpolicy']
        new_ipsec_policy = self.plugin.create_ipsecpolicy(self.context, info)
        self.assertDictSupersetOf(expected, new_ipsec_policy)

    def create_vpn_service(self, with_subnet=True):
        private_subnet, router = self.create_basic_topology()
        if not with_subnet:
            private_subnet = None
        info = self.prepare_service_info(private_subnet, router)
        return self.plugin.create_vpnservice(self.context, info)

    def create_ike_policy(self):
        info = self.prepare_ike_policy_info()
        return self.plugin.create_ikepolicy(self.context, info)

    def create_ipsec_policy(self):
        info = self.prepare_ipsec_policy_info()
        return self.plugin.create_ipsecpolicy(self.context, info)

    def create_endpoint_group(self, group_type, endpoints):
        info = self.prepare_endpoint_info(group_type=group_type,
                                          endpoints=endpoints)
        return self.plugin.create_endpoint_group(self.context, info)

    def prepare_connection_info(self, service_id, ike_policy_id,
                                ipsec_policy_id, local_id=''):
        """Creates connection request dictionary.

        The peer_cidrs, local_ep_group_id, and peer_ep_group_id are set to
        defaults. Caller must then fill in either CIDRs or endpoints, before
        creating a connection.
        """

        return {'ipsec_site_connection': {'name': 'my connection',
                                          'description': 'my description',
                                          'peer_id': '192.168.1.10',
                                          'peer_address': '192.168.1.10',
                                          'peer_cidrs': [],
                                          'local_id': local_id,
                                          'mtu': 1500,
                                          'psk': 'shhhh!!!',
                                          'initiator': 'bi-directional',
                                          'dpd_action': 'hold',
                                          'dpd_interval': 30,
                                          'dpd_timeout': 120,
                                          'vpnservice_id': service_id,
                                          'ikepolicy_id': ike_policy_id,
                                          'ipsecpolicy_id': ipsec_policy_id,
                                          'admin_state_up': True,
                                          'tenant_id': self._tenant_id,
                                          'local_ep_group_id': None,
                                          'peer_ep_group_id': None}}

    def build_expected_connection_result(self, info):
        """Create the expected IPsec connection dict from the request info.

        The DPD information is stored and converted to a nested dict, instead
        of individual fields.
        """

        expected = copy.copy(info['ipsec_site_connection'])
        expected['dpd'] = {'action': expected['dpd_action'],
                           'interval': expected['dpd_interval'],
                           'timeout': expected['dpd_timeout']}
        del expected['dpd_action']
        del expected['dpd_interval']
        del expected['dpd_timeout']
        expected['status'] = 'PENDING_CREATE'
        return expected

    def prepare_for_ipsec_connection_create(self, with_subnet=True):
        service = self.create_vpn_service(with_subnet)
        ike_policy = self.create_ike_policy()
        ipsec_policy = self.create_ipsec_policy()
        return self.prepare_connection_info(service['id'],
                                            ike_policy['id'],
                                            ipsec_policy['id'])

    def test_create_ipsec_site_connection_with_peer_cidrs(self):
        """Create connection using old API with peer CIDRs specified."""
        info = self.prepare_for_ipsec_connection_create()
        info['ipsec_site_connection']['peer_cidrs'] = ['10.1.0.0/24',
                                                       '10.2.0.0/24']
        expected = self.build_expected_connection_result(info)

        new_conn = self.plugin.create_ipsec_site_connection(self.context,
                                                            info)
        self.assertDictSupersetOf(expected, new_conn)

    def test_create_ipsec_site_connection_with_endpoint_groups(self):
        """Create connection using new API with endpoint groups."""
        # Skip validation, which is tested separately
        mock.patch.object(self.plugin, '_get_validator').start()
        local_net = self.create_network(overrides={'name': 'local'})
        overrides = {'name': 'local-subnet',
                     'cidr': '30.0.0.0/24',
                     'gateway_ip': '30.0.0.1',
                     'network_id': local_net['id']}
        local_subnet = self.create_subnet(overrides=overrides)

        info = self.prepare_for_ipsec_connection_create(with_subnet=False)
        local_ep_group = self.create_endpoint_group(
            group_type='subnet', endpoints=[local_subnet['id']])
        peer_ep_group = self.create_endpoint_group(
            group_type='cidr', endpoints=['20.1.0.0/24', '20.2.0.0/24'])
        info['ipsec_site_connection'].update(
            {'local_ep_group_id': local_ep_group['id'],
             'peer_ep_group_id': peer_ep_group['id']})
        expected = self.build_expected_connection_result(info)

        new_conn = self.plugin.create_ipsec_site_connection(self.context,
                                                            info)
        self.assertDictSupersetOf(expected, new_conn)

    def test_fail_endpoint_group_delete_when_in_use_by_ipsec_conn(self):
        """Ensure endpoint group is not deleted from under IPSec connection."""
        # Skip validation, which is tested separately
        mock.patch.object(self.plugin, '_get_validator').start()
        local_net = self.create_network(overrides={'name': 'local'})
        overrides = {'name': 'local-subnet',
                     'cidr': '30.0.0.0/24',
                     'gateway_ip': '30.0.0.1',
                     'network_id': local_net['id']}
        local_subnet = self.create_subnet(overrides=overrides)

        info = self.prepare_for_ipsec_connection_create(with_subnet=False)
        local_ep_group = self.create_endpoint_group(
            group_type='subnet', endpoints=[local_subnet['id']])
        peer_ep_group = self.create_endpoint_group(
            group_type='cidr', endpoints=['20.1.0.0/24', '20.2.0.0/24'])
        info['ipsec_site_connection'].update(
            {'local_ep_group_id': local_ep_group['id'],
             'peer_ep_group_id': peer_ep_group['id']})
        self.plugin.create_ipsec_site_connection(self.context, info)
        self.assertRaises(vpn_exception.EndpointGroupInUse,
                          self.plugin.delete_endpoint_group,
                          self.context,
                          local_ep_group['id'])
        self.assertRaises(vpn_exception.EndpointGroupInUse,
                          self.plugin.delete_endpoint_group,
                          self.context,
                          peer_ep_group['id'])
        unused_ep_group = self.create_endpoint_group(
            group_type=constants.CIDR_ENDPOINT, endpoints=['30.0.0.0/24'])
        self.plugin.delete_endpoint_group(self.context, unused_ep_group['id'])

    def test_fail_subnet_delete_when_in_use_by_endpoint_group(self):
        """Ensure don't delete subnet from under endpoint group."""
        # mock.patch.object(self.plugin, '_get_validator').start()
        local_net = self.create_network(overrides={'name': 'local'})
        overrides = {'name': 'local-subnet',
                     'cidr': '30.0.0.0/24',
                     'gateway_ip': '30.0.0.1',
                     'network_id': local_net['id']}
        local_subnet = self.create_subnet(overrides=overrides)
        self.create_endpoint_group(group_type='subnet',
                                   endpoints=[local_subnet['id']])
        self.assertRaises(vpn_exception.SubnetInUseByEndpointGroup,
                          self.plugin.check_subnet_in_use_by_endpoint_group,
                          self.context, local_subnet['id'])

    def test_subnet_in_use_by_ipsec_site_connection(self):
        mock.patch.object(self.plugin, '_get_validator').start()

        private_subnet, router = self.create_basic_topology(
            create_router_port=False)
        self.l3_plugin.add_router_interface(
            self.context,
            router['id'],
            {'subnet_id': private_subnet['id']})
        vpn_service_info = self.prepare_service_info(private_subnet=None,
                                                     router=router)
        vpn_service = self.plugin.create_vpnservice(self.context,
                                                    vpn_service_info)

        ike_policy = self.create_ike_policy()
        ipsec_policy = self.create_ipsec_policy()
        ipsec_site_connection = self.prepare_connection_info(
            vpn_service['id'],
            ike_policy['id'],
            ipsec_policy['id'])

        local_ep_group = self.create_endpoint_group(
            group_type='subnet', endpoints=[private_subnet['id']])
        peer_ep_group = self.create_endpoint_group(
            group_type='cidr', endpoints=['20.1.0.0/24', '20.2.0.0/24'])
        ipsec_site_connection['ipsec_site_connection'].update(
            {'local_ep_group_id': local_ep_group['id'],
             'peer_ep_group_id': peer_ep_group['id']})
        self.plugin.create_ipsec_site_connection(self.context,
                                                 ipsec_site_connection)

        self.assertRaises(vpn_exception.SubnetInUseByIPsecSiteConnection,
                          self.plugin.check_subnet_in_use,
                          self.context,
                          private_subnet['id'],
                          router['id'])

    def _setup_ipsec_site_connections_with_ep_groups(self, peer_cidr_lists):
        private_subnet, router = self.create_basic_topology()
        vpn_service_info = self.prepare_service_info(private_subnet=None,
                                                     router=router)
        vpn_service = self.plugin.create_vpnservice(self.context,
                                                    vpn_service_info)

        ike_policy = self.create_ike_policy()
        ipsec_policy = self.create_ipsec_policy()
        ipsec_site_connection = self.prepare_connection_info(
            vpn_service['id'],
            ike_policy['id'],
            ipsec_policy['id'])

        local_ep_group = self.create_endpoint_group(
            group_type='subnet', endpoints=[private_subnet['id']])
        for peer_cidrs in peer_cidr_lists:
            peer_ep_group = self.create_endpoint_group(
                group_type='cidr', endpoints=peer_cidrs)
            ipsec_site_connection['ipsec_site_connection'].update(
                {'local_ep_group_id': local_ep_group['id'],
                'peer_ep_group_id': peer_ep_group['id']})
            self.plugin.create_ipsec_site_connection(self.context,
                                                    ipsec_site_connection)
        return private_subnet, router

    def _setup_ipsec_site_connections_without_ep_groups(self, peer_cidr_lists):
        private_subnet, router = self.create_basic_topology()
        vpn_service_info = \
            self.prepare_service_info(private_subnet=private_subnet,
                                      router=router)
        vpn_service = self.plugin.create_vpnservice(self.context,
                                                    vpn_service_info)

        ike_policy = self.create_ike_policy()
        ipsec_policy = self.create_ipsec_policy()
        ipsec_site_connection = self.prepare_connection_info(
            vpn_service['id'],
            ike_policy['id'],
            ipsec_policy['id'])

        for peer_cidrs in peer_cidr_lists:
            ipsec_site_connection['ipsec_site_connection'].update(
                {'peer_cidrs': peer_cidrs})
            self.plugin.create_ipsec_site_connection(self.context,
                                                     ipsec_site_connection)
        return private_subnet, router

    def _test_get_peer_cidrs_for_router(self, setup_func):
        mock.patch.object(self.plugin, '_get_validator').start()

        # create 1st setup with two connections
        peer_cidrs = [
            ['20.1.0.0/24', '20.2.0.0/24'],
            ['20.3.0.0/24']
        ]
        private_subnet, router = setup_func(peer_cidrs)

        # create a 2nd setup for a different router
        setup_func([['10.1.0.0/24', '10.2.0.0/24']])

        returned_cidrs = self.plugin.get_peer_cidrs_for_router(self.context,
                                                               router['id'])
        expected = ['20.1.0.0/24', '20.2.0.0/24', '20.3.0.0/24']
        self.assertEqual(sorted(expected), sorted(returned_cidrs))

    def test_get_peer_cidrs_for_router_with_ep_groups(self):
        self._test_get_peer_cidrs_for_router(
            self._setup_ipsec_site_connections_with_ep_groups)

    def test_get_peer_cidrs_for_router_without_ep_groups(self):
        self._test_get_peer_cidrs_for_router(
            self._setup_ipsec_site_connections_without_ep_groups)
