# Copyright 2023 SysEleven GmbH.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from neutron.api import extensions
from neutron.common.ovn import constants as ovn_constants
from neutron import policy
from neutron.tests.common import helpers
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import testlib_api
from neutron import wsgi
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_db import exception as db_exc
import oslo_messaging
from oslo_utils import uuidutils
from sqlalchemy import orm
from webob import exc

from neutron_vpnaas.api.rpc.agentnotifiers import vpn_rpc_agent_api
from neutron_vpnaas.extensions import vpn_agentschedulers
from neutron_vpnaas.services.vpn.common import constants
from neutron_vpnaas.tests.unit.db.vpn import test_vpn_db


VPN_HOSTA = "host-1"
VPN_HOSTB = "host-2"


class VPNAgentSchedulerTestMixIn(object):
    def _request_list(self, path, admin_context=True,
                      expected_code=exc.HTTPOk.code):
        req = self._path_req(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        return self.deserialize(self.fmt, res)

    def _path_req(self, path, method='GET', data=None,
                  query_string=None,
                  admin_context=True):
        content_type = 'application/%s' % self.fmt
        body = None
        if data is not None:  # empty dict is valid
            body = wsgi.Serializer().serialize(data, content_type)
        if admin_context:
            return testlib_api.create_request(
                path, body, content_type, method, query_string=query_string)
        else:
            return testlib_api.create_request(
                path, body, content_type, method, query_string=query_string,
                context=context.Context('', 'tenant_id'))

    def _path_create_request(self, path, data, admin_context=True):
        return self._path_req(path, method='POST', data=data,
                              admin_context=admin_context)

    def _path_show_request(self, path, admin_context=True):
        return self._path_req(path, admin_context=admin_context)

    def _path_delete_request(self, path, admin_context=True):
        return self._path_req(path, method='DELETE',
                              admin_context=admin_context)

    def _path_update_request(self, path, data, admin_context=True):
        return self._path_req(path, method='PUT', data=data,
                              admin_context=admin_context)

    def _list_routers_hosted_by_vpn_agent(self, agent_id,
                                          expected_code=exc.HTTPOk.code,
                                          admin_context=True):
        path = "/agents/%s/%s.%s" % (agent_id,
                                     vpn_agentschedulers.VPN_ROUTERS,
                                     self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _add_router_to_vpn_agent(self, id, router_id,
                                 expected_code=exc.HTTPCreated.code,
                                 admin_context=True):
        path = "/agents/%s/%s.%s" % (id,
                                     vpn_agentschedulers.VPN_ROUTERS,
                                     self.fmt)
        req = self._path_create_request(path,
                                        {'router_id': router_id},
                                        admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)

    def _list_vpn_agents_hosting_router(self, router_id,
                                        expected_code=exc.HTTPOk.code,
                                        admin_context=True):
        path = "/routers/%s/%s.%s" % (router_id,
                                      vpn_agentschedulers.VPN_AGENTS,
                                      self.fmt)
        return self._request_list(path, expected_code=expected_code,
                                  admin_context=admin_context)

    def _remove_router_from_vpn_agent(self, id, router_id,
                                      expected_code=exc.HTTPNoContent.code,
                                      admin_context=True):
        path = "/agents/%s/%s/%s.%s" % (id,
                                        vpn_agentschedulers.VPN_ROUTERS,
                                        router_id,
                                        self.fmt)
        req = self._path_delete_request(path, admin_context=admin_context)
        res = req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)


class VPNAgentSchedulerTestCaseBase(test_vpn_db.VPNTestMixin,
                                    test_l3.L3NatTestCaseMixin,
                                    VPNAgentSchedulerTestMixIn,
                                    test_plugin.NeutronDbPluginV2TestCase):
    fmt = 'json'

    def setUp(self):
        # NOTE(ivasilevskaya) mocking this way allows some control over mocked
        # client like further method mocking with asserting calls
        self.client_mock = mock.MagicMock(name="mocked client")
        mock.patch.object(
            n_rpc, 'get_client').start().return_value = self.client_mock

        service_plugins = {
            'vpnaas_plugin': 'neutron_vpnaas.services.vpn.ovn_plugin.'
                             'VPNOVNPlugin'}
        plugin_str = 'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin'
        super().setUp(plugin_str, service_plugins=service_plugins)

        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()

        self.core_plugin = directory.get_plugin()
        self.core_plugin.get_agents = \
            mock.MagicMock(side_effect=self._get_agents)
        self.core_plugin.get_agent = \
            mock.MagicMock(side_effect=self._get_agent)
        self._agents = {}
        self._vpn_agents_by_host = {}

        self.service_plugin = directory.get_plugin(plugin_constants.VPN)
        policy.init()

    def _get_agents(self, context, filters=None):
        if not filters:
            return self._agents.values()

        agents = []
        for agent in self._agents.values():
            for key, values in filters.items():
                if agent[key] not in values:
                    break
            else:
                agents.append(agent)
        return agents

    def _get_agent(self, context, agent_id):
        try:
            return self._agents[agent_id]
        except KeyError:
            raise n_exc.agent.AgentNotFound(id=agent_id)

    def _get_any_metadata_agent_id(self):
        for agent in self._agents.values():
            if agent['agent_type'] == ovn_constants.OVN_METADATA_AGENT:
                return agent['id']

    def _take_down_vpn_agent(self, host):
        self._vpn_agents_by_host[host]['alive'] = False

    def _get_another_agent_host(self, host):
        for agent in self._vpn_agents_by_host.values():
            if agent['host'] != host:
                return agent['host']

    def _register_agent_states(self):
        self._register_vpn_agent(host=VPN_HOSTA)
        self._register_vpn_agent(host=VPN_HOSTB)
        self._register_metadata_agent(host=VPN_HOSTA)
        self._register_metadata_agent(host=VPN_HOSTB)

    def _register_vpn_agent(self, host=None):
        agent = {
            'id': uuidutils.generate_uuid(),
            'binary': "neutron-ovn-vpn-agent",
            'host': host,
            'availability_zone': helpers.DEFAULT_AZ,
            'topic': 'n/a',
            'configurations': {},
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_VPN,
            'alive': True,
            'admin_state_up': True}
        self._agents[agent['id']] = agent
        self._vpn_agents_by_host[host] = agent

    def _register_metadata_agent(self, host=None):
        agent = {
            'id': uuidutils.generate_uuid(),
            'binary': "neutron-ovn-metadata-agent",
            'host': host,
            'availability_zone': helpers.DEFAULT_AZ,
            'topic': 'n/a',
            'configurations': {},
            'start_flag': True,
            'agent_type': ovn_constants.OVN_METADATA_AGENT,
            'alive': True,
            'admin_state_up': True}
        self._agents[agent['id']] = agent


class VPNAgentSchedulerTestCase(VPNAgentSchedulerTestCaseBase):
    def _take_down_agent_and_run_reschedule(self, host):
        self._take_down_vpn_agent(host)
        plugin = directory.get_plugin(plugin_constants.VPN)
        plugin.reschedule_vpnservices_from_down_agents()

    def _get_agent_host_by_router(self, router_id):
        agents = self._list_vpn_agents_hosting_router(router_id)
        return agents['agents'][0]['host']

    def test_schedule_router(self):
        self._register_agent_states()
        with self.router() as router:
            router_id = router['router']['id']
            self.service_plugin.schedule_router(self.adminContext, router_id)
            host = self._get_agent_host_by_router(router_id)

        self.assertIn(host, (VPN_HOSTA, VPN_HOSTB))

    def test_router_rescheduler_catches_rpc_db_and_reschedule_exceptions(self):
        self._register_agent_states()
        agent_a_id = self._vpn_agents_by_host[VPN_HOSTA]['id']

        with self.router() as router:
            router_id = router['router']['id']
            self._add_router_to_vpn_agent(agent_a_id, router_id)
            mock.patch.object(
                self.service_plugin, 'reschedule_router',
                side_effect=[
                    db_exc.DBError(), oslo_messaging.RemoteError(),
                    vpn_agentschedulers.RouterReschedulingFailed(
                        router_id='f'),
                    ValueError('this raises'),
                    Exception()
                ]).start()
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)  # DBError
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)  # RemoteError
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)  # schedule err
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)  # Value error
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)  # Exception

    def test_router_rescheduler_catches_exceptions_on_fetching_bindings(self):
        with mock.patch('neutron_lib.context.get_admin_context') as get_ctx:
            mock_ctx = mock.Mock()
            get_ctx.return_value = mock_ctx
            mock_ctx.session.query.side_effect = db_exc.DBError()

            # check that no exception is raised
            self.service_plugin.reschedule_vpnservices_from_down_agents()

    def test_router_rescheduler_iterates_after_reschedule_failure(self):
        self._register_agent_states()
        agent_a = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTA)

        with self.vpnservice() as s1, self.vpnservice() as s2:
            # schedule the services to agent A
            self.service_plugin.auto_schedule_routers(
                self.adminContext, agent_a)

            rs_mock = mock.patch.object(
                self.service_plugin, 'reschedule_router',
                side_effect=vpn_agentschedulers.RouterReschedulingFailed(
                    router_id='f'),
            ).start()
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)
            # make sure both had a reschedule attempt even though first failed
            router_id_1 = s1['vpnservice']['router_id']
            router_id_2 = s2['vpnservice']['router_id']
            rs_mock.assert_has_calls(
                [mock.call(mock.ANY, router_id_1, agent_a),
                 mock.call(mock.ANY, router_id_2, agent_a)],
                any_order=True)

    def test_router_is_not_rescheduled_from_alive_agent(self):
        self._register_agent_states()
        agent_a_id = self._vpn_agents_by_host[VPN_HOSTA]['id']

        with self.router() as router:
            router_id = router['router']['id']
            self._add_router_to_vpn_agent(agent_a_id, router_id)

            patch_func_str = ('neutron_vpnaas.db.vpn.vpn_agentschedulers_db.'
                              'VPNAgentSchedulerDbMixin.reschedule_router')
            with mock.patch(patch_func_str) as rr:
                # take down the unrelated agent and run reschedule check
                self._take_down_agent_and_run_reschedule(VPN_HOSTB)
                self.assertFalse(rr.called)

    def test_router_reschedule_from_dead_agent(self):
        self._register_agent_states()
        agent_a_id = self._vpn_agents_by_host[VPN_HOSTA]['id']

        with self.router() as router:
            router_id = router['router']['id']
            self._add_router_to_vpn_agent(agent_a_id, router_id)
            host_before = self._get_agent_host_by_router(router_id)

            self._take_down_agent_and_run_reschedule(VPN_HOSTA)
            host_after = self._get_agent_host_by_router(router_id)

        self.assertEqual(VPN_HOSTA, host_before)
        self.assertEqual(VPN_HOSTB, host_after)

    def test_router_reschedule_succeeded_after_failed_notification(self):
        self._register_agent_states()
        agent_a = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTA)

        with self.vpnservice() as service:
            # schedule the vpn routers to agent A
            self.service_plugin.auto_schedule_routers(
                self.adminContext, agent_a)
            ctxt_mock = mock.MagicMock()
            call_mock = mock.MagicMock(
                side_effect=[oslo_messaging.MessagingTimeout, None])
            ctxt_mock.call = call_mock
            self.client_mock.prepare = mock.MagicMock(return_value=ctxt_mock)
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)
            self.assertEqual(2, call_mock.call_count)
            # make sure vpn service was rescheduled even when first attempt
            # failed to notify VPN agent
            router_id = service['vpnservice']['router_id']
            host = self._get_agent_host_by_router(router_id)

            vpn_agents = self._list_vpn_agents_hosting_router(router_id)
            self.assertEqual(1, len(vpn_agents['agents']))
            self.assertEqual(VPN_HOSTB, host)

    def test_router_reschedule_failed_notification_all_attempts(self):
        self._register_agent_states()
        agent_a = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTA)

        with self.vpnservice() as vpnservice:
            # schedule the vpn routers to agent A
            self.service_plugin.auto_schedule_routers(
                self.adminContext, agent_a)
            # mock client.prepare and context.call
            ctxt_mock = mock.MagicMock()
            call_mock = mock.MagicMock(
                side_effect=oslo_messaging.MessagingTimeout)
            ctxt_mock.call = call_mock
            self.client_mock.prepare = mock.MagicMock(return_value=ctxt_mock)
            # perform operations
            self._take_down_agent_and_run_reschedule(VPN_HOSTA)
            self.assertEqual(
                vpn_rpc_agent_api.AGENT_NOTIFY_MAX_ATTEMPTS,
                call_mock.call_count)
            router_id = vpnservice['vpnservice']['router_id']
            vpn_agents = self._list_vpn_agents_hosting_router(router_id)
            self.assertEqual(0, len(vpn_agents['agents']))

    def test_router_auto_schedule_with_hosted(self):
        self._register_agent_states()
        agent_a = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTA)
        agent_b = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTB)

        with self.vpnservice() as vpnservice:
            self._register_agent_states()
            ret_a = self.service_plugin.auto_schedule_routers(
                self.adminContext, agent_a)
            ret_b = self.service_plugin.auto_schedule_routers(
                self.adminContext, agent_b)
            router_id = vpnservice['vpnservice']['router_id']
            vpn_agents = self._list_vpn_agents_hosting_router(router_id)
            host = self._get_agent_host_by_router(router_id)
            self.assertTrue(len(ret_a))
            self.assertIn(router_id, ret_a)
            self.assertFalse(len(ret_b))
        self.assertEqual(1, len(vpn_agents['agents']))
        self.assertEqual(VPN_HOSTA, host)

    def test_add_router_to_vpn_agent(self):
        self._register_agent_states()
        agent_a = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTA)
        agent_a_id = agent_a['id']
        agent_b = self.service_plugin.get_vpn_agent_on_host(
            self.adminContext, VPN_HOSTB)
        agent_b_id = agent_b['id']

        with self.router() as router:
            router_id = router['router']['id']
            num_before_add = len(
                self._list_routers_hosted_by_vpn_agent(
                    agent_a_id)['routers'])
            self._add_router_to_vpn_agent(agent_a_id, router_id)
            # add router again to same agent is fine
            self._add_router_to_vpn_agent(agent_a_id, router_id)
            # add router to a second agent is a conflict
            self._add_router_to_vpn_agent(agent_b_id, router_id,
                                          expected_code=exc.HTTPConflict.code)
            num_after_add = len(
                self._list_routers_hosted_by_vpn_agent(
                    agent_a_id)['routers'])
        self.assertEqual(0, num_before_add)
        self.assertEqual(1, num_after_add)

    def test_add_router_to_vpn_agent_wrong_type(self):
        self._register_agent_states()
        agent_id = self._get_any_metadata_agent_id()

        with self.router() as router:
            router_id = router['router']['id']
            # add_router_to_vpn_agent with a metadata agent id shall fail
            self._add_router_to_vpn_agent(
                agent_id, router_id,
                expected_code=exc.HTTPNotFound.code)

    def _test_add_router_to_vpn_agent_db_error(self, exception):
        self._register_agent_states()
        agent_id = self._vpn_agents_by_host[VPN_HOSTA]['id']

        with self.router() as router, \
                mock.patch.object(orm.Session, 'add', side_effect=exception):
            router_id = router['router']['id']

            self._add_router_to_vpn_agent(
                agent_id, router_id,
                expected_code=exc.HTTPConflict.code)

    def test_add_router_to_vpn_agent_duplicate(self):
        self._test_add_router_to_vpn_agent_db_error(db_exc.DBDuplicateEntry)

    def test_add_router_to_vpn_agent_reference_error(self):
        self._test_add_router_to_vpn_agent_db_error(
            db_exc.DBReferenceError('', '', '', ''))

    def test_add_router_to_vpn_agent_db_error(self):
        self._test_add_router_to_vpn_agent_db_error(db_exc.DBError)

    def test_list_routers_hosted_by_vpn_agent_with_invalid_agent(self):
        invalid_agentid = 'non_existing_agent'
        self._list_routers_hosted_by_vpn_agent(invalid_agentid,
                                               exc.HTTPNotFound.code)

    def test_remove_router_from_vpn_agent(self):
        self._register_agent_states()
        agent_id = self._vpn_agents_by_host[VPN_HOSTA]['id']

        with self.router() as router:
            router_id = router['router']['id']

            self._add_router_to_vpn_agent(agent_id, router_id)
            routers = self._list_routers_hosted_by_vpn_agent(agent_id)
            num_before = len(routers['routers'])

            self._remove_router_from_vpn_agent(agent_id, router_id)
            routers = self._list_routers_hosted_by_vpn_agent(agent_id)
            num_after = len(routers['routers'])

        self.assertEqual(1, num_before)
        self.assertEqual(0, num_after)

    def test_remove_router_from_vpn_agent_wrong_agent(self):
        self._register_agent_states()
        agent_a_id = self._vpn_agents_by_host[VPN_HOSTA]['id']
        agent_b_id = self._vpn_agents_by_host[VPN_HOSTB]['id']

        with self.router() as router:
            router_id = router['router']['id']

            self._add_router_to_vpn_agent(agent_a_id, router_id)
            routers = self._list_routers_hosted_by_vpn_agent(agent_a_id)
            num_before = len(routers['routers'])

            # try to remove router from wrong agent is not an error
            self._remove_router_from_vpn_agent(agent_b_id, router_id)
            routers = self._list_routers_hosted_by_vpn_agent(agent_a_id)
            num_after = len(routers['routers'])

        self.assertEqual(1, num_before)
        self.assertEqual(1, num_after)

    def test_remove_router_from_vpn_agent_unknown_agent(self):
        self._register_agent_states()
        agent_a_id = self._vpn_agents_by_host[VPN_HOSTA]['id']

        with self.router() as router:
            router_id = router['router']['id']

            self._add_router_to_vpn_agent(agent_a_id, router_id)
            routers = self._list_routers_hosted_by_vpn_agent(agent_a_id)
            num_before = len(routers['routers'])

            # try to remove router from unknown agent is an error
            self._remove_router_from_vpn_agent(
                'unknown-agent', router_id,
                expected_code=exc.HTTPNotFound.code)
            routers = self._list_routers_hosted_by_vpn_agent(agent_a_id)
            num_after = len(routers['routers'])

        self.assertEqual(1, num_before)
        self.assertEqual(1, num_after)
