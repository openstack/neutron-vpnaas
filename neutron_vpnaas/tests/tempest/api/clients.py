# Copyright 2012 OpenStack Foundation
# Copyright 2016 Hewlett Packard Enterprise Development Company
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

from tempest.lib.services.identity.v2 import tenants_client as tenants_cli
from tempest import manager

from neutron.tests.tempest import config
from neutron.tests.tempest.services.network.json import network_client


CONF = config.CONF


class NetworkClient(network_client.NetworkClientJSON):

    def pluralize(self, resource_name):

        resource_plural_map = {
            'ikepolicy': 'ikepolicies',
            'ipsecpolicy': 'ipsecpolicies'
        }

        if resource_name in resource_plural_map:
            return resource_plural_map.get(resource_name)

        return super(NetworkClient, self).pluralize(resource_name)

    def get_uri(self, plural_name):
        # get service prefix from resource name

        service_resource_prefix_list = [
            'vpnservices',
            'ikepolicies',
            'ipsecpolicies',
            'ipsec_site_connections',
            'endpoint_groups',
        ]

        if plural_name in service_resource_prefix_list:
            plural_name = plural_name.replace("_", "-")
            service_prefix = 'vpn'
            uri = '%s/%s/%s' % (self.uri_prefix, service_prefix,
                                plural_name)
            return uri

        return super(NetworkClient, self).get_uri(plural_name)


class Manager(manager.Manager):

    """
    Top level manager for OpenStack tempest clients
    """

    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    # NOTE: Tempest uses timeout values of compute API if project specific
    # timeout values don't exist.
    default_params_with_timeout_values = {
        'build_interval': CONF.compute.build_interval,
        'build_timeout': CONF.compute.build_timeout
    }
    default_params_with_timeout_values.update(default_params)

    def __init__(self, credentials=None, service=None):
        super(Manager, self).__init__(credentials=credentials)

        self._set_identity_clients()

        self.network_client = NetworkClient(
            self.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **self.default_params)

    def _set_identity_clients(self):
        params = {
            'service': CONF.identity.catalog_type,
            'region': CONF.identity.region,
            'endpoint_type': 'adminURL'
        }
        params.update(self.default_params_with_timeout_values)

        params_v2_admin = params.copy()
        params_v2_admin['endpoint_type'] = CONF.identity.v2_admin_endpoint_type
        # Client uses admin endpoint type of Keystone API v2
        self.tenants_client = tenants_cli.TenantsClient(self.auth_provider,
                                                        **params_v2_admin)
