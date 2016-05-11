#!/bin/bash
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ``upgrade-neutron-vpnaas``
set -o errexit
source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions
source $BASE_DEVSTACK_DIR/functions
source $BASE_DEVSTACK_DIR/stackrc  # needed for status directory

# TODO(kevinbenton): figure out best way to source this from devstack plugin
function neutron_vpnaas_stop {
    local ipsec_data_dir=$DATA_DIR/neutron/ipsec
    local pids
    if [ -d $ipsec_data_dir ]; then
        pids=$(find $ipsec_data_dir -name 'pluto.pid' -exec cat {} \;)
    fi
    if [ -n "$pids" ]; then
        sudo kill $pids
    fi
    stop_process neutron-vpnaas
}
ENABLED_SERVICES+=,neutron-vpnaas
set -o xtrace
neutron_vpnaas_stop
