#!/usr/bin/env bash

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


set -e


IS_GATE=${IS_GATE:-False}
USE_CONSTRAINT_ENV=${USE_CONSTRAINT_ENV:-False}
PROJECT_NAME=${PROJECT_NAME:-neutron-vpnaas}
REPO_BASE=${GATE_DEST:-$(cd $(dirname "$BASH_SOURCE")/../.. && pwd)}
NEUTRON_DIR=$REPO_BASE/neutron

source $REPO_BASE/neutron/tools/configure_for_func_testing.sh
source $REPO_BASE/neutron-vpnaas/devstack/settings
source $NEUTRON_VPNAAS_DIR/devstack/plugin.sh


function _install_vpn_package {
    case $VENV in
        dsvm-functional-sswan*)
            IPSEC_PACKAGE=strongswan
            ;;
        *)
            IPSEC_PACKAGE=openswan
            ;;
    esac

    echo_summary "Installing $IPSEC_PACKAGE for $VENV"
    neutron_agent_vpnaas_install_agent_packages
}

function configure_host_for_vpn_func_testing {
    echo_summary "Configuring for VPN functional testing"
    if [ "$IS_GATE" == "True" ]; then
        configure_host_for_func_testing
    fi
    # Note(pc_m): Need to ensure this is installed so we have
    # oslo-config-generator present (as this script runs before tox.ini).
    sudo pip3 install --force oslo.config
    _install_vpn_package
}


if [ "$IS_GATE" != "True" ]; then
    configure_host_for_vpn_func_testing
fi

