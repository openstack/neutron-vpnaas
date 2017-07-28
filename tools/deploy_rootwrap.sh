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

set -eu

if [ $# -ne 2 ]; then
  >&2 echo "Usage: $0 /path/to/repo /path/to/virtual-env
Deploy rootwrap configuration and filters.

Warning: Any existing rootwrap files at the specified etc path will be
removed by this script.

Optional: set OS_SUDO_TESTING=1 to deploy the filters required by
Neutron's functional testing suite."
  exit 1
fi

OS_SUDO_TESTING=${OS_SUDO_TESTING:-0}

repo_path=$1
venv_path=$2

src_conf_path=${repo_path}/neutron_vpnaas/tests/contrib
src_conf=${src_conf_path}/functional-test-rootwrap.conf
src_rootwrap_path=${repo_path}/etc/neutron/rootwrap.d

dst_conf_path=${venv_path}/etc/neutron
dst_conf=${dst_conf_path}/rootwrap.conf
dst_rootwrap_path=${dst_conf_path}/rootwrap.d

# Clear any existing filters in virtual env
if [[ -d "$dst_rootwrap_path" ]]; then
    rm -rf ${dst_rootwrap_path}
fi
mkdir -p -m 755 ${dst_rootwrap_path}

# Get all needed filters
cp -p ${src_rootwrap_path}/* ${dst_rootwrap_path}/
if [[ "$OS_SUDO_TESTING" = "1" ]]; then
    cp -p ${repo_path}/neutron_vpnaas/tests/contrib/functional-testing.filters \
        ${dst_rootwrap_path}/
fi
# Get config file and modify for this repo
cp -p ${src_conf} ${dst_conf}
sed -i "s:^filters_path=.*$:filters_path=${dst_rootwrap_path}:" ${dst_conf}
sed -i "s:^\(exec_dirs=.*\)$:\1,${venv_path}/bin:" ${dst_conf}
sudo mkdir -p /etc/neutron/
sudo cp ${dst_conf} /etc/neutron/
