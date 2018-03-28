#!/usr/bin/env bash

set -xe

NEUTRON_VPNAAS_DIR="$BASE/new/neutron-vpnaas"
TEMPEST_CONFIG_DIR="$BASE/new/tempest/etc"
SCRIPTS_DIR="/usr/os-testr-env/bin"

VENV=${1:-"dsvm-functional"}

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .stestr
    if [ -f ".stestr/0" ] ; then
        .tox/$VENV/bin/subunit-1to2 < .stestr/0 > ./stestr.subunit
        $SCRIPTS_DIR/subunit2html ./stestr.subunit testr_results.html
        gzip -9 ./stestr.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}

case $VENV in
    dsvm-functional | dsvm-functional-sswan)
        owner=stack
        sudo_env=

        # Set owner permissions according to job's requirements.
        cd $NEUTRON_VPNAAS_DIR
        sudo chown -R $owner:stack $NEUTRON_VPNAAS_DIR

        echo "Running neutron $VENV test suite"
        set +e
        sudo -H -u $owner $sudo_env tox -e $VENV --notest
        # Development version of neutron is not installed from g-r.
        # We need to install neutron master explicitly.
        sudo -H -u $owner $sudo_env .tox/$VENV/bin/pip install -e ../neutron
        sudo -H -u $owner $sudo_env tox -e $VENV
        testr_exit_code=$?
        set -e

        # Collect and parse results
        generate_testr_results
        exit $testr_exit_code
        ;;
esac
