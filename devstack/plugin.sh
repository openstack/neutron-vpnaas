# plugin.sh - DevStack plugin.sh dispatch script template

VPNAAS_XTRACE=$(set +o | grep xtrace)
set -o xtrace

function neutron_vpnaas_install {
    setup_develop $NEUTRON_VPNAAS_DIR
    if is_service_enabled q-l3; then
        neutron_agent_vpnaas_install_agent_packages
    fi
}

function neutron_agent_vpnaas_install_agent_packages {
    install_package $IPSEC_PACKAGE
    if is_ubuntu && [[ "$IPSEC_PACKAGE" == "strongswan" ]]; then
        install_package apparmor
        sudo ln -sf /etc/apparmor.d/usr.lib.ipsec.charon /etc/apparmor.d/disable/
        sudo ln -sf /etc/apparmor.d/usr.lib.ipsec.stroke /etc/apparmor.d/disable/
        # NOTE: Due to https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/1387220
        # one must use 'sudo start apparmor ACTION=reload' for Ubuntu 14.10
        restart_service apparmor
    fi
}

function neutron_vpnaas_configure_common {
    cp $NEUTRON_VPNAAS_DIR/etc/neutron_vpnaas.conf.sample $NEUTRON_VPNAAS_CONF
    _neutron_service_plugin_class_add $VPN_PLUGIN
    _neutron_deploy_rootwrap_filters $NEUTRON_VPNAAS_DIR
    inicomment $NEUTRON_VPNAAS_CONF service_providers service_provider
    iniadd $NEUTRON_VPNAAS_CONF service_providers service_provider $NEUTRON_VPNAAS_SERVICE_PROVIDER
    iniset $NEUTRON_CONF DEFAULT service_plugins $Q_SERVICE_PLUGIN_CLASSES
}

function neutron_vpnaas_configure_db {
    $NEUTRON_BIN_DIR/neutron-db-manage --subproject neutron-vpnaas --config-file $NEUTRON_CONF --config-file /$Q_PLUGIN_CONF_FILE upgrade head
}

function neutron_vpnaas_configure_agent {
    local conf_file=${1:-$Q_VPN_CONF_FILE}
    cp $NEUTRON_VPNAAS_DIR/etc/vpn_agent.ini.sample $conf_file
    if [[ "$IPSEC_PACKAGE" == "strongswan" ]]; then
        if is_fedora; then
            iniset_multiline $conf_file vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.fedora_strongswan_ipsec.FedoraStrongSwanDriver
        else
            iniset_multiline $conf_file vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec.StrongSwanDriver
        fi
    elif [[ "$IPSEC_PACKAGE" == "libreswan" ]]; then
        iniset_multiline $Q_VPN_CONF_FILE vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.libreswan_ipsec.LibreSwanDriver
    else
        iniset_multiline $conf_file vpnagent vpn_device_driver $NEUTRON_VPNAAS_DEVICE_DRIVER
    fi
}

function neutron_vpnaas_start {
    local cfg_file
    local opts="--config-file $NEUTRON_CONF --config-file=$Q_L3_CONF_FILE --config-file=$Q_VPN_CONF_FILE"
    for cfg_file in ${Q_VPN_EXTRA_CONF_FILES[@]}; do
        opts+=" --config-file $cfg_file"
    done
    run_process neutron-vpnaas "$AGENT_VPN_BINARY $opts"
}

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

function neutron_vpnaas_generate_config_files {
    # Uses oslo config generator to generate VPNaaS sample configuration files
    (cd $NEUTRON_VPNAAS_DIR && exec sudo ./tools/generate_config_file_samples.sh)
}

# Main plugin processing

# NOP for pre-install step

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing neutron-vpnaas"
    neutron_vpnaas_install

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    neutron_vpnaas_generate_config_files
    neutron_vpnaas_configure_common
    if is_service_enabled q-svc; then
        echo_summary "Configuring neutron-vpnaas on controller"
        neutron_vpnaas_configure_db
    fi
    if is_service_enabled q-l3; then
        echo_summary "Configuring neutron-vpnaas agent"
        neutron_vpnaas_configure_agent
    fi

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    if is_service_enabled q-l3; then
        echo_summary "Initializing neutron-vpnaas"
        neutron_vpnaas_start
    fi

elif [[ "$1" == "unstack" ]]; then
    if is_service_enabled q-l3; then
        neutron_vpnaas_stop
    fi

# NOP for clean step

fi

$VPNAAS_XTRACE
