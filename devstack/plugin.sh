# plugin.sh - DevStack plugin.sh dispatch script template

VPNAAS_XTRACE=$(set +o | grep xtrace)
set -o xtrace

# Source L3 agent extension management
LIBDIR=$DEST/neutron-vpnaas/devstack/lib
source $LIBDIR/l3_agent

NEUTRON_L3_CONF=${NEUTRON_L3_CONF:-$Q_L3_CONF_FILE}

function is_ovn_enabled {
    [[ $Q_AGENT == "ovn" ]] && return 0
    return 1
}

function neutron_vpnaas_install {
    setup_develop $NEUTRON_VPNAAS_DIR
    if is_service_enabled q-l3 neutron-l3 q-ovn-vpn-agent; then
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
    neutron_server_config_add $NEUTRON_VPNAAS_CONF
    neutron_service_plugin_class_add $VPN_PLUGIN
    neutron_deploy_rootwrap_filters $NEUTRON_VPNAAS_DIR
    inicomment $NEUTRON_VPNAAS_CONF service_providers service_provider
    iniadd $NEUTRON_VPNAAS_CONF service_providers service_provider $NEUTRON_VPNAAS_SERVICE_PROVIDER
}

function neutron_vpnaas_configure_agent {
    plugin_agent_add_l3_agent_extension vpnaas
    configure_l3_agent
    if [[ "$IPSEC_PACKAGE" == "strongswan" ]]; then
        iniset_multiline $NEUTRON_L3_CONF vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.strongswan_ipsec.StrongSwanDriver
    elif [[ "$IPSEC_PACKAGE" == "libreswan" ]]; then
        iniset_multiline $NEUTRON_L3_CONF vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.libreswan_ipsec.LibreSwanDriver
    else
        iniset_multiline $NEUTRON_L3_CONF vpnagent vpn_device_driver $NEUTRON_VPNAAS_DEVICE_DRIVER
    fi
}

function neutron_vpnaas_configure_ovn_agent {
    cp $NEUTRON_VPNAAS_DIR/etc/neutron_ovn_vpn_agent.ini.sample $OVN_VPNAGENT_CONF

    iniset $OVN_VPNAGENT_CONF DEFAULT interface_driver openvswitch
    iniset $OVN_VPNAGENT_CONF DEFAULT state_path $DATA_DIR/neutron
    iniset_rpc_backend neutron-vpnaas $OVN_VPNAGENT_CONF
    iniset $OVN_VPNAGENT_CONF agent root_helper "$Q_RR_COMMAND"
    if [[ "$Q_USE_ROOTWRAP_DAEMON" == "True" ]]; then
        iniset $OVN_VPNAGENT_CONF agent root_helper_daemon "$Q_RR_DAEMON_COMMAND"
    fi

    if [[ "$IPSEC_PACKAGE" == "strongswan" ]]; then
        iniset_multiline $OVN_VPNAGENT_CONF vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.ovn_ipsec.OvnStrongSwanDriver
    elif [[ "$IPSEC_PACKAGE" == "libreswan" ]]; then
        iniset_multiline $OVN_VPNAGENT_CONF vpnagent vpn_device_driver neutron_vpnaas.services.vpn.device_drivers.ovn_ipsec.OvnLibreSwanDriver
    else
        iniset_multiline $OVN_VPNAGENT_CONF vpnagent vpn_device_driver $NEUTRON_VPNAAS_DEVICE_DRIVER
    fi

    OVSDB_SERVER_LOCAL_HOST=$SERVICE_LOCAL_HOST
    if [[ "$SERVICE_IP_VERSION" == 6 ]]; then
        OVSDB_SERVER_LOCAL_HOST=[$OVSDB_SERVER_LOCAL_HOST]
    fi
    OVN_SB_REMOTE=${OVN_SB_REMOTE:-$OVN_PROTO:$SERVICE_HOST:6642}

    iniset $OVN_VPNAGENT_CONF ovs ovsdb_connection tcp:$OVSDB_SERVER_LOCAL_HOST:6640
    iniset $OVN_VPNAGENT_CONF ovn ovn_sb_connection $OVN_SB_REMOTE
    if is_service_enabled tls-proxy; then
        iniset $OVN_VPNAGENT_CONF ovn \
            ovn_sb_ca_cert $INT_CA_DIR/ca-chain.pem
        iniset $OVN_VPNAGENT_CONF ovn \
            ovn_sb_certificate $INT_CA_DIR/$DEVSTACK_CERT_NAME.crt
        iniset $OVN_VPNAGENT_CONF ovn \
            ovn_sb_private_key $INT_CA_DIR/private/$DEVSTACK_CERT_NAME.key
    fi
}

function neutron_vpnaas_configure_db {
    $NEUTRON_BIN_DIR/neutron-db-manage --subproject neutron-vpnaas --config-file $NEUTRON_CONF upgrade head
}

function neutron_vpnaas_generate_config_files {
    # Uses oslo config generator to generate VPNaaS sample configuration files
    (cd $NEUTRON_VPNAAS_DIR && exec ./tools/generate_config_file_samples.sh)
}

function neutron_vpnaas_start_vpnagent {
    NEUTRON_OVN_BIN_DIR=$(get_python_exec_prefix)
    NEUTRON_OVN_VPNAGENT_BINARY="neutron-ovn-vpn-agent"

    run_process q-ovn-vpn-agent "$NEUTRON_OVN_BIN_DIR/$NEUTRON_OVN_VPNAGENT_BINARY --config-file $OVN_VPNAGENT_CONF"
    # Format logging
    setup_logging $OVN_VPNAGENT_CONF
}

# Main plugin processing

# NOP for pre-install step

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo_summary "Installing neutron-vpnaas"
    neutron_vpnaas_install

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    neutron_vpnaas_generate_config_files
    neutron_vpnaas_configure_common
    if is_service_enabled q-svc neutron-api; then
        echo_summary "Configuring neutron-vpnaas on controller"
        neutron_vpnaas_configure_db
    fi
    if is_service_enabled q-l3 neutron-l3; then
        echo_summary "Configuring neutron-vpnaas agent"
        neutron_vpnaas_configure_agent
    fi
    if is_service_enabled q-ovn-vpn-agent && is_ovn_enabled; then
        echo_summary "Configuring neutron-ovn-vpn-agent"
        neutron_vpnaas_configure_ovn_agent
    fi

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    if is_service_enabled q-ovn-vpn-agent && is_ovn_enabled; then
        neutron_vpnaas_start_vpnagent
    fi

# NOP for clean step

fi

$VPNAAS_XTRACE
