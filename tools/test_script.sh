#!/usr/bin/env bash

EXT_NW_ID=`openstack network show public -c id -f value`
EXTERNAL_SUBNET_IP_VERSION='v4'
WEST_SUBNET='192.168.1.0/24'
EAST_SUBNET='192.168.2.0/24'

function setup_site(){
  local site_name=$1
  local cidr=$2
  openstack network create net_$site_name
  openstack subnet create --network net_$site_name --subnet-range $2 subnet_$site_name
  openstack router create router_$site_name
  openstack router add subnet router_$site_name subnet_$site_name
  openstack router set --external-gateway $EXT_NW_ID router_$site_name
  openstack vpn service create --subnet subnet_$site_name --router router_$site_name vpn_$site_name
}

function get_external_ip(){
  echo `openstack vpn service show $1 -c external_${EXTERNAL_SUBNET_IP_VERSION}_ip -f value`
}

function clean_site(){
  local site_name=$1
  openstack vpn ipsec site connection delete conn_$site_name
  openstack vpn service delete vpn_$site_name
  openstack router unset --external-gateway router_$site_name
  openstack router remove subnet router_$site_name subnet_$site_name
  openstack router delete router_$site_name
  openstack subnet delete subnet_$site_name
  openstack network delete net_$site_name
}

function setup(){
  openstack vpn ike policy create ikepolicy1
  openstack vpn ipsec policy create ipsecpolicy1
  setup_site west $WEST_SUBNET
  WEST_IP=$(get_external_ip vpn_west)
  setup_site east $EAST_SUBNET
  EAST_IP=$(get_external_ip vpn_east)
  openstack vpn ipsec site connection create \
      --vpnservice vpn_east --ikepolicy ikepolicy1 --ipsecpolicy ipsecpolicy1 \
      --peer-address $WEST_IP --peer-id $WEST_IP --peer-cidr $WEST_SUBNET \
      --psk secret conn_east
  openstack vpn ipsec site connection create \
      --vpnservice vpn_west --ikepolicy ikepolicy1 --ipsecpolicy ipsecpolicy1 \
      --peer-address $EAST_IP --peer-id $EAST_IP --peer-cidr $EAST_SUBNET \
      --psk secret conn_west
}

function cleanup(){
  clean_site west
  clean_site east
  openstack vpn ike policy delete ikepolicy1
  openstack vpn ipsec policy delete ipsecpolicy1
}

cleanup
setup
