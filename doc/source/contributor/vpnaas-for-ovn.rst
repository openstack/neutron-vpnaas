==========================
Configuring VPNaaS for OVN
==========================

A general instruction to enable neutron VPNaaS is described in
`the Networking Guide
<https://docs.openstack.org/neutron/latest/admin/vpnaas-scenario.html#enabling-vpnaas>`__.

For an OVN-based setup some details are different though. The following instructions adapt the general ones
accordingly.

Enabling VPNaaS for OVN
~~~~~~~~~~~~~~~~~~~~~~~

#. Enable the VPNaaS plug-in in the ``/etc/neutron/neutron.conf`` file
   by appending ``ovn-vpnaas`` to ``service_plugins`` in ``[DEFAULT]``:

   .. code-block:: ini

      [DEFAULT]
      # ...
      service_plugins = ovn-vpnaas

   .. note::

      ``ovn-vpnaas`` is the plugin variant of the reference implementation that supports OVN.


#. Configure the VPNaaS service provider by creating the
   ``/etc/neutron/neutron_vpnaas.conf`` file as follows, ``strongswan`` used in Ubuntu distribution:

   .. code-block:: ini

      [service_providers]
      service_provider = VPN:strongswan:neutron_vpnaas.services.vpn.service_drivers.ovn_ipsec.IPsecOvnVPNDriver

#. With OVN there is no L3 agent. Instead a stand-alone VPN agent is installed. There is a new "binary" called
   ``neutron-ovn-vpn-agent``. Create its configuration file ``/etc/neutron/ovn_vpn_agent.ini``
   with the following contents:

   .. code-block:: ini

      [DEFAULT]
      transport_url = rabbit://openstack:RABBIT_PASS@CONTROLLER_IP
      interface_driver = neutron.agent.linux.interface.OVSInterfaceDriver

      [AGENT]
      extensions = vpnaas

      [vpnagent]
      vpn_device_driver = neutron_vpnaas.services.vpn.device_drivers.ovn_ipsec.OvnStrongSwanDriver

      [ovs]
      ovsdb_connection="unix:/var/run/openvswitch/db.sock"

      [ovn]
      ovn_sb_connection = tcp:OVSDB_SERVER_IP:6642

   .. note::

      Replace ``OVSDB_SERVER_IP`` with the IP address of the controller node that
      runs the ``ovsdb-server`` service.
      Replace ``RABBIT_PASS`` with the password you chose for the
      ``openstack`` account in RabbitMQ and CONTROLLER_IP with the IP address of
      the controller node that runs the RabbitMQ server.

#. Create the required tables in the database:

   .. code-block:: console

      # neutron-db-manage --subproject neutron-vpnaas upgrade head

#. Restart the ``neutron-server`` in controller node to apply the settings.

#. Start the ``neutron-ovn-vpn-agent`` in network node to apply the settings.

Specifics of the OVN variant of the plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Details about the architecture are described in
`the feature spec
<https://opendev.org/openstack/neutron-specs/src/branch/master/specs/xena/vpnaas-ovn.rst>`__.
