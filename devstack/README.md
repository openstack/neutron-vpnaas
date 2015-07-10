This directory contains the neutron-vpnaas devstack plugin.  To
configure VPNaaS, in the [[local|localrc]] section, you will need
to enable the neutron-vpnaas devstack plugin.

Add a line of the form:

    enable_plugin neutron-vpnaas <GITURL> [GITREF]

where

    <GITURL> is the URL of a neutron-vpnaas repository
    [GITREF] is an optional git ref (branch/ref/tag).  The default is
             master.

For example

    enable_plugin neutron-vpnaas https://git.openstack.org/openstack/neutron-vpnaas stable/kilo

Note: Since the VPN agent process, is a subclass of the L3 agent,
which is a subclass of the FW agent, the DevStack plugin will
check for the FW service being enabled, and if so, will include
the config file specified in Q_FWAAS_CONF_FILE (default is
fwaas_driver.ini).

For more information, see the "Externally Hosted Plugins" section of
http://docs.openstack.org/developer/devstack/plugins.html.
