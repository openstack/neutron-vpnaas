===============================
Configuring VPNaaS for DevStack
===============================

-----------------------
Multinode vs All-In-One
-----------------------

Devstack typically runs in single or "All-In-One" (AIO) mode.  However, it
can also be deployed to run on multiple nodes. For VPNaaS, running on an
AIO setup is simple, as everything happens on the same node. However, to
deploy to a multinode setup requires the following things to happen:

#. Each controller node requires database migrations in support of running
   VPNaaS.

#. Each network node that would run VPNaaS L3 agent extension.

Therefore, the devstack plugin script needs some extra logic.

----------------
How to Configure
----------------

To configure VPNaaS, it is only necessary to enable the neutron-vpnaas
devstack plugin by adding the following line to the ``[[local|localrc]]``
section of devstack's local.conf file::

   enable_plugin neutron-vpnaas <GITURL> [BRANCH]

``<GITURL>`` is the URL of a neutron-vpnaas repository
``[BRANCH]`` is an optional git ref (branch/ref/tag). The default is master.

For example::

   enable_plugin neutron-vpnaas https://opendev.org/openstack/neutron-vpnaas stable/kilo

The default implementation for IPSEC package under DevStack is 'strongswan'.
However, depending upon the Linux distribution, you may need to override
this value. Select 'libreswan' for Fedora/RHEL/CentOS.

For example, install libreswan for CentOS/RHEL 7::

    IPSEC_PACKAGE=libreswan

This VPNaaS devstack plugin code will then

#. Install the common VPNaaS configuration and code,

#. Apply database migrations on nodes that are running the controller (as
   determined by enabling the q-svc service),
