===================
Configuration Guide
===================

Configuration
-------------

This section provides a list of all possible options for each
configuration file.

Neutron VPNaaS uses the following configuration files for its various services.

.. toctree::
   :maxdepth: 1

   neutron_vpnaas
   l3_agent
   neutron_ovn_vpn_agent

The following are sample configuration files for Neutron VPNaaS services and
utilities. These are generated from code and reflect the current state of code
in the neutron-vpnaas repository.

.. toctree::
   :glob:
   :maxdepth: 1

   samples/*

Policy
------

Neutron VPNaaS, like most OpenStack projects, uses a policy language to
restrict permissions on REST API actions.

.. toctree::
   :maxdepth: 1

   Policy Reference <policy>
   Sample Policy File <policy-sample>
