Welcome!
========

This contains rally testing code for the Neutron VPN as a Service (VPNaaS) service. The tests
currently require rally to be installed via devstack or standalone. It is assumed that you
also have Neutron with the Neutron VPNaaS service installed.

Please see /neutron-vpnaas/devstack/README.md for the required devstack configuration settings
for Neutron-VPNaaS.

Structure:
==========

1. plugins - Directory where you can add rally plugins. Almost everything in Rally is a plugin.
Contains base, common methods and actual scenario tests
2. rally-configs - Contains input config for the scenario tests

How to test:
============

Included in the repo are rally tests. For information on rally, please see the rally README :

https://github.com/openstack/rally/blob/master/README.rst

* Create the folder structure as below
   $> sudo mkdir /opt/rally
* Create a symbolic link to the plugin
   $> cd /opt/rally
   $> sudo ln -s /opt/stack/neutron-vpnaas/rally-jobs/plugins
* Run the tests
   $> rally task start /opt/stack/neutron-vpnaas/rally-jobs/rally-configs/rally_config.yaml

External Resources:
===================

For more information on the rally testing framework see: <https://github.com/openstack/rally>
