===================
VPNaaS Rally Tests
===================

This contains the rally test codes for the Neutron VPN as a Service (VPNaaS) service. The tests
currently require rally to be installed via devstack or standalone. It is assumed that you
also have Neutron with the Neutron VPNaaS service installed.

These tests could also be run against a multinode openstack.

Please see /neutron-vpnaas/devstack/README.md for the required devstack configuration settings
for Neutron-VPNaaS.

Structure
=========

1. plugins - Directory where you can add rally plugins. Almost everything in Rally is a plugin.
   Contains base, common methods and actual scenario tests
2. rally-configs - Contains input configurations for the scenario tests

How to test
===========

Included in the repo are rally tests. For information on rally,
please see the rally `README <https://github.com/openstack/rally/blob/master/README.rst>`__.

Create a rally deployment for your cloud and make sure it is active.

.. code-block:: console

   rally deployment create --file=cloud_cred.json --name=MyCloud

You can also create a rally deployment from the environment variables.

.. code-block:: console

   rally deployment create --fromenv --name=MyCloud

Create a folder structure as below

.. code-block:: console

   sudo mkdir /opt/rally

Create a symbolic link to the plugins directory

.. code-block:: console

   cd /opt/rally
   sudo ln -s /opt/stack/neutron-vpnaas/rally-jobs/plugins

Run the tests. You can run the tests in various combinations.

* Single Node with DVR with admin credentials
* Single Node with DVR with non admin credentials
* Multi Node with DVR with admin credentials
* Multi Node with DVR with non admin credentials
* Single Node, Non DVR with admin credentials
* Multi Node, Non DVR with admin credentials

Create a ``args.json`` file with the correct credentials depending on whether
it is a single node or multinode cloud.
A ``args_template.json`` file is available at
``/opt/stack/neutron-vpnaas/rally-jobs/rally-configs/args_template.json``
for your reference.

Update the ``rally_config_dvr.yaml`` or ``rally_config_non_dvr.yaml`` file to
change the admin/non_admin credentials.

Use the appropriate config files to run either dvr or non_dvr tests.

With DVR:

.. code-block:: console

   rally task start \
     /opt/stack/neutron-vpnaas/rally-jobs/rally-configs/rally_config_dvr.yaml \
     --task-args-file /opt/stack/neutron-vpnaas/rally-jobs/rally-configs/args.json

Non DVR:

.. code-block:: console

   rally task start \
     /opt/stack/neutron-vpnaas/rally-jobs/rally-configs/rally_config_non_dvr.yaml \
    --task-args-file /opt/stack/neutron-vpnaas/rally-jobs/rally-configs/args.json

.. note::

   Non DVR scenario can only be run as admin as you need admin credentials to create
   a non DVR router.

External Resources
==================

For more information on the rally testing framework see: https://github.com/openstack/rally/.
