..
      Copyright 2015 OpenStack Foundation
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Developer Guide
===============

In the Developer Guide, you will find information on the design, and
architecture of the Neutron Virtual Private Network as a Service repo.
This include things like, information on the reference implementation
flavors, design details on VPNaaS internals, and testing. Developers
will extend this, as needed, in the future to contain more information.

If you would like to contribute to the development of OpenStack, you must
follow the steps documented at:
https://docs.openstack.org/infra/manual/developers.html

Once those steps have been completed, changes to OpenStack should be submitted
for review via the Gerrit tool, following the workflow documented at:
https://docs.openstack.org/infra/manual/developers.html#development-workflow

Pull requests submitted through GitHub will be ignored.

Bugs should be filed on Launchpad in the `neutron`__ project with ``vpnaas`` tag added.

New features should be filed on Launchpad in the `neutron`__ project with ``rfe`` tag
added in order to get decision from `neutron drivers`_ team. Before doing that, it is
recommended to check `Request for Feature Enhancements`_ (RFE) process.

.. __: https://bugs.launchpad.net/neutron/+bugs?field.tag=vpnaas
.. __: https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe
.. _`neutron drivers`: https://review.openstack.org/#/admin/groups/464,members
.. _`Request for Feature Enhancements`: https://docs.openstack.org/neutron/latest/contributor/policies/blueprints.html#neutron-request-for-feature-enhancements

To get in touch with the neutron-vpnaas community,
look at the following resource:

- Join the ``#openstack-vpnaas`` IRC channel on Freenode. This is where the
  VPNaaS team is available for discussion.
- We will hold for `VPN-as-a-Service (bi-)weekly IRC meeting`
  when needed in the near further.

These are great places to get recommendations on where to start contributing
to neutron-vpnaas.


VPNaaS Team
-----------
.. toctree::
   :maxdepth: 3

   team

VPNaaS Flavors
-----------------
.. toctree::
   :maxdepth: 3

.. todo::

   Info on the different Swan flavors, how they are different, and what
   Operating Systems support them.

VPNaaS Internals
-----------------
.. toctree::
   :maxdepth: 3

   multiple-local-subnets

VPNaaS Tests
------------
.. toctree::
   :maxdepth: 3

   vpnaas-tempest-test
   vpnaas-rally-test

Testing
-------
.. toctree::
   :maxdepth: 3

   devstack
   testing-with-devstack

.. todo::

   Add notes about functional testing, with info on how
   different reference drivers are tested.

Module Reference
----------------
.. toctree::
   :maxdepth: 3

.. todo::

    Add in all the big modules as automodule indexes.


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
