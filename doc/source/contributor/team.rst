=====================================
Core reviewers and Driver maintainers
=====================================

Core reviewers
--------------

The `Neutron VPNaaS Core Reviewer Team <https://review.opendev.org/#/admin/groups/502,members>`_
is responsible for many things that same as `Neutron team <https://docs.openstack.org/neutron/latest/contributor/policies/neutron-teams.html>`_.

Driver maintainers
------------------

The driver maintainers are supposed to try:

- Test the driver
- Fix bugs in the driver
- Keep the driver up-to-date for Neutron
- Keep the driver up-to-date for its backend
- Review relevant patches

The following is a list of drivers and their maintainers.
It includes both of in-tree and out-of-tree drivers.
(alphabetical order)

+----------------------------+---------------------------+------------------+
| Driver                     | Contact person            | IRC nick         |
+============================+===========================+==================+
| LibreSwanDriver            | Dongcan Ye                | yedongcan        |
+----------------------------+---------------------------+------------------+
| MidonetIPsecVPNDriver [#]_ | YAMAMOTO Takashi          | yamamoto         |
+----------------------------+---------------------------+------------------+
| NSXvIPsecVpnDriver [#]_    | Roey Chen                 | roeyc            |
+----------------------------+---------------------------+------------------+
| OpenSwanDriver             | Lingxian Kong             | kong             |
+----------------------------+---------------------------+------------------+
|                            | Lingxian Kong             | kong             |
| StrongSwanDriver           +---------------------------+------------------+
|                            | Cao Xuan Hoang            | hoangcx          |
+----------------------------+---------------------------+------------------+

.. [#] networking-midonet: https://docs.openstack.org/networking-midonet/latest/install/installation.html#vpnaas
.. [#] vmware-nsx: Maintained under the vmware-nsx repository - https://github.com/openstack/vmware-nsx
