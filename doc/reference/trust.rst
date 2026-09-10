Cross-realm trusts
==================

Manage trust relationship between IPA and Active Directory domains.

In order to allow users from a remote domain to access resources in IPA domain,
trust relationship needs to be established. Currently IPA supports only trusts
between IPA and Active Directory domains under control of Windows Server 2008
or later, with functional level 2008 or later.

Please note that DNS on both IPA and Active Directory domain sides should be
configured properly to discover each other. Trust relationship relies on
ability to discover special resources in the other domain via DNS records.


**Examples**

1. Establish cross-realm trust with Active Directory using AD administrator
   credentials:


.. code-block:: console

   ipa trust-add --type=ad <ad.domain> --admin <AD domain administrator>            --password

2. List all existing trust relationships:


.. code-block:: console

   ipa trust-find

3. Show details of the specific trust relationship:


.. code-block:: console

   ipa trust-show <ad.domain>

4. Delete existing trust relationship:


.. code-block:: console

   ipa trust-del <ad.domain>

Once trust relationship is established, remote users will need to be mapped
to local POSIX groups in order to actually use IPA resources. The mapping
should be done via use of external membership of non-POSIX group and then
this group should be included into one of local POSIX groups.


**Example**

1. Create group for the trusted domain admins' mapping and their local POSIX
group:


.. code-block:: console

   ipa group-add --desc='<ad.domain> admins external map'            ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the
   ad_admins_external group:


.. code-block:: console

   ipa group-add-member ad_admins_external --external 'AD\Domain Admins'

3. Allow members of ad_admins_external group to be associated with
   ad_admins POSIX group:


.. code-block:: console

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see
   their SIDs:


.. code-block:: console

   ipa group-show ad_admins_external


**GLOBAL TRUST CONFIGURATION**

When IPA AD trust subpackage is installed and ipa-adtrust-install is run, a
local domain configuration (SID, GUID, NetBIOS name) is generated. These
identifiers are then used when communicating with a trusted domain of the
particular type.

1. Show global trust configuration for Active Directory type of trusts:


.. code-block:: console

   ipa trustconfig-show --type ad

2. Modify global configuration for all trusts of Active Directory type and set
   a different fallback primary group (fallback primary group GID is used as a
   primary user GID if user authenticating to IPA domain does not have any
   other primary GID already set):


.. code-block:: console

   ipa trustconfig-mod --type ad --fallback-primary-group "another AD group"

3. Change primary fallback group back to default hidden group (any group with
   posixGroup object class is allowed):


.. code-block:: console

   ipa trustconfig-mod --type ad --fallback-primary-group "Default SMB Group"


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `trust-add`_
     - Add new trust to use.
   * - `trust-del`_
     - Delete a trust.
   * - `trust-fetch-domains`_
     - Refresh list of the domains associated with the trust
   * - `trust-find`_
     - Search for trusts.
   * - `trust-mod`_
     - Modify a trust (for future use).
   * - `trust-show`_
     - Display information about a trust.
   * - `trustconfig-mod`_
     - Modify global trust configuration.
   * - `trustconfig-show`_
     - Show global trust configuration.
   * - `trustdomain-del`_
     - Remove information about the domain associated with the trust.
   * - `trustdomain-disable`_
     - Disable use of IPA resources by the domain of the trust
   * - `trustdomain-enable`_
     - Allow use of IPA resources by the domain of the trust
   * - `trustdomain-find`_
     - Search domains of the trust

----

.. _trust-add:

trust-add
~~~~~~~~~

**Usage:** ``ipa [global-options] trust-add REALM [options]``

Add new trust to use.

This command establishes trust relationship to another domain
which becomes 'trusted'. As result, users of the trusted domain
may access resources of this domain.

Only trusts to Active Directory domains are supported right now.

The command can be safely run multiple times against the same domain,
this will cause change to trust relationship credentials on both
sides.

Note that if the command was previously run with a specific range type,
or with automatic detection of the range type, and you want to configure a
different range type, you may need to delete first the ID range using
ipa ``idrange-del`` before retrying the command with the desired range type.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``REALM``
     - yes
     - Realm name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--type TYPE``
     - Trust type (ad for Active Directory, default)
   * - ``--admin ADMIN``
     - Active Directory domain administrator
   * - ``--password PASSWORD``
     - Active Directory domain administrator's password
   * - ``--server SERVER``
     - Domain controller for the Active Directory domain (optional)
   * - ``--trust-secret TRUST-SECRET``
     - Shared secret for the trust
   * - ``--base-id BASE-ID``
     - First Posix ID of the range reserved for the trusted domain
   * - ``--range-size RANGE-SIZE``
     - Size of the ID range reserved for the trusted domain
   * - ``--range-type RANGE-TYPE``
     - Type of trusted domain ID range, one of allowed values
   * - ``--two-way TWO-WAY``
     - Establish bi-directional trust. By default trust is inbound one-way only.
   * - ``--external EXTERNAL``
     - Establish external trust to a domain in another forest. The trust is not transitive beyond the domain.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _trust-del:

trust-del
~~~~~~~~~

**Usage:** ``ipa [global-options] trust-del REALM [options]``

Delete a trust.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``REALM``
     - yes
     - Realm name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.

----

.. _trust-fetch-domains:

trust-fetch-domains
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trust-fetch-domains REALM [options]``

Refresh list of the domains associated with the trust

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``REALM``
     - yes
     - Realm name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--admin ADMIN``
     - Active Directory domain administrator
   * - ``--password PASSWORD``
     - Active Directory domain administrator's password
   * - ``--server SERVER``
     - Domain controller for the Active Directory domain (optional)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _trust-find:

trust-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] trust-find [CRITERIA] [options]``

Search for trusts.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CRITERIA``
     - no
     - A string searched in all relevant object attributes

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--realm REALM``
     - Realm name
   * - ``--flat-name FLAT-NAME``
     - Domain NetBIOS name
   * - ``--sid SID``
     - Domain Security Identifier
   * - ``--sid-blacklist-incoming SID-BLACKLIST-INCOMING``
     - SID blocklist incoming
   * - ``--sid-blacklist-outgoing SID-BLACKLIST-OUTGOING``
     - SID blocklist outgoing
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("realm")

----

.. _trust-mod:

trust-mod
~~~~~~~~~

**Usage:** ``ipa [global-options] trust-mod REALM [options]``

Modify a trust (for future use).


.. code-block:: console

    Currently only the default option to modify the LDAP attributes is
    available. More specific options will be added in coming releases.


Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``REALM``
     - yes
     - Realm name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--sid-blacklist-incoming SID-BLACKLIST-INCOMING``
     - SID blocklist incoming
   * - ``--sid-blacklist-outgoing SID-BLACKLIST-OUTGOING``
     - SID blocklist outgoing
   * - ``--upn-suffixes UPN-SUFFIXES``
     - UPN suffixes
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _trust-show:

trust-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] trust-show REALM [options]``

Display information about a trust.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``REALM``
     - yes
     - Realm name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _trustconfig-mod:

trustconfig-mod
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trustconfig-mod [options]``

Modify global trust configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--fallback-primary-group FALLBACK-PRIMARY-GROUP``
     - Fallback primary group
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--type TYPE``
     - Trust type (ad for Active Directory, default)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _trustconfig-show:

trustconfig-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trustconfig-show [options]``

Show global trust configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--type TYPE``
     - Trust type (ad for Active Directory, default)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _trustdomain-del:

trustdomain-del
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trustdomain-del TRUST DOMAIN [options]``

Remove information about the domain associated with the trust.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TRUST``
     - yes
     - Realm name
   * - ``DOMAIN``
     - yes
     - Domain name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.

----

.. _trustdomain-disable:

trustdomain-disable
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trustdomain-disable TRUST DOMAIN [options]``

Disable use of IPA resources by the domain of the trust

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TRUST``
     - yes
     - Realm name
   * - ``DOMAIN``
     - yes
     - Domain name

----

.. _trustdomain-enable:

trustdomain-enable
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trustdomain-enable TRUST DOMAIN [options]``

Allow use of IPA resources by the domain of the trust

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TRUST``
     - yes
     - Realm name
   * - ``DOMAIN``
     - yes
     - Domain name

----

.. _trustdomain-find:

trustdomain-find
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] trustdomain-find TRUST [CRITERIA] [options]``

Search domains of the trust

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TRUST``
     - yes
     - Realm name
   * - ``CRITERIA``
     - no
     - A string searched in all relevant object attributes

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--domain DOMAIN``
     - Domain name
   * - ``--flat-name FLAT-NAME``
     - Domain NetBIOS name
   * - ``--sid SID``
     - Domain Security Identifier
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("domain")

