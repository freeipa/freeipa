Hosts/Machines
==============

A host represents a machine. It can be used in a number of contexts:

- service entries are associated with a host
- a host stores the host/ service principal
- a host can be used in Host-based Access Control (HBAC) rules
- every enrolled client generates a host entry


**ENROLLMENT**

There are three enrollment scenarios when enrolling a new client:

1. You are enrolling as a full administrator. The host entry may exist
   or not. A full administrator is a member of the hostadmin role
   or the admins group.
2. You are enrolling as a limited administrator. The host must already
   exist. A limited administrator is a member a role with the
   Host Enrollment privilege.
3. The host has been created with a one-time password.


**RE-ENROLLMENT**

Host that has been enrolled at some point, and lost its configuration (e.g. VM
destroyed) can be re-enrolled.

For more information, consult the manual pages for ipa-client-install.

A host can optionally store information such as where it is located,
the OS that it runs, etc.


**EXAMPLES**

 Add a new host:

 .. code-block:: console

    ipa host-add --location="3rd floor lab" --locality=Dallas test.example.com

 Delete a host:

 .. code-block:: console

    ipa host-del test.example.com

 Add a new host with a one-time password:

 .. code-block:: console

    ipa host-add --os='Fedora 12' --password=Secret123 test.example.com

 Add a new host with a random one-time password:

 .. code-block:: console

    ipa host-add --os='Fedora 12' --random test.example.com

 Modify information about a host:

 .. code-block:: console

    ipa host-mod --os='Fedora 12' test.example.com

 Remove SSH public keys of a host and update DNS to reflect this change:

 .. code-block:: console

    ipa host-mod --sshpubkey= --updatedns test.example.com

 Disable the host Kerberos key, SSL certificate and all of its services:

 .. code-block:: console

    ipa host-disable test.example.com

 Add a host that can manage this host's keytab and certificate:

 .. code-block:: console

    ipa host-add-managedby --hosts=test2 test

 Allow user to create a keytab:

 .. code-block:: console

    ipa host-allow-create-keytab test2 --users=tuser1


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `host-add`_
     - Add a new host.
   * - `host-add-cert`_
     - Add certificates to host entry
   * - `host-add-delegation`_
     - Add new resource delegation to a host
   * - `host-add-managedby`_
     - Add hosts that can manage this host.
   * - `host-add-principal`_
     - Add new principal alias to host entry
   * - `host-allow-add-delegation`_
     - Allow users, groups, hosts or host groups to handle a resource delegation of this host.
   * - `host-allow-create-keytab`_
     - Allow users, groups, hosts or host groups to create a keytab of this host.
   * - `host-allow-retrieve-keytab`_
     - Allow users, groups, hosts or host groups to retrieve a keytab of this host.
   * - `host-del`_
     - Delete a host.
   * - `host-disable`_
     - Disable the Kerberos key, SSL certificate and all services of a host.
   * - `host-disallow-add-delegation`_
     - Disallow users, groups, hosts or host groups to handle a resource delegation of this host.
   * - `host-disallow-create-keytab`_
     - Disallow users, groups, hosts or host groups to create a keytab of this host.
   * - `host-disallow-retrieve-keytab`_
     - Disallow users, groups, hosts or host groups to retrieve a keytab of this host.
   * - `host-find`_
     - Search for hosts.
   * - `host-mod`_
     - Modify information about a host.
   * - `host-remove-cert`_
     - Remove certificates from host entry
   * - `host-remove-delegation`_
     - Remove resource delegation from a host
   * - `host-remove-managedby`_
     - Remove hosts that can manage this host.
   * - `host-remove-principal`_
     - Remove principal alias from a host entry
   * - `host-show`_
     - Display information about a host.

----

.. _host-add:

host-add
~~~~~~~~

**Usage:** ``ipa [global-options] host-add HOSTNAME [options]``

Add a new host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this host
   * - ``--locality LOCALITY``
     - Host locality (e.g. "Baltimore, MD")
   * - ``--location LOCATION``
     - Host physical location hint (e.g. "Lab 2")
   * - ``--platform PLATFORM``
     - Host hardware platform (e.g. "Lenovo T61")
   * - ``--os OS``
     - Host operating system and version (e.g. "Fedora 9")
   * - ``--password PASSWORD``
     - Password used in bulk enrollment
   * - ``--random``
     - Generate a random password to be used in bulk enrollment
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded host certificate
   * - ``--macaddress MACADDRESS``
     - Hardware MAC address(es) on this host
   * - ``--sshpubkey SSHPUBKEY``
     - SSH public key
   * - ``--class CLASS``
     - Host category (semantics placed on this attribute are for local interpretation)
   * - ``--auth-ind AUTH-IND``
     - Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use 'pkinit' to allow PKINIT-based 2FA authentications. Use 'hardened' to allow brute-force hardened password authentication by SPAKE or FAST. Use 'idp' to allow External Identity Provider authentications. Use 'passkey' to allow passkey-based 2FA authentications. With no indicator specified, all authentication mechanisms are allowed.
   * - ``--requires-pre-auth REQUIRES-PRE-AUTH``
     - Pre-authentication is required for the service
   * - ``--ok-as-delegate OK-AS-DELEGATE``
     - Client credentials may be delegated to the service
   * - ``--ok-to-auth-as-delegate OK-TO-AUTH-AS-DELEGATE``
     - The service is allowed to authenticate on behalf of a client
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--force``
     - force host name even if not in DNS
   * - ``--no-reverse``
     - skip reverse DNS detection
   * - ``--ip-address IP-ADDRESS``
     - Add the host to DNS with this IP address
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _host-add-cert:

host-add-cert
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-add-cert HOSTNAME [options]``

Add certificates to host entry

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded host certificate

----

.. _host-add-delegation:

host-add-delegation
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-add-delegation HOSTNAME PRINCIPAL [options]``

Add new resource delegation to a host

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name
   * - ``PRINCIPAL``
     - yes
     - Delegation principal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _host-add-managedby:

host-add-managedby
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-add-managedby HOSTNAME [options]``

Add hosts that can manage this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--hosts HOSTS``
     - hosts to add

----

.. _host-add-principal:

host-add-principal
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-add-principal HOSTNAME KRBPRINCIPALNAME [options]``

Add new principal alias to host entry

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name
   * - ``KRBPRINCIPALNAME``
     - yes
     - Principal alias

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _host-allow-add-delegation:

host-allow-add-delegation
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-allow-add-delegation HOSTNAME [options]``

Allow users, groups, hosts or host groups to handle a resource delegation of this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--users USERS``
     - users to add
   * - ``--groups GROUPS``
     - groups to add
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _host-allow-create-keytab:

host-allow-create-keytab
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-allow-create-keytab HOSTNAME [options]``

Allow users, groups, hosts or host groups to create a keytab of this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--users USERS``
     - users to add
   * - ``--groups GROUPS``
     - groups to add
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _host-allow-retrieve-keytab:

host-allow-retrieve-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-allow-retrieve-keytab HOSTNAME [options]``

Allow users, groups, hosts or host groups to retrieve a keytab of this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--users USERS``
     - users to add
   * - ``--groups GROUPS``
     - groups to add
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _host-del:

host-del
~~~~~~~~

**Usage:** ``ipa [global-options] host-del HOSTNAME [options]``

Delete a host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--updatedns``
     - Remove A, AAAA, SSHFP and PTR records of the host(s) managed by IPA DNS

----

.. _host-disable:

host-disable
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-disable HOSTNAME [options]``

Disable the Kerberos key, SSL certificate and all services of a host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

----

.. _host-disallow-add-delegation:

host-disallow-add-delegation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-disallow-add-delegation HOSTNAME [options]``

Disallow users, groups, hosts or host groups to handle a resource delegation of this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--users USERS``
     - users to remove
   * - ``--groups GROUPS``
     - groups to remove
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _host-disallow-create-keytab:

host-disallow-create-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-disallow-create-keytab HOSTNAME [options]``

Disallow users, groups, hosts or host groups to create a keytab of this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--users USERS``
     - users to remove
   * - ``--groups GROUPS``
     - groups to remove
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _host-disallow-retrieve-keytab:

host-disallow-retrieve-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-disallow-retrieve-keytab HOSTNAME [options]``

Disallow users, groups, hosts or host groups to retrieve a keytab of this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--users USERS``
     - users to remove
   * - ``--groups GROUPS``
     - groups to remove
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _host-find:

host-find
~~~~~~~~~

**Usage:** ``ipa [global-options] host-find [CRITERIA] [options]``

Search for hosts.

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
   * - ``--hostname HOSTNAME``
     - Host name
   * - ``--desc DESC``
     - A description of this host
   * - ``--locality LOCALITY``
     - Host locality (e.g. "Baltimore, MD")
   * - ``--location LOCATION``
     - Host physical location hint (e.g. "Lab 2")
   * - ``--platform PLATFORM``
     - Host hardware platform (e.g. "Lenovo T61")
   * - ``--os OS``
     - Host operating system and version (e.g. "Fedora 9")
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded host certificate
   * - ``--macaddress MACADDRESS``
     - Hardware MAC address(es) on this host
   * - ``--class CLASS``
     - Host category (semantics placed on this attribute are for local interpretation)
   * - ``--auth-ind AUTH-IND``
     - Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use 'pkinit' to allow PKINIT-based 2FA authentications. Use 'hardened' to allow brute-force hardened password authentication by SPAKE or FAST. Use 'idp' to allow External Identity Provider authentications. Use 'passkey' to allow passkey-based 2FA authentications. With no indicator specified, all authentication mechanisms are allowed.
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("hostname")
   * - ``--in-hostgroups IN-HOSTGROUPS``
     - Search for hosts with these member of host groups.
   * - ``--not-in-hostgroups NOT-IN-HOSTGROUPS``
     - Search for hosts without these member of host groups.
   * - ``--in-netgroups IN-NETGROUPS``
     - Search for hosts with these member of netgroups.
   * - ``--not-in-netgroups NOT-IN-NETGROUPS``
     - Search for hosts without these member of netgroups.
   * - ``--in-roles IN-ROLES``
     - Search for hosts with these member of roles.
   * - ``--not-in-roles NOT-IN-ROLES``
     - Search for hosts without these member of roles.
   * - ``--in-hbacrules IN-HBACRULES``
     - Search for hosts with these member of HBAC rules.
   * - ``--not-in-hbacrules NOT-IN-HBACRULES``
     - Search for hosts without these member of HBAC rules.
   * - ``--in-sudorules IN-SUDORULES``
     - Search for hosts with these member of sudo rules.
   * - ``--not-in-sudorules NOT-IN-SUDORULES``
     - Search for hosts without these member of sudo rules.
   * - ``--enroll-by-users ENROLL-BY-USERS``
     - Search for hosts with these enrolled by users.
   * - ``--not-enroll-by-users NOT-ENROLL-BY-USERS``
     - Search for hosts without these enrolled by users.
   * - ``--man-by-hosts MAN-BY-HOSTS``
     - Search for hosts with these managed by hosts.
   * - ``--not-man-by-hosts NOT-MAN-BY-HOSTS``
     - Search for hosts without these managed by hosts.
   * - ``--man-hosts MAN-HOSTS``
     - Search for hosts with these managing hosts.
   * - ``--not-man-hosts NOT-MAN-HOSTS``
     - Search for hosts without these managing hosts.

----

.. _host-mod:

host-mod
~~~~~~~~

**Usage:** ``ipa [global-options] host-mod HOSTNAME [options]``

Modify information about a host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - A description of this host
   * - ``--locality LOCALITY``
     - Host locality (e.g. "Baltimore, MD")
   * - ``--location LOCATION``
     - Host physical location hint (e.g. "Lab 2")
   * - ``--platform PLATFORM``
     - Host hardware platform (e.g. "Lenovo T61")
   * - ``--os OS``
     - Host operating system and version (e.g. "Fedora 9")
   * - ``--password PASSWORD``
     - Password used in bulk enrollment
   * - ``--random``
     - Generate a random password to be used in bulk enrollment
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded host certificate
   * - ``--krbprincipalname KRBPRINCIPALNAME``
     - Principal alias
   * - ``--macaddress MACADDRESS``
     - Hardware MAC address(es) on this host
   * - ``--sshpubkey SSHPUBKEY``
     - SSH public key
   * - ``--class CLASS``
     - Host category (semantics placed on this attribute are for local interpretation)
   * - ``--auth-ind AUTH-IND``
     - Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use 'pkinit' to allow PKINIT-based 2FA authentications. Use 'hardened' to allow brute-force hardened password authentication by SPAKE or FAST. Use 'idp' to allow External Identity Provider authentications. Use 'passkey' to allow passkey-based 2FA authentications. With no indicator specified, all authentication mechanisms are allowed.
   * - ``--requires-pre-auth REQUIRES-PRE-AUTH``
     - Pre-authentication is required for the service
   * - ``--ok-as-delegate OK-AS-DELEGATE``
     - Client credentials may be delegated to the service
   * - ``--ok-to-auth-as-delegate OK-TO-AUTH-AS-DELEGATE``
     - The service is allowed to authenticate on behalf of a client
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--updatedns``
     - Update DNS entries
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _host-remove-cert:

host-remove-cert
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-remove-cert HOSTNAME [options]``

Remove certificates from host entry

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded host certificate

----

.. _host-remove-delegation:

host-remove-delegation
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-remove-delegation HOSTNAME PRINCIPAL [options]``

Remove resource delegation from a host

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name
   * - ``PRINCIPAL``
     - yes
     - Delegation principal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _host-remove-managedby:

host-remove-managedby
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-remove-managedby HOSTNAME [options]``

Remove hosts that can manage this host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--hosts HOSTS``
     - hosts to remove

----

.. _host-remove-principal:

host-remove-principal
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] host-remove-principal HOSTNAME KRBPRINCIPALNAME [options]``

Remove principal alias from a host entry

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name
   * - ``KRBPRINCIPALNAME``
     - yes
     - Principal alias

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _host-show:

host-show
~~~~~~~~~

**Usage:** ``ipa [global-options] host-show HOSTNAME [options]``

Display information about a host.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - Host name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--out OUT``
     - file to store certificate in
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

