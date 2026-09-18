Manage CA ACL rules.
====================

This plugin is used to define rules governing which CAs and profiles
may be used to issue certificates to particular principals or groups
of principals.


**SUBJECT PRINCIPAL SCOPE**

For a certificate request to be allowed, the principal(s) that are
the subject of a certificate request (not necessarily the principal
actually requesting the certificate) must be included in the scope
of a CA ACL that also includes the target CA and profile.

Users can be included by name, group or the "all users" category.
Hosts can be included by name, hostgroup or the "all hosts"
category.  Services can be included by service name or the "all
services" category.  CA ACLs may be associated with a single type of
principal, or multiple types.


**CERTIFICATE AUTHORITY SCOPE**

A CA ACL can be associated with one or more CAs by name, or by the
"all CAs" category.  For compatibility reasons, a CA ACL with no CA
association implies an association with the 'ipa' CA (and only this
CA).


**PROFILE SCOPE**

A CA ACL can be associated with one or more profiles by Profile ID.
The Profile ID is a string without spaces or punctuation starting
with a letter and followed by a sequence of letters, digits or
underscore ("_").


**EXAMPLES**

  Create a CA ACL "test" that grants all users access to the

  "UserCert" profile on all CAs:

  .. code-block:: console

      ipa caacl-add test --usercat=all --cacat=all
      ipa caacl-add-profile test --certprofiles UserCert

  Display the properties of a named CA ACL:

  .. code-block:: console

      ipa caacl-show test

  Create a CA ACL to let user "alice" use the "DNP3" profile on "DNP3-CA":

  .. code-block:: console

      ipa caacl-add alice_dnp3
      ipa caacl-add-ca alice_dnp3 --cas DNP3-CA
      ipa caacl-add-profile alice_dnp3 --certprofiles DNP3
      ipa caacl-add-user alice_dnp3 --user=alice

  Disable a CA ACL:

  .. code-block:: console

      ipa caacl-disable test

  Remove a CA ACL:

  .. code-block:: console

      ipa caacl-del test


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `caacl-add`_
     - Create a new CA ACL.
   * - `caacl-add-ca`_
     - Add CAs to a CA ACL.
   * - `caacl-add-host`_
     - Add target hosts and hostgroups to a CA ACL.
   * - `caacl-add-profile`_
     - Add profiles to a CA ACL.
   * - `caacl-add-service`_
     - Add services to a CA ACL.
   * - `caacl-add-user`_
     - Add users and groups to a CA ACL.
   * - `caacl-del`_
     - Delete a CA ACL.
   * - `caacl-disable`_
     - Disable a CA ACL.
   * - `caacl-enable`_
     - Enable a CA ACL.
   * - `caacl-find`_
     - Search for CA ACLs.
   * - `caacl-mod`_
     - Modify a CA ACL.
   * - `caacl-remove-ca`_
     - Remove CAs from a CA ACL.
   * - `caacl-remove-host`_
     - Remove target hosts and hostgroups from a CA ACL.
   * - `caacl-remove-profile`_
     - Remove profiles from a CA ACL.
   * - `caacl-remove-service`_
     - Remove services from a CA ACL.
   * - `caacl-remove-user`_
     - Remove users and groups from a CA ACL.
   * - `caacl-show`_
     - Display the properties of a CA ACL.

----

.. _caacl-add:

caacl-add
~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-add NAME [options]``

Create a new CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--cacat CACAT``
     - CA category the ACL applies to
   * - ``--profilecat PROFILECAT``
     - Profile category the ACL applies to
   * - ``--usercat USERCAT``
     - User category the ACL applies to
   * - ``--hostcat HOSTCAT``
     - Host category the ACL applies to
   * - ``--servicecat SERVICECAT``
     - Service category the ACL applies to
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _caacl-add-ca:

caacl-add-ca
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-add-ca NAME [options]``

Add CAs to a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--cas CAS``
     - Certificate Authorities to add

----

.. _caacl-add-host:

caacl-add-host
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-add-host NAME [options]``

Add target hosts and hostgroups to a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _caacl-add-profile:

caacl-add-profile
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-add-profile NAME [options]``

Add profiles to a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--certprofiles CERTPROFILES``
     - Certificate Profiles to add

----

.. _caacl-add-service:

caacl-add-service
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-add-service NAME [options]``

Add services to a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--services SERVICES``
     - services to add

----

.. _caacl-add-user:

caacl-add-user
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-add-user NAME [options]``

Add users and groups to a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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

----

.. _caacl-del:

caacl-del
~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-del NAME [options]``

Delete a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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

.. _caacl-disable:

caacl-disable
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-disable NAME [options]``

Disable a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

----

.. _caacl-enable:

caacl-enable
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-enable NAME [options]``

Enable a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

----

.. _caacl-find:

caacl-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-find [CRITERIA] [options]``

Search for CA ACLs.

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
   * - ``--name NAME``
     - ACL name
   * - ``--desc DESC``
     - Description
   * - ``--cacat CACAT``
     - CA category the ACL applies to
   * - ``--profilecat PROFILECAT``
     - Profile category the ACL applies to
   * - ``--usercat USERCAT``
     - User category the ACL applies to
   * - ``--hostcat HOSTCAT``
     - Host category the ACL applies to
   * - ``--servicecat SERVICECAT``
     - Service category the ACL applies to
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _caacl-mod:

caacl-mod
~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-mod NAME [options]``

Modify a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--cacat CACAT``
     - CA category the ACL applies to
   * - ``--profilecat PROFILECAT``
     - Profile category the ACL applies to
   * - ``--usercat USERCAT``
     - User category the ACL applies to
   * - ``--hostcat HOSTCAT``
     - Host category the ACL applies to
   * - ``--servicecat SERVICECAT``
     - Service category the ACL applies to
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
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _caacl-remove-ca:

caacl-remove-ca
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-remove-ca NAME [options]``

Remove CAs from a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--cas CAS``
     - Certificate Authorities to remove

----

.. _caacl-remove-host:

caacl-remove-host
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-remove-host NAME [options]``

Remove target hosts and hostgroups from a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _caacl-remove-profile:

caacl-remove-profile
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-remove-profile NAME [options]``

Remove profiles from a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--certprofiles CERTPROFILES``
     - Certificate Profiles to remove

----

.. _caacl-remove-service:

caacl-remove-service
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-remove-service NAME [options]``

Remove services from a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--services SERVICES``
     - services to remove

----

.. _caacl-remove-user:

caacl-remove-user
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-remove-user NAME [options]``

Remove users and groups from a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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

----

.. _caacl-show:

caacl-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] caacl-show NAME [options]``

Display the properties of a CA ACL.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``NAME``
     - yes
     - ACL name

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
   * - ``--no-members``
     - Suppress processing of membership attributes.

