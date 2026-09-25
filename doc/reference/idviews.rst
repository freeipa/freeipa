ID Views
========

Manage ID Views

IPA allows to override certain properties of users and groups per each host.
This functionality is primarily used to allow migration from older systems or
other Identity Management solutions.

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `idoverridegroup-add`_
     - Add a new Group ID override.
   * - `idoverridegroup-del`_
     - Delete an Group ID override.
   * - `idoverridegroup-find`_
     - Search for an Group ID override.
   * - `idoverridegroup-mod`_
     - Modify an Group ID override.
   * - `idoverridegroup-show`_
     - Display information about an Group ID override.
   * - `idoverrideuser-add`_
     - Add a new User ID override.
   * - `idoverrideuser-add-cert`_
     - Add one or more certificates to the idoverrideuser entry
   * - `idoverrideuser-del`_
     - Delete an User ID override.
   * - `idoverrideuser-find`_
     - Search for an User ID override.
   * - `idoverrideuser-mod`_
     - Modify an User ID override.
   * - `idoverrideuser-remove-cert`_
     - Remove one or more certificates to the idoverrideuser entry
   * - `idoverrideuser-show`_
     - Display information about an User ID override.
   * - `idview-add`_
     - Add a new ID View.
   * - `idview-apply`_
     - Applies ID View to specified hosts or current members of specified hostgroups. If any other ID View is applied to the host, it is overridden.
   * - `idview-del`_
     - Delete an ID View.
   * - `idview-find`_
     - Search for an ID View.
   * - `idview-mod`_
     - Modify an ID View.
   * - `idview-show`_
     - Display information about an ID View.
   * - `idview-unapply`_
     - Clears ID View from specified hosts or current members of specified hostgroups.

----

.. _idoverridegroup-add:

idoverridegroup-add
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverridegroup-add IDVIEW ANCHOR [options]``

Add a new Group ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--group-name GROUP-NAME``
     - Group name
   * - ``--gid GID``
     - Group ID Number
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _idoverridegroup-del:

idoverridegroup-del
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverridegroup-del IDVIEW ANCHOR [options]``

Delete an Group ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.

----

.. _idoverridegroup-find:

idoverridegroup-find
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverridegroup-find IDVIEW [CRITERIA] [options]``

Search for an Group ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
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
   * - ``--anchor ANCHOR``
     - Anchor to override
   * - ``--desc DESC``
     - Description
   * - ``--group-name GROUP-NAME``
     - Group name
   * - ``--gid GID``
     - Group ID Number
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("anchor")

----

.. _idoverridegroup-mod:

idoverridegroup-mod
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverridegroup-mod IDVIEW ANCHOR [options]``

Modify an Group ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--group-name GROUP-NAME``
     - Group name
   * - ``--gid GID``
     - Group ID Number
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--rename RENAME``
     - Rename the Group ID override object

----

.. _idoverridegroup-show:

idoverridegroup-show
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverridegroup-show IDVIEW ANCHOR [options]``

Display information about an Group ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _idoverrideuser-add:

idoverrideuser-add
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-add IDVIEW ANCHOR [options]``

Add a new User ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--login LOGIN``
     - User login
   * - ``--uid UID``
     - User ID Number
   * - ``--gecos GECOS``
     - GECOS
   * - ``--gidnumber GIDNUMBER``
     - Group ID Number
   * - ``--homedir HOMEDIR``
     - Home directory
   * - ``--shell SHELL``
     - Login shell
   * - ``--sshpubkey SSHPUBKEY``
     - SSH public key
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _idoverrideuser-add-cert:

idoverrideuser-add-cert
~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-add-cert IDVIEW ANCHOR [options]``

Add one or more certificates to the idoverrideuser entry

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate

----

.. _idoverrideuser-del:

idoverrideuser-del
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-del IDVIEW ANCHOR [options]``

Delete an User ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.

----

.. _idoverrideuser-find:

idoverrideuser-find
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-find IDVIEW [CRITERIA] [options]``

Search for an User ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
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
   * - ``--anchor ANCHOR``
     - Anchor to override
   * - ``--desc DESC``
     - Description
   * - ``--login LOGIN``
     - User login
   * - ``--uid UID``
     - User ID Number
   * - ``--gecos GECOS``
     - GECOS
   * - ``--gidnumber GIDNUMBER``
     - Group ID Number
   * - ``--homedir HOMEDIR``
     - Home directory
   * - ``--shell SHELL``
     - Login shell
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("anchor")

----

.. _idoverrideuser-mod:

idoverrideuser-mod
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-mod IDVIEW ANCHOR [options]``

Modify an User ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--login LOGIN``
     - User login
   * - ``--uid UID``
     - User ID Number
   * - ``--gecos GECOS``
     - GECOS
   * - ``--gidnumber GIDNUMBER``
     - Group ID Number
   * - ``--homedir HOMEDIR``
     - Home directory
   * - ``--shell SHELL``
     - Login shell
   * - ``--sshpubkey SSHPUBKEY``
     - SSH public key
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--rename RENAME``
     - Rename the User ID override object

----

.. _idoverrideuser-remove-cert:

idoverrideuser-remove-cert
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-remove-cert IDVIEW ANCHOR [options]``

Remove one or more certificates to the idoverrideuser entry

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded user certificate

----

.. _idoverrideuser-show:

idoverrideuser-show
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idoverrideuser-show IDVIEW ANCHOR [options]``

Display information about an User ID override.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``IDVIEW``
     - yes
     - ID View Name
   * - ``ANCHOR``
     - yes
     - Anchor to override

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--fallback-to-ldap``
     - Allow falling back to AD DC LDAP when resolving AD trusted objects. For two-way trusts only.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _idview-add:

idview-add
~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-add NAME [options]``

Add a new ID View.

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
     - ID View Name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--domain-resolution-order DOMAIN-RESOLUTION-ORDER``
     - colon-separated list of domains used for short name qualification
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _idview-apply:

idview-apply
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-apply NAME [options]``

Applies ID View to specified hosts or current members of specified hostgroups. If any other ID View is applied to the host, it is overridden.

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
     - ID View Name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--hosts HOSTS``
     - Hosts to apply the ID View to
   * - ``--hostgroups HOSTGROUPS``
     - Hostgroups to whose hosts apply the ID View to. Please note that view is not applied automatically to any hosts added to the hostgroup after running the idview-apply command.

----

.. _idview-del:

idview-del
~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-del NAME [options]``

Delete an ID View.

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
     - ID View Name

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

.. _idview-find:

idview-find
~~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-find [CRITERIA] [options]``

Search for an ID View.

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
     - ID View Name
   * - ``--desc DESC``
     - Description
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

.. _idview-mod:

idview-mod
~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-mod NAME [options]``

Modify an ID View.

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
     - ID View Name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--domain-resolution-order DOMAIN-RESOLUTION-ORDER``
     - colon-separated list of domains used for short name qualification
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
   * - ``--rename RENAME``
     - Rename the ID View object

----

.. _idview-show:

idview-show
~~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-show NAME [options]``

Display information about an ID View.

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
     - ID View Name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--show-hosts``
     - Enumerate all the hosts the view applies to.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _idview-unapply:

idview-unapply
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idview-unapply [options]``

Clears ID View from specified hosts or current members of specified hostgroups.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--hosts HOSTS``
     - Hosts to clear (any) ID View from.
   * - ``--hostgroups HOSTGROUPS``
     - Hostgroups whose hosts should have ID Views cleared. Note that view is not cleared automatically from any host added to the hostgroup after running idview-unapply command.

