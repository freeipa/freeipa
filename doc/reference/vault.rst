Vaults
======

Manage vaults.

Vault is a secure place to store a secret. One vault can only
store one secret. When archiving a secret in a vault, the
existing secret (if any) is overwritten.

Based on the ownership there are three vault categories:

- user/private vault
- service vault
- shared vault

User vaults are vaults owned used by a particular user. Private
vaults are vaults owned the current user. Service vaults are
vaults owned by a service. Shared vaults are owned by the admin
but they can be used by other users or services.

Based on the security mechanism there are three types of
vaults:

- standard vault
- symmetric vault
- asymmetric vault

Standard vault uses a secure mechanism to transport and
store the secret. The secret can only be retrieved by users
that have access to the vault.

Symmetric vault is similar to the standard vault, but it
pre-encrypts the secret using a password before transport.
The secret can only be retrieved using the same password.

Asymmetric vault is similar to the standard vault, but it
pre-encrypts the secret using a public key before transport.
The secret can only be retrieved using the private key.


**EXAMPLES**

 List vaults:

 .. code-block:: console

    ipa vault-find
        [--user <user>|--service <service>|--shared]

 Add a standard vault:

 .. code-block:: console

    ipa vault-add <name>
        [--user <user>|--service <service>|--shared]
        --type standard

 Add a symmetric vault:

 .. code-block:: console

    ipa vault-add <name>
        [--user <user>|--service <service>|--shared]
        --type symmetric --password-file password.txt

 Add an asymmetric vault:

 .. code-block:: console

    ipa vault-add <name>
        [--user <user>|--service <service>|--shared]
        --type asymmetric --public-key-file public.pem

 Show a vault:

 .. code-block:: console

    ipa vault-show <name>
        [--user <user>|--service <service>|--shared]

 Modify vault description:

 .. code-block:: console

    ipa vault-mod <name>
        [--user <user>|--service <service>|--shared]
        --desc <description>

 Modify vault type:

 .. code-block:: console

    ipa vault-mod <name>
        [--user <user>|--service <service>|--shared]
        --type <type>
        [old password/private key]
        [new password/public key]

 Modify symmetric vault password:

 .. code-block:: console

    ipa vault-mod <name>
        [--user <user>|--service <service>|--shared]
        --change-password
    ipa vault-mod <name>
        [--user <user>|--service <service>|--shared]
        --old-password <old password>
        --new-password <new password>
    ipa vault-mod <name>
        [--user <user>|--service <service>|--shared]
        --old-password-file <old password file>
        --new-password-file <new password file>

 Modify asymmetric vault keys:

 .. code-block:: console

    ipa vault-mod <name>
        [--user <user>|--service <service>|--shared]
        --private-key-file <old private key file>
        --public-key-file <new public key file>

 Delete a vault:

 .. code-block:: console

    ipa vault-del <name>
        [--user <user>|--service <service>|--shared]

 Display vault configuration:

 .. code-block:: console

    ipa vaultconfig-show

 Archive data into standard vault:

 .. code-block:: console

    ipa vault-archive <name>
        [--user <user>|--service <service>|--shared]
        --in <input file>

 Archive data into symmetric vault:

 .. code-block:: console

    ipa vault-archive <name>
        [--user <user>|--service <service>|--shared]
        --in <input file>
        --password-file password.txt

 Archive data into asymmetric vault:

 .. code-block:: console

    ipa vault-archive <name>
        [--user <user>|--service <service>|--shared]
        --in <input file>

 Retrieve data from standard vault:

 .. code-block:: console

    ipa vault-retrieve <name>
        [--user <user>|--service <service>|--shared]
        --out <output file>

 Retrieve data from symmetric vault:

 .. code-block:: console

    ipa vault-retrieve <name>
        [--user <user>|--service <service>|--shared]
        --out <output file>
        --password-file password.txt

 Retrieve data from asymmetric vault:

 .. code-block:: console

    ipa vault-retrieve <name>
        [--user <user>|--service <service>|--shared]
        --out <output file> --private-key-file private.pem

 Add vault owners:

 .. code-block:: console

    ipa vault-add-owner <name>
        [--user <user>|--service <service>|--shared]
        [--users <users>]  [--groups <groups>] [--services <services>]

 Delete vault owners:

 .. code-block:: console

    ipa vault-remove-owner <name>
        [--user <user>|--service <service>|--shared]
        [--users <users>] [--groups <groups>] [--services <services>]

 Add vault members:

 .. code-block:: console

    ipa vault-add-member <name>
        [--user <user>|--service <service>|--shared]
        [--users <users>] [--groups <groups>] [--services <services>]

 Delete vault members:

 .. code-block:: console

    ipa vault-remove-member <name>
        [--user <user>|--service <service>|--shared]
        [--users <users>] [--groups <groups>] [--services <services>]


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `vault-add-member`_
     - Add members to a vault.
   * - `vault-add-owner`_
     - Add owners to a vault.
   * - `vault-del`_
     - Delete a vault.
   * - `vault-find`_
     - Search for vaults.
   * - `vault-remove-member`_
     - Remove members from a vault.
   * - `vault-remove-owner`_
     - Remove owners from a vault.
   * - `vault-show`_
     - Display information about a vault.
   * - `vaultconfig-show`_
     - Show vault configuration.
   * - `vaultcontainer-add-owner`_
     - Add owners to a vault container.
   * - `vaultcontainer-del`_
     - Delete a vault container.
   * - `vaultcontainer-remove-owner`_
     - Remove owners from a vault container.
   * - `vaultcontainer-show`_
     - Display information about a vault container.

----

.. _vault-add-member:

vault-add-member
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vault-add-member NAME [options]``

Add members to a vault.

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
     - Vault name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
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
   * - ``--services SERVICES``
     - services to add

----

.. _vault-add-owner:

vault-add-owner
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vault-add-owner NAME [options]``

Add owners to a vault.

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
     - Vault name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
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
   * - ``--services SERVICES``
     - services to add

----

.. _vault-del:

vault-del
~~~~~~~~~

**Usage:** ``ipa [global-options] vault-del NAME [options]``

Delete a vault.

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
     - Vault name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault

----

.. _vault-find:

vault-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] vault-find [CRITERIA] [options]``

Search for vaults.

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
     - Vault name
   * - ``--desc DESC``
     - Vault description
   * - ``--type TYPE``
     - Vault type
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
   * - ``--services``
     - List all service vaults
   * - ``--users``
     - List all user vaults
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _vault-remove-member:

vault-remove-member
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vault-remove-member NAME [options]``

Remove members from a vault.

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
     - Vault name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
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
   * - ``--services SERVICES``
     - services to remove

----

.. _vault-remove-owner:

vault-remove-owner
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vault-remove-owner NAME [options]``

Remove owners from a vault.

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
     - Vault name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
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
   * - ``--services SERVICES``
     - services to remove

----

.. _vault-show:

vault-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] vault-show NAME [options]``

Display information about a vault.

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
     - Vault name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _vaultconfig-show:

vaultconfig-show
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vaultconfig-show [options]``

Show vault configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--transport-out TRANSPORT-OUT``
     - Output file to store the transport certificate
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _vaultcontainer-add-owner:

vaultcontainer-add-owner
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vaultcontainer-add-owner [options]``

Add owners to a vault container.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
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
   * - ``--services SERVICES``
     - services to add

----

.. _vaultcontainer-del:

vaultcontainer-del
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vaultcontainer-del [options]``

Delete a vault container.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--continue``
     - Continuous mode: Don't stop on errors.
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault

----

.. _vaultcontainer-remove-owner:

vaultcontainer-remove-owner
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vaultcontainer-remove-owner [options]``

Remove owners from a vault container.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
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
   * - ``--services SERVICES``
     - services to remove

----

.. _vaultcontainer-show:

vaultcontainer-show
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] vaultcontainer-show [options]``

Display information about a vault container.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--service SERVICE``
     - Service name of the service vault
   * - ``--shared``
     - Shared vault
   * - ``--user USER``
     - Username of the user vault
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

