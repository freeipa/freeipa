Passkey configuration
=====================

Manage Passkey configuration.

IPA supports the use of passkeys for authentication. A passkey
device has to be registered to SSSD and the resulting authentication mapping
stored in the user entry.
The passkey authentication supports the following configuration option:
require user verification. When set, the method for user verification depends
on the type of device (PIN, fingerprint, external pad...)


**EXAMPLES**

 Display the Passkey configuration:

 .. code-block:: console

    ipa passkeyconfig-show

 Modify the Passkey configuration to always require user verification:

 .. code-block:: console

    ipa passkeyconfig-mod --require-user-verification=TRUE


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `passkeyconfig-mod`_
     - Modify Passkey configuration.
   * - `passkeyconfig-show`_
     - Show the current Passkey configuration.

----

.. _passkeyconfig-mod:

passkeyconfig-mod
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] passkeyconfig-mod [options]``

Modify Passkey configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--require-user-verification REQUIRE-USER-VERIFICATION``
     - Require user verification during authentication
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

.. _passkeyconfig-show:

passkeyconfig-show
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] passkeyconfig-show [options]``

Show the current Passkey configuration.

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

