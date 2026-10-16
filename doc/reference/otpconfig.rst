OTP configuration
=================

Manage the default values that IPA uses for OTP tokens.


**EXAMPLES**

 Show basic OTP configuration:

 .. code-block:: console

    ipa otpconfig-show

 Show all OTP configuration options:

 .. code-block:: console

    ipa otpconfig-show --all

 Change maximum TOTP authentication window to 10 minutes:

 .. code-block:: console

    ipa otpconfig-mod --totp-auth-window=600

 Change maximum TOTP synchronization window to 12 hours:

 .. code-block:: console

    ipa otpconfig-mod --totp-sync-window=43200

 Change maximum HOTP authentication window to 5:

 .. code-block:: console

    ipa hotpconfig-mod --hotp-auth-window=5

 Change maximum HOTP synchronization window to 50:

 .. code-block:: console

    ipa hotpconfig-mod --hotp-sync-window=50


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `otpconfig-mod`_
     - Modify OTP configuration options.
   * - `otpconfig-show`_
     - Show the current OTP configuration.

----

.. _otpconfig-mod:

otpconfig-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otpconfig-mod [options]``

Modify OTP configuration options.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--totp-auth-window TOTP-AUTH-WINDOW``
     - TOTP authentication time variance (seconds)
   * - ``--totp-sync-window TOTP-SYNC-WINDOW``
     - TOTP synchronization time variance (seconds)
   * - ``--hotp-auth-window HOTP-AUTH-WINDOW``
     - HOTP authentication skip-ahead
   * - ``--hotp-sync-window HOTP-SYNC-WINDOW``
     - HOTP synchronization skip-ahead
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

.. _otpconfig-show:

otpconfig-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otpconfig-show [options]``

Show the current OTP configuration.

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

