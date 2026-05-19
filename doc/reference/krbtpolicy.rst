Kerberos ticket policy
======================

There is a single Kerberos ticket policy. This policy defines the
maximum ticket lifetime and the maximum renewal age, the period during
which the ticket is renewable.

You can also create a per-user ticket policy by specifying the user login.

For changes to the global policy to take effect, restarting the KDC service
is required, which can be achieved using:

service krb5kdc restart

Changes to per-user policies take effect immediately for newly requested
tickets (e.g. when the user next runs kinit).


**EXAMPLES**

 Display the current Kerberos ticket policy:

  ipa ``krbtpolicy-show``

 Reset the policy to the default:

  ipa ``krbtpolicy-reset``

 Modify the policy to 8 hours max life, 1-day max renewal:

  ipa ``krbtpolicy-mod`` --maxlife=28800 --maxrenew=86400

 Display effective Kerberos ticket policy for user 'admin':

  ipa ``krbtpolicy-show`` admin

 Reset per-user policy for user 'admin':

  ipa ``krbtpolicy-reset`` admin

 Modify per-user policy for user 'admin':

  ipa ``krbtpolicy-mod`` admin --maxlife=3600

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `krbtpolicy-mod`_
     - Modify Kerberos ticket policy.
   * - `krbtpolicy-reset`_
     - Reset Kerberos ticket policy to the default values.
   * - `krbtpolicy-show`_
     - Display the current Kerberos ticket policy.

----

.. _krbtpolicy-mod:

krbtpolicy-mod
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] krbtpolicy-mod [USER] [options]``

Modify Kerberos ticket policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``USER``
     - no
     - Manage ticket policy for specific user

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--maxlife MAXLIFE``
     - Maximum ticket life (seconds)
   * - ``--maxrenew MAXRENEW``
     - Maximum renewable age (seconds)
   * - ``--otp-maxlife OTP-MAXLIFE``
     - OTP token maximum ticket life (seconds)
   * - ``--otp-maxrenew OTP-MAXRENEW``
     - OTP token ticket maximum renewable age (seconds)
   * - ``--radius-maxlife RADIUS-MAXLIFE``
     - RADIUS maximum ticket life (seconds)
   * - ``--radius-maxrenew RADIUS-MAXRENEW``
     - RADIUS ticket maximum renewable age (seconds)
   * - ``--pkinit-maxlife PKINIT-MAXLIFE``
     - PKINIT maximum ticket life (seconds)
   * - ``--pkinit-maxrenew PKINIT-MAXRENEW``
     - PKINIT ticket maximum renewable age (seconds)
   * - ``--hardened-maxlife HARDENED-MAXLIFE``
     - Hardened ticket maximum ticket life (seconds)
   * - ``--hardened-maxrenew HARDENED-MAXRENEW``
     - Hardened ticket maximum renewable age (seconds)
   * - ``--idp-maxlife IDP-MAXLIFE``
     - External Identity Provider ticket maximum ticket life (seconds)
   * - ``--idp-maxrenew IDP-MAXRENEW``
     - External Identity Provider ticket maximum renewable age (seconds)
   * - ``--passkey-maxlife PASSKEY-MAXLIFE``
     - Passkey ticket maximum ticket life (seconds)
   * - ``--passkey-maxrenew PASSKEY-MAXRENEW``
     - Passkey ticket maximum renewable age (seconds)
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

.. _krbtpolicy-reset:

krbtpolicy-reset
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] krbtpolicy-reset [USER] [options]``

Reset Kerberos ticket policy to the default values.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``USER``
     - no
     - Manage ticket policy for specific user

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

----

.. _krbtpolicy-show:

krbtpolicy-show
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] krbtpolicy-show [USER] [options]``

Display the current Kerberos ticket policy.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``USER``
     - no
     - Manage ticket policy for specific user

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

