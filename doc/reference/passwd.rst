Set a user's password
=====================

If someone other than a user changes that user's password (e.g., Helpdesk
resets it) then the password will need to be changed the first time it
is used. This is so the end-user is the only one who knows the password.

The IPA password policy controls how often a password may be changed,
what strength requirements exist, and the length of the password history.

If the user authentication method is set to password+OTP, the user should
pass the --otp option when resetting the password.


**EXAMPLES**

 To reset your own password:

 .. code-block:: console

    ipa passwd

 To reset your own password when password+OTP is set as authentication method:

 .. code-block:: console

    ipa passwd --otp

 To change another user's password:

 .. code-block:: console

    ipa passwd tuser1


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `passwd`_
     - Set a user's password.

----

.. _passwd:

passwd
~~~~~~

**Usage:** ``ipa [global-options] passwd [USER] PASSWORD [CURRENT-PASSWORD] [options]``

Set a user's password.

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
     - User name
   * - ``PASSWORD``
     - yes
     - New Password
   * - ``CURRENT-PASSWORD``
     - no
     - Current Password

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--otp OTP``
     - The OTP if the user has a token configured

