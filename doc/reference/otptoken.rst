OTP Tokens
==========

Manage OTP tokens.

IPA supports the use of OTP tokens for multi-factor authentication. This
code enables the management of OTP tokens.


**EXAMPLES**

 Add a new token:

 .. code-block:: console

    ipa otptoken-add --type=totp --owner=jdoe --desc="My soft token"

 Examine the token:

 .. code-block:: console

    ipa otptoken-show a93db710-a31a-4639-8647-f15b2c70b78a

 Change the vendor:

 .. code-block:: console

    ipa otptoken-mod a93db710-a31a-4639-8647-f15b2c70b78a --vendor="Red Hat"

 Delete a token:

 .. code-block:: console

    ipa otptoken-del a93db710-a31a-4639-8647-f15b2c70b78a


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `otptoken-add`_
     - Add a new OTP token.
   * - `otptoken-add-managedby`_
     - Add users that can manage this token.
   * - `otptoken-del`_
     - Delete an OTP token.
   * - `otptoken-find`_
     - Search for OTP token.
   * - `otptoken-mod`_
     - Modify a OTP token.
   * - `otptoken-remove-managedby`_
     - Remove users that can manage this token.
   * - `otptoken-show`_
     - Display information about an OTP token.

----

.. _otptoken-add:

otptoken-add
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-add [ID] [options]``

Add a new OTP token.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - no
     - Unique ID

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--type TYPE``
     - Type of the token
   * - ``--desc DESC``
     - Token description (informational only)
   * - ``--owner OWNER``
     - Assigned user of the token (default: self)
   * - ``--disabled DISABLED``
     - Mark the token as disabled (default: false)
   * - ``--not-before NOT-BEFORE``
     - First date/time the token can be used
   * - ``--not-after NOT-AFTER``
     - Last date/time the token can be used
   * - ``--vendor VENDOR``
     - Token vendor name (informational only)
   * - ``--model MODEL``
     - Token model (informational only)
   * - ``--serial SERIAL``
     - Token serial (informational only)
   * - ``--key KEY``
     - Token secret (Base32; default: random)
   * - ``--algo ALGO``
     - Token hash algorithm
   * - ``--digits DIGITS``
     - Number of digits each token code will have
   * - ``--offset OFFSET``
     - TOTP token / IPA server time difference
   * - ``--interval INTERVAL``
     - Length of TOTP token code validity
   * - ``--counter COUNTER``
     - Initial counter for the HOTP token
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--no-qrcode``
     - Do not display QR code
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _otptoken-add-managedby:

otptoken-add-managedby
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-add-managedby ID [options]``

Add users that can manage this token.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Unique ID

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

----

.. _otptoken-del:

otptoken-del
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-del ID [options]``

Delete an OTP token.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Unique ID

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

.. _otptoken-find:

otptoken-find
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-find [CRITERIA] [options]``

Search for OTP token.

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
   * - ``--id ID``
     - Unique ID
   * - ``--type TYPE``
     - Type of the token
   * - ``--desc DESC``
     - Token description (informational only)
   * - ``--owner OWNER``
     - Assigned user of the token (default: self)
   * - ``--disabled DISABLED``
     - Mark the token as disabled (default: false)
   * - ``--not-before NOT-BEFORE``
     - First date/time the token can be used
   * - ``--not-after NOT-AFTER``
     - Last date/time the token can be used
   * - ``--vendor VENDOR``
     - Token vendor name (informational only)
   * - ``--model MODEL``
     - Token model (informational only)
   * - ``--serial SERIAL``
     - Token serial (informational only)
   * - ``--algo ALGO``
     - Token hash algorithm
   * - ``--digits DIGITS``
     - Number of digits each token code will have
   * - ``--offset OFFSET``
     - TOTP token / IPA server time difference
   * - ``--interval INTERVAL``
     - Length of TOTP token code validity
   * - ``--counter COUNTER``
     - Initial counter for the HOTP token
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("id")

----

.. _otptoken-mod:

otptoken-mod
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-mod ID [options]``

Modify a OTP token.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Unique ID

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Token description (informational only)
   * - ``--owner OWNER``
     - Assigned user of the token (default: self)
   * - ``--disabled DISABLED``
     - Mark the token as disabled (default: false)
   * - ``--not-before NOT-BEFORE``
     - First date/time the token can be used
   * - ``--not-after NOT-AFTER``
     - Last date/time the token can be used
   * - ``--vendor VENDOR``
     - Token vendor name (informational only)
   * - ``--model MODEL``
     - Token model (informational only)
   * - ``--serial SERIAL``
     - Token serial (informational only)
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
   * - ``--rename RENAME``
     - Rename the OTP token object

----

.. _otptoken-remove-managedby:

otptoken-remove-managedby
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-remove-managedby ID [options]``

Remove users that can manage this token.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Unique ID

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

----

.. _otptoken-show:

otptoken-show
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] otptoken-show ID [options]``

Display information about an OTP token.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``ID``
     - yes
     - Unique ID

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

