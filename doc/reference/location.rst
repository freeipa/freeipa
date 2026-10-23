IPA locations
=============

Manipulate DNS locations


**EXAMPLES**

  Find all locations:

  .. code-block:: console

      ipa location-find

  Show specific location:

  .. code-block:: console

      ipa location-show location

  Add location:

  .. code-block:: console

      ipa location-add location --description 'My location'

  Delete location:

  .. code-block:: console

      ipa location-del location


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `location-add`_
     - Add a new IPA location.
   * - `location-del`_
     - Delete an IPA location.
   * - `location-find`_
     - Search for IPA locations.
   * - `location-mod`_
     - Modify information about an IPA location.
   * - `location-show`_
     - Display information about an IPA location.

----

.. _location-add:

location-add
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] location-add NAME [options]``

Add a new IPA location.

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
     - IPA location name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--description DESCRIPTION``
     - IPA Location description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _location-del:

location-del
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] location-del NAME [options]``

Delete an IPA location.

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
     - IPA location name

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

.. _location-find:

location-find
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] location-find [CRITERIA] [options]``

Search for IPA locations.

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
     - IPA location name
   * - ``--description DESCRIPTION``
     - IPA Location description
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

.. _location-mod:

location-mod
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] location-mod NAME [options]``

Modify information about an IPA location.

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
     - IPA location name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--description DESCRIPTION``
     - IPA Location description
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

.. _location-show:

location-show
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] location-show NAME [options]``

Display information about an IPA location.

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
     - IPA location name

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

