Automount
=========

Stores automount(8) configuration for autofs(8) in IPA.

The base of an automount configuration is the configuration file auto.master.
This is also the base location in IPA. Multiple auto.master configurations
can be stored in separate locations. A location is implementation-specific
with the default being a location named 'default'. For example, you can have
locations by geographic region, by floor, by type, etc.

Automount has three basic object types: locations, maps and keys.

A location defines a set of maps anchored in auto.master. This allows you
to store multiple automount configurations. A location in itself isn't
very interesting, it is just a point to start a new automount map.

A map is roughly equivalent to a discrete automount file and provides
storage for keys.

A key is a mount point associated with a map.

When a new location is created, two maps are automatically created for
it: auto.master and auto.direct. auto.master is the root map for all
automount maps for the location. auto.direct is the default map for
direct mounts and is mounted on /-.

An automount map may contain a submount key. This key defines a mount
location within the map that references another map. This can be done
either using ``automountmap-add-indirect`` --parentmap or manually
with ``automountkey-add`` and setting info to "-type=autofs :<mapname>".


**EXAMPLES**


**Locations**

  Create a named location, "Baltimore":

  .. code-block:: console

      ipa automountlocation-add baltimore

  Display the new location:

  .. code-block:: console

      ipa automountlocation-show baltimore

  Find available locations:

  .. code-block:: console

      ipa automountlocation-find

  Remove a named automount location:

  .. code-block:: console

      ipa automountlocation-del baltimore

  Show what the automount maps would look like if they were in the filesystem:

  .. code-block:: console

      ipa automountlocation-tofiles baltimore

  Import an existing configuration into a location:

  .. code-block:: console

      ipa automountlocation-import baltimore /etc/auto.master

      The import will fail if any duplicate entries are found. For
      continuous operation where errors are ignored, use the --continue
      option.


**Maps**

  Create a new map, "auto.share":

  .. code-block:: console

      ipa automountmap-add baltimore auto.share

  Display the new map:

  .. code-block:: console

      ipa automountmap-show baltimore auto.share

  Find maps in the location baltimore:

  .. code-block:: console

      ipa automountmap-find baltimore

  Create an indirect map with auto.share as a submount:

  .. code-block:: console

      ipa automountmap-add-indirect baltimore --parentmap=auto.share --mount=sub auto.man

      This is equivalent to:

      ipa automountmap-add-indirect baltimore --mount=/man auto.man
      ipa automountkey-add baltimore auto.man --key=sub --info="-fstype=autofs ldap:auto.share"

  Remove the auto.share map:

  .. code-block:: console

      ipa automountmap-del baltimore auto.share


**Keys**

  Create a new key for the auto.share map in location baltimore. This ties

  the map we previously created to auto.master:

  .. code-block:: console

      ipa automountkey-add baltimore auto.master --key=/share --info=auto.share

  Create a new key for our auto.share map, an NFS mount for man pages:

  .. code-block:: console

      ipa automountkey-add baltimore auto.share --key=man --info="-ro,soft,rsize=8192,wsize=8192 ipa.example.com:/shared/man"

  Find all keys for the auto.share map:

  .. code-block:: console

      ipa automountkey-find baltimore auto.share

  Find all direct automount keys:

  .. code-block:: console

      ipa automountkey-find baltimore --key=/-

  Remove the man key from the auto.share map:

  .. code-block:: console

      ipa automountkey-del baltimore auto.share --key=man


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `automountkey-add`_
     - Create a new automount key.
   * - `automountkey-del`_
     - Delete an automount key.
   * - `automountkey-find`_
     - Search for an automount key.
   * - `automountkey-mod`_
     - Modify an automount key.
   * - `automountkey-show`_
     - Display an automount key.
   * - `automountlocation-add`_
     - Create a new automount location.
   * - `automountlocation-del`_
     - Delete an automount location.
   * - `automountlocation-find`_
     - Search for an automount location.
   * - `automountlocation-show`_
     - Display an automount location.
   * - `automountlocation-tofiles`_
     - Generate automount files for a specific location.
   * - `automountmap-add`_
     - Create a new automount map.
   * - `automountmap-add-indirect`_
     - Create a new indirect mount point.
   * - `automountmap-del`_
     - Delete an automount map.
   * - `automountmap-find`_
     - Search for an automount map.
   * - `automountmap-mod`_
     - Modify an automount map.
   * - `automountmap-show`_
     - Display an automount map.

----

.. _automountkey-add:

automountkey-add
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountkey-add AUTOMOUNTLOCATION AUTOMOUNTMAP [options]``

Create a new automount key.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``AUTOMOUNTMAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--key KEY``
     - Automount key name.
   * - ``--info INFO``
     - Mount information
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automountkey-del:

automountkey-del
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountkey-del AUTOMOUNTLOCATION AUTOMOUNTMAP [options]``

Delete an automount key.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``AUTOMOUNTMAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--key KEY``
     - Automount key name.
   * - ``--info INFO``
     - Mount information

----

.. _automountkey-find:

automountkey-find
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountkey-find AUTOMOUNTLOCATION AUTOMOUNTMAP [CRITERIA] [options]``

Search for an automount key.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``AUTOMOUNTMAP``
     - yes
     - Automount map name.
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
   * - ``--key KEY``
     - Automount key name.
   * - ``--info INFO``
     - Mount information
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automountkey-mod:

automountkey-mod
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountkey-mod AUTOMOUNTLOCATION AUTOMOUNTMAP [options]``

Modify an automount key.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``AUTOMOUNTMAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--key KEY``
     - Automount key name.
   * - ``--info INFO``
     - Mount information
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--newinfo NEWINFO``
     - New mount information
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--rename RENAME``
     - Rename the automount key object

----

.. _automountkey-show:

automountkey-show
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountkey-show AUTOMOUNTLOCATION AUTOMOUNTMAP [options]``

Display an automount key.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``AUTOMOUNTMAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--key KEY``
     - Automount key name.
   * - ``--info INFO``
     - Mount information
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automountlocation-add:

automountlocation-add
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountlocation-add LOCATION [options]``

Create a new automount location.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOCATION``
     - yes
     - Automount location name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automountlocation-del:

automountlocation-del
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountlocation-del LOCATION [options]``

Delete an automount location.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOCATION``
     - yes
     - Automount location name.

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

.. _automountlocation-find:

automountlocation-find
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountlocation-find [CRITERIA] [options]``

Search for an automount location.

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
   * - ``--location LOCATION``
     - Automount location name.
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("location")

----

.. _automountlocation-show:

automountlocation-show
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountlocation-show LOCATION [options]``

Display an automount location.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOCATION``
     - yes
     - Automount location name.

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

----

.. _automountlocation-tofiles:

automountlocation-tofiles
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountlocation-tofiles LOCATION [options]``

Generate automount files for a specific location.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``LOCATION``
     - yes
     - Automount location name.

----

.. _automountmap-add:

automountmap-add
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountmap-add AUTOMOUNTLOCATION MAP [options]``

Create a new automount map.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``MAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automountmap-add-indirect:

automountmap-add-indirect
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountmap-add-indirect AUTOMOUNTLOCATION MAP [options]``

Create a new indirect mount point.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``MAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--mount MOUNT``
     - Mount point
   * - ``--parentmap PARENTMAP``
     - Name of parent automount map (default: auto.master).
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _automountmap-del:

automountmap-del
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountmap-del AUTOMOUNTLOCATION MAP [options]``

Delete an automount map.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``MAP``
     - yes
     - Automount map name.

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

.. _automountmap-find:

automountmap-find
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountmap-find AUTOMOUNTLOCATION [CRITERIA] [options]``

Search for an automount map.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
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
   * - ``--map MAP``
     - Automount map name.
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
     - Results should contain primary key attribute only ("map")

----

.. _automountmap-mod:

automountmap-mod
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountmap-mod AUTOMOUNTLOCATION MAP [options]``

Modify an automount map.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``MAP``
     - yes
     - Automount map name.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--desc DESC``
     - Description
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

.. _automountmap-show:

automountmap-show
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] automountmap-show AUTOMOUNTLOCATION MAP [options]``

Display an automount map.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``AUTOMOUNTLOCATION``
     - yes
     - Automount location name.
   * - ``MAP``
     - yes
     - Automount map name.

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

