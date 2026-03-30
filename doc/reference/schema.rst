API Schema
==========

Provides API introspection capabilities.


**EXAMPLES**

 Show ``user-find`` details:

 .. code-block:: console

    ipa command-show user-find

 Find ``user-find`` parameters:

 .. code-block:: console

    ipa param-find user-find


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `class-find`_
     - Search for classes.
   * - `class-show`_
     - Display information about a class.
   * - `command-find`_
     - Search for commands.
   * - `command-show`_
     - Display information about a command.
   * - `output-find`_
     - Search for command outputs.
   * - `output-show`_
     - Display information about a command output.
   * - `param-find`_
     - Search command parameters.
   * - `param-show`_
     - Display information about a command parameter.
   * - `topic-find`_
     - Search for help topics.
   * - `topic-show`_
     - Display information about a help topic.

----

.. _class-find:

class-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] class-find [CRITERIA] [options]``

Search for classes.

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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _class-show:

class-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] class-show FULL-NAME [options]``

Display information about a class.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``FULL-NAME``
     - yes
     - Full name

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

.. _command-find:

command-find
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] command-find [CRITERIA] [options]``

Search for commands.

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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _command-show:

command-show
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] command-show FULL-NAME [options]``

Display information about a command.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``FULL-NAME``
     - yes
     - Full name

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

.. _output-find:

output-find
~~~~~~~~~~~

**Usage:** ``ipa [global-options] output-find COMMAND [CRITERIA] [options]``

Search for command outputs.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``COMMAND``
     - yes
     - Full name
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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _output-show:

output-show
~~~~~~~~~~~

**Usage:** ``ipa [global-options] output-show COMMAND NAME [options]``

Display information about a command output.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``COMMAND``
     - yes
     - Full name
   * - ``NAME``
     - yes
     - Name

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

.. _param-find:

param-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] param-find METAOBJECT [CRITERIA] [options]``

Search command parameters.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``METAOBJECT``
     - yes
     - Full name
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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _param-show:

param-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] param-show METAOBJECT NAME [options]``

Display information about a command parameter.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``METAOBJECT``
     - yes
     - Full name
   * - ``NAME``
     - yes
     - Name

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

.. _topic-find:

topic-find
~~~~~~~~~~

**Usage:** ``ipa [global-options] topic-find [CRITERIA] [options]``

Search for help topics.

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
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _topic-show:

topic-show
~~~~~~~~~~

**Usage:** ``ipa [global-options] topic-show FULL-NAME [options]``

Display information about a help topic.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``FULL-NAME``
     - yes
     - Full name

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

