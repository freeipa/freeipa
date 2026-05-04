Topology
========

Management of a replication topology at domain level 1.

IPA server's data is stored in LDAP server in two suffixes:

- domain suffix, e.g., 'dc=example,dc=com', contains all domain related data
- ca suffix, 'o=ipaca', is present only on server with CA installed. It
  contains data for Certificate Server component

Data stored on IPA servers is replicated to other IPA servers. The way it is
replicated is defined by replication agreements. Replication agreements needs
to be set for both suffixes separately. On domain level 0 they are managed
using ipa-replica-manage and ipa-csreplica-manage tools. With domain level 1
they are managed centrally using `ipa topology*` commands.

Agreements are represented by topology segments. By default topology segment
represents 2 replication agreements - one for each direction, e.g., A to B and
B to A. Creation of unidirectional segments is not allowed.

To verify that no server is disconnected in the topology of the given suffix,
use:

  ipa ``topologysuffix-verify`` $suffix


Examples:

  Find all IPA servers:

  .. code-block:: console

      ipa server-find

  Find all suffixes:

  .. code-block:: console

      ipa topologysuffix-find

  Add topology segment to 'domain' suffix:

  .. code-block:: console

      ipa topologysegment-add domain --left IPA_SERVER_A --right IPA_SERVER_B

  Add topology segment to 'ca' suffix:

  .. code-block:: console

      ipa topologysegment-add ca --left IPA_SERVER_A --right IPA_SERVER_B

  List all topology segments in 'domain' suffix:

  .. code-block:: console

      ipa topologysegment-find domain

  List all topology segments in 'ca' suffix:

  .. code-block:: console

      ipa topologysegment-find ca

  Delete topology segment in 'domain' suffix:

  .. code-block:: console

      ipa topologysegment-del domain segment_name

  Delete topology segment in 'ca' suffix:

  .. code-block:: console

      ipa topologysegment-del ca segment_name

  Verify topology of 'domain' suffix:

  .. code-block:: console

      ipa topologysuffix-verify domain

  Verify topology of 'ca' suffix:

  .. code-block:: console

      ipa topologysuffix-verify ca


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `topologysegment-add`_
     - Add a new segment.
   * - `topologysegment-del`_
     - Delete a segment.
   * - `topologysegment-find`_
     - Search for topology segments.
   * - `topologysegment-mod`_
     - Modify a segment.
   * - `topologysegment-reinitialize`_
     - Request a full re-initialization of the node retrieving data from the other node.
   * - `topologysegment-show`_
     - Display a segment.
   * - `topologysuffix-find`_
     - Search for topology suffixes.
   * - `topologysuffix-show`_
     - Show managed suffix.
   * - `topologysuffix-verify`_
     - Verify replication topology for suffix.

----

.. _topologysegment-add:

topologysegment-add
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysegment-add TOPOLOGYSUFFIX NAME [options]``

Add a new segment.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TOPOLOGYSUFFIX``
     - yes
     - Suffix name
   * - ``NAME``
     - yes
     - Arbitrary string identifying the segment

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--leftnode LEFTNODE``
     - Left replication node - an IPA server
   * - ``--rightnode RIGHTNODE``
     - Right replication node - an IPA server
   * - ``--stripattrs STRIPATTRS``
     - A space separated list of attributes which are removed from replication updates.
   * - ``--replattrs REPLATTRS``
     - Attributes that are not replicated to a consumer server during a fractional update. E.g., \`(objectclass=\*) $ EXCLUDE accountlockout memberof
   * - ``--replattrstotal REPLATTRSTOTAL``
     - Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=\*) $ EXCLUDE accountlockout
   * - ``--timeout TIMEOUT``
     - Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _topologysegment-del:

topologysegment-del
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysegment-del TOPOLOGYSUFFIX NAME [options]``

Delete a segment.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TOPOLOGYSUFFIX``
     - yes
     - Suffix name
   * - ``NAME``
     - yes
     - Arbitrary string identifying the segment

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

.. _topologysegment-find:

topologysegment-find
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysegment-find TOPOLOGYSUFFIX [CRITERIA] [options]``

Search for topology segments.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TOPOLOGYSUFFIX``
     - yes
     - Suffix name
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
     - Arbitrary string identifying the segment
   * - ``--leftnode LEFTNODE``
     - Left replication node - an IPA server
   * - ``--rightnode RIGHTNODE``
     - Right replication node - an IPA server
   * - ``--stripattrs STRIPATTRS``
     - A space separated list of attributes which are removed from replication updates.
   * - ``--replattrs REPLATTRS``
     - Attributes that are not replicated to a consumer server during a fractional update. E.g., \`(objectclass=\*) $ EXCLUDE accountlockout memberof
   * - ``--replattrstotal REPLATTRSTOTAL``
     - Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=\*) $ EXCLUDE accountlockout
   * - ``--timeout TIMEOUT``
     - Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing
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

.. _topologysegment-mod:

topologysegment-mod
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysegment-mod TOPOLOGYSUFFIX NAME [options]``

Modify a segment.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TOPOLOGYSUFFIX``
     - yes
     - Suffix name
   * - ``NAME``
     - yes
     - Arbitrary string identifying the segment

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--stripattrs STRIPATTRS``
     - A space separated list of attributes which are removed from replication updates.
   * - ``--replattrs REPLATTRS``
     - Attributes that are not replicated to a consumer server during a fractional update. E.g., \`(objectclass=\*) $ EXCLUDE accountlockout memberof
   * - ``--replattrstotal REPLATTRSTOTAL``
     - Attributes that are not replicated to a consumer server during a total update. E.g. (objectclass=\*) $ EXCLUDE accountlockout
   * - ``--timeout TIMEOUT``
     - Number of seconds outbound LDAP operations waits for a response from the remote replica before timing out and failing
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

.. _topologysegment-reinitialize:

topologysegment-reinitialize
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysegment-reinitialize TOPOLOGYSUFFIX NAME [options]``

Request a full re-initialization of the node retrieving data from the other node.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TOPOLOGYSUFFIX``
     - yes
     - Suffix name
   * - ``NAME``
     - yes
     - Arbitrary string identifying the segment

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--left``
     - Initialize left node
   * - ``--right``
     - Initialize right node
   * - ``--stop``
     - Stop already started refresh of chosen node(s)

----

.. _topologysegment-show:

topologysegment-show
~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysegment-show TOPOLOGYSUFFIX NAME [options]``

Display a segment.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``TOPOLOGYSUFFIX``
     - yes
     - Suffix name
   * - ``NAME``
     - yes
     - Arbitrary string identifying the segment

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

.. _topologysuffix-find:

topologysuffix-find
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysuffix-find [CRITERIA] [options]``

Search for topology suffixes.

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
     - Suffix name
   * - ``--suffix-dn SUFFIX-DN``
     - Managed LDAP suffix DN
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

.. _topologysuffix-show:

topologysuffix-show
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysuffix-show NAME [options]``

Show managed suffix.

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
     - Suffix name

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

.. _topologysuffix-verify:

topologysuffix-verify
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] topologysuffix-verify NAME [options]``

Verify replication topology for suffix.

Checks done:

  1. check if a topology is not disconnected. In other words if there are
     replication paths between all servers.
  2. check if servers don't have more than the recommended number of
     replication agreements

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
     - Suffix name

