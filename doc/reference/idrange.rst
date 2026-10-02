ID ranges
=========

Manage ID ranges  used to map Posix IDs to SIDs and back.

There are two type of ID ranges which are both handled by this utility:

 - the ID ranges of the local domain
 - the ID ranges of trusted remote domains

Both types have the following attributes in common:

 - base-id: the first ID of the Posix ID range
 - range-size: the size of the range

With those two attributes a range object can reserve the Posix IDs starting
with base-id up to but not including base-id+range-size exclusively.

Additionally an ID range of the local domain must set

 - rid-base: the first RID(*) of the corresponding RID range
 - secondary-rid-base: first RID of the secondary RID range

If the server is updated from a previous version and defines local ID ranges
missing the rid-base and secondary-rid-base, it is recommended to use
`ipa-idrange-fix` command to identify the missing values and fix the ID ranges.

and an ID range of a trusted domain must set

 - rid-base: the first RID of the corresponding RID range
 - sid: domain SID of the trusted domain

and an ID range of a trusted domain may set

 - auto-private-groups: [true|false|hybrid] automatic creation of private groups



EXAMPLE: Add a new ID range for a trusted domain

Since there might be more than one trusted domain the domain SID must be given
while creating the ID range.

  ipa ``idrange-add`` --base-id=1200000 --range-size=200000 --rid-base=0 \

  .. code-block:: console

                    --dom-sid=S-1-5-21-123-456-789 trusted_dom_range

This ID range is then used by the IPA server and the SSSD IPA provider to
assign Posix UIDs to users from the trusted domain.

If e.g. a range for a trusted domain is configured with the following values:

 base-id = 1200000

 range-size = 200000

 rid-base = 0

the RIDs 0 to 199999 are mapped to the Posix ID from 1200000 to 13999999. So
RID 1000 <-> Posix ID 1201000



EXAMPLE: Add a new ID range for the local domain

To create an ID range for the local domain it is not necessary to specify a
domain SID. But since it is possible that a user and a group can have the same
value as Posix ID a second RID interval is needed to handle conflicts.

  ipa ``idrange-add`` --base-id=1200000 --range-size=200000 --rid-base=1000 \

  .. code-block:: console

                    --secondary-rid-base=1000000 local_range

The data from the ID ranges of the local domain are used by the IPA server
internally to assign SIDs to IPA users and groups. The SID will then be stored
in the user or group objects.

If e.g. the ID range for the local domain is configured with the values from
the example above then a new user with the UID 1200007 will get the RID 1007.
If this RID is already used by a group the RID will be 1000007. This can only
happen if a user or a group object was created with a fixed ID because the
automatic assignment will not assign the same ID twice. Since there are only
users and groups sharing the same ID namespace it is sufficient to have only
one fallback range to handle conflicts.

To find the Posix ID for a given RID from the local domain it has to be
checked first if the RID falls in the primary or secondary RID range and
the rid-base or the secondary-rid-base has to be subtracted, respectively,
and the base-id has to be added to get the Posix ID.

Typically the creation of ID ranges happens behind the scenes and this CLI
must not be used at all. The ID range for the local domain will be created
during installation or upgrade from an older version. The ID range for a
trusted domain will be created together with the trust by 'ipa ``trust-add`` ...'.


**USE CASES**

  Add an ID range from a transitively trusted domain


  .. code-block:: console

      If the trusted domain (A) trusts another domain (B) as well and this trust
      is transitive 'ipa trust-add domain-A' will only create a range for
      domain A.  The ID range for domain B must be added manually.

  Add an additional ID range for the local domain


  .. code-block:: console

      If the ID range of the local domain is exhausted, i.e. no new IDs can be
      assigned to Posix users or groups by the DNA plugin, a new range has to be
      created to allow new users and groups to be added. (Currently there is no
      connection between this range CLI and the DNA plugin, but a future version
      might be able to modify the configuration of the DNS plugin as well)

In general it is not necessary to modify or delete ID ranges. If there is no
other way to achieve a certain configuration than to modify or delete an ID
range it should be done with great care. Because UIDs are stored in the file
system and are used for access control it might be possible that users are
allowed to access files of other users if an ID range got deleted and reused
for a different domain.

(*) The RID is typically the last integer of a user or group SID which follows
the domain SID. E.g. if the domain SID is S-1-5-21-123-456-789 and a user from
this domain has the SID S-1-5-21-123-456-789-1010 then 1010 is the RID of the
user. RIDs are unique in a domain, 32bit values and are used for users and
groups.


**WARNING**

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
local domain. Currently the DNA plugin *cannot* be reconfigured itself based
on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for
the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
modified to match the new range.


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `idrange-add`_
     - Add new ID range.
   * - `idrange-del`_
     - Delete an ID range.
   * - `idrange-find`_
     - Search for ranges.
   * - `idrange-mod`_
     - Modify ID range.
   * - `idrange-show`_
     - Display information about a range.

----

.. _idrange-add:

idrange-add
~~~~~~~~~~~

**Usage:** ``ipa [global-options] idrange-add NAME [options]``

Add new ID range.


.. code-block:: console

    To add a new ID range you always have to specify

        --base-id
        --range-size

    Additionally

        --rid-base
        --secondary-rid-base

    may be given for a new ID range for the local domain while

        --auto-private-groups

    may be given for a new ID range for a trusted AD domain and

        --rid-base
        --dom-sid

    must be given to add a new range for a trusted AD domain.


**WARNING**

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
local domain. Currently the DNA plugin *cannot* be reconfigured itself based
on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for
the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
modified to match the new range.


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
     - Range name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--base-id BASE-ID``
     - First Posix ID of the range
   * - ``--range-size RANGE-SIZE``
     - Number of IDs in the range
   * - ``--rid-base RID-BASE``
     - First RID of the corresponding RID range
   * - ``--secondary-rid-base SECONDARY-RID-BASE``
     - First RID of the secondary RID range
   * - ``--dom-sid DOM-SID``
     - Domain SID of the trusted domain
   * - ``--dom-name DOM-NAME``
     - Name of the trusted domain
   * - ``--type TYPE``
     - ID range type, one of allowed values
   * - ``--auto-private-groups AUTO-PRIVATE-GROUPS``
     - Auto creation of private groups, one of allowed values
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _idrange-del:

idrange-del
~~~~~~~~~~~

**Usage:** ``ipa [global-options] idrange-del NAME [options]``

Delete an ID range.

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
     - Range name

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

.. _idrange-find:

idrange-find
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idrange-find [CRITERIA] [options]``

Search for ranges.

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
     - Range name
   * - ``--base-id BASE-ID``
     - First Posix ID of the range
   * - ``--range-size RANGE-SIZE``
     - Number of IDs in the range
   * - ``--rid-base RID-BASE``
     - First RID of the corresponding RID range
   * - ``--secondary-rid-base SECONDARY-RID-BASE``
     - First RID of the secondary RID range
   * - ``--dom-sid DOM-SID``
     - Domain SID of the trusted domain
   * - ``--type TYPE``
     - ID range type, one of allowed values
   * - ``--auto-private-groups AUTO-PRIVATE-GROUPS``
     - Auto creation of private groups, one of allowed values
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

.. _idrange-mod:

idrange-mod
~~~~~~~~~~~

**Usage:** ``ipa [global-options] idrange-mod NAME [options]``

Modify ID range.


**WARNING**

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
local domain. Currently the DNA plugin *cannot* be reconfigured itself based
on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for
the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
modified to match the new range.


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
     - Range name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--base-id BASE-ID``
     - First Posix ID of the range
   * - ``--range-size RANGE-SIZE``
     - Number of IDs in the range
   * - ``--rid-base RID-BASE``
     - First RID of the corresponding RID range
   * - ``--secondary-rid-base SECONDARY-RID-BASE``
     - First RID of the secondary RID range
   * - ``--auto-private-groups AUTO-PRIVATE-GROUPS``
     - Auto creation of private groups, one of allowed values
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

.. _idrange-show:

idrange-show
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] idrange-show NAME [options]``

Display information about a range.

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
     - Range name

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

