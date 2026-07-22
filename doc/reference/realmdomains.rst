Realm domains
=============

Manage the list of domains associated with IPA realm.

This list is useful for Domain Controllers from other realms which have
established trust with this IPA realm. They need the information to know
which request should be forwarded to KDC of this IPA realm.

Automatic management: a domain is automatically added to the realm domains
list when a new DNS Zone managed by IPA is created. Same applies for deletion.

Externally managed DNS: domains which are not managed in IPA server DNS
need to be manually added to the list using ipa ``realmdomains-mod`` command.


**EXAMPLES**

 Display the current list of realm domains:

 .. code-block:: console

    ipa realmdomains-show

 Replace the list of realm domains:

 .. code-block:: console

    ipa realmdomains-mod --domain=example.com
    ipa realmdomains-mod --domain={example1.com,example2.com,example3.com}

 Add a domain to the list of realm domains:

 .. code-block:: console

    ipa realmdomains-mod --add-domain=newdomain.com

 Delete a domain from the list of realm domains:

 .. code-block:: console

    ipa realmdomains-mod --del-domain=olddomain.com


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `realmdomains-mod`_
     - Modify realm domains
   * - `realmdomains-show`_
     - Display the list of realm domains.

----

.. _realmdomains-mod:

realmdomains-mod
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] realmdomains-mod [options]``

Modify realm domains


.. code-block:: console

    DNS check: When manually adding a domain to the list, a DNS check is
    performed by default. It ensures that the domain is associated with
    the IPA realm, by checking whether the domain has a _kerberos TXT record
    containing the IPA realm name. This check can be skipped by specifying
    --force option.

    Removal: when a realm domain which has a matching DNS zone managed by
    IPA is being removed, a corresponding _kerberos TXT record in the zone is
    removed automatically as well. Other records in the zone or the zone
    itself are not affected.


Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--domain DOMAIN``
     - Domain
   * - ``--add-domain ADD-DOMAIN``
     - Add domain
   * - ``--del-domain DEL-DOMAIN``
     - Delete domain
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--force``
     - Force adding domain even if not in DNS
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _realmdomains-show:

realmdomains-show
~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] realmdomains-show [options]``

Display the list of realm domains.

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

