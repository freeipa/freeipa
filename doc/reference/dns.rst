Domain Name System (DNS)
========================

Manage DNS zone and resource records.


**SUPPORTED ZONE TYPES**

 - Master zone (dnszone-\*), contains authoritative data.
 - Forward zone (dnsforwardzone-\*), forwards queries to configured forwarders
   (a set of DNS servers).


**USING STRUCTURED PER-TYPE OPTIONS**

There are many structured DNS RR types where DNS data stored in LDAP server
is not just a scalar value, for example an IP address or a domain name, but
a data structure which may be often complex. A good example is a LOC record
[RFC1876] which consists of many mandatory and optional parts (degrees,
minutes, seconds of latitude and longitude, altitude or precision).

It may be difficult to manipulate such DNS records without making a mistake
and entering an invalid value. DNS module provides an abstraction over these
raw records and allows to manipulate each RR type with specific options. For
each supported RR type, DNS module provides a standard option to manipulate
a raw records with format --<rrtype>-rec, e.g. --mx-rec, and special options
for every part of the RR structure with format --<rrtype>-<partname>, e.g.
--mx-preference and --mx-exchanger.

When adding a record, either RR specific options or standard option for a raw
value can be used, they just should not be combined in one add operation. When
modifying an existing entry, new RR specific options can be used to change
one part of a DNS record, where the standard option for raw value is used
to specify the modified value. The following example demonstrates
a modification of MX record preference from 0 to 1 in a record without
modifying the exchanger:
ipa ``dnsrecord-mod`` --mx-rec="0 mx.example.com." --mx-preference=1



**EXAMPLES**

 Add new zone:

 .. code-block:: console

    ipa dnszone-add example.com --admin-email=admin@example.com

 Add system permission that can be used for per-zone privilege delegation:

 .. code-block:: console

    ipa dnszone-add-permission example.com

 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:

 .. code-block:: console

    ipa dnszone-mod example.com --dynamic-update=TRUE

    This is the equivalent of:
      ipa dnszone-mod example.com --dynamic-update=TRUE \
       --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA; grant EXAMPLE.COM krb5-self * SSHFP;"

 Modify the zone to allow zone transfers for local network only:

 .. code-block:: console

    ipa dnszone-mod example.com --allow-transfer=192.0.2.0/24

 Add new reverse zone specified by network IP address:

 .. code-block:: console

    ipa dnszone-add --name-from-ip=192.0.2.0/24

 Add second nameserver for example.com:

 .. code-block:: console

    ipa dnsrecord-add example.com @ --ns-rec=nameserver2.example.com

 Add a mail server for example.com:

 .. code-block:: console

    ipa dnsrecord-add example.com @ --mx-rec="10 mail1"

 Add another record using MX record specific options:

  ipa ``dnsrecord-add`` example.com @ --mx-preference=20 --mx-exchanger=mail2

 Add another record using interactive mode (started when ``dnsrecord-add``, ``dnsrecord-mod``,

 or ``dnsrecord-del`` are executed with no options):

  ipa ``dnsrecord-add`` example.com @

  Please choose a type of DNS resource record to be added

  The most common types for this type of zone are: NS, MX, LOC

  DNS resource record type: MX

  MX Preference: 30

  MX Exchanger: mail3

  .. code-block:: console

      Record name: example.com
      MX record: 10 mail1, 20 mail2, 30 mail3
      NS record: nameserver.example.com., nameserver2.example.com.

 Delete previously added nameserver from example.com:

 .. code-block:: console

    ipa dnsrecord-del example.com @ --ns-rec=nameserver2.example.com.

 Add LOC record for example.com:

 .. code-block:: console

    ipa dnsrecord-add example.com @ --loc-rec="49 11 42.4 N 16 36 29.6 E 227.64m"

 Add new A record for www.example.com. Create a reverse record in appropriate

 reverse zone as well. In this case a PTR record "2" pointing to www.example.com

 will be created in zone 2.0.192.in-addr.arpa.

 .. code-block:: console

    ipa dnsrecord-add example.com www --a-rec=192.0.2.2 --a-create-reverse

 Add new PTR record for www.example.com

 .. code-block:: console

    ipa dnsrecord-add 2.0.192.in-addr.arpa. 2 --ptr-rec=www.example.com.

 Add new SRV records for LDAP servers. Three quarters of the requests

 should go to fast.example.com, one quarter to slow.example.com. If neither

 is available, switch to backup.example.com.

 .. code-block:: console

    ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 3 389 fast.example.com"
    ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 1 389 slow.example.com"
    ipa dnsrecord-add example.com _ldap._tcp --srv-rec="1 1 389 backup.example.com"

 The interactive mode can be used for easy modification:

  ipa ``dnsrecord-mod`` example.com _ldap._tcp

  No option to modify specific record provided.

  Current DNS record contents:

  SRV record: 0 3 389 fast.example.com, 0 1 389 slow.example.com, 1 1 389 backup.example.com

  Modify SRV record '0 3 389 fast.example.com'? Yes/No (default No):

  Modify SRV record '0 1 389 slow.example.com'? Yes/No (default No): y

  SRV Priority [0]:                     (keep the default value)

  SRV Weight [1]: 2                     (modified value)

  SRV Port [389]:                       (keep the default value)

  SRV Target [slow.example.com]:        (keep the default value)

  1 SRV record skipped. Only one value per DNS record type can be modified at one time.

  .. code-block:: console

      Record name: _ldap._tcp
      SRV record: 0 3 389 fast.example.com, 1 1 389 backup.example.com, 0 2 389 slow.example.com

 After this modification, three fifths of the requests should go to

 fast.example.com and two fifths to slow.example.com.

 An example of the interactive mode for ``dnsrecord-del`` command:

 .. code-block:: console

    ipa dnsrecord-del example.com www
    No option to delete specific record provided.
    Delete all? Yes/No (default No):     (do not delete all records)
    Current DNS record contents:

    A record: 192.0.2.2, 192.0.2.3

    Delete A record '192.0.2.2'? Yes/No (default No):
    Delete A record '192.0.2.3'? Yes/No (default No): y
      Record name: www
      A record: 192.0.2.2               (A record 192.0.2.3 has been deleted)

 Show zone example.com:

 .. code-block:: console

    ipa dnszone-show example.com

 Find zone with "example" in its domain name:

 .. code-block:: console

    ipa dnszone-find example

 Find records for resources with "www" in their name in zone example.com:

 .. code-block:: console

    ipa dnsrecord-find example.com www

 Find A records with value 192.0.2.2 in zone example.com

 .. code-block:: console

    ipa dnsrecord-find example.com --a-rec=192.0.2.2

 Show records for resource www in zone example.com

 .. code-block:: console

    ipa dnsrecord-show example.com www

 Delegate zone sub.example to another nameserver:

 .. code-block:: console

    ipa dnsrecord-add example.com ns.sub --a-rec=203.0.113.1
    ipa dnsrecord-add example.com sub --ns-rec=ns.sub.example.com.

 Delete zone example.com with all resource records:

 .. code-block:: console

    ipa dnszone-del example.com

 If a global forwarder is configured, all queries for which this server is not

 authoritative (e.g. sub.example.com) will be routed to the global forwarder.

 Global forwarding configuration can be overridden per-zone.

 Semantics of forwarding in IPA matches BIND semantics and depends on the type

 of zone:

   - Master zone: local BIND replies authoritatively to queries for data in

 .. code-block:: console

    the given zone (including authoritative NXDOMAIN answers) and forwarding
    affects only queries for names below zone cuts (NS records) of locally
    served zones.

    * Forward zone: forward zone contains no authoritative data. BIND forwards
    queries, which cannot be answered from its local cache, to configured
    forwarders.

 Semantics of the --forward-policy option:
   - none - disable forwarding for the given zone.
   - first - forward all queries to configured forwarders. If they fail,

 .. code-block:: console

    do resolution using DNS root servers.
    * only - forward all queries to configured forwarders and if they fail,
    return failure.

 Disable global forwarding for given sub-tree:

 .. code-block:: console

    ipa dnszone-mod example.com --forward-policy=none

 This configuration forwards all queries for names outside the example.com
 sub-tree to global forwarders. Normal recursive resolution process is used
 for names inside the example.com sub-tree (i.e. NS records are followed etc.).

 Forward all requests for the zone external.example.com to another forwarder

 using a "first" policy (it will send the queries to the selected forwarder

 and if not answered it will use global root servers):

 .. code-block:: console

    ipa dnsforwardzone-add external.example.com --forward-policy=first \
                                --forwarder=203.0.113.1

 Change forward-policy for external.example.com:

 .. code-block:: console

    ipa dnsforwardzone-mod external.example.com --forward-policy=only

 Show forward zone external.example.com:

 .. code-block:: console

    ipa dnsforwardzone-show external.example.com

 List all forward zones:

 .. code-block:: console

    ipa dnsforwardzone-find

 Delete forward zone external.example.com:

 .. code-block:: console

    ipa dnsforwardzone-del external.example.com

 Resolve a host name to see if it exists (will add default IPA domain

 if one is not included):

 .. code-block:: console

    ipa dns-resolve www.example.com
    ipa dns-resolve www


**GLOBAL DNS CONFIGURATION**

DNS configuration passed to command line install script is stored in a local
configuration file on each IPA server where DNS service is configured. These
local settings can be overridden with a common configuration stored in LDAP
server:

 Show global DNS configuration:

 .. code-block:: console

    ipa dnsconfig-show

 Modify global DNS configuration and set a list of global forwarders:

 .. code-block:: console

    ipa dnsconfig-mod --forwarder=203.0.113.113


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `dns-update-system-records`_
     - Update location and IPA server DNS records
   * - `dnsconfig-mod`_
     - Modify global DNS configuration.
   * - `dnsconfig-show`_
     - Show the current global DNS configuration.
   * - `dnsforwardzone-add`_
     - Create new DNS forward zone.
   * - `dnsforwardzone-add-permission`_
     - Add a permission for per-forward zone access delegation.
   * - `dnsforwardzone-del`_
     - Delete DNS forward zone.
   * - `dnsforwardzone-disable`_
     - Disable DNS Forward Zone.
   * - `dnsforwardzone-enable`_
     - Enable DNS Forward Zone.
   * - `dnsforwardzone-find`_
     - Search for DNS forward zones.
   * - `dnsforwardzone-mod`_
     - Modify DNS forward zone.
   * - `dnsforwardzone-remove-permission`_
     - Remove a permission for per-forward zone access delegation.
   * - `dnsforwardzone-show`_
     - Display information about a DNS forward zone.
   * - `dnsrecord-add`_
     - Add new DNS resource record.
   * - `dnsrecord-del`_
     - Delete DNS resource record.
   * - `dnsrecord-find`_
     - Search for DNS resources.
   * - `dnsrecord-mod`_
     - Modify a DNS resource record.
   * - `dnsrecord-show`_
     - Display DNS resource.
   * - `dnsserver-add`_
     - Add a new DNS server.
   * - `dnsserver-del`_
     - Delete a DNS server
   * - `dnsserver-find`_
     - Search for DNS servers.
   * - `dnsserver-mod`_
     - Modify DNS server configuration
   * - `dnsserver-show`_
     - Display configuration of a DNS server.
   * - `dnszone-add`_
     - Create new DNS zone (SOA record).
   * - `dnszone-add-permission`_
     - Add a permission for per-zone access delegation.
   * - `dnszone-del`_
     - Delete DNS zone (SOA record).
   * - `dnszone-disable`_
     - Disable DNS Zone.
   * - `dnszone-enable`_
     - Enable DNS Zone.
   * - `dnszone-find`_
     - Search for DNS zones (SOA records).
   * - `dnszone-mod`_
     - Modify DNS zone (SOA record).
   * - `dnszone-remove-permission`_
     - Remove a permission for per-zone access delegation.
   * - `dnszone-show`_
     - Display information about a DNS zone (SOA record).

----

.. _dns-update-system-records:

dns-update-system-records
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dns-update-system-records [options]``

Update location and IPA server DNS records

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--dry-run``
     - Do not update records only return expected records
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnsconfig-mod:

dnsconfig-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsconfig-mod [options]``

Modify global DNS configuration.

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--forwarder FORWARDER``
     - Global forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Global forwarding policy. Set to "none" to disable any configured global forwarders.
   * - ``--allow-sync-ptr ALLOW-SYNC-PTR``
     - Allow synchronization of forward (A, AAAA) and reverse (PTR) records
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

.. _dnsconfig-show:

dnsconfig-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsconfig-show [options]``

Show the current global DNS configuration.

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

.. _dnsforwardzone-add:

dnsforwardzone-add
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-add NAME [options]``

Create new DNS forward zone.

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
     - Zone name (FQDN)

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--name-from-ip NAME-FROM-IP``
     - IP network to create reverse zone name from
   * - ``--forwarder FORWARDER``
     - Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--skip-overlap-check``
     - Force DNS zone creation even if it will overlap with an existing zone.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnsforwardzone-add-permission:

dnsforwardzone-add-permission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-add-permission NAME [options]``

Add a permission for per-forward zone access delegation.

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
     - Zone name (FQDN)

----

.. _dnsforwardzone-del:

dnsforwardzone-del
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-del NAME [options]``

Delete DNS forward zone.

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
     - Zone name (FQDN)

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

.. _dnsforwardzone-disable:

dnsforwardzone-disable
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-disable NAME [options]``

Disable DNS Forward Zone.

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
     - Zone name (FQDN)

----

.. _dnsforwardzone-enable:

dnsforwardzone-enable
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-enable NAME [options]``

Enable DNS Forward Zone.

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
     - Zone name (FQDN)

----

.. _dnsforwardzone-find:

dnsforwardzone-find
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-find [CRITERIA] [options]``

Search for DNS forward zones.

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
     - Zone name (FQDN)
   * - ``--name-from-ip NAME-FROM-IP``
     - IP network to create reverse zone name from
   * - ``--zone-active ZONE-ACTIVE``
     - Is zone active?
   * - ``--forwarder FORWARDER``
     - Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
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

.. _dnsforwardzone-mod:

dnsforwardzone-mod
~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-mod NAME [options]``

Modify DNS forward zone.

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
     - Zone name (FQDN)

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--name-from-ip NAME-FROM-IP``
     - IP network to create reverse zone name from
   * - ``--forwarder FORWARDER``
     - Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
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

.. _dnsforwardzone-remove-permission:

dnsforwardzone-remove-permission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-remove-permission NAME [options]``

Remove a permission for per-forward zone access delegation.

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
     - Zone name (FQDN)

----

.. _dnsforwardzone-show:

dnsforwardzone-show
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsforwardzone-show NAME [options]``

Display information about a DNS forward zone.

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
     - Zone name (FQDN)

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

.. _dnsrecord-add:

dnsrecord-add
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsrecord-add DNSZONE NAME [options]``

Add new DNS resource record.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DNSZONE``
     - yes
     - Zone name (FQDN)
   * - ``NAME``
     - yes
     - Record name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--ttl TTL``
     - Time to live
   * - ``--a-rec A-REC``
     - Raw A records
   * - ``--a-ip-address A-IP-ADDRESS``
     - A IP Address
   * - ``--a-create-reverse``
     - Create reverse record for this IP Address
   * - ``--aaaa-rec AAAA-REC``
     - Raw AAAA records
   * - ``--aaaa-ip-address AAAA-IP-ADDRESS``
     - AAAA IP Address
   * - ``--aaaa-create-reverse``
     - Create reverse record for this IP Address
   * - ``--a6-rec A6-REC``
     - Raw A6 records
   * - ``--a6-data A6-DATA``
     - A6 Record data
   * - ``--afsdb-rec AFSDB-REC``
     - Raw AFSDB records
   * - ``--afsdb-subtype AFSDB-SUBTYPE``
     - AFSDB Subtype
   * - ``--afsdb-hostname AFSDB-HOSTNAME``
     - AFSDB Hostname
   * - ``--cert-rec CERT-REC``
     - Raw CERT records
   * - ``--cert-type CERT-TYPE``
     - CERT Certificate Type
   * - ``--cert-key-tag CERT-KEY-TAG``
     - CERT Key Tag
   * - ``--cert-algorithm CERT-ALGORITHM``
     - CERT Algorithm
   * - ``--cert-certificate-or-crl CERT-CERTIFICATE-OR-CRL``
     - CERT Certificate/CRL
   * - ``--cname-rec CNAME-REC``
     - Raw CNAME records
   * - ``--cname-hostname CNAME-HOSTNAME``
     - A hostname which this alias hostname points to
   * - ``--dlv-rec DLV-REC``
     - Raw DLV records
   * - ``--dlv-key-tag DLV-KEY-TAG``
     - DLV Key Tag
   * - ``--dlv-algorithm DLV-ALGORITHM``
     - DLV Algorithm
   * - ``--dlv-digest-type DLV-DIGEST-TYPE``
     - DLV Digest Type
   * - ``--dlv-digest DLV-DIGEST``
     - DLV Digest
   * - ``--dname-rec DNAME-REC``
     - Raw DNAME records
   * - ``--dname-target DNAME-TARGET``
     - DNAME Target
   * - ``--ds-rec DS-REC``
     - Raw DS records
   * - ``--ds-key-tag DS-KEY-TAG``
     - DS Key Tag
   * - ``--ds-algorithm DS-ALGORITHM``
     - DS Algorithm
   * - ``--ds-digest-type DS-DIGEST-TYPE``
     - DS Digest Type
   * - ``--ds-digest DS-DIGEST``
     - DS Digest
   * - ``--kx-rec KX-REC``
     - Raw KX records
   * - ``--kx-preference KX-PREFERENCE``
     - Preference given to this exchanger. Lower values are more preferred
   * - ``--kx-exchanger KX-EXCHANGER``
     - A host willing to act as a key exchanger
   * - ``--loc-rec LOC-REC``
     - Raw LOC records
   * - ``--loc-lat-deg LOC-LAT-DEG``
     - LOC Degrees Latitude
   * - ``--loc-lat-min LOC-LAT-MIN``
     - LOC Minutes Latitude
   * - ``--loc-lat-sec LOC-LAT-SEC``
     - LOC Seconds Latitude
   * - ``--loc-lat-dir LOC-LAT-DIR``
     - LOC Direction Latitude
   * - ``--loc-lon-deg LOC-LON-DEG``
     - LOC Degrees Longitude
   * - ``--loc-lon-min LOC-LON-MIN``
     - LOC Minutes Longitude
   * - ``--loc-lon-sec LOC-LON-SEC``
     - LOC Seconds Longitude
   * - ``--loc-lon-dir LOC-LON-DIR``
     - LOC Direction Longitude
   * - ``--loc-altitude LOC-ALTITUDE``
     - LOC Altitude
   * - ``--loc-size LOC-SIZE``
     - LOC Size
   * - ``--loc-h-precision LOC-H-PRECISION``
     - LOC Horizontal Precision
   * - ``--loc-v-precision LOC-V-PRECISION``
     - LOC Vertical Precision
   * - ``--mx-rec MX-REC``
     - Raw MX records
   * - ``--mx-preference MX-PREFERENCE``
     - Preference given to this exchanger. Lower values are more preferred
   * - ``--mx-exchanger MX-EXCHANGER``
     - A host willing to act as a mail exchanger
   * - ``--naptr-rec NAPTR-REC``
     - Raw NAPTR records
   * - ``--naptr-order NAPTR-ORDER``
     - NAPTR Order
   * - ``--naptr-preference NAPTR-PREFERENCE``
     - NAPTR Preference
   * - ``--naptr-flags NAPTR-FLAGS``
     - NAPTR Flags
   * - ``--naptr-service NAPTR-SERVICE``
     - NAPTR Service
   * - ``--naptr-regexp NAPTR-REGEXP``
     - NAPTR Regular Expression
   * - ``--naptr-replacement NAPTR-REPLACEMENT``
     - NAPTR Replacement
   * - ``--ns-rec NS-REC``
     - Raw NS records
   * - ``--ns-hostname NS-HOSTNAME``
     - NS Hostname
   * - ``--ptr-rec PTR-REC``
     - Raw PTR records
   * - ``--ptr-hostname PTR-HOSTNAME``
     - The hostname this reverse record points to
   * - ``--srv-rec SRV-REC``
     - Raw SRV records
   * - ``--srv-priority SRV-PRIORITY``
     - Lower number means higher priority. Clients will attempt to contact the server with the lowest-numbered priority they can reach.
   * - ``--srv-weight SRV-WEIGHT``
     - Relative weight for entries with the same priority.
   * - ``--srv-port SRV-PORT``
     - SRV Port
   * - ``--srv-target SRV-TARGET``
     - The domain name of the target host or '.' if the service is decidedly not available at this domain
   * - ``--sshfp-rec SSHFP-REC``
     - Raw SSHFP records
   * - ``--sshfp-algorithm SSHFP-ALGORITHM``
     - SSHFP Algorithm
   * - ``--sshfp-fp-type SSHFP-FP-TYPE``
     - SSHFP Fingerprint Type
   * - ``--sshfp-fingerprint SSHFP-FINGERPRINT``
     - SSHFP Fingerprint
   * - ``--tlsa-rec TLSA-REC``
     - Raw TLSA records
   * - ``--tlsa-cert-usage TLSA-CERT-USAGE``
     - TLSA Certificate Usage
   * - ``--tlsa-selector TLSA-SELECTOR``
     - TLSA Selector
   * - ``--tlsa-matching-type TLSA-MATCHING-TYPE``
     - TLSA Matching Type
   * - ``--tlsa-cert-association-data TLSA-CERT-ASSOCIATION-DATA``
     - TLSA Certificate Association Data
   * - ``--txt-rec TXT-REC``
     - Raw TXT records
   * - ``--txt-data TXT-DATA``
     - TXT Text Data
   * - ``--uri-rec URI-REC``
     - Raw URI records
   * - ``--uri-priority URI-PRIORITY``
     - Lower number means higher priority. Clients will attempt to contact the URI with the lowest-numbered priority they can reach.
   * - ``--uri-weight URI-WEIGHT``
     - Relative weight for entries with the same priority.
   * - ``--uri-target URI-TARGET``
     - Target Uniform Resource Identifier according to RFC 3986
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--force``
     - force NS record creation even if its hostname is not in DNS
   * - ``--structured``
     - Parse all raw DNS records and return them in a structured way
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnsrecord-del:

dnsrecord-del
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsrecord-del DNSZONE NAME [options]``

Delete DNS resource record.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DNSZONE``
     - yes
     - Zone name (FQDN)
   * - ``NAME``
     - yes
     - Record name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--ttl TTL``
     - Time to live
   * - ``--a-rec A-REC``
     - Raw A records
   * - ``--aaaa-rec AAAA-REC``
     - Raw AAAA records
   * - ``--a6-rec A6-REC``
     - Raw A6 records
   * - ``--afsdb-rec AFSDB-REC``
     - Raw AFSDB records
   * - ``--cert-rec CERT-REC``
     - Raw CERT records
   * - ``--cname-rec CNAME-REC``
     - Raw CNAME records
   * - ``--dlv-rec DLV-REC``
     - Raw DLV records
   * - ``--dname-rec DNAME-REC``
     - Raw DNAME records
   * - ``--ds-rec DS-REC``
     - Raw DS records
   * - ``--kx-rec KX-REC``
     - Raw KX records
   * - ``--loc-rec LOC-REC``
     - Raw LOC records
   * - ``--mx-rec MX-REC``
     - Raw MX records
   * - ``--naptr-rec NAPTR-REC``
     - Raw NAPTR records
   * - ``--ns-rec NS-REC``
     - Raw NS records
   * - ``--ptr-rec PTR-REC``
     - Raw PTR records
   * - ``--srv-rec SRV-REC``
     - Raw SRV records
   * - ``--sshfp-rec SSHFP-REC``
     - Raw SSHFP records
   * - ``--tlsa-rec TLSA-REC``
     - Raw TLSA records
   * - ``--txt-rec TXT-REC``
     - Raw TXT records
   * - ``--uri-rec URI-REC``
     - Raw URI records
   * - ``--del-all``
     - Delete all associated records
   * - ``--structured``
     - Parse all raw DNS records and return them in a structured way
   * - ``--raw``
     - <raw>

----

.. _dnsrecord-find:

dnsrecord-find
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsrecord-find DNSZONE [CRITERIA] [options]``

Search for DNS resources.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DNSZONE``
     - yes
     - Zone name (FQDN)
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
     - Record name
   * - ``--ttl TTL``
     - Time to live
   * - ``--a-rec A-REC``
     - Raw A records
   * - ``--aaaa-rec AAAA-REC``
     - Raw AAAA records
   * - ``--a6-rec A6-REC``
     - Raw A6 records
   * - ``--afsdb-rec AFSDB-REC``
     - Raw AFSDB records
   * - ``--cert-rec CERT-REC``
     - Raw CERT records
   * - ``--cname-rec CNAME-REC``
     - Raw CNAME records
   * - ``--dlv-rec DLV-REC``
     - Raw DLV records
   * - ``--dname-rec DNAME-REC``
     - Raw DNAME records
   * - ``--ds-rec DS-REC``
     - Raw DS records
   * - ``--kx-rec KX-REC``
     - Raw KX records
   * - ``--loc-rec LOC-REC``
     - Raw LOC records
   * - ``--mx-rec MX-REC``
     - Raw MX records
   * - ``--naptr-rec NAPTR-REC``
     - Raw NAPTR records
   * - ``--ns-rec NS-REC``
     - Raw NS records
   * - ``--ptr-rec PTR-REC``
     - Raw PTR records
   * - ``--srv-rec SRV-REC``
     - Raw SRV records
   * - ``--sshfp-rec SSHFP-REC``
     - Raw SSHFP records
   * - ``--tlsa-rec TLSA-REC``
     - Raw TLSA records
   * - ``--txt-rec TXT-REC``
     - Raw TXT records
   * - ``--uri-rec URI-REC``
     - Raw URI records
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--structured``
     - Parse all raw DNS records and return them in a structured way
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _dnsrecord-mod:

dnsrecord-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsrecord-mod DNSZONE NAME [options]``

Modify a DNS resource record.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DNSZONE``
     - yes
     - Zone name (FQDN)
   * - ``NAME``
     - yes
     - Record name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--ttl TTL``
     - Time to live
   * - ``--a-rec A-REC``
     - Raw A records
   * - ``--a-ip-address A-IP-ADDRESS``
     - A IP Address
   * - ``--aaaa-rec AAAA-REC``
     - Raw AAAA records
   * - ``--aaaa-ip-address AAAA-IP-ADDRESS``
     - AAAA IP Address
   * - ``--a6-rec A6-REC``
     - Raw A6 records
   * - ``--a6-data A6-DATA``
     - A6 Record data
   * - ``--afsdb-rec AFSDB-REC``
     - Raw AFSDB records
   * - ``--afsdb-subtype AFSDB-SUBTYPE``
     - AFSDB Subtype
   * - ``--afsdb-hostname AFSDB-HOSTNAME``
     - AFSDB Hostname
   * - ``--cert-rec CERT-REC``
     - Raw CERT records
   * - ``--cert-type CERT-TYPE``
     - CERT Certificate Type
   * - ``--cert-key-tag CERT-KEY-TAG``
     - CERT Key Tag
   * - ``--cert-algorithm CERT-ALGORITHM``
     - CERT Algorithm
   * - ``--cert-certificate-or-crl CERT-CERTIFICATE-OR-CRL``
     - CERT Certificate/CRL
   * - ``--cname-rec CNAME-REC``
     - Raw CNAME records
   * - ``--cname-hostname CNAME-HOSTNAME``
     - A hostname which this alias hostname points to
   * - ``--dlv-rec DLV-REC``
     - Raw DLV records
   * - ``--dlv-key-tag DLV-KEY-TAG``
     - DLV Key Tag
   * - ``--dlv-algorithm DLV-ALGORITHM``
     - DLV Algorithm
   * - ``--dlv-digest-type DLV-DIGEST-TYPE``
     - DLV Digest Type
   * - ``--dlv-digest DLV-DIGEST``
     - DLV Digest
   * - ``--dname-rec DNAME-REC``
     - Raw DNAME records
   * - ``--dname-target DNAME-TARGET``
     - DNAME Target
   * - ``--ds-rec DS-REC``
     - Raw DS records
   * - ``--ds-key-tag DS-KEY-TAG``
     - DS Key Tag
   * - ``--ds-algorithm DS-ALGORITHM``
     - DS Algorithm
   * - ``--ds-digest-type DS-DIGEST-TYPE``
     - DS Digest Type
   * - ``--ds-digest DS-DIGEST``
     - DS Digest
   * - ``--kx-rec KX-REC``
     - Raw KX records
   * - ``--kx-preference KX-PREFERENCE``
     - Preference given to this exchanger. Lower values are more preferred
   * - ``--kx-exchanger KX-EXCHANGER``
     - A host willing to act as a key exchanger
   * - ``--loc-rec LOC-REC``
     - Raw LOC records
   * - ``--loc-lat-deg LOC-LAT-DEG``
     - LOC Degrees Latitude
   * - ``--loc-lat-min LOC-LAT-MIN``
     - LOC Minutes Latitude
   * - ``--loc-lat-sec LOC-LAT-SEC``
     - LOC Seconds Latitude
   * - ``--loc-lat-dir LOC-LAT-DIR``
     - LOC Direction Latitude
   * - ``--loc-lon-deg LOC-LON-DEG``
     - LOC Degrees Longitude
   * - ``--loc-lon-min LOC-LON-MIN``
     - LOC Minutes Longitude
   * - ``--loc-lon-sec LOC-LON-SEC``
     - LOC Seconds Longitude
   * - ``--loc-lon-dir LOC-LON-DIR``
     - LOC Direction Longitude
   * - ``--loc-altitude LOC-ALTITUDE``
     - LOC Altitude
   * - ``--loc-size LOC-SIZE``
     - LOC Size
   * - ``--loc-h-precision LOC-H-PRECISION``
     - LOC Horizontal Precision
   * - ``--loc-v-precision LOC-V-PRECISION``
     - LOC Vertical Precision
   * - ``--mx-rec MX-REC``
     - Raw MX records
   * - ``--mx-preference MX-PREFERENCE``
     - Preference given to this exchanger. Lower values are more preferred
   * - ``--mx-exchanger MX-EXCHANGER``
     - A host willing to act as a mail exchanger
   * - ``--naptr-rec NAPTR-REC``
     - Raw NAPTR records
   * - ``--naptr-order NAPTR-ORDER``
     - NAPTR Order
   * - ``--naptr-preference NAPTR-PREFERENCE``
     - NAPTR Preference
   * - ``--naptr-flags NAPTR-FLAGS``
     - NAPTR Flags
   * - ``--naptr-service NAPTR-SERVICE``
     - NAPTR Service
   * - ``--naptr-regexp NAPTR-REGEXP``
     - NAPTR Regular Expression
   * - ``--naptr-replacement NAPTR-REPLACEMENT``
     - NAPTR Replacement
   * - ``--ns-rec NS-REC``
     - Raw NS records
   * - ``--ns-hostname NS-HOSTNAME``
     - NS Hostname
   * - ``--ptr-rec PTR-REC``
     - Raw PTR records
   * - ``--ptr-hostname PTR-HOSTNAME``
     - The hostname this reverse record points to
   * - ``--srv-rec SRV-REC``
     - Raw SRV records
   * - ``--srv-priority SRV-PRIORITY``
     - Lower number means higher priority. Clients will attempt to contact the server with the lowest-numbered priority they can reach.
   * - ``--srv-weight SRV-WEIGHT``
     - Relative weight for entries with the same priority.
   * - ``--srv-port SRV-PORT``
     - SRV Port
   * - ``--srv-target SRV-TARGET``
     - The domain name of the target host or '.' if the service is decidedly not available at this domain
   * - ``--sshfp-rec SSHFP-REC``
     - Raw SSHFP records
   * - ``--sshfp-algorithm SSHFP-ALGORITHM``
     - SSHFP Algorithm
   * - ``--sshfp-fp-type SSHFP-FP-TYPE``
     - SSHFP Fingerprint Type
   * - ``--sshfp-fingerprint SSHFP-FINGERPRINT``
     - SSHFP Fingerprint
   * - ``--tlsa-rec TLSA-REC``
     - Raw TLSA records
   * - ``--tlsa-cert-usage TLSA-CERT-USAGE``
     - TLSA Certificate Usage
   * - ``--tlsa-selector TLSA-SELECTOR``
     - TLSA Selector
   * - ``--tlsa-matching-type TLSA-MATCHING-TYPE``
     - TLSA Matching Type
   * - ``--tlsa-cert-association-data TLSA-CERT-ASSOCIATION-DATA``
     - TLSA Certificate Association Data
   * - ``--txt-rec TXT-REC``
     - Raw TXT records
   * - ``--txt-data TXT-DATA``
     - TXT Text Data
   * - ``--uri-rec URI-REC``
     - Raw URI records
   * - ``--uri-priority URI-PRIORITY``
     - Lower number means higher priority. Clients will attempt to contact the URI with the lowest-numbered priority they can reach.
   * - ``--uri-weight URI-WEIGHT``
     - Relative weight for entries with the same priority.
   * - ``--uri-target URI-TARGET``
     - Target Uniform Resource Identifier according to RFC 3986
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--structured``
     - Parse all raw DNS records and return them in a structured way
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--rename RENAME``
     - Rename the DNS resource record object

----

.. _dnsrecord-show:

dnsrecord-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsrecord-show DNSZONE NAME [options]``

Display DNS resource.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``DNSZONE``
     - yes
     - Zone name (FQDN)
   * - ``NAME``
     - yes
     - Record name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--structured``
     - Parse all raw DNS records and return them in a structured way
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnsserver-add:

dnsserver-add
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsserver-add HOSTNAME [options]``

Add a new DNS server.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - DNS Server name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--soa-mname-override SOA-MNAME-OVERRIDE``
     - SOA mname (authoritative server) override
   * - ``--forwarder FORWARDER``
     - Per-server forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-server conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnsserver-del:

dnsserver-del
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsserver-del HOSTNAME [options]``

Delete a DNS server

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - DNS Server name

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

.. _dnsserver-find:

dnsserver-find
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsserver-find [CRITERIA] [options]``

Search for DNS servers.

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
   * - ``--hostname HOSTNAME``
     - DNS Server name
   * - ``--soa-mname-override SOA-MNAME-OVERRIDE``
     - SOA mname (authoritative server) override
   * - ``--forwarder FORWARDER``
     - Per-server forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-server conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("hostname")

----

.. _dnsserver-mod:

dnsserver-mod
~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsserver-mod HOSTNAME [options]``

Modify DNS server configuration

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - DNS Server name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--soa-mname-override SOA-MNAME-OVERRIDE``
     - SOA mname (authoritative server) override
   * - ``--forwarder FORWARDER``
     - Per-server forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-server conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
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

.. _dnsserver-show:

dnsserver-show
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnsserver-show HOSTNAME [options]``

Display configuration of a DNS server.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``HOSTNAME``
     - yes
     - DNS Server name

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

.. _dnszone-add:

dnszone-add
~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-add NAME [options]``

Create new DNS zone (SOA record).

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
     - Zone name (FQDN)

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--name-from-ip NAME-FROM-IP``
     - IP network to create reverse zone name from
   * - ``--forwarder FORWARDER``
     - Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
   * - ``--name-server NAME-SERVER``
     - Authoritative nameserver domain name
   * - ``--admin-email ADMIN-EMAIL``
     - Administrator e-mail address
   * - ``--refresh REFRESH``
     - SOA record refresh time
   * - ``--retry RETRY``
     - SOA record retry time
   * - ``--expire EXPIRE``
     - SOA record expire time
   * - ``--minimum MINIMUM``
     - How long should negative responses be cached
   * - ``--ttl TTL``
     - Time to live for records at zone apex
   * - ``--default-ttl DEFAULT-TTL``
     - Time to live for records without explicit TTL definition
   * - ``--update-policy UPDATE-POLICY``
     - BIND update policy
   * - ``--dynamic-update DYNAMIC-UPDATE``
     - Allow dynamic updates.
   * - ``--allow-query ALLOW-QUERY``
     - Semicolon separated list of IP addresses or networks which are allowed to issue queries
   * - ``--allow-transfer ALLOW-TRANSFER``
     - Semicolon separated list of IP addresses or networks which are allowed to transfer the zone
   * - ``--allow-sync-ptr ALLOW-SYNC-PTR``
     - Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone
   * - ``--dnssec DNSSEC``
     - Allow inline DNSSEC signing of records in the zone
   * - ``--nsec3param-rec NSEC3PARAM-REC``
     - NSEC3PARAM record for zone in format: hash\_algorithm flags iterations salt
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--skip-overlap-check``
     - Force DNS zone creation even if it will overlap with an existing zone.
   * - ``--force``
     - Force DNS zone creation even if nameserver is not resolvable. (Deprecated)
   * - ``--skip-nameserver-check``
     - Force DNS zone creation even if nameserver is not resolvable.
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnszone-add-permission:

dnszone-add-permission
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-add-permission NAME [options]``

Add a permission for per-zone access delegation.

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
     - Zone name (FQDN)

----

.. _dnszone-del:

dnszone-del
~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-del NAME [options]``

Delete DNS zone (SOA record).

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
     - Zone name (FQDN)

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

.. _dnszone-disable:

dnszone-disable
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-disable NAME [options]``

Disable DNS Zone.

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
     - Zone name (FQDN)

----

.. _dnszone-enable:

dnszone-enable
~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-enable NAME [options]``

Enable DNS Zone.

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
     - Zone name (FQDN)

----

.. _dnszone-find:

dnszone-find
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-find [CRITERIA] [options]``

Search for DNS zones (SOA records).

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
     - Zone name (FQDN)
   * - ``--name-from-ip NAME-FROM-IP``
     - IP network to create reverse zone name from
   * - ``--zone-active ZONE-ACTIVE``
     - Is zone active?
   * - ``--forwarder FORWARDER``
     - Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
   * - ``--name-server NAME-SERVER``
     - Authoritative nameserver domain name
   * - ``--admin-email ADMIN-EMAIL``
     - Administrator e-mail address
   * - ``--refresh REFRESH``
     - SOA record refresh time
   * - ``--retry RETRY``
     - SOA record retry time
   * - ``--expire EXPIRE``
     - SOA record expire time
   * - ``--minimum MINIMUM``
     - How long should negative responses be cached
   * - ``--ttl TTL``
     - Time to live for records at zone apex
   * - ``--default-ttl DEFAULT-TTL``
     - Time to live for records without explicit TTL definition
   * - ``--update-policy UPDATE-POLICY``
     - BIND update policy
   * - ``--dynamic-update DYNAMIC-UPDATE``
     - Allow dynamic updates.
   * - ``--allow-query ALLOW-QUERY``
     - Semicolon separated list of IP addresses or networks which are allowed to issue queries
   * - ``--allow-transfer ALLOW-TRANSFER``
     - Semicolon separated list of IP addresses or networks which are allowed to transfer the zone
   * - ``--allow-sync-ptr ALLOW-SYNC-PTR``
     - Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone
   * - ``--dnssec DNSSEC``
     - Allow inline DNSSEC signing of records in the zone
   * - ``--nsec3param-rec NSEC3PARAM-REC``
     - NSEC3PARAM record for zone in format: hash\_algorithm flags iterations salt
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--forward-only``
     - Search for forward zones only
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("name")

----

.. _dnszone-mod:

dnszone-mod
~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-mod NAME [options]``

Modify DNS zone (SOA record).

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
     - Zone name (FQDN)

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--name-from-ip NAME-FROM-IP``
     - IP network to create reverse zone name from
   * - ``--forwarder FORWARDER``
     - Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP\_ADDRESS port PORT"
   * - ``--forward-policy FORWARD-POLICY``
     - Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.
   * - ``--name-server NAME-SERVER``
     - Authoritative nameserver domain name
   * - ``--admin-email ADMIN-EMAIL``
     - Administrator e-mail address
   * - ``--refresh REFRESH``
     - SOA record refresh time
   * - ``--retry RETRY``
     - SOA record retry time
   * - ``--expire EXPIRE``
     - SOA record expire time
   * - ``--minimum MINIMUM``
     - How long should negative responses be cached
   * - ``--ttl TTL``
     - Time to live for records at zone apex
   * - ``--default-ttl DEFAULT-TTL``
     - Time to live for records without explicit TTL definition
   * - ``--update-policy UPDATE-POLICY``
     - BIND update policy
   * - ``--dynamic-update DYNAMIC-UPDATE``
     - Allow dynamic updates.
   * - ``--allow-query ALLOW-QUERY``
     - Semicolon separated list of IP addresses or networks which are allowed to issue queries
   * - ``--allow-transfer ALLOW-TRANSFER``
     - Semicolon separated list of IP addresses or networks which are allowed to transfer the zone
   * - ``--allow-sync-ptr ALLOW-SYNC-PTR``
     - Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone
   * - ``--dnssec DNSSEC``
     - Allow inline DNSSEC signing of records in the zone
   * - ``--nsec3param-rec NSEC3PARAM-REC``
     - NSEC3PARAM record for zone in format: hash\_algorithm flags iterations salt
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--delattr DELATTR``
     - Delete an attribute/value pair. The option will be evaluated
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--force``
     - Force nameserver change even if nameserver not in DNS
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _dnszone-remove-permission:

dnszone-remove-permission
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-remove-permission NAME [options]``

Remove a permission for per-zone access delegation.

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
     - Zone name (FQDN)

----

.. _dnszone-show:

dnszone-show
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] dnszone-show NAME [options]``

Display information about a DNS zone (SOA record).

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
     - Zone name (FQDN)

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

