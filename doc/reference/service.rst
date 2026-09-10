Services
========

A IPA service represents a service that runs on a host. The IPA service
record can store a Kerberos principal, an SSL certificate, or both.

An IPA service can be managed directly from a machine, provided that
machine has been given the correct permission. This is true even for
machines other than the one the service is associated with. For example,
requesting an SSL certificate using the host service principal credentials
of the host. To manage a service using host credentials you need to
kinit as the host:

 # kinit -kt /etc/krb5.keytab host/ipa.example.com@EXAMPLE.COM

Adding an IPA service allows the associated service to request an SSL
certificate or keytab, but this is performed as a separate step; they
are not produced as a result of adding the service.

Only the public aspect of a certificate is stored in a service record;
the private key is not stored.


**EXAMPLES**

 Add a new IPA service:

 .. code-block:: console

    ipa service-add HTTP/web.example.com

 Allow a host to manage an IPA service certificate:

 .. code-block:: console

    ipa service-add-host --hosts=web.example.com HTTP/web.example.com
    ipa role-add-member --hosts=web.example.com certadmin

 Override a default list of supported PAC types for the service:

 .. code-block:: console

    ipa service-mod HTTP/web.example.com --pac-type=MS-PAC

    A typical use case where overriding the PAC type is needed is NFS.
    Currently the related code in the Linux kernel can only handle Kerberos
    tickets up to a maximal size. Since the PAC data can become quite large it
    is recommended to set --pac-type=NONE for NFS services.

 Delete an IPA service:

 .. code-block:: console

    ipa service-del HTTP/web.example.com

 Find all IPA services associated with a host:

 .. code-block:: console

    ipa service-find web.example.com

 Find all HTTP services:

 .. code-block:: console

    ipa service-find HTTP

 Disable the service Kerberos key and SSL certificate:

 .. code-block:: console

    ipa service-disable HTTP/web.example.com

 Request a certificate for an IPA service:

 .. code-block:: console

    ipa cert-request --principal=HTTP/web.example.com example.csr

 Allow user to create a keytab:

 .. code-block:: console

    ipa service-allow-create-keytab HTTP/web.example.com --users=tuser1

 Generate and retrieve a keytab for an IPA service:

 .. code-block:: console

    ipa-getkeytab -s ipa.example.com -p HTTP/web.example.com -k /etc/httpd/httpd.keytab


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `service-add`_
     - Add a new IPA service.
   * - `service-add-cert`_
     - Add new certificates to a service
   * - `service-add-delegation`_
     - Add new resource delegation to a service
   * - `service-add-host`_
     - Add hosts that can manage this service.
   * - `service-add-principal`_
     - Add new principal alias to a service
   * - `service-add-smb`_
     - Add a new SMB service.
   * - `service-allow-add-delegation`_
     - Allow users, groups, hosts or host groups to handle a resource delegation of this service.
   * - `service-allow-create-keytab`_
     - Allow users, groups, hosts or host groups to create a keytab of this service.
   * - `service-allow-retrieve-keytab`_
     - Allow users, groups, hosts or host groups to retrieve a keytab of this service.
   * - `service-del`_
     - Delete an IPA service.
   * - `service-disable`_
     - Disable the Kerberos key and SSL certificate of a service.
   * - `service-disallow-add-delegation`_
     - Disallow users, groups, hosts or host groups to handle a resource delegation of this service.
   * - `service-disallow-create-keytab`_
     - Disallow users, groups, hosts or host groups to create a keytab of this service.
   * - `service-disallow-retrieve-keytab`_
     - Disallow users, groups, hosts or host groups to retrieve a keytab of this service.
   * - `service-find`_
     - Search for IPA services.
   * - `service-mod`_
     - Modify an existing IPA service.
   * - `service-remove-cert`_
     - Remove certificates from a service
   * - `service-remove-delegation`_
     - Remove resource delegation from a service
   * - `service-remove-host`_
     - Remove hosts that can manage this service.
   * - `service-remove-principal`_
     - Remove principal alias from a service
   * - `service-show`_
     - Display information about an IPA service.

----

.. _service-add:

service-add
~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-add CANONICAL-PRINCIPAL [options]``

Add a new IPA service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded service certificate
   * - ``--pac-type PAC-TYPE``
     - Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service, e.g. this might be necessary for NFS services.
   * - ``--auth-ind AUTH-IND``
     - Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use 'pkinit' to allow PKINIT-based 2FA authentications. Use 'hardened' to allow brute-force hardened password authentication by SPAKE or FAST. Use 'idp' to allow authentication against an external Identity Provider supporting OAuth 2.0 Device Authorization Flow (RFC 8628). Use 'passkey' to allow passkey-based 2FA authentications. With no indicator specified, all authentication mechanisms are allowed.
   * - ``--requires-pre-auth REQUIRES-PRE-AUTH``
     - Pre-authentication is required for the service
   * - ``--ok-as-delegate OK-AS-DELEGATE``
     - Client credentials may be delegated to the service
   * - ``--ok-to-auth-as-delegate OK-TO-AUTH-AS-DELEGATE``
     - The service is allowed to authenticate on behalf of a client
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--force``
     - force principal name even if host not in DNS
   * - ``--skip-host-check``
     - force service to be created even when host object does not exist to manage it
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _service-add-cert:

service-add-cert
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-add-cert CANONICAL-PRINCIPAL [options]``

Add new certificates to a service

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded service certificate

----

.. _service-add-delegation:

service-add-delegation
~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-add-delegation CANONICAL-PRINCIPAL PRINCIPAL [options]``

Add new resource delegation to a service

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal
   * - ``PRINCIPAL``
     - yes
     - Delegation principal

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

----

.. _service-add-host:

service-add-host
~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-add-host CANONICAL-PRINCIPAL [options]``

Add hosts that can manage this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--hosts HOSTS``
     - hosts to add

----

.. _service-add-principal:

service-add-principal
~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-add-principal CANONICAL-PRINCIPAL PRINCIPAL [options]``

Add new principal alias to a service

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal
   * - ``PRINCIPAL``
     - yes
     - Service principal alias

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

----

.. _service-add-smb:

service-add-smb
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-add-smb HOSTNAME [NETBIOSNAME] [options]``

Add a new SMB service.

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
     - Host name
   * - ``NETBIOSNAME``
     - no
     - SMB service NetBIOS name

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
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded service certificate
   * - ``--ok-as-delegate OK-AS-DELEGATE``
     - Client credentials may be delegated to the service
   * - ``--ok-to-auth-as-delegate OK-TO-AUTH-AS-DELEGATE``
     - The service is allowed to authenticate on behalf of a client
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

----

.. _service-allow-add-delegation:

service-allow-add-delegation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-allow-add-delegation CANONICAL-PRINCIPAL [options]``

Allow users, groups, hosts or host groups to handle a resource delegation of this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--groups GROUPS``
     - groups to add
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _service-allow-create-keytab:

service-allow-create-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-allow-create-keytab CANONICAL-PRINCIPAL [options]``

Allow users, groups, hosts or host groups to create a keytab of this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--groups GROUPS``
     - groups to add
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _service-allow-retrieve-keytab:

service-allow-retrieve-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-allow-retrieve-keytab CANONICAL-PRINCIPAL [options]``

Allow users, groups, hosts or host groups to retrieve a keytab of this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--groups GROUPS``
     - groups to add
   * - ``--hosts HOSTS``
     - hosts to add
   * - ``--hostgroups HOSTGROUPS``
     - host groups to add

----

.. _service-del:

service-del
~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-del CANONICAL-PRINCIPAL [options]``

Delete an IPA service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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

.. _service-disable:

service-disable
~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-disable CANONICAL-PRINCIPAL [options]``

Disable the Kerberos key and SSL certificate of a service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

----

.. _service-disallow-add-delegation:

service-disallow-add-delegation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-disallow-add-delegation CANONICAL-PRINCIPAL [options]``

Disallow users, groups, hosts or host groups to handle a resource delegation of this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--groups GROUPS``
     - groups to remove
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _service-disallow-create-keytab:

service-disallow-create-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-disallow-create-keytab CANONICAL-PRINCIPAL [options]``

Disallow users, groups, hosts or host groups to create a keytab of this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--groups GROUPS``
     - groups to remove
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _service-disallow-retrieve-keytab:

service-disallow-retrieve-keytab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-disallow-retrieve-keytab CANONICAL-PRINCIPAL [options]``

Disallow users, groups, hosts or host groups to retrieve a keytab of this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--groups GROUPS``
     - groups to remove
   * - ``--hosts HOSTS``
     - hosts to remove
   * - ``--hostgroups HOSTGROUPS``
     - host groups to remove

----

.. _service-find:

service-find
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-find [CRITERIA] [options]``

Search for IPA services.

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
   * - ``--canonical-principal CANONICAL-PRINCIPAL``
     - Service principal
   * - ``--principal PRINCIPAL``
     - Service principal alias
   * - ``--pac-type PAC-TYPE``
     - Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service, e.g. this might be necessary for NFS services.
   * - ``--auth-ind AUTH-IND``
     - Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use 'pkinit' to allow PKINIT-based 2FA authentications. Use 'hardened' to allow brute-force hardened password authentication by SPAKE or FAST. Use 'idp' to allow authentication against an external Identity Provider supporting OAuth 2.0 Device Authorization Flow (RFC 8628). Use 'passkey' to allow passkey-based 2FA authentications. With no indicator specified, all authentication mechanisms are allowed.
   * - ``--timelimit TIMELIMIT``
     - Time limit of search in seconds (0 is unlimited)
   * - ``--sizelimit SIZELIMIT``
     - Maximum number of entries returned (0 is unlimited)
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--pkey-only``
     - Results should contain primary key attribute only ("canonical-principal")
   * - ``--man-by-hosts MAN-BY-HOSTS``
     - Search for services with these managed by hosts.
   * - ``--not-man-by-hosts NOT-MAN-BY-HOSTS``
     - Search for services without these managed by hosts.

----

.. _service-mod:

service-mod
~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-mod CANONICAL-PRINCIPAL [options]``

Modify an existing IPA service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--principal PRINCIPAL``
     - Service principal alias
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded service certificate
   * - ``--pac-type PAC-TYPE``
     - Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service, e.g. this might be necessary for NFS services.
   * - ``--auth-ind AUTH-IND``
     - Defines an allow list for Authentication Indicators. Use 'otp' to allow OTP-based 2FA authentications. Use 'radius' to allow RADIUS-based 2FA authentications. Use 'pkinit' to allow PKINIT-based 2FA authentications. Use 'hardened' to allow brute-force hardened password authentication by SPAKE or FAST. Use 'idp' to allow authentication against an external Identity Provider supporting OAuth 2.0 Device Authorization Flow (RFC 8628). Use 'passkey' to allow passkey-based 2FA authentications. With no indicator specified, all authentication mechanisms are allowed.
   * - ``--requires-pre-auth REQUIRES-PRE-AUTH``
     - Pre-authentication is required for the service
   * - ``--ok-as-delegate OK-AS-DELEGATE``
     - Client credentials may be delegated to the service
   * - ``--ok-to-auth-as-delegate OK-TO-AUTH-AS-DELEGATE``
     - The service is allowed to authenticate on behalf of a client
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

----

.. _service-remove-cert:

service-remove-cert
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-remove-cert CANONICAL-PRINCIPAL [options]``

Remove certificates from a service

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--certificate CERTIFICATE``
     - Base-64 encoded service certificate

----

.. _service-remove-delegation:

service-remove-delegation
~~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-remove-delegation CANONICAL-PRINCIPAL PRINCIPAL [options]``

Remove resource delegation from a service

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal
   * - ``PRINCIPAL``
     - yes
     - Delegation principal

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

----

.. _service-remove-host:

service-remove-host
~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-remove-host CANONICAL-PRINCIPAL [options]``

Remove hosts that can manage this service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

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
   * - ``--hosts HOSTS``
     - hosts to remove

----

.. _service-remove-principal:

service-remove-principal
~~~~~~~~~~~~~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-remove-principal CANONICAL-PRINCIPAL PRINCIPAL [options]``

Remove principal alias from a service

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal
   * - ``PRINCIPAL``
     - yes
     - Service principal alias

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

----

.. _service-show:

service-show
~~~~~~~~~~~~

**Usage:** ``ipa [global-options] service-show CANONICAL-PRINCIPAL [options]``

Display information about an IPA service.

Arguments
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Argument
     - Required
     - Description
   * - ``CANONICAL-PRINCIPAL``
     - yes
     - Service principal

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--rights``
     - Display the access rights of this entry (requires --all). See ipa man page for details.
   * - ``--out OUT``
     - file to store certificate in
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.
   * - ``--no-members``
     - Suppress processing of membership attributes.

