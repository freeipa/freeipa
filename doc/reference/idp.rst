External Identity Provider References
=====================================

Manage External Identity Provider References.

IPA supports the use of an external Identity Provider for OAuth2.0 Device Flow
authentication.


**EXAMPLES**

 Add a new external Identity Provider reference:

 .. code-block:: console

    ipa idp-add MyIdP --client-id jhkQty13       --auth-uri https://oauth2.idp.com/auth       --token-uri https://oauth2.idp.com/token --secret

 Add a new external Identity Provider reference using github predefined

 endpoints:

 .. code-block:: console

    ipa idp-add MyIdp --client-id jhkQty13 --provider github --secret

 Find all external Identity Provider references whose entries include the string

 "test.com":

 .. code-block:: console

    ipa idp-find test.com

 Examine the configuration of an external Identity Provider reference:

 .. code-block:: console

    ipa idp-show MyIdP

 Change the secret:

 .. code-block:: console

    ipa idp-mod MyIdP --secret

 Delete an external Identity Provider reference:

 .. code-block:: console

    ipa idp-del MyIdP


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `idp-add`_
     - Add a new Identity Provider reference.
   * - `idp-del`_
     - Delete an Identity Provider reference.
   * - `idp-find`_
     - Search for Identity Provider references.
   * - `idp-mod`_
     - Modify an Identity Provider reference.
   * - `idp-show`_
     - Display information about an Identity Provider reference.

----

.. _idp-add:

idp-add
~~~~~~~

**Usage:** ``ipa [global-options] idp-add NAME [options]``

Add a new Identity Provider reference.

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
     - Identity Provider reference name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--auth-uri AUTH-URI``
     - OAuth 2.0 authorization endpoint
   * - ``--dev-auth-uri DEV-AUTH-URI``
     - Device authorization endpoint
   * - ``--token-uri TOKEN-URI``
     - Token endpoint
   * - ``--userinfo-uri USERINFO-URI``
     - User information endpoint
   * - ``--keys-uri KEYS-URI``
     - JWKS endpoint
   * - ``--issuer-url ISSUER-URL``
     - The Identity Provider OIDC URL
   * - ``--client-id CLIENT-ID``
     - OAuth 2.0 client identifier
   * - ``--secret SECRET``
     - OAuth 2.0 client secret
   * - ``--scope SCOPE``
     - OAuth 2.0 scope. Multiple scopes separated by space
   * - ``--idp-user-id IDP-USER-ID``
     - Attribute for user identity in OAuth 2.0 userinfo
   * - ``--setattr SETATTR``
     - Set an attribute to a name/value pair. Format is attr=value.
   * - ``--addattr ADDATTR``
     - Add an attribute/value pair. Format is attr=value. The attribute
   * - ``--provider PROVIDER``
     - Choose a pre-defined template to use
   * - ``--organization ORGANIZATION``
     - Organization ID or Realm name for IdP provider templates
   * - ``--base-url BASE-URL``
     - Base URL for IdP provider templates
   * - ``--all``
     - Retrieve and print all attributes from the server. Affects command output.
   * - ``--raw``
     - Print entries as stored on the server. Only affects output format.

----

.. _idp-del:

idp-del
~~~~~~~

**Usage:** ``ipa [global-options] idp-del NAME [options]``

Delete an Identity Provider reference.

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
     - Identity Provider reference name

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

.. _idp-find:

idp-find
~~~~~~~~

**Usage:** ``ipa [global-options] idp-find [CRITERIA] [options]``

Search for Identity Provider references.

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
     - Identity Provider reference name
   * - ``--auth-uri AUTH-URI``
     - OAuth 2.0 authorization endpoint
   * - ``--dev-auth-uri DEV-AUTH-URI``
     - Device authorization endpoint
   * - ``--token-uri TOKEN-URI``
     - Token endpoint
   * - ``--userinfo-uri USERINFO-URI``
     - User information endpoint
   * - ``--keys-uri KEYS-URI``
     - JWKS endpoint
   * - ``--issuer-url ISSUER-URL``
     - The Identity Provider OIDC URL
   * - ``--scope SCOPE``
     - OAuth 2.0 scope. Multiple scopes separated by space
   * - ``--idp-user-id IDP-USER-ID``
     - Attribute for user identity in OAuth 2.0 userinfo
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

.. _idp-mod:

idp-mod
~~~~~~~

**Usage:** ``ipa [global-options] idp-mod NAME [options]``

Modify an Identity Provider reference.

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
     - Identity Provider reference name

Options
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Description
   * - ``--auth-uri AUTH-URI``
     - OAuth 2.0 authorization endpoint
   * - ``--dev-auth-uri DEV-AUTH-URI``
     - Device authorization endpoint
   * - ``--token-uri TOKEN-URI``
     - Token endpoint
   * - ``--userinfo-uri USERINFO-URI``
     - User information endpoint
   * - ``--keys-uri KEYS-URI``
     - JWKS endpoint
   * - ``--issuer-url ISSUER-URL``
     - The Identity Provider OIDC URL
   * - ``--client-id CLIENT-ID``
     - OAuth 2.0 client identifier
   * - ``--secret SECRET``
     - OAuth 2.0 client secret
   * - ``--scope SCOPE``
     - OAuth 2.0 scope. Multiple scopes separated by space
   * - ``--idp-user-id IDP-USER-ID``
     - Attribute for user identity in OAuth 2.0 userinfo
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
   * - ``--rename RENAME``
     - Rename the Identity Provider reference object

----

.. _idp-show:

idp-show
~~~~~~~~

**Usage:** ``ipa [global-options] idp-show NAME [options]``

Display information about an Identity Provider reference.

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
     - Identity Provider reference name

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

