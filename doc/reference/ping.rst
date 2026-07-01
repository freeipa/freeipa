Ping the remote IPA server to ensure it is running.
===================================================

The ping command sends an echo request to an IPA server. The server
returns its version information. This is used by an IPA client
to confirm that the server is available and accepting requests.

The server from xmlrpc_uri in /etc/ipa/default.conf is contacted first.
If it does not respond then the client will contact any servers defined
by ldap SRV records in DNS.


**EXAMPLES**

 Ping an IPA server:

**ipa ping**


**IPA server version 2.1.9. API version 2.20**


 Ping an IPA server verbosely:

 .. code-block:: console

    ipa -v ping
    ipa: INFO: trying https://ipa.example.com/ipa/xml
    ipa: INFO: Forwarding 'ping' to server 'https://ipa.example.com/ipa/xml'
    -----------------------------------------------------
    IPA server version 2.1.9. API version 2.20
    -----------------------------------------------------


Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Description
   * - `ping`_
     - Ping a remote server.

----

.. _ping:

ping
~~~~

**Usage:** ``ipa [global-options] ping [options]``

Ping a remote server.

