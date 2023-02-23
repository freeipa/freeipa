Unit 12: Authentication against external Identity Providers
===========================================================

**Prerequisites:**

- `Unit 11: Kerberos ticket policy <11-kerberos-ticket-policy.rst>`_

In this module you will explore how to manage use external OAuth 2.0 servers to
authorize issuance of Kerberos tickets in FreeIPA.

**Note:** To complete this module, FreeIPA-4.10 or later is needed.

Authentication using external Identity Providers
------------------------------------------------

It is possible to let FreeIPA to delegate authentication and authorization
process of issuing Kerberos tickets to an external entity. FreeIPA has been
supporting RADIUS server proxying for some time. This is exposed over
Kerberos with the help of 'otp' pre-authentication mechanism.

Configuration of the RADIUS proxy authentication is done in two steps: first,
create a RADIUS proxy object in FreeIPA and then associate the user account with
this RADIUS proxy object.

There is no specific requirement as to how RADIUS proxy actually authenticates
the user. It is left outside the FreeIPA scope. The connection to the RADIUS
server becomes critical and is important to protect.

This approach has been extended to allow FreeIPA to contact an OAuth 2.0
Authorization Server instead of RADIUS server. OAuth 2.0 authorization framework
is a modern way to delegate authorization decisions between loosely coupled
parties. It heavily relies on the ability to use HTTP redirects to guide a
user's browser to hop between OAuth 2.0 parties and reach the one that logs user
in and the one that authorizes the access.

Traditionally, it was hard to integrate with OAuth 2.0-enabled systems in POSIX
environment because there is no way to run a browser session from within the
shell or console. Most of OAuth 2.0 identity providers (IdP) heavily rely on
JavaScript and other modern browser features to provide an enhanced user
experience. Emulating the login pages as part of line- and packet-oriented SSH
protocol or console login script is not possible.

OAuth 2.0 Device Authorization Grant is defined in
`RFC 8628 <https://www.rfc-editor.org/rfc/rfc8628>`_ and allows devices that either
lack a browser or input constrained to obtain user authorization to access
protected resources. Instead of performing the authorization flow right at the
device where OAuth authorization grant is requested, a user would perform it at
a separate device that has required rich browsing or input capabilities.

Following figure demonstrates a generic device authorization flow:

.. uml::

  participant "End User at Browser"
  participant "Device Client"
  participant "Authorization Server"
  "Device Client" -> "Authorization Server": (A) Client Identifier
  "Authorization Server" -> "Device Client": (B) Device Code, User Code & Verification URI
  "Device Client" -> "End User at Browser": (C) User Code & Verification URI
  "End User at Browser" <-> "Authorization Server": (D) End user reviews authorization request
  "Device Client" -> "Authorization Server": (E) Polling with Device Code and Client Identifier
  "Authorization Server" -> "Device Client": (F) Access Token (& Optional Refresh Token)

FreeIPA implements a variation of this flow and hides it behind Kerberos KDC. A
special pre-authentication method in MIT Kerberos, ``idp`` is implemented in
SSSD 2.7.0 to facilitate the process outlined above.

Device authorization grant flow decouples the process into several steps:

- the device initiates OAuth 2.0 flow and receives a response from the
  Authorization Server that contains a special code and a link to a website user
  needs to visit to authorize the device;
- user opens this website somewhere else (mobile, desktop, etc) where a proper
  browser is available;
- user is asked to enter the special code;
- if needed, user would be asked login into an OAuth 2.0-based IdP;
- once logged in, IdP would ask user if they authorize this device to access
  certain user information;
- once the access request is granted, user comes back to the device's prompt and
  confirms it;
- the device at this point would poll OAuth 2.0 Authorization Server on whether
  it is allowed to access user information already.

Set up external IdP integration in FreeIPA
------------------------------------------

In order to perform OAuth 2.0 device authorization grant flow against an IdP, an
OAuth 2.0 client has to be registered with the IdP and a capability to allow the
device authorization grant has to be given to it. Not all IdPs support this
feature. Out of the known public ones, following IdPs do support device
authorization grant flow:

* Microsoft Identity Platform, including Azure AD
* Google
* Github
* Keycloak, including Red Hat SSO
* Okta

Many OAuth 2.0 platforms do not support device authorization grant flow and
cannot be directly enabled to operate with FreeIPA. However, one can always
chain (federate) IdPs. It means that, for example, one can deploy Keycloak
locally to allow users to sign in with identities from a different IdP. In that
case the local Keycloak instance would need to be registered as an OAuth 2.0
client with the remote IdP. Local Keycloak instance would then be registered
with IPA.

Setting up IdP references (OAuth 2.0 clients) in IPA can be done with ``ipa
idp-add`` command. The command accepts an option to specify a pre-defined
template for one of the known IdPs. If none of the pre-defined templates is
suitable, individual parameters can also be added::

  ipa help idp-add
  Usage: ipa [global-options] idp-add NAME [options]

  Add a new Identity Provider reference.
  Options:
    -h, --help            show this help message and exit
    --auth-uri=STR        OAuth 2.0 authorization endpoint
    --dev-auth-uri=STR    Device authorization endpoint
    --token-uri=STR       Token endpoint
    --userinfo-uri=STR    User information endpoint
    --keys-uri=STR        JWKS endpoint
    --issuer-url=STR      The Identity Provider OIDC URL
    --client-id=STR       OAuth 2.0 client identifier
    --secret              OAuth 2.0 client secret
    --scope=STR           OAuth 2.0 scope. Multiple scopes separated by space
    --idp-user-id=STR     Attribute for user identity in OAuth 2.0 userinfo
    --setattr=STR         Set an attribute to a name/value pair. Format is
                          attr=value. For multi-valued attributes, the command
                          replaces the values already present.
    --addattr=STR         Add an attribute/value pair. Format is attr=value. The
                          attribute must be part of the schema.
    --provider=['google', 'github', 'microsoft', 'okta', 'keycloak']
                          Choose a pre-defined template to use
    --organization=STR    Organization ID or Realm name for IdP provider
                          templates
    --base-url=STR        Base URL for IdP provider templates
    --all                 Retrieve and print all attributes from the server.
                          Affects command output.
    --raw                 Print entries as stored on the server. Only affects
                          output format.

In this part we would use Keycloak IdP to integrate with IPA. Next section shows
how to set up Keycloak on a host enrolled into IPA domain. All shell scripts
below assume execution under ``root`` privileges.

Set up Keycloak IdP on enrolled IPA client
------------------------------------------

In this section, we set up `Keycloak <https://www.keycloak.org>`_ IdP on IPA
client and use it to authenticate IPA users. User database in Keycloak would be
different from the one in IPA, one would need to keep user accounts duplicated
in both places but this would simplify our configuration. We also would use
automation provided by the Keycloak to set up OAuth 2.0 clients and user
accounts.

First, we would download keycloak and unpack it into ``/opt/keycloak-<VERSION>`` as ``root``::

  [root@client ~]# dnf -y install java-11-openjdk-headless openssl

  #### download keycloak ####
  [root@client ~]# export KEYCLOAK_VERSION=18.0.0
  [root@client ~]# wget https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz
  [root@client ~]# tar zxf keycloak-${KEYCLOAK_VERSION}.tar.gz -C /opt

  #### add keycloak system user/group and folder ####
  [root@client ~]# groupadd keycloak
  [root@client ~]# useradd -r -g keycloak -d /opt/keycloak-${KEYCLOAK_VERSION} keycloak
  [root@client ~]# chown -R keycloak:keycloak /opt/keycloak-${KEYCLOAK_VERSION}
  [root@client ~]# chmod o+x /opt/keycloak-${KEYCLOAK_VERSION}/bin/

  [root@client ~]# restorecon -R /opt/keycloak-${KEYCLOAK_VERSION}

Next step would be to prepare a TLS certificate to be used to protect HTTPS
connections in Keycloak. Since our system is already enrolled into IPA, we can
rely on two features:

* Enrolled IPA client has Kerberos host principal registered with keytab in ``/etc/krb5.keytab``
* Enrolled IPA client host Kerberos principal can manage Kerberos services on the same host

This means we can create ``HTTP/client...`` Kerberos service right from the IPA
client and use ``certmonger`` to issue TLS certificate for it. Certmonger would
automatically renew the certificate. The following sequence of commands
demonstrates how to achieve this, run as root::

  ########## setup TLS certificate using IPA CA ###############################
  [root@client ~]# kinit -k
  [root@client ~]# ipa service-add HTTP/$(hostname)
  [root@client ~]# ipa-getcert request -K HTTP/$(hostname) -D $(hostname) \
                      -o keycloak -O keycloak \
                      -m 0600 -M 0644 \
                      -k /etc/pki/tls/private/keycloak.key \
                      -f /etc/pki/tls/certs/keycloak.crt \
                      -w

  [root@client ~]# keytool -import \
      -keystore /etc/pki/tls/private/keycloak.store \
      -file /etc/ipa/ca.crt \
      -alias ipa_ca \
      -trustcacerts -storepass Secret123 -noprompt

  [root@client ~]# chown keycloak:keycloak /etc/pki/tls/private/keycloak.store

The private key for this certificate is stored in
``/etc/pki/tls/private/keycloak.key``, only accessible to the keycloak user.
Public part of the certificate is stored in ``/etc/pki/tls/certs/keycloak.crt``
and has permissions 0644.

We also import IPA CA's chain to a Java keystore that would be used by Keycloak,
stored at ``/etc/pki/tls/private/keycloak.store``.

Finally, we need to set up ``systemd`` service to run Keycloak::

  # Setup keycloak service and config files

  [root@client ~]# cat > /etc/sysconfig/keycloak <<EOF
  KEYCLOAK_ADMIN=admin
  KEYCLOAK_ADMIN_PASSWORD=Secret123
  #KC_LOG_LEVEL=debug
  KC_HOSTNAME=$(hostname):8443
  KC_HTTPS_CERTIFICATE_FILE=/etc/pki/tls/certs/keycloak.crt
  KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/pki/tls/private/keycloak.key
  KC_HTTPS_TRUST_STORE_FILE=/etc/pki/tls/private/keycloak.store
  KC_HTTPS_TRUST_STORE_PASSWORD=Secret123
  KC_HTTP_RELATIVE_PATH=/auth
  EOF

  [root@client ~]# cat > /etc/systemd/system/keycloak.service <<EOF
  [Unit]
  Description=Keycloak Server
  After=network.target

  [Service]
  Type=idle
  EnvironmentFile=/etc/sysconfig/keycloak

  User=keycloak
  Group=keycloak
  ExecStart=/opt/keycloak-${KEYCLOAK_VERSION}/bin/kc.sh start
  TimeoutStartSec=600
  TimeoutStopSec=600

  [Install]
  WantedBy=multi-user.target
  EOF

  [root@client ~]# systemctl daemon-reload


When ``systemd`` service is prepared, Keycloak needs to be initialized::

  [root@client ~]# su - keycloak -c '''
  export KEYCLOAK_ADMIN=admin
  export KEYCLOAK_ADMIN_PASSWORD=Secret123
  export KC_HOSTNAME=$(hostname):8443
  export KC_HTTPS_CERTIFICATE_FILE=/etc/pki/tls/certs/keycloak.crt
  export KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/pki/tls/private/keycloak.key
  export KC_HTTPS_TRUST_STORE_FILE=/etc/pki/tls/private/keycloak.store
  export KC_HTTPS_TRUST_STORE_PASSWORD=Secret123
  export KC_HTTP_RELATIVE_PATH=/auth
  /opt/keycloak-${KEYCLOAK_VERSION}/bin/kc.sh --verbose build
  '''

and can be started with the standard ``systemctl`` tool::

  [root@client ~]# systemctl start keycloak

  [root@client ~]# systemctl status --lines 3 --no-pager keycloak 
  ● keycloak.service - Keycloak Server
       Loaded: loaded (/etc/systemd/system/keycloak.service; disabled; vendor preset: disabled)
       Active: active (running) since Fri 2022-05-06 10:43:06 UTC; 9min ago
     Main PID: 27170 (java)
        Tasks: 37 (limit: 2318)
       Memory: 297.1M
          CPU: 25.560s
       CGroup: /system.slice/keycloak.service
               └─27170 java -Xms64m -Xmx512m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true -D…

  May 06 10:43:28 client.ipademo.local kc.sh[27170]: 2022-05-06 10:43:28,411 INFO  [io.quarkus] (main) Keycloak 18.0.0 on …0.0:8443
  May 06 10:43:28 client.ipademo.local kc.sh[27170]: 2022-05-06 10:43:28,412 INFO  [io.quarkus] (main) Profile prod activated.
  May 06 10:43:28 client.ipademo.local kc.sh[27170]: 2022-05-06 10:43:28,412 INFO  [io.quarkus] (main) Installed features: [agroal…
  Hint: Some lines were ellipsized, use -l to show in full.

Now we can use it for setting up users and OAuth 2.0 clients. There are two
handy scripts, ``kcadm.sh`` and ``kcreg.sh`` that allow to perform all
operations without visiting the Keycloak Web UI.

With ``kcadm.sh`` we login as admin and create user ``testuser1`` and set a password::

  [root@client ~]# /opt/keycloak-18.0.0/bin/kcadm.sh config truststore \
        --trustpass Secret123 \
        /etc/pki/tls/private/keycloak.store

  [root@client ~]# /opt/keycloak-18.0.0/bin/kcadm.sh config credentials \
        --server https://$(hostname):8443/auth/ \
        --realm master --user admin --password Secret123
  Logging into https://client.ipademo.local:8443/auth/ as user admin of realm master

  [root@client ~]# /opt/keycloak-18.0.0/bin/kcadm.sh create users \
        -r master \
        -s username=testuser1 -s enabled=true -s email=testuser1@ipademo.local
  Created new user with id 'd319b32a-4cea-43c5-8ef8-19b2b8418d0a'

  [root@client ~]# /opt/keycloak-18.0.0/bin/kcadm.sh set-password \
        -r master \
        --username testuser1 --new-password Secret123

With ``kcreg.sh`` we can create OAuth 2.0 client using a pre-defined template
that will include all parameters we need to allow OAuth 2.0 Device Authorization
Grant flow::

  [root@client ~]# /opt/keycloak-18.0.0/bin/kcreg.sh config credentials \
        --server https://$(hostname):8443/auth \
        --realm master --user admin --password Secret123

  [root@client ~]# cat >ipa_client.json <<EOF
  {
    "enabled" : true,
    "redirectUris" : [ "https://ipa-ca.$(hostname -d)/ipa/idp/*" ],
    "webOrigins" : [ "https://ipa-ca.$(hostname -d)" ],
    "protocol" : "openid-connect",
    "publicClient" : true,
    "attributes" : {
      "oauth2.device.authorization.grant.enabled" : "true",
      "oauth2.device.polling.interval": "5"
    }
  }
  EOF

  [root@client ~]# /opt/keycloak-18.0.0/bin/kcreg.sh create \
        -f ipa_client.json  \
        -s clientId=ipa_oidc_client

At this point, we have a Keycloak instance with a default ``master`` realm
(organization) and base URL ``https://$(hostname):8443/auth/``. In this realm we
have created ``testuser1`` user with a simple password. We also created OAuth
2.0 client ``ipa_oidc_client`` that is allowed to utilize OAuth 2.0 device
authorization grant flow. This client has no client secret ("public OAuth 2.0
client") associated. Confidential clients can also support device authorization
grant flows.

The client details include information about the redirect URIs. These are required
to specify for public OAuth 2.0 clients, but they aren't used for OAuth 2.0
device authorization grant flow.

Two attributes specified in the OAuth 2.0 client definition for Keycloak:

- ``oauth2.device.authorization.grant.enabled``, set to ``true``, allows OAuth 2.0
  device authorization grant processing,
- ``oauth2.device.polling.interval``, set to 5, defines the polling interval for
  the client to 5 seconds.

Keycloak 17.0.0 and 18.0.0 releases have a bug that sets default polling
interval to 600 seconds. This makes impossible actual polling process as the
lifespan of the device code is also set to 600 seconds. Keycloak's
[pull request 11893](https://github.com/keycloak/keycloak/pull/11893) needs
to be merged to fix the default settings.

Add IdP reference to IPA
------------------------

The following command adds IdP reference named ``keycloak`` as IPA administrator::

  [root@client ~]# kinit admin
  ..
  [root@client ~]# echo -e "Secret123\nSecret123" | \
  [root@client ~]# ipa idp-add keycloak --provider keycloak \
        --org master \
        --base-url https://client.ipademo.local:8443/auth \
        --client-id ipa_oidc_client \
        --secret
  -----------------------------------------
  Added Identity Provider reference "keycloak"
  -----------------------------------------
    Identity Provider reference name: keycloak
    Authorization URI: https://client.ipademo.local:8443/auth/realms/master/protocol/openid-connect/auth
    Device authorization URI: https://client.ipademo.local:8443/auth/realms/master/protocol/openid-connect/auth/device
    Token URI: https://client.ipademo.local:8443/auth/realms/master/protocol/openid-connect/token
    User info URI: https://client.ipademo.local:8443/auth/realms/master/protocol/openid-connect/userinfo
    Client identifier: ipa_oidc_client
    Secret: U2VjcmV0MTIz
    Scope: openid email
    External IdP user identifier attribute: email

The name for the IdP reference is only used to associate an IdP with users in
IPA. Option ``--provider keycloak`` allows us to fill-in pre-defined template
for Keycloak or Red Hat SSO IdPs. The template expects both Keycloak's realm
(``--org`` option) and a base URL (``--base-url`` option) because Keycloak is
typically deployed as a part of a larger solution. These options may not be
needed for other pre-defined templates like Google or Github.

Associate IdP reference with IPA user
-------------------------------------

While we have added ``testuser1`` to Keycloak instance, this user needs to exist
in IPA to be visible to all enrolled systems. Currently there is no good
solution to integrate between IPA and Keycloak to allow automatically propagate
changes between the two. For the purpose of this workshop we would create users
manually -- we already did that for Keycloak.

Create a user ``testuser1`` in IPA::

  [root@client ~]# ipa user-add testuser1 --first Test --last User1
  ----------------------
  Added user "testuser1"
  ----------------------
    User login: testuser1
    First name: Test
    Last name: User1
    Full name: Test User1
    Display name: Test User1
    Initials: TU
    Home directory: /home/testuser1
    GECOS: Test User1
    Login shell: /bin/sh
    Principal name: testuser1@ipademo.local
    Principal alias: testuser1@ipademo.local
    Email address: testuser1@ipademo.local
    UID: 35000003
    GID: 35000003
    Password: False
    Member of groups: ipausers
    Kerberos keys available: False

Once user is added, associate it with ``keycloak`` IdP reference we just
created. In order to allow user to login via IdP we need few conditions to be
satisfied:

* IdP reference defined for this IdP in IPA
* IdP reference associated with the user (``--idp`` option to ``ipa user-add``
  or ``ipa user-mod``)
* IdP identity for the user is set in the user entry (``--idp-user-id`` option
  to ``ipa user-add`` or ``ipa user-mod``)
* finally, user should be allowed to use ``idp`` user authentication method
  (``--user-auth-type=idp`` option to ``ipa user-add`` or ``ipa user-mod`` or
  ``idp`` method set globally)

We can set these options to ``testuser1`` with ``ipa user-mod`` command::

  [root@client ~]# ipa user-mod testuser1 --idp keycloak \
                         --idp-user-id testuser1@ipademo.local \
                         --user-auth-type=idp
  -------------------------
  Modified user "testuser1"
  -------------------------
    User login: testuser1
    First name: Test
    Last name: User1
    Home directory: /home/testuser1
    Login shell: /bin/sh
    Principal name: testuser1@ipademo.local
    Principal alias: testuser1@ipademo.local
    Email address: testuser1@ipademo.local
    UID: 35000003
    GID: 35000003
    User authentication types: idp
    External IdP configuration: keycloak
    External IdP user identifier: testuser1@ipademo.local
    Account disabled: False
    Password: False
    Member of groups: ipausers
    Kerberos keys available: False

As can be seen in the output, the account for ``testuser1`` has no password and
no Kerberos keys. It will not be able to authenticate to IPA services without
IdP's help.

Access IPA resources as an IdP user
-----------------------------------

There are two ways to trigger authentication and authorization of ``testuser1``
via our Keycloak IdP instance:

* obtain Kerberos ticket with ``kinit`` tool
* login to the target system via SSH or on the console

In order to obtain initial Kerberos ticket, we need to use ``kinit`` tool. SSSD
2.7.0 provides a special package ``sssd-idp`` which implements Kerberos
pre-authentication method ``idp``. When this package is installed, MIT Kerberos
configuration on the host is updated to automatically allow use of ``idp``
method. However, ``idp`` method requires use of FAST channel in order to provide
a secure connection between the Kerberos client and KDC. This is similar to
``otp`` pre-authentication method FreeIPA already provided for several years.
When IPA is deployed with integrated CA, IPA also provides a way to obtain a
special ticket, called Anonymous PKINIT, to use as a FAST channel factor.

Let's use Anonymous PKINIT to obtain a ticket and store it in the file
``./fast.ccache``. Then we can enable FAST channel with the use of ``-T`` option
for ``kinit`` tool::

  [root@client ~]# kinit -n -c ./fast.ccache
  [root@client ~]# kinit -T ./fast.ccache testuser1
  Authenticate at https://client.ipademo.local:8443/auth/realms/master/device?user_code=YHMQ-XKTL and press ENTER.:

The prompt indicates that ``idp`` method was chosen between the KDC and the
Kerberos client. When KDC received the initial ticket granting ticket request,
IPA database driver (KDB) performed an LDAP lookup of the Kerberos principal and
found out that ``testuser1@IPADEMO.LOCAL`` Kerberos principal has ``idp`` user
authentication type. This, in turn, activated KDC side of the ``idp``
pre-authentication method and led to a request to ``ipa-otpd`` daemon. Finally,
``ipa-otpd`` daemon asked ``oidc_child`` to request a device code authorization
grant from the IdP associated with the ``testuser1@IPADEMO.LOCAL`` principal.
The grant flow resulted in IdP returning a code and a message which was
propagated back to the Kerberos client and displayed by the client side of the
``idp`` pre-authentication method.

At this point we need to visit the page and authorize access to the information.
Once it is done, we complete the process by pressing ``<ENTER>`` key. If
authorization was granted, KDC will issue a Kerberos ticket to and it will be
stored in the credentials cache::

  [root@client ~]# klist
  Ticket cache: KCM:0:58420
  Default principal: testuser1@IPADEMO.LOCAL

  Valid starting     Expires            Service principal
  05/09/22 07:48:23  05/10/22 07:03:07  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL


Similar process happens when ``pam_sss`` PAM module is used, for example, to
authenticate and authorize access to PAM services. Applications which use PAM to
authenticate and authorize remote access can also benefit from the flow. For
example, SSH daemon can be configured with ``keyboard-interactive`` method which
will allow PAM authentication and authorization. As part of it, PAM messages
will be relayed to the SSH client and SSH client's user input will be sent back
to PAM::

  $ ssh testuser1@client.ipademo.local
  (testuser1@client.ipademo.local) Authenticate at https://client.ipademo.local:8443/auth/realms/master/device?user_code=XYFL-ROYR and press ENTER.
  Last login: Mon May  9 07:48:25 2022 from 10.0.190.227
  -sh-5.1$ klist
  Ticket cache: KCM:7800003:58420
  Default principal: testuser1@IPADEMO.LOCAL

  Valid starting     Expires            Service principal
  05/09/22 07:49:38  05/10/22 07:49:24  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL
  -sh-5.1$

Once initial Kerberos ticket is available, it can be used to perform normal IPA
operations:

- access IPA API with command line tool ``ipa`` or through a Web UI in a browser
- login to other systems with GSSAPI authentication
- access PAM services which use ``pam_sss_gss`` module in their PAM stack definitions

Direct authentication to Web UI with the help of OAuth 2.0 client is not implemented yet.

Troubleshooting IdP integration
-------------------------------

Communication with an IdP server happens on IPA server when KDC calls out to
``ipa-otpd`` daemon and ``ipa-otpd`` daemon launches ``oidc_child`` helper.
Journal logs for ``ipa-otpd`` can be checked with the ``journalctl`` tool.
``ipa-otpd`` processes start on demand and content from all sessions can be
captured with the following command::

  [root@master #] journalctl -u 'ipa-otpd@*'

The output would look similar to the following real world example::

  May 02 18:51:28 dc.ipa.test systemd[1]: Started ipa-otpd service (PID 1473660/UID 0).
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: LDAP: ldapi://%2Frun%2Fslapd-IPA-TEST.socket
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: request received
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: user query start
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: user query end: uid=ab,cn=users,cn=accounts,dc=ipa,dc=test
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: idp query start: cn=github,cn=idp,dc=ipa,dc=test
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: idp query end: github
  May 02 18:51:28 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: oauth2 start: Get device code
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: Received: [{"device_code":"f071833afe966eaf596d83646f55250cfdb57418","expires_in":899,"interval":5}
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: oauth2 {"verification_uri": "https://github.com/login/device", "user_code": "ECD3-4310"}
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: ]
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: sent: 0 data: 200
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: ..sent: 200 data: 200
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: ab@IPA.TEST: response sent: Access-Challenge
  May 02 18:51:29 dc.ipa.test ipa-otpd[1636136]: Socket closed, shutting down...

First part of the output until ``idp query start`` is similar to RADIUS proxy
operation. Unlike RADIUS proxy, in the case of IdP communication, ``ipa-otpd``
first receives an initial state from the ``oidc_child`` process and sends it
back to the KDC within a RADIUS packet with ``Access-Challenge`` message.

The state is then transferred to the Kerberos client and results in a message
that instructs to visit the verification URI and enter the code. Some IdPs also
return a complete message to show, like in the case of Keycloak in our examples
above.

Once the Kerberos client returns, another ``ipa-otpd`` call is performed,
this time to request an access token::

  May 02 18:51:50 dc.ipa.test systemd[1]: Started ipa-otpd service (PID 1473661/UID 0).
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: LDAP: ldapi://%2Frun%2Fslapd-IPA-TEST.socket
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: request received
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: user query start
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: user query end: uid=ab,cn=users,cn=accounts,dc=ipa,dc=test
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: idp query start: cn=github,cn=idp,dc=ipa,dc=test
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: idp query end: github
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: oauth2 start: Get access token
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: Received: [abbra]
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: sent: 0 data: 20
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: ..sent: 20 data: 20
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: ab@IPA.TEST: response sent: Access-Accept
  May 02 18:51:50 dc.ipa.test ipa-otpd[1636149]: Socket closed, shutting down...

An access token request followed by the request to obtain a user information.
The resource owner's subject then compared with the value set in the LDAP entry
for this Kerberos principal with the help of ``--idp-user-id`` option. Subject's
field name is chosen through the same option to the IdP reference. If the check
is successful, ``ipa-otpd`` sends a RADIUS packet with ``Access-Accept``
response code.

Communication performed by ``oidc_child`` is not included into the journal logs
by default. If there are issues in accessing IdPs, a special option can be added
to ``/etc/ipa/default.conf`` to increase log level of ``oidc_child`` output. By
default, it is 0 and could be any number between 0 and 10::

  [global]
  oidc_child_debug_level=10

A value greater than 6 would include debug output from the ``libcurl`` utility::

  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: oidc_child started.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Running with effective IDs: [0][0].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Running with real IDs [0][0].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: JSON device code: [{"device_code":"f071833afe966eaf596d83646f55250cfdb57418","expires_in":899,"interval":5}].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Result does not contain the 'user_code' string.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Result does not contain the 'verification_uri' string.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Result does not contain the 'verification_url' string.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Result does not contain the 'verification_uri_complete' string.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Result does not contain the 'message' string.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: device_code: [f071833afe966eaf596d83646f55250cfdb57418].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: expires_in: [899].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: interval: [5].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: POST data: [grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=some-client-id&device_code=f071833afe966eaf596d83646f55250cfdb57418].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *   Trying 140.82.121.3:443...
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Connected to github.com (140.82.121.3) port 443 (#0)
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * ALPN, offering h2
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * ALPN, offering http/1.1
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * successfully set certificate verify locations:
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  CAfile: /etc/pki/tls/certs/ca-bundle.crt
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  CApath: none
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (OUT), TLS handshake, Client hello (1):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Server hello (2):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Certificate (11):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, CERT verify (15):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Finished (20):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (OUT), TLS handshake, Finished (20):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * ALPN, server accepted to use h2
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Server certificate:
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  subject: C=US; ST=California; L=San Francisco; O=GitHub, Inc.; CN=github.com
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  start date: Mar 15 00:00:00 2022 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  expire date: Mar 15 23:59:59 2023 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  subjectAltName: host "github.com" matched cert's "github.com"
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  issuer: C=US; O=DigiCert Inc; CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  SSL certificate verify ok.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Using HTTP2, server supports multiplexing
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Connection state changed (HTTP/2 confirmed)
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Using Stream ID: 1 (easy handle 0x562cd1ee96e0)
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: > POST /login/oauth/access_token HTTP/2
                                                   Host: github.com
                                                   user-agent: SSSD oidc_child/0.0
                                                   accept: application/json
                                                   content-length: 139
                                                   content-type: application/x-www-form-urlencoded
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * We are completely uploaded and fine
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * old SSL session ID is stale, removing
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < HTTP/2 200
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < server: GitHub.com
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < date: Mon, 02 May 2022 18:51:50 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < content-type: application/json; charset=utf-8
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < vary: X-PJAX, X-PJAX-Container
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < permissions-policy: interest-cohort=()
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < etag: W/"some-e-tag-value"
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < cache-control: max-age=0, private, must-revalidate
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < strict-transport-security: max-age=31536000; includeSubdomains; preload
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-frame-options: deny
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-content-type-options: nosniff
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-xss-protection: 0
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < referrer-policy: origin-when-cross-origin, strict-origin-when-cross-origin
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < expect-ct: max-age=2592000, report-uri="https://api.github.com/_private/browser/errors"
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < content-security-policy: default-src 'none'; base-uri 'self'; block-all-mixed-content; child-src github.com/assets-cdn/worker/ gist.github.com/assets-cdn/worker/; connect-src 'self' uploads.git>
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < vary: Accept-Encoding, Accept, X-Requested-With
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-github-request-id: D1EA:541D:48A585:4BF8E5:62702846
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: <
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: {"access_token":"some-access-token","token_type":"bearer","scope":"user"}
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Connection #0 to host github.com left intact
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: Result does not contain the 'id_token' string.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: access_token: [some-access-token].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: id_token: [(null)].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *   Trying 140.82.121.6:443...
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Connected to api.github.com (140.82.121.6) port 443 (#0)
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * ALPN, offering h2
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * ALPN, offering http/1.1
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * successfully set certificate verify locations:
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  CAfile: /etc/pki/tls/certs/ca-bundle.crt
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  CApath: none
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (OUT), TLS handshake, Client hello (1):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Server hello (2):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Certificate (11):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, CERT verify (15):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Finished (20):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (OUT), TLS handshake, Finished (20):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * ALPN, server accepted to use h2
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Server certificate:
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  subject: C=US; ST=California; L=San Francisco; O=GitHub, Inc.; CN=*.github.com
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  start date: Mar 16 00:00:00 2022 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  expire date: Mar 16 23:59:59 2023 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  subjectAltName: host "api.github.com" matched cert's "*.github.com"
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  issuer: C=US; O=DigiCert Inc; CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: *  SSL certificate verify ok.
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Using HTTP2, server supports multiplexing
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Connection state changed (HTTP/2 confirmed)
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Server auth using Bearer with user ''
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Using Stream ID: 1 (easy handle 0x562cd1f92ae0)
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: > GET /user HTTP/2
                                                   Host: api.github.com
                                                   authorization: Bearer some-token-value
                                                   user-agent: SSSD oidc_child/0.0
                                                   accept: application/json
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * old SSL session ID is stale, removing
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < HTTP/2 200
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < server: GitHub.com
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < date: Mon, 02 May 2022 18:51:50 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < content-type: application/json; charset=utf-8
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < content-length: 1357
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < cache-control: private, max-age=60, s-maxage=60
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < vary: Accept, Authorization, Cookie, X-GitHub-OTP
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < etag: "some-e-tag-value"
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < last-modified: Mon, 14 Mar 2022 14:05:20 GMT
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-oauth-scopes: user
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-accepted-oauth-scopes:
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-oauth-client-id: some-client-id
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-github-media-type: github.v3
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-ratelimit-limit: 5000
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-ratelimit-remaining: 4996
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-ratelimit-reset: 1651520567
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-ratelimit-used: 4
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-ratelimit-resource: core
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < access-control-expose-headers: ETag, Link, Location, Retry-After, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Used, X-RateLimit-Resource, X-RateLimit-Reset, X-OAuth-Scop>
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < access-control-allow-origin: *
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < strict-transport-security: max-age=31536000; includeSubdomains; preload
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-frame-options: deny
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-content-type-options: nosniff
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-xss-protection: 0
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < referrer-policy: origin-when-cross-origin, strict-origin-when-cross-origin
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < content-security-policy: default-src 'none'
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < vary: Accept-Encoding, Accept, X-Requested-With
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: < x-github-request-id: C5B8:5B48:4C0EB7:4D8AF2:62702846
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: <
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: {"login":"abbra","id":some-id,"node_id":"some-node","avatar_url":"some-avatar-url","gravatar_id":"","url":"some-user-url","html_ur
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: l":"some-url","followers_url":"some-api-url","following_url":"some-following-url","gists_url":"some-gists-url>
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: libcurl: * Connection #0 to host api.github.com left intact
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: userinfo: [{"login": "abbra", "id": some-id, "node_id": "some-node", "avatar_url": "some-avatar-rul", "gravatar_id": "", "url": "some-user-url", ">
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: User identifier: [abbra].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: User identifier: [abbra].
  May 02 18:51:50 dc.ipa.test oidc_child[1636150]: oidc_child finished successful!

Don't forget to remove ``oidc_child_debug_level`` from the
``/etc/ipa/default.conf`` once troubleshooting is done. Information like above
often contains personal details of the user and should probably not stored in
the system journal.
