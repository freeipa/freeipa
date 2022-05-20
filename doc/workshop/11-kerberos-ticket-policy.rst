Unit 11: Kerberos ticket policy
=========================================

**Prerequisites:**

- `Unit 3: User management and Kerberos authentication <3-user-management.rst>`_

In this module you will explore how to manage properties of Kerberos
authentication and authorization in FreeIPA.

**Note:** To complete this module, FreeIPA-4.8.4 or later is needed.

Kerberos ticket policies
------------------------

FreeIPA's primary authentication mechanism is based on Kerberos infrastructure.
Each user has an associated Kerberos principal and potential aliases. Each FreeIPA
service has its own Kerberos service and, optionally, alias names as well. Depending
on who initiates a communication flow, in Kerberos terminology there are client
and a target (server) principals. Any Kerberos principal can be used in both
client and server roles, though typically FreeIPA services are used as targets
and users are used as clients.

A client first authenticates to a Key Distribution Center (KDC) and obtains a
ticket granting ticket (TGT). With the ticket granting ticket in possession, the
client then asks a KDC for a service ticket to the target Kerberos principal.
After the service ticket is issued by the KDC, the client can initiate its
application-specific communication to the target application server.

When a KDC issues a ticket, there are few properties that can be controlled with
the help of a Kerberos policy in FreeIPA. Each ticket has its own life time and
a potential renewal age: a ticket can be renewed before its life time has ended
but until the renewal age expired.

The combination of Kerberos ticket life time and renewal age altogether
comprises a **Kerberos ticket policy**. The policy itself is not stored in a single
place because individual parts of it are applied to different objects and at
different stages of authentication and authorization processes. Instead, it is
split into several parts which are associated with the corresponding Kerberos
principals, whether they are used as clients or as targets.

For users, Kerberos ticket life time and renewal age can be managed with
Kerberos ticket policy commands described in ``ipa help krbtpolicy`` manual.

If no specific policy is associated with a user, a default one is applied. To
manage the default policy the same ``ipa krbtpolicy-*`` commands are used,
without an explicit user name.

Display the default Kerberos ticket policy::

  [admin@client]$ kinit admin
  Password for admin@IPADEMO.LOCAL:
  [admin@client]$ ipa krbtpolicy-show
    Max life: 86400
    Max renew: 604800

Modify the default policy to 8 hours max life, 1-day max renewal::

  [admin@client]$ ipa krbtpolicy-mod --maxlife=28800 --maxrenew=86400
    Max life: 28800
    Max renew: 86640

Display effective Kerberos ticket policy for user ``admin``::

  [admin@client]$ ipa krbtpolicy-show admin
    Max life: 28800
    Max renew: 86640

Modify per-user policy for user 'admin'::

  [admin@client]$ ipa krbtpolicy-mod admin --maxlife=3600
    Max life: 3600

Reset per-user policy for user ``admin``::

  [admin@client]$ ipa krbtpolicy-reset admin
    Max life: 28800
    Max renew: 86640

Currently (FreeIPA 4.8.4), FreeIPA does not allow a Kerberos service principal
to have a custom Kerberos ticket policy. As result, only default Kerberos ticket
policy is applicable to service principals.

Kerberos authentication indicators
----------------------------------

A Kerberos client may have different means to prove possession of a client
principal credentials to a KDC. There are several so-called 'pre-authentication
mechanisms' that are used for this purpose. FreeIPA KDC is able to record which
pre-authentication method was used when issuing the ticket granting ticket. The
specific label is called an **authentication indicator**. 

Authentication indicators are associated with the following pre-authentication mechanisms:

=========================   ========================
Authentication indicator    Pre-authentication mechanism
=========================   ========================
radius                      RADIUS
otp                         FreeIPA two factor authentication (password + OTP)
pkinit                      PKINIT, smart-card or certificate authentication
hardened                    Hardened Password (by SPAKE or FAST)
idp                         External Identity Provider
=========================   ========================

**Hardened** authentication indicator is set by FreeIPA KDC when a Kerberos
client has used one of two pre-authentication mechanisms that allow protecting
an exchange between the client and the KDC:

 - **FAST** is a Kerberos pre-authentication mechanism defined in
   `RFC 6113, section 5.4 <https://tools.ietf.org/htlm/rfc6113#section-5.4>`_.
   It is used to securely pass so-called **FAST factors** to the KDC. Such
   factors might represent a traditional password-based exchange, or two-factor
   authentication, or something else. There are multiple types of FAST armors
   supported by FreeIPA.
 - **SPAKE** is a new pre-authentication mechanism,
   `being standardized <https://tools.ietf.org/html/draft-ietf-kitten-krb-spake-preauth>`_
   by the IETF Kitten working group. Its purpose is to increase security of
   Kerberos pre-authentication exchanges by making offline brute-force attacks
   infeasible and to enable use of multi-factor authentication without relying
   on FAST. SPAKE implementation in FreeIPA currently only supports a single
   factor authentication.

In the context of authentication indicators, FAST and SPAKE pre-authentication
methods give higher level of protection than an exchange using encrypted
timestamp method, traditional for Kerberos 5.

Each authentication indicator conveys the fact that KDC was able to
pre-authenticate the initial ticket granting ticket exchange using chosen
mechanism. This fact can further be used to differentiate the issued ticket life
time and renewal age.

With FreeIPA 4.8.4 or later, Kerberos ticket policy allows an administrator to
set different life time and renewal age for ticket granting tickets obtained
with different pre-authentication methods. Each policy setting may include
authentication indicator to say that the life time or renewal age applies to
TGTs with which include this indicator::

  [admin@client]$ ipa krbtpolicy-mod --help
    Usage: ipa [global-options] krbtpolicy-mod [USER] [options]

    Modify Kerberos ticket policy.
    Options:
      -h, --help            show this help message and exit
      --maxlife=INT         Maximum ticket life (seconds)
      --maxrenew=INT        Maximum renewable age (seconds)
      --otp-maxlife=INT     OTP token maximum ticket life (seconds)
      --otp-maxrenew=INT    OTP token ticket maximum renewable age (seconds)
      --radius-maxlife=INT  RADIUS maximum ticket life (seconds)
      --radius-maxrenew=INT
                            RADIUS ticket maximum renewable age (seconds)
      --pkinit-maxlife=INT  PKINIT maximum ticket life (seconds)
      --pkinit-maxrenew=INT
                            PKINIT ticket maximum renewable age (seconds)
      --hardened-maxlife=INT
                            Hardened ticket maximum ticket life (seconds)
      --hardened-maxrenew=INT
                            Hardened ticket maximum renewable age (seconds)
     ....

For example, we can allow ``admin`` user to renew its ticket for two days if it
was obtained with ``hardened`` authentication indicator::

  [admin@client]$ ipa krbtpolicy-mod admin --hardened-maxrenew=$((2*24*60*60))
    Hardened max renew: 172800
  [admin@client]$ ipa krbtpolicy-show admin
    Max life: 28800
    Max renew: 86640
    Hardened max renew: 172800

There is no way to see authentication indicators for already issued tickets with
existing Kerberos utilities. However, MIT Kerberos tracing facilities can be
used to see what pre-authentication method was used to obtain a ticket::

   [admin@client]$ KRB5_TRACE=/dev/stderr kinit admin
   [29708] 1583503381.62516: Getting initial credentials for admin@IPADEMO.LOCAL
   [29708] 1583503381.62518: Sending unauthenticated request
   [29708] 1583503381.62519: Sending request (176 bytes) to IPADEMO.LOCAL
   [29708] 1583503381.62520: Initiating TCP connection to stream AA.BB.CC.DD:88
   [29708] 1583503381.62521: Sending TCP request to stream AA.BB.CC.DD:88
   [29708] 1583503381.62522: Received answer (515 bytes) from stream AA.BB.CC.DD:88
   [29708] 1583503381.62523: Terminating TCP connection to stream AA.BB.CC.DD:88
   [29708] 1583503381.62524: Response was from master KDC
   [29708] 1583503381.62525: Received error from KDC: -1765328359/Additional pre-authentication required
   [29708] 1583503381.62528: Preauthenticating using KDC method data
   [29708] 1583503381.62529: Processing preauth types: PA-PK-AS-REQ (16), PA-PK-AS-REP_OLD (15), PA-PK-AS-REQ_OLD (14), PA-FX-FAST (136), PA-ETYPE-INFO2 (19), PA-PKINIT-KX (147), PA-SPAKE (151), PA-ENC-TIMESTAMP (2), PA_AS_FRESHNESS (150), PA-FX-COOKIE (133)
   [29708] 1583503381.62530: Selected etype info: etype aes256-cts, salt "SOME-VALUE", params ""
   [29708] 1583503381.62531: Received cookie: SOME-VALUE
   [29708] 1583503381.62532: PKINIT client has no configured identity; giving up
   [29708] 1583503381.62533: Preauth module pkinit (147) (info) returned: 0/Success
   [29708] 1583503381.62534: PKINIT client received freshness token from KDC
   [29708] 1583503381.62535: Preauth module pkinit (150) (info) returned: 0/Success
   [29708] 1583503381.62536: PKINIT client has no configured identity; giving up
   [29708] 1583503381.62537: Preauth module pkinit (16) (real) returned: 22/Invalid argument
   [29708] 1583503381.62538: PKINIT client ignoring draft 9 offer from RFC 4556 KDC
   [29708] 1583503381.62539: Preauth module pkinit (15) (real) returned: -1765328360/Preauthentication failed
   [29708] 1583503381.62540: PKINIT client ignoring draft 9 offer from RFC 4556 KDC
   [29708] 1583503381.62541: Preauth module pkinit (14) (real) returned: -1765328360/Preauthentication failed
   [29708] 1583503381.62542: SPAKE challenge received with group 1, pubkey 327144B7EC68505214E5A3606FD2091A7C47CBB60020D7D94B8C4878456B879E
   Password for admin@IPADEMO.LOCAL: 
   [29708] 1583503386.372820: SPAKE key generated with pubkey F0AD6539C037C28758B692FA38FF8F924D5E52C593E485B3700DBF7FD2856477
   [29708] 1583503386.372821: SPAKE algorithm result: B53EC5E8C1A22F36F91FD584915F19B3F06CDF3CE460704E2C900AE83DF53EDC
   [29708] 1583503386.372822: SPAKE final transcript hash: AC42F4221481B9C9ED3169568A09BBDA9FAACE46DE13F6DCAFF8261003115A9C
   [29708] 1583503386.372823: Sending SPAKE response
   [29708] 1583503386.372824: Preauth module spake (151) (real) returned: 0/Success
   [29708] 1583503386.372825: Produced preauth for next request: PA-FX-COOKIE (133), PA-SPAKE (151)
   [29708] 1583503386.372826: Sending request (435 bytes) to IPADEMO.LOCAL
   [29708] 1583503386.372827: Initiating TCP connection to stream AA.BB.CC.DD:88
   [29708] 1583503386.372828: Sending TCP request to stream AA.BB.CC.DD:88
   [29708] 1583503386.372829: Received answer (1419 bytes) from stream AA.BB.CC.DD:88
   [29708] 1583503386.372830: Terminating TCP connection to stream AA.BB.CC.DD:88
   [29708] 1583503386.372831: Response was from master KDC
   [29708] 1583503386.372832: AS key determined by preauth: aes256-cts/AE1D
   [29708] 1583503386.372833: Decrypted AS reply; session key is: aes256-cts/12C3
   [29708] 1583503386.372834: FAST negotiation: available
   [29708] 1583503386.372835: Initializing KCM:123456 with default princ admin@IPADEMO.LOCAL
   [29708] 1583503386.372836: Storing admin@IPADEMO.LOCAL -> krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL in KCM:123456
   [29708] 1583503386.372837: Storing config in KCM:123456 for krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL: fast_avail: yes
   [29708] 1583503386.372838: Storing admin@IPADEMO.LOCAL -> krb5_ccache_conf_data/fast_avail/krbtgt\/IPADEMO.LOCAL\@IPADEMO.LOCAL@X-CACHECONF: in KCM:123456
   [29708] 1583503386.372839: Storing config in KCM:123456 for krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL: pa_type: 151
   [29708] 1583503386.372840: Storing admin@IPADEMO.LOCAL -> krb5_ccache_conf_data/pa_type/krbtgt\/IPADEMO.LOCAL\@IPADEMO.LOCAL@X-CACHECONF: in KCM:123456

As can be seen above, pre-authentication type, ``pa_type``, 151 (SPAKE)
was used in for pre-authentication. A look at the credential cache content will
show that the renewal age policy applied corresponds to the ``hardened`` variant::

   [admin@client]$ klist -f -d -e
   Ticket cache: KCM:123456
   Default principal: admin@IPADEMO.LOCAL

   Valid starting       Expires              Service principal
   06.03.2020 09.03.06  06.03.2020 17.03.06  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL
        renew until 07.03.2020 09.03.01, Flags: FRIA
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types: 

As result, ``admin`` user can now use its ticket up to 8 hours and renew it
until 48 hours since the original ticket was obtained.

Finally, we can reset the default Kerberos ticket policy to the installation
default::

  [admin@client]$ ipa krbtpolicy-reset
    Max life: 86400
    Max renew: 604800


Enforcing authentication indicators
-----------------------------------

Authentication indicators from the ticket granting ticket are copied by the KDC
into service tickets issued with the help of the TGT presented by a Kerberos
client. The indicators can be seen by the applications receiving a communication
encrypted with the service ticket. This allows an application administrator to
permit restricted access to only those clients who used specific
pre-authentication mechanisms to obtain their initial ticket granting ticket.
For example, an application might decide to only allow access to a specialized
resource to people who used smart-card authentication initially, even if the
application itself only supports Kerberos authentication.

At the moment, there is only one known application that implements
authentication indicator-based authorization. Since version 2.6.0, SSSD provides
a PAM module ``pam_sss_gss`` which allows to authenticate users with GSSAPI
(Kerberos ticket) and optionally check authentication indicator that was used to
obtain this ticket. More information can be found in the man page for
``pam_sss_gss` and for ``sssd.conf`` where options starting with ``pam_gssapi_``
prefix are documented. This feature was also backported to SSSD 2.4.2 and 2.5.0.

For example, setting the following in SSSD configuration would allow GSSAPI
authentication to ``sudo`` and ``sudo -i`` only if the Kerberos ticket was
obtained with the use of a smartcard or certificate-based authentcation::

   [pam]
     pam_gssapi_services = sudo, sudo-i
     pam_gssapi_indicators_map = sudo:pkinit, sudo-i:pkinit

The actual enforcement requires use of ``pam_sss_gss`` module in the PAM stack.
Fedora and RHEL distributions provide ``authselect`` tool to handle PAM and NSS
configuration. ``authselect`` was extended to allow use of ``pam_sss_gss`` as
SSSD feature ``with-gssapi``::

  [root@client ~]# authselect enable-feature with-gssapi
  Make sure that SSSD service is configured and enabled. See SSSD documentation for more information.

  - with-gssapi is selected, make sure that GSSAPI authenticaiton is enabled in SSSD
  - set pam_gssapi_services to a list of allowed services in /etc/sssd/sssd.conf
  - see additional information in pam_sss_gss(8)

Once this change made and SSSD configuration updated to allow PAM services to
use GSSAPI authentication, it will be possible to use Kerberos ticket to
authenticate over a chosen PAM service. A session below demonstrates it::

   [root@client ~]# vim /etc/sssd/sssd.conf
   [root@client ~]# systemctl restart sssd
   [root@client ~]# id testuser
   uid=167200003(testuser) gid=167200003(testuser) groups=167200003(testuser)
   [root@client ~]# ssh testuser@`hostname`
   (testuser@client.ipa.test) password:
   Last login: Thu Mar 24 13:54:21 2022 from 192.168.122.141
   -sh-5.1$ klist
   Ticket cache: KCM:167200003:41683
   Default principal: testuser@IPA.TEST

   Valid starting     Expires            Service principal
   03/25/22 13:47:55  03/26/22 13:04:47  krbtgt/IPA.TEST@IPA.TEST
   -sh-5.1$ sudo -l
   Matching Defaults entries for testuser on client:
       !visiblepw, always_set_home, match_group_by_gid,
       always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME
       HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS
       LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
       LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
       LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
       XAUTHORITY",
       secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

   User testuser may run the following commands on dc:
       (ALL) ALL

FreeIPA also provides a check for an authentication indicator at KDC side. This
means that a lack of a specific authentication indicator in TGT can result in
denying an issuance of a requested service ticket. A consequence is that an
application will never see any user with a ticket that does not contain a
specified authentication indicator.

In order to enable the check, add authentication indicator to a service using
``ipa service-mod`` command. We can create a new service and associate
the ``pkinit`` authentication indicator with it::

   [admin@client]$ ipa service-add my-service/`hostname`
   ---------------------------------------------------
   Added service "my-service/client.ipademo.local@IPADEMO.LOCAL"
   ---------------------------------------------------
     Principal name: my-service/client.ipademo.local@IPADEMO.LOCAL
     Principal alias: my-service/client.ipademo.local@IPADEMO.LOCAL
     Managed by: client.ipademo.local
   [admin@client]$ ipa-getkeytab -k my-service.keytab -p my-service/`hostname`
   Keytab successfully retrieved and stored in: my-service.keytab

A new service, ``my-service/client.ipademo.local``, was created and a set of
random Kerberos keys was associated with it by retrieving a keytab with the
keys. If we want to request a service ticket to the service, the service must
have Kerberos keys.

MIT Kerberos provides a nice tool to request Kerberos service tickets: ``kvno``.
At this point our service has no authentication indicator associated and a
request will succeed::

   [admin@client]$ KRB5_TRACE=/dev/stderr kvno -S my-service `hostname`
   [29770] 1583505522.60592: Getting credentials admin@IPADEMO.LOCAL -> my-service/client.ipademo.local@IPADEMO.LOCAL using ccache KCM:123456
   [29770] 1583505522.60593: Retrieving admin@IPADEMO.LOCAL -> my-service/client.ipademo.local@IPADEMO.LOCAL from KCM:!23456 with result: -1765328243/Matching credential not found
   [29770] 1583505522.60594: Retrieving admin@IPADEMO.LOCAL -> krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL from KCM:!23456 with result: 0/Success
   [29770] 1583505522.60595: Starting with TGT for client realm: admin@IPADEMO.LOCAL -> krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL
   [29770] 1583505522.60596: Requesting tickets for my-service/client.ipademo.local@IPADEMO.LOCAL, referrals on
   [29770] 1583505522.60597: Generated subkey for TGS request: aes256-cts/8F4D
   [29770] 1583505522.60598: etypes requested in TGS request: aes256-cts, aes128-cts, aes256-sha2, aes128-sha2, des3-cbc-sha1, rc4-hmac, camellia128-cts, camellia256-cts
   [29770] 1583505522.60600: Encoding request body and padata into FAST request
   [29770] 1583505522.60601: Sending request (1655 bytes) to IPADEMO.LOCAL
   [29770] 1583505522.60602: Initiating TCP connection to stream AA.BB.CC.DD:88
   [29770] 1583505522.60603: Sending TCP request to stream AA.BB.CC.DD:88
   [29770] 1583505522.60604: Received answer (1626 bytes) from stream AA.BB.CC.DD:88
   [29770] 1583505522.60605: Terminating TCP connection to stream AA.BB.CC.DD:88
   [29770] 1583505522.60606: Response was from master KDC
   [29770] 1583505522.60607: Decoding FAST response
   [29770] 1583505522.60608: FAST reply key: aes256-cts/71CF
   [29770] 1583505522.60609: TGS reply is for admin@IPADEMO.LOCAL -> my-service/client.ipademo.local@IPADEMO.LOCAL with session key aes256-cts/8B3E
   [29770] 1583505522.60610: TGS request result: 0/Success
   [29770] 1583505522.60611: Received creds for desired service my-service/client.ipademo.local@IPADEMO.LOCAL
   [29770] 1583505522.60612: Storing admin@IPADEMO.LOCAL -> my-service/client.ipademo.local@IPADEMO.LOCAL in KCM:123456
   my-service/client.ipademo.local@IPADEMO.LOCAL: kvno = 1

Let's associate ``pkinit`` authentication indicator with the service::

   [admin@client]$ ipa service-mod my-service/`hostname` --auth-ind pkinit
   ------------------------------------------------------
   Modified service "my-service/client.ipademo.local@IPADEMO.LOCAL"
   ------------------------------------------------------
     Principal name: my-service/client.ipademo.local@IPADEMO.LOCAL
     Principal alias: my-service/client.ipademo.local@IPADEMO.LOCAL
     Authentication Indicators: pkinit
     Managed by: client.ipademo.local

Since our credentials cache already contains Kerberos ticket to
``my-service/client.ipademo.local`` from the previous step, ``kvno`` will not
attempt to obtain a new ticket if we just request it again. Instead, we need to
destroy our credentials cache or specify a different one and re-try again::

   [admin@client]$ kdestroy
   [admin@client]$ kinit admin
   Password for admin@IPADEMO.LOCAL: 
   [admin@client]$ KRB5_TRACE=/dev/stderr kvno -S my-service `hostname`
   [29811] 1583506366.899807: Getting credentials admin@IPADEMO.LOCAL -> my-service/client.ipademo.local@IPADEMO.LOCAL using ccache KCM:123456
   [29811] 1583506366.899808: Retrieving admin@IPADEMO.LOCAL -> my-service/client.ipademo.local@IPADEMO.LOCAL from KCM:123456 with result: -1765328243/Matching credential not found
   [29811] 1583506366.899809: Retrieving admin@IPADEMO.LOCAL -> krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL from KCM:123456 with result: 0/Success
   [29811] 1583506366.899810: Starting with TGT for client realm: admin@IPADEMO.LOCAL -> krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL
   [29811] 1583506366.899811: Requesting tickets for my-service/client.ipademo.local@IPADEMO.LOCAL, referrals on
   [29811] 1583506366.899812: Generated subkey for TGS request: aes256-cts/8737
   [29811] 1583506366.899813: etypes requested in TGS request: aes256-cts, aes128-cts, aes256-sha2, aes128-sha2, des3-cbc-sha1, rc4-hmac, camellia128-cts, camellia256-cts
   [29811] 1583506366.899815: Encoding request body and padata into FAST request
   [29811] 1583506366.899816: Sending request (1655 bytes) to IPADEMO.LOCAL
   [29811] 1583506366.899817: Initiating TCP connection to stream AA.BB.CC.DD:88
   [29811] 1583506366.899818: Sending TCP request to stream AA.BB.CC.DD:88
   [29811] 1583506366.899819: Received answer (447 bytes) from stream AA.BB.CC.DD:88
   [29811] 1583506366.899820: Terminating TCP connection to stream AA.BB.CC.DD:88
   [29811] 1583506366.899821: Response was from master KDC
   [29811] 1583506366.899822: Decoding FAST response
   [29811] 1583506366.899823: TGS request result: -1765328372/KDC policy rejects request
   [29811] 1583506366.899824: Requesting tickets for my-service/client.ipademo.local@IPADEMO.LOCAL, referrals off
   [29811] 1583506366.899825: Generated subkey for TGS request: aes256-cts/CC99
   [29811] 1583506366.899826: etypes requested in TGS request: aes256-cts, aes128-cts, aes256-sha2, aes128-sha2, des3-cbc-sha1, rc4-hmac, camellia128-cts, camellia256-cts
   [29811] 1583506366.899828: Encoding request body and padata into FAST request
   [29811] 1583506366.899829: Sending request (1655 bytes) to IPADEMO.LOCAL
   [29811] 1583506366.899830: Initiating TCP connection to stream AA.BB.CC.DD:88
   [29811] 1583506366.899831: Sending TCP request to stream AA.BB.CC.DD:88
   [29811] 1583506366.899832: Received answer (447 bytes) from stream AA.BB.CC.DD:88
   [29811] 1583506366.899833: Terminating TCP connection to stream AA.BB.CC.DD:88
   [29811] 1583506366.899834: Response was from master KDC
   [29811] 1583506366.899835: Decoding FAST response
   [29811] 1583506366.899836: TGS request result: -1765328372/KDC policy rejects request
   kvno: KDC policy rejects request while getting credentials for my-service/client.ipademo.local@IPADEMO.LOCAL

Finally, we can remove the indicator from ``my-service/client.ipademo.local``::

   [admin@client]$ ipa service-mod my-service/`hostname` --auth-ind ''
   ------------------------------------------------------
   Modified service "my-service/client.ipademo.local@IPADEMO.LOCAL"
   ------------------------------------------------------
     Principal name: my-service/client.ipademo.local@IPADEMO.LOCAL
     Principal alias: my-service/client.ipademo.local@IPADEMO.LOCAL
     Managed by: client.ipademo.local

Authentication indicators and FreeIPA services
----------------------------------------------

Authentication indicators can become an effective way to enforce the use of a
particular pre-authentication method. However, there are caveats. Since
KDC-based enforcement does not allow anyone to obtain a service ticket to a
Kerberos service if they do not possess an authentication indicator in question,
great care has to be used when assigning authentication indicators to internal
FreeIPA services.

Internal FreeIPA services include following Kerberos services on each IPA master
or replica:

 - ``HTTP/master.ipademo.local@IPADEMO.LOCAL``
 - ``ldap/master.ipademo.local@IPADEMO.LOCAL``
 - ``DNS/master.ipademo.local@IPADEMO.LOCAL``
 - ``cifs/master.ipademo.local@IPADEMO.LOCAL``

These services are used by automated tools and internally by FreeIPA server
applications themselves. The tools and servers currently cannot perform
interactive authentication steps required by PKINIT and multi-factor
authentication methods.
