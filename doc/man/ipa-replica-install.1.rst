.. AUTO-GENERATED FILE, DO NOT EDIT!

===============================================
ipa-replica-install(1) -- Create an IPA replica
===============================================

SYNOPSIS
========

ipa-replica-install [*OPTION*]...

DESCRIPTION
===========

Configures a new IPA server that is a replica of the server. Once it has
been created it is an exact copy of the original IPA server and is an
equal master. Changes made to any master are automatically replicated to
other masters.

Domain level 0 is not supported anymore.

To create a replica, the machine only needs to be enrolled in the
FreeIPA domain first. This process of turning the IPA client into a
replica is also referred to as replica promotion.

If you're starting with an existing IPA client, simply run
ipa-replica-install to have it promoted into a replica. The NTP
configuration cannot be updated during client promotion.

To promote a blank machine into a replica, you have two options, you can
either run ipa-client-install in a separate step, or pass the enrollment
related options to the ipa-replica-install (see CLIENT ENROLLMENT
OPTIONS). In the latter case, ipa-replica-install will join the machine
to the IPA realm automatically and will proceed with the promotion step.

If the installation fails you may need to run ipa-server-install
--uninstall and ipa-client-install before running ipa-replica-install
again.

The installation will fail if the host you are installing the replica on
exists as a host in IPA or an existing replication agreement exists (for
example, from a previously failed installation).

A replica should only be installed on the same or higher version of IPA
on the remote system.

OPTIONS
=======

OPTIONS
-------

.. option:: -P, --principal

   The user principal which will be used to promote the client to the
   replica and enroll the client itself, if necessary.

.. option:: -w, --admin-password

   The Kerberos password for the given principal.

CLIENT ENROLLMENT OPTIONS
-------------------------

To install client and promote it to replica using a host keytab or One
Time Password, the host needs to be a member of ipaservers group. This
requires to create a host entry and add it to the host group prior
replica installation.

--server, --domain, --realm options are autodiscovered via DNS records
by default. See manual page **ipa-client-install**\ (1) for further
details about these options.

.. option:: -p <PASSWORD>, --password=<PASSWORD>

   One Time Password for joining a machine to the IPA realm.

.. option:: -k, --keytab

   Path to host keytab.

.. option:: --server

   The fully qualified domain name of the IPA server to enroll to. The
   IPA server must provide the CA role if ``**--setup-ca**`` option is
   specified, and the KRA role if ``**--setup-kra**`` option is specified.

.. option:: -n, --domain=<DOMAIN>

   The primary DNS domain of an existing IPA deployment, e.g.
   example.com. This DNS domain should contain the SRV records generated
   by the IPA server installer.

.. option:: -r, --realm=<REALM_NAME>

   The Kerberos realm of an existing IPA deployment.

.. option:: --hostname

   The hostname of this machine (FQDN). If specified, the hostname will
   be set and the system configuration will be updated to persist over
   reboot.

.. option:: --force-join

   Join the host even if it is already enrolled.

BASIC OPTIONS
-------------

.. option:: --ip-address=<IP_ADDRESS>

   The IP address of this server. If this address does not match the
   address the host resolves to and --setup-dns is not selected the
   installation will fail. If the server hostname is not resolvable, a
   record for the hostname and IP_ADDRESS is added to /etc/hosts. This
   option can be used multiple times to specify more IP addresses of the
   server (e.g. multihomed and/or dualstacked server).

.. option:: --mkhomedir

   Create home directories for users on their first login

.. option:: --ntp-server=<NTP_SERVER>

   Configure chronyd to use this NTP server. This option can be used
   multiple times and it is used to specify exactly one time server.

.. option:: --ntp-pool=<NTP_SERVER_POOL>

   Configure chronyd to use this NTP server pool. This option is meant
   to be pool of multiple servers resolved as one host name. This pool's
   servers may vary but pool address will be still same and chrony will
   choose only one server from this pool.

.. option:: -N, --no-ntp

   Do not configure NTP client (chronyd).

.. option:: --no-ui-redirect

   Do not automatically redirect to the Web UI.

.. option:: --ssh-trust-dns

   Configure OpenSSH client to trust DNS SSHFP records.

.. option:: --no-ssh

   Do not configure OpenSSH client.

.. option:: --no-sshd

   Do not configure OpenSSH server.

.. option:: --skip-conncheck

   Skip connection check to remote master

.. option:: -d, --debug

   Enable debug logging when more verbose output is needed

.. option:: -U, --unattended

   An unattended installation that will never prompt for user input

.. option:: --dirsrv-config-file

   The path to LDIF file that will be used to modify configuration of
   dse.ldif during installation of the directory server instance

CERTIFICATE SYSTEM OPTIONS
--------------------------

.. option:: --setup-ca

   Install and configure a CA on this replica. If a CA is not configured
   then certificate operations will be forwarded to a master with a CA
   installed.

.. option:: --no-pkinit

   Disables pkinit setup steps.

.. option:: --dirsrv-cert-file=<FILE>

   File containing the Directory Server SSL certificate and private key

.. option:: --http-cert-file=<FILE>

   File containing the Apache Server SSL certificate and private key

.. option:: --pkinit-cert-file=<FILE>

   File containing the Kerberos KDC SSL certificate and private key

.. option:: --dirsrv-pin=<PIN>

   The password to unlock the Directory Server private key

.. option:: --http-pin=<PIN>

   The password to unlock the Apache Server private key

.. option:: --pkinit-pin=<PIN>

   The password to unlock the Kerberos KDC private key

.. option:: --dirsrv-cert-name=<NAME>

   Name of the Directory Server SSL certificate to install

.. option:: --http-cert-name=<NAME>

   Name of the Apache Server SSL certificate to install

.. option:: --pkinit-cert-name=<NAME>

   Name of the Kerberos KDC SSL certificate to install

.. option:: --pki-config-override=<FILE>

   File containing overrides for CA and KRA installation.

.. option:: --skip-schema-check

   Skip check for updated CA DS schema on the remote master

SECRET MANAGEMENT OPTIONS
-------------------------

.. option:: --setup-kra

   Install and configure a KRA on this replica. If a KRA is not
   configured then vault operations will be forwarded to a master with a
   KRA installed.

DNS OPTIONS
-----------

.. option:: --setup-dns

   Configure an integrated DNS server, create a primary DNS zone (name
   specified by --domain or taken from an existing deployment), and fill
   it with service records necessary for IPA deployment. In cases where
   the IPA server name does not belong to the primary DNS domain and is
   not resolvable using DNS, create a DNS zone containing the IPA server
   name as well.

   This option requires that you either specify at least one DNS
   forwarder through the ``**--forwarder**`` option or use the
   ``**--no-forwarders**`` option.

   Note that you can set up a DNS at any time after the initial IPA
   server install by running **ipa-dns-install** (see
   **ipa-dns-install**\ (1)). IPA DNS cannot be uninstalled.

.. option:: --forwarder=<IP_ADDRESS>

   Add a DNS forwarder to the DNS configuration. You can use this option
   multiple times to specify more forwarders, but at least one must be
   provided, unless the ``**--no-forwarders**`` option is specified.

.. option:: --no-forwarders

   Do not add any DNS forwarders. Root DNS servers will be used instead.

.. option:: --auto-forwarders

   Add DNS forwarders configured in /etc/resolv.conf to the list of
   forwarders used by IPA DNS.

.. option:: --forward-policy=<first|only>

   DNS forwarding policy for global forwarders specified using other
   options. Defaults to first if no IP address belonging to a private or
   reserved ranges is detected on local interfaces (RFC 6303). Defaults
   to only if a private IP address is detected.

.. option:: --reverse-zone=<REVERSE_ZONE>

   The reverse DNS zone to use. This option can be used multiple times
   to specify multiple reverse zones.

.. option:: --no-reverse

   Do not create new reverse DNS zone. If a reverse DNS zone already
   exists for the subnet, it will be used.

.. option:: --auto-reverse

   Create necessary reverse zones

.. option:: --allow-zone-overlap

   Create DNS zone even if it already exists

.. option:: --no-host-dns

   Do not use DNS for hostname lookup during installation

.. option:: --no-dns-sshfp

   Do not automatically create DNS SSHFP records.

.. option:: --no-dnssec-validation

   Disable DNSSEC validation on this server.

AD TRUST OPTIONS
----------------

.. option:: --setup-adtrust

   Configure AD Trust capability on a replica.

.. option:: --netbios-name=<NETBIOS_NAME>

   The NetBIOS name for the IPA domain. If not provided then this is
   determined based on the leading component of the DNS domain name.
   Running ipa-adtrust-install for a second time with a different
   NetBIOS name will change the name. Please note that changing the
   NetBIOS name might break existing trust relationships to other
   domains.

.. option:: --add-sids

   Add SIDs to existing users and groups as on of final steps of the
   ipa-adtrust-install run. If there a many existing users and groups
   and a couple of replicas in the environment this operation might lead
   to a high replication traffic and a performance degradation of all
   IPA servers in the environment. To avoid this the SID generation can
   be run after ipa-adtrust-install is run and scheduled independently.
   To start this task you have to load an edited version of
   ipa-sidgen-task-run.ldif with the ldapmodify command info the
   directory server.

.. option:: --add-agents

   Add IPA masters to the list that allows to serve information about
   users from trusted forests. Starting with FreeIPA 4.2, a regular IPA
   master can provide this information to SSSD clients. IPA masters
   aren't added to the list automatically as restart of the LDAP service
   on each of them is required. The host where ipa-adtrust-install is
   being run is added automatically.

   Note that IPA masters where ipa-adtrust-install wasn't run, can serve
   information about users from trusted forests only if they are enabled
   via ipa-adtrust-install run on any other IPA master. At least SSSD
   version 1.13 on IPA master is required to be able to perform as a
   trust agent.

.. option:: --rid-base=<RID_BASE>

   First RID value of the local domain. The first Posix ID of the local
   domain will be assigned to this RID, the second to RID+1 etc. See the
   online help of the idrange CLI for details.

.. option:: --secondary-rid-base=<SECONDARY_RID_BASE>

   Start value of the secondary RID range, which is only used in the
   case a user and a group share numerically the same Posix ID. See the
   online help of the idrange CLI for details.

.. option:: --enable-compat

   Enables support for trusted domains users for old clients through
   Schema Compatibility plugin. SSSD supports trusted domains natively
   starting with version 1.9. For platforms that lack SSSD or run older
   SSSD version one needs to use this option. When enabled, slapi-nis
   package needs to be installed and schema-compat-plugin will be
   configured to provide lookup of users and groups from trusted domains
   via SSSD on IPA server. These users and groups will be available
   under **cn=users,cn=compat,$SUFFIX** and
   **cn=groups,cn=compat,$SUFFIX** trees. SSSD will normalize names of
   users and groups to lower case.

   In addition to providing these users and groups through the compat
   tree, this option enables authentication over LDAP for trusted domain
   users with DN under compat tree, i.e. using bind DN
   **uid=administrator@ad.domain,cn=users,cn=compat,$SUFFIX**.

   LDAP authentication performed by the compat tree is done via PAM
   '**system-auth**' service. This service exists by default on Linux
   systems and is provided by pam package as /etc/pam.d/system-auth. If
   your IPA install does not have default HBAC rule 'allow_all' enabled,
   then make sure to define in IPA special service called
   '**system-auth**' and create an HBAC rule to allow access to anyone
   to this rule on IPA masters.

   As '**system-auth**' PAM service is not used directly by any other
   application, it is safe to use it for trusted domain users via
   compatibility path.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

3 if the host exists in the IPA server or a replication agreement to the
remote master already exists

4 if the remote master specified for enrollment does not provide
required services such as CA or KRA
