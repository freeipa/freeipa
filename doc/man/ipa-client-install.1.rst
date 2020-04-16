.. AUTO-GENERATED FILE, DO NOT EDIT!

================================================
ipa-client-install(1) -- Configure an IPA client
================================================

SYNOPSIS
========

ipa-client-install [*OPTION*]...

DESCRIPTION
===========

Configures a client machine to use IPA for authentication and identity
services.

By default this configures SSSD to connect to an IPA server for
authentication and authorization. Optionally one can instead configure
PAM and NSS (Name Switching Service) to work with an IPA server over
Kerberos and LDAP.

An authorized user is required to join a client machine to IPA. This can
take the form of a kerberos principal or a one-time password associated
with the machine.

This same tool is used to unconfigure IPA and attempts to return the
machine to its previous state. Part of this process is to unenroll the
host from the IPA server. Unenrollment consists of disabling the
principal key on the IPA server so that it may be re-enrolled. The
machine principal in /etc/krb5.keytab (host/<fqdn>@REALM) is used to
authenticate to the IPA server to unenroll itself. If this principal
does not exist then unenrollment will fail and an administrator will
need to disable the host principal (ipa host-disable <fqdn>).

Assumptions
-----------

The ipa-client-install script assumes that the machine has already
generated SSH keys. It will not generate SSH keys of its own accord. If
SSH keys are not present (e.g. when running the ipa-client-install in a
kickstart, before ever running sshd), they will not be uploaded to the
client host entry on the server.

Hostname Requirements
---------------------

Client must use a **static hostname**. If the machine hostname changes
for example due to a dynamic hostname assignment by a DHCP server,
client enrollment to IPA server breaks and user then would not be able
to perform Kerberos authentication.

--hostname option may be used to specify a static hostname that persists
over reboot.

DNS Autodiscovery
-----------------

Client installer by default tries to search for \_ldap._tcp.DOMAIN DNS
SRV records for all domains that are parent to its hostname. For
example, if a client machine has a hostname 'client1.lab.example.com',
the installer will try to retrieve an IPA server hostname from
\_ldap._tcp.lab.example.com, \_ldap._tcp.example.com and \_ldap._tcp.com
DNS SRV records, respectively. The discovered domain is then used to
configure client components (e.g. SSSD and Kerberos 5 configuration) on
the machine.

When the client machine hostname is not in a subdomain of an IPA server,
its domain can be passed with --domain option. In that case, both SSSD
and Kerberos components have the domain set in the configuration files
and will use it to autodiscover IPA servers.

Client machine can also be configured without a DNS autodiscovery at
all. When both --server and --domain options are used, client installer
will use the specified server and domain directly. --server option
accepts multiple server hostnames which can be used for failover
mechanism. Without DNS autodiscovery, Kerberos is configured with a
fixed list of KDC and Admin servers. SSSD is still configured to either
try to read domain's SRV records or the specified fixed list of servers.
When --fixed-primary option is specified, SSSD will not try to read DNS
SRV record at all (see sssd-ipa(5) for details).

The Failover Mechanism
----------------------

When some of the IPA servers is not available, client components are
able to fallback to other IPA replica and thus preserving a continued
service. When client machine is configured to use DNS SRV record
autodiscovery (no fixed server was passed to the installer), client
components do the fallback automatically, based on the IPA server
hostnames and priorities discovered from the DNS SRV records.

If DNS autodiscovery is not available, clients should be configured at
least with a fixed list of IPA servers that can be used in case of a
failure. When only one IPA server is configured, IPA client services
will not be available in case of a failure of the IPA server. Please
note, that in case of a fixed list of IPA servers, the fixed server
lists in client components need to be updated when a new IPA server is
enrolled or a current IPA server is decommissioned.

Coexistence With Other Directory Servers
----------------------------------------

Other directory servers deployed in the network (e.g. Microsoft Active
Directory) may use the same DNS SRV records to denote hosts with a
directory service (_ldap._tcp.DOMAIN). Such DNS SRV records may break
the installation if the installer discovers these DNS records before it
finds DNS SRV records pointing to IPA servers. The installer would then
fail to discover the IPA server and exit with error.

In order to avoid the aforementioned DNS autodiscovery issues, the
client machine hostname should be in a domain with properly defined DNS
SRV records pointing to IPA servers, either manually with a custom DNS
server or with IPA DNS integrated solution. A second approach would be
to avoid autodiscovery and configure the installer to use a fixed list
of IPA server hostnames using the --server option and with a
--fixed-primary option disabling DNS SRV record autodiscovery in SSSD.

Re-enrollment of the host
-------------------------

Requirements:

| 1. Host has not been un-enrolled (the ipa-client-install --uninstall
  command has not been run).
| 2. The host entry has not been disabled via the ipa host-disable
  command.

If this has been the case, host can be re-enrolled using the usual
methods.

There are two method of authenticating a re-enrollment:

| 1. You can use --force-join option with ipa-client-install command.
  This authenticates the re-enrollment using the admin's credentials
  provided via the -w/--password option.
| 2. If providing the admin's password via the command line is not an
  option (e.g. you want to create a script to re-enroll a host and keep
  the admin's password secure), you can use backed up keytab from the
  previous enrollment of this host to authenticate. See --keytab option.

Consequences of the re-enrollment on the host entry:

| 1. A new host certificate is issued
| 2. The old host certificate is revoked
| 3. New SSH keys are generated
| 4. ipaUniqueID is preserved

OPTIONS
=======

BASIC OPTIONS
-------------

.. option:: --domain=<DOMAIN>

   The primary DNS domain of an existing IPA deployment, e.g.
   example.com. This DNS domain should contain the SRV records generated
   by the IPA server installer. Usually the name is a lower-cased name
   of an IPA Kerberos realm name.

   When no --server option is specified, this domain will be used by the
   installer to discover all available servers via DNS SRV record
   autodiscovery (see DNS Autodiscovery section for details).

   The default value used by the installer is the domain part of the
   hostname. This option needs to be specified if the primary IPA DNS
   domain is different from the default value.

.. option:: --server=<SERVER>

   Set the FQDN of the IPA server to connect to. May be specified
   multiple times to add multiple servers to ipa_server value in
   sssd.conf or krb5.conf. Only the first value is considered when used
   with --no-sssd. When this option is used, DNS autodiscovery for
   Kerberos is disabled and a fixed list of KDC and Admin servers is
   configured.

   Under normal circumstances, this option is not needed as the list of
   servers is retrieved from the primary IPA DNS domain.

.. option:: --realm=<REALM_NAME>

   The Kerberos realm of an existing IPA deployment. Usually it is an
   upper-cased name of the primary DNS domain used by the IPA
   installation.

   Under normal circumstances, this option is not needed as the realm
   name is retrieved from the IPA server.

.. option:: --fixed-primary

   Configure SSSD to use a fixed server as the primary IPA server. The
   default is to use DNS SRV records to determine the primary server to
   use and fall back to the server the client is enrolled with. When
   used in conjunction with --server then no \_srv\_ value is set in the
   ipa_server option in sssd.conf.

.. option:: -p, --principal

   Authorized kerberos principal to use to join the IPA realm.

.. option:: -w <PASSWORD>, --password=<PASSWORD>

   Password for joining a machine to the IPA realm. Assumes bulk
   password unless principal is also set.

.. option:: -W

   Prompt for the password for joining a machine to the IPA realm.

.. option:: -k, --keytab

   Path to backed up host keytab from previous enrollment. Joins the
   host even if it is already enrolled.

.. option:: --mkhomedir

   Configure PAM to create a users home directory if it does not exist.

.. option:: --hostname

   The hostname of this machine (FQDN). If specified, the hostname will
   be set and the system configuration will be updated to persist over
   reboot. By default the result of getfqdn() call from Python's socket
   module is used.

.. option:: --force-join

   Join the host even if it is already enrolled.

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

.. option:: --nisdomain=<NIS_DOMAIN>

   Set the NIS domain name as specified. By default, this is set to the
   IPA domain name.

.. option:: --no-nisdomain

   Do not configure NIS domain name.

.. option:: --ssh-trust-dns

   Configure OpenSSH client to trust DNS SSHFP records.

.. option:: --no-ssh

   Do not configure OpenSSH client.

.. option:: --no-sshd

   Do not configure OpenSSH server.

.. option:: --no-sudo

   Do not configure SSSD as a data source for sudo.

.. option:: --no-dns-sshfp

   Do not automatically create DNS SSHFP records.

.. option:: --noac

   Do not use Authconfig to modify the nsswitch.conf and PAM
   configuration.

.. option:: -f, --force

   Force the settings even if errors occur

.. option:: --kinit-attempts=<KINIT_ATTEMPTS>

   In case of unresponsive KDC (e.g. when enrolling multiple hosts at
   once in a heavy load environment) repeat the request for host
   Kerberos ticket up to a total number of *KINIT_ATTEMPTS* times before
   giving up and aborting client installation. Default number of
   attempts is 5. The request is not repeated when there is a problem
   with host credentials themselves (e.g. wrong keytab format or invalid
   principal) so using this option will not lead to account lockouts.

.. option:: -d, --debug

   Print debugging information to stdout

.. option:: -U, --unattended

   Unattended installation. The user will not be prompted.

.. option:: --ca-cert-file=<CA_FILE>

   Do not attempt to acquire the IPA CA certificate via automated means,
   instead use the CA certificate found locally in in *CA_FILE*. The
   *CA_FILE* must be an absolute path to a PEM formatted certificate
   file. The CA certificate found in *CA_FILE* is considered
   authoritative and will be installed without checking to see if it's
   valid for the IPA domain.

.. option:: --request-cert

   **DEPRECATED:** The option is deprecated and will be removed in a
   future release.

   Request certificate for the machine. The certificate will be stored
   in /etc/ipa/nssdb under the nickname "Local IPA host".

   Using this option requires that D-Bus is properly configured or not
   configured at all. In environment where this condition is not met
   (e.g. anaconda kickstart chroot environment) set the system bus
   address to /dev/null to enable workaround in ipa-client-install.

::

       # env DBUS_SYSTEM_BUS_ADDRESS=unix:path=/dev/null ipa-client-install --request-cert

Note that requesting the certificate when certmonger is not running only
creates tracking request and the certmonger service must be started to
be able to track certificates.

.. option:: --automount-location=<LOCATION>

   Configure automount by running ipa-client-automount(1) with
   *LOCATION* as automount location.

.. option:: --configure-firefox

   Configure Firefox to use IPA domain credentials.

.. option:: --firefox-dir=<DIR>

   Specify Firefox installation directory. For example:
   '/usr/lib/firefox'

.. option:: --ip-address=<IP_ADDRESS>

   Use *IP_ADDRESS* in DNS A/AAAA record for this host. May be specified
   multiple times to add multiple DNS records.

.. option:: --all-ip-addresses

   Create DNS A/AAAA record for each IP address on this host.

SSSD OPTIONS
------------

.. option:: --permit

   Configure SSSD to permit all access. Otherwise the machine will be
   controlled by the Host-based Access Controls (HBAC) on the IPA
   server.

.. option:: --enable-dns-updates

   This option tells SSSD to automatically update DNS with the IP
   address of this client.

.. option:: --no-krb5-offline-passwords

   Configure SSSD not to store user password when the server is offline.

.. option:: -S, --no-sssd

   Do not configure the client to use SSSD for authentication, use
   nss_ldap instead.

.. option:: --preserve-sssd

   Disabled by default. When enabled, preserves old SSSD configuration
   if it is not possible to merge it with a new one. Effectively, if the
   merge is not possible due to SSSDConfig reader encountering
   unsupported options, **ipa-client-install** will not run further and
   ask to fix SSSD config first. When this option is not specified,
   **ipa-client-install** will back up SSSD config and create new one.
   The back up version will be restored during uninstall.

UNINSTALL OPTIONS
-----------------

.. option:: --uninstall

   Remove the IPA client software and restore the configuration to the
   pre-IPA state.

``-U, --unattended``
   Unattended uninstallation. The user will not be prompted.

FILES
=====

Files that will be replaced if SSSD is configured (default):

/etc/sssd/sssd.conf

Files that will be replaced if they exist and SSSD is not configured (--no-sssd):

| /etc/ldap.conf
| /etc/nss_ldap.conf
| /etc/libnss-ldap.conf
| /etc/pam_ldap.conf
| /etc/nslcd.conf

Files replaced if NTP client (chronyd) configuration is enabled:

/etc/chrony.conf

Files always created (replacing existing content):

| /etc/krb5.conf
| /etc/ipa/ca.crt
| /etc/ipa/default.conf
| /etc/ipa/nssdb
| /etc/openldap/ldap.conf

Files updated, existing content is maintained:

| /etc/nsswitch.conf
| /etc/krb5.keytab
| /etc/sysconfig/network

File updated, existing content is maintained if ssh is configured (default):

/etc/ssh/ssh_config

File updated, existing content is maintained if sshd is configured (default):

/etc/ssh/sshd_config

DEPRECATED OPTIONS
==================

``--request-cert``

EXIT STATUS
===========

0 if the installation was successful

1 if an error occurred

2 if uninstalling and the client is not configured

3 if installing and the client is already configured

4 if an uninstall error occurred

SEE ALSO
========

**ipa-client-automount(1),** **krb5.conf(5),** **sssd.conf(5)**
