.. AUTO-GENERATED FILE, DO NOT EDIT!

===================================================================
ipa-client-samba(1) -- Configure Samba file server on an IPA client
===================================================================

SYNOPSIS
========

ipa-client-samba [*OPTION*]...

DESCRIPTION
===========

Configures a Samba file server on the client machine to use IPA domain
controller for authentication and identity services.

The tool configures Samba file server to be a domain member of IPA
domain. Samba file server will use SSSD to resolve information about
users and groups, and will use IPA master it is enrolled against as its
domain controller.

It is not possible to reconciliate original Samba environment if that
was pre-existing on the client with new configuration. Samba databases
will be updated to follow IPA domain details and **smb.conf**
configuration will will be overwritten. It is recommended to enable
Samba suite on a freshly deployed IPA client.

During the configuration process, the tool will perform following steps:

1. Discover details of IPA domain: realm, domain SID, domain ID range

2. Discover details of trusted Actvide Directory domains: domain name,
domain SID, domain ID range

3. Create Samba configuration file using the details discovered above.

4. Create Samba Kerberos service using host credentials and fetch its
keytab into /etc/samba/samba.keytab. The Kerberos service key is pre-set
to a randomly generated value that is shared with Samba.

5. Populate Samba databases by setting the domain details and the
randomly generated machine account password from the previous step.

6. Create a default [homes] share to allow users to log in to their home
directories unless --no-homes option was specified.

The tool does not start nor does it enable Samba file services after the configuration. In order to enable and start Samba file services, one needs to enable both **smb.service** and **winbind.service** system services. Please check that **/etc/samba/smb.conf** contains all settings for your use case as starting Samba service will make identity mapping details written into the Samba databases. To enable and start Samba file services at the same time one can use **systemctl enable --now** command:

systemctl enable --now smb winbind

Assumptions
-----------

The ipa-client-samba script assumes that the machine has alreaby been
enrolled into IPA.

IPA Master Requirements
-----------------------

At least one IPA master must hold a **Trust Controller** role. This can
be achieved by running ipa-adtrust-install on the IPA master. The
utility will configure IPA master to be a domain controller for IPA
domain.

IPA master holding a **Trust Controller** role has also to have support
for a special service command to create SMB service, **ipa
service-add-smb**. This command is available with FreeIPA 4.8.0 or later
release.

OPTIONS
=======

BASIC OPTIONS
-------------

.. option:: --server=<SERVER>

   Set the FQDN of the IPA server to connect to. Under normal
   circumstances, this option is not needed as the server to use is
   discovered automatically.

.. option:: --no-homes

   Do not configure a **[homes]** share by default to allow users to
   access their home directories.

.. option:: --no-nfs

   Do not enable SELinux booleans to allow Samba to re-share NFS shares.

.. option:: --netbios-name=<NETBIOS_NAME>

   NetBIOS name of this machine. If not provided then this is determined
   based on the leading component of the hostname.

.. option:: -d, --debug

   Print debugging information to stdout

.. option:: -U, --unattended

   Unattended installation. The user will not be prompted.

.. option:: --uninstall

   Revert Samba suite configuration changes and remove SMB service
   principal. It is not possible to preserve original Samba
   configuration: while **smb.conf** configuration file will be
   restored, various Samba databases would not be restored. In general,
   it is not possible to restore full original Samba environment.

.. option:: --force

   Force through the installation steps even if they were done before

FILES
=====

Files that will be replaced if Samba is configured:

| /etc/samba/smb.conf
| /etc/samba/samba.keytab

EXIT STATUS
===========

0 if the installation was successful

1 if an error occurred

SEE ALSO
========

**smb.conf(5),** **krb5.conf(5),** **sssd.conf(5),** **systemctl(1)**
