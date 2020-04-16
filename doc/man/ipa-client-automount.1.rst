.. AUTO-GENERATED FILE, DO NOT EDIT!

==============================================================
ipa-client-automount(1) -- Configure automount and NFS for IPA
==============================================================

SYNOPSIS
========

ipa-client-automount [*OPTION*]... <location>

DESCRIPTION
===========

Configures automount for IPA.

The automount configuration consists of three files:

o. /etc/nsswitch.conf

p. /etc/sysconfig/autofs

q. /etc/autofs_ldap_auth.conf

By default this will use DNS discovery to attempt to determine the IPA server(s) to use. If IPA servers are discovered then the automount client will be configured to use DNS discovery.
If DNS discovery fails or a specific server is desired, use the --server option.
The default automount location is named default. To specify a different one use the --location option.
The IPA client must already be configured in order to configure automount. The IPA client is configured as part of a server installation.
There are two ways to configure automount. The default is to use sssd to manage the automount maps. Alternatively autofs can configured to bind to LDAP over GSSAPI and authenticate using the machine's host principal.
The nsswitch automount service is configured to use either sss or ldap and files depending on whether SSSD is configured or not.
NFSv4 is also configured. The rpc.gssd and rpc.idmapd are started on clients to support Kerberos-secured mounts.

OPTIONS
=======

.. option:: --server=<SERVER>

   Set the FQDN of the IPA server to connect to.

.. option:: --location=<LOCATION>

   Automount location.

.. option:: -S, --no-sssd

   Do not configure the client to use SSSD for automount.

.. option:: --idmap-domain=<IDMAP_DOMAIN>

   NFS domain for idmapd.conf. If unset, defaults to the IPA domain. If
   set to DNS, let idmapd or nfsidmap determine the domain from DNS (see
   idmapd(8) or nfsidmap(5) for details). If set to anything else, set
   idmapd.conf's Domain entry to that value.

.. option:: -d, --debug

   Print debugging information to stdout.

.. option:: -U, --unattended

   Unattended installation. The user will not be prompted.

.. option:: --uninstall

   Restore the automount configuration files.

FILES
=====

Files that will be always be configured:

/etc/nsswitch.conf

Files that will be configured when SSSD is the automount client (default):

/etc/sssd/sssd.conf

Files that will be configured when using the ldap automount client:

/etc/sysconfig/autofs

/etc/autofs_ldap_auth.conf

EXIT STATUS
===========

0 if the installation was successful

1 if an error occurred

2 if uninstalling and automount is not configured

3 if installing and automount already configured
