.. AUTO-GENERATED FILE, DO NOT EDIT!

=======================================================================
ipa-adtrust-install(1) -- Prepare an IPA server to be able to establish
=======================================================================
trust relationships with AD domains

SYNOPSIS
========

ipa-adtrust-install [*OPTION*]...

DESCRIPTION
===========

Adds all necessary objects and configuration to allow an IPA server to
create a trust to an Active Directory domain. This requires that the IPA
server is already installed and configured.

Please note you will not be able to establish a trust to an Active
Directory domain unless the realm name of the IPA server matches its
domain name.

ipa-adtrust-install can be run multiple times to reinstall deleted
objects or broken configuration files. E.g. a fresh samba configuration
(smb.conf) file and registry based configuration can be created. Other
items like e.g. the configuration of the local range cannot be changed
by running ipa-adtrust-install a second time because with changes here
other objects might be affected as well.

Firewall Requirements
---------------------

In addition to the IPA server firewall requirements, ipa-adtrust-install
requires the following ports to be open to allow IPA and Active
Directory to communicate together:

**TCP Ports**

   · 135/tcp EPMAP

   · 138/tcp NetBIOS-DGM

   · 139/tcp NetBIOS-SSN

   · 445/tcp Microsoft-DS

   · 1024/tcp through 1300/tcp to allow EPMAP on port 135/tcp to create
   a TCP listener based on an incoming request.

   · 3268/tcp Microsoft-GC

**UDP Ports**
   · 138/udp NetBIOS-DGM

   · 139/udp NetBIOS-SSN

   · 389/udp LDAP

OPTIONS
=======

.. option:: -d, --debug

   Enable debug logging when more verbose output is needed.

.. option:: --netbios-name=<NETBIOS_NAME>

   The NetBIOS name for the IPA domain. If not provided then this is
   determined based on the leading component of the DNS domain name.
   Running ipa-adtrust-install for a second time with a different
   NetBIOS name will change the name. Please note that changing the
   NetBIOS name might break existing trust relationships to other
   domains.

.. option:: --add-sids

   Add SIDs to existing users and groups as one of the final steps of
   the ipa-adtrust-install run. If there a many existing users and
   groups and a couple of replicas in the environment this operation
   might lead to a high replication traffic and a performance
   degradation of all IPA servers in the environment. To avoid this the
   SID generation can be run after ipa-adtrust-install is run and
   scheduled independently. To start this task you have to load an
   edited version of ipa-sidgen-task-run.ldif with the ldapmodify
   command info the directory server.

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

.. option:: -U, --unattended

   An unattended installation that will never prompt for user input.

.. option:: --rid-base=<RID_BASE>

   First RID value of the local domain. The first POSIX ID of the local
   domain will be assigned to this RID, the second to RID+1 etc. See the
   online help of the idrange CLI for details.

.. option:: --secondary-rid-base=<SECONDARY_RID_BASE>

   Start value of the secondary RID range, which is only used in the
   case a user and a group share numerically the same POSIX ID. See the
   online help of the idrange CLI for details.

.. option:: -A, --admin-name=<ADMIN_NAME>

   The name of the user with administrative privileges for this IPA
   server. Defaults to 'admin'.

.. option:: -a, --admin-password=<password>

   The password of the user with administrative privileges for this IPA
   server. Will be asked interactively if **-U** is not specified.

   The credentials of the admin user will be used to obtain Kerberos
   ticket before configuring cross-realm trusts support and afterwards,
   to ensure that the ticket contains MS-PAC information required to
   actually add a trust with Active Directory domain via 'ipa trust-add
   --type=ad' command.

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

0 if the installation was successful

1 if an error occurred
