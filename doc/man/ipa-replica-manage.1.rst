.. AUTO-GENERATED FILE, DO NOT EDIT!

==============================================
ipa-replica-manage(1) -- Manage an IPA replica
==============================================

SYNOPSIS
========

ipa-replica-manage [*OPTION*]... [COMMAND]

DESCRIPTION
===========

Manages the replication agreements of an IPA server.

To manage IPA replication agreements in a domain, use IPA CLI or Web UI,
see \`ipa help topology\` for additional information.

The available commands are:

**connect** [SERVER_A] <SERVER_B>
   Adds a new replication agreement between SERVER_A/localhost and
   SERVER_B. Applicable only for winsync agreements.

**disconnect** [SERVER_A] <SERVER_B>
   Removes a replication agreement between SERVER_A/localhost and
   SERVER_B. Applicable only for winsync agreements.

**del** <SERVER>
   Removes all replication agreements and data about SERVER. Removes
   data and agreements for both suffixes - domain and ca.

**list** [SERVER]
   Lists all the servers or the list of agreements of SERVER

**re-initialize**
   Forces a full re-initialization of the IPA server retrieving data
   from the server specified with the --from option

**force-sync**
   Immediately flush any data to be replicated from a server specified
   with the --from option

**list-ruv**
   List the replication IDs on this server.

**clean-ruv** [REPLICATION_ID]
   Run the CLEANALLRUV task to remove a replication ID.

**clean-dangling-ruv**
   Cleans all RUVs and CS-RUVs that are left in the system from
   uninstalled replicas.

**abort-clean-ruv** [REPLICATION_ID]
   Abort a running CLEANALLRUV task. With --force option the task does
   not wait for all the replica servers to have been sent the abort
   task, or be online, before completing.

**list-clean-ruv**
   List all running CLEANALLRUV and abort CLEANALLRUV tasks.

**dnarange-show [SERVER]**
   List the DNA ranges

**dnarange-set SERVER START-END**
   Set the DNA range on a master

**dnanextrange-show [SERVER]**
   List the next DNA ranges

**dnanextrange-set SERVER START-END**
   Set the DNA next range on a master

The connect and disconnect options are used to manage the replication topology. When a replica is created it is only connected with the master that created it. The connect option may be used to connect it to other existing replicas.
The disconnect option cannot be used to remove the last link of a replica. To remove a replica from the topology use the del option.
If a replica is deleted and then re-added within a short time-frame then the 389-ds instance on the master that created it should be restarted before re-installing the replica. The master will have the old service principals cached which will cause replication to fail.
Each IPA master server has a unique replication ID. This ID is used by 389-ds-base when storing information about replication status. The output consists of the masters and their respective replication ID. See **clean-ruv**
When a master is removed, all other masters need to remove its replication ID from the list of masters. Normally this occurs automatically when a master is deleted with ipa-replica-manage. If one or more masters was down or unreachable when ipa-replica-manage was executed then this replica ID may still exist. The clean-ruv command may be used to clean up an unused replication ID.

**NOTE**: clean-ruv is **VERY DANGEROUS**. Execution against the wrong
replication ID can result in inconsistent data on that master. The
master should be re-initialized from another if this happens.

The replication topology is examined when a master is deleted and will attempt to prevent a master from being orphaned. For example, if your topology is A <-> B <-> C and you attempt to delete master B it will fail because that would leave masters and A and C orphaned.
The list of masters is stored in cn=masters,cn=ipa,cn=etc,dc=example,dc=com. This should be cleaned up automatically when a master is deleted. If it occurs that you have deleted the master and all the agreements but these entries still exist then you will not be able to re-install IPA on it, the installation will fail with:
An IPA master host cannot be deleted or disabled using standard commands (host-del, for example).
An orphaned master may be cleaned up using the del directive with the --cleanup option. This will remove the entries from cn=masters,cn=ipa,cn=etc that otherwise prevent host-del from working, its dna profile, s4u2proxy configuration, service principals and remove it from the default DUA profile defaultServerList.

OPTIONS
=======

.. option:: -H <HOST>, --host=<HOST>

   The IPA server to manage. The default is the machine on which the
   command is run Not honoured by the re-initialize command.

.. option:: -p <DM_PASSWORD>, --password=<DM_PASSWORD>

   The Directory Manager password to use for authentication

.. option:: -v, --verbose

   Provide additional information

.. option:: -f, --force

   Ignore some types of errors, don't prompt when deleting a master

.. option:: -c, --cleanup

   When deleting a master with the --force flag, remove leftover
   references to an already deleted master.

.. option:: --no-lookup

   Do not perform DNS lookup checks.

.. option:: --binddn=<ADMIN_DN>

   Bind DN to use with remote server (default is cn=Directory Manager) -
   Be careful to quote this value on the command line

.. option:: --bindpw=<ADMIN_PWD>

   Password for Bind DN to use with remote server (default is the
   DM_PASSWORD above)

.. option:: --winsync

   Specifies to create/use a Windows Sync Agreement

.. option:: --cacert=</path/to/cacertfile>

   Full path and filename of CA certificate to use with TLS/SSL to the
   remote server - this CA certificate will be installed in the
   directory server's certificate database

.. option:: --win-subtree=<cn=Users,dc=example,dc=com>

   DN of Windows subtree containing the users you want to sync (default
   cn=Users,<domain suffix> - this is typically what Windows AD uses as
   the default value) - Be careful to quote this value on the command
   line

.. option:: --passsync=<PASSSYNC_PWD>

   Password for the IPA system user used by the Windows PassSync plugin
   to synchronize passwords. Required when using --winsync. This does
   not mean you have to use the PassSync service.

.. option:: --from=<SERVER>

   The server to pull the data from, used by the re-initialize and
   force-sync commands.

RANGES
======

IPA uses the 389-ds Distributed Numeric Assignment (DNA) Plugin to
allocate POSIX ids for users and groups. A range is created when IPA is
installed and half the range is assigned to the first IPA master for the
purposes of allocation.

New IPA masters do not automatically get a DNA range assignment. A range assignment is done only when a user or POSIX group is added on that master.
The DNA plugin also supports an "on-deck" or next range configuration. When the primary range is exhaused, rather than going to another master to ask for more, it will use its on-deck range if one is defined. Each master can have only one range and one on-deck range defined.
When a master is removed an attempt is made to save its DNA range(s) onto another master in its on-deck range. IPA will not attempt to extend or merge ranges. If there are no available on-deck range slots then this is reported to the user. The range is effectively lost unless it is manually merged into the range of another master.
The DNA range and on-deck (next) values can be managed using the dnarange-set and dnanextrange-set commands. The rules for managing these ranges are:

-  The range must be completely contained within a local range as
   defined by the ipa idrange command.

-  The range cannot overlap the DNA range or on-deck range on another
   IPA master.

-  The range cannot overlap the ID range of an AD Trust.

-  The primary DNA range cannot be removed.

-  An on-deck range range can be removed by setting it to 0-0. The
   assumption is that the range will be manually moved or merged
   elsewhere.

The range and next range of a specific master can be displayed by passing the FQDN of that master to the dnarange-show or dnanextrange-show command.
Performing range changes as a delegated administrator (e.g. not using the Directory Manager password) requires additional 389-ds ACIs. These are installed in upgraded masters but not existing ones. The changes are made in cn=config which is not replicated. The result is that DNA ranges cannot be managed on non-upgraded masters as a delegated administrator.

EXAMPLES
========

List all masters:

::

    # ipa-replica-manage list
    srv1.example.com: master
    srv2.example.com: master
    srv3.example.com: master
    srv4.example.com: master

List a server's replication agreements.

::

    # ipa-replica-manage list srv1.example.com
    srv2.example.com: replica
    srv3.example.com: replica

Re-initialize a replica:
   # ipa-replica-manage re-initialize --from srv2.example.com

This will re-initialize the data on the server where you execute the
command, retrieving the data from the srv2.example.com replica

Add a new replication agreement:

::

    # ipa-replica-manage connect srv2.example.com srv4.example.com

Remove an existing replication agreement:
   # ipa-replica-manage disconnect srv1.example.com srv3.example.com

Completely remove a replica:

::

    # ipa-replica-manage del srv4.example.com

Using connect/disconnect you can manage the replication topology.
List the replication IDs in use:

::

    # ipa-replica-manage list-ruv
    Replica Update Vectors:
        srv1.example.com:389: 7
        srv2.example.com:389: 4
    Certificate Server Replica Update Vectors:
        srv1.example.com:389: 9

Remove references to an orphaned and deleted master:
   # ipa-replica-manage del --force --cleanup master.example.com

WINSYNC
=======

Creating a Windows AD Synchronization agreement is similar to creating
an IPA replication agreement, there are just a couple of extra steps.

A special user entry is created for the PassSync service. The DN of this
entry is uid=passsync,cn=sysaccounts,cn=etc,<basedn>. You are not
required to use PassSync to use a Windows synchronization agreement but
setting a password for the user is required.

The following examples use the AD administrator account as the
synchronization user. This is not mandatory but the user must have
read-access to the subtree.

1. Transfer the base64-encoded Windows AD CA Certificate to your IPA Server
2. Remove any existing kerberos credentials

::

     # kdestroy

3. Add the winsync replication agreement

::

     # ipa-replica-manage connect --winsync \
       --passsync=<bindpwd_for_syncuser_that will_be_used_for_agreement> \
       --cacert=/path/to/adscacert/WIN-CA.cer \
       --binddn "cn=administrator,cn=users,dc=ad,dc=example,dc=com" \
       --bindpw <ads_administrator_password> \
       -v <adserver.fqdn>

You will be prompted to supply the Directory Manager's password.
Create a winsync replication agreement:

::

    # ipa-replica-manage connect --winsync --passsync=MySecret \
      --cacert=/root/WIN-CA.cer \
      --binddn "cn=administrator,cn=users,dc=ad,dc=example,dc=com" \
      --bindpw MySecret \
      -v windows.ad.example.com

Remove a winsync replication agreement:

::

    # ipa-replica-manage disconnect windows.ad.example.com

PASSSYNC
========

PassSync is a Windows service that runs on AD Domain Controllers to
intercept password changes. It sends these password changes to the IPA
LDAP server over TLS. These password changes bypass normal IPA password
policy settings and the password is not set to immediately expire. This
is because by the time IPA receives the password change it has already
been accepted by AD so it is too late to reject it.

IPA maintains a list of DNs that are exempt from password policy. A special user is added automatically when a winsync replication agreement is created. The DN of this user is added to the exemption list stored in passSyncManagersDNs in the entry cn=ipa_pwd_extop,cn=plugins,cn=config.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred
