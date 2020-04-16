.. AUTO-GENERATED FILE, DO NOT EDIT!

===================================================
ipa-csreplica-manage(1) -- Manage an IPA CS replica
===================================================

SYNOPSIS
========

ipa-csreplica-manage [*OPTION*]...
[connect|disconnect|del|list|re-initialize|force-sync]

DESCRIPTION
===========

Manages the CA replication agreements of an IPA server for domain at
domain level 0.

To manage CA replication agreements in a domain at domain level 1, use
IPA CLI or Web UI, see \`ipa help topology\` for additional information.

**connect** [SERVER_A] <SERVER_B>
   Adds a new replication agreement between SERVER_A/localhost and
   SERVER_B. Applicable only at domain level 0.

**disconnect** [SERVER_A] <SERVER_B>
   Removes a replication agreement between SERVER_A/localhost and
   SERVER_B. Applicable only at domain level 0.

**del** <SERVER>
   Removes all replication agreements and data about SERVER. Applicable
   only at domain level 0.

**list** [SERVER]
   Lists all the servers or the list of agreements of SERVER

**re-initialize**
   Forces a full re-initialization of the IPA CA server retrieving data
   from the server specified with the --from option

**force-sync**
   Immediately flush any data to be replicated from a server specified
   with the --from option

**set-renewal-master** [SERVER]
   Set CA server which handles renewal of CA subsystem certificates to
   SERVER

The connect and disconnect options are used to manage the replication topology. When a replica is created it is only connected with the master that created it. The connect option may be used to connect it to other existing replicas.
The disconnect option cannot be used to remove the last link of a replica. To remove a replica from the topology use the del option.
If a replica is deleted and then re-added within a short time-frame then the 389-ds instance on the master that created it should be restarted before re-installing the replica. The master will have the old service principals cached which will cause replication to fail.

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

   Ignore some types of errors

.. option:: --from=<SERVER>

   The server to pull the data from, used by the re-initialize and
   force-sync commands.

EXAMPLES
========

List a server's replication agreements.

::

    # ipa-csreplica-manage list srv1.example.com
    srv2.example.com
    srv3.example.com

Re-initialize a replica:

::

    # ipa-csreplica-manage re-initialize --from srv2.example.com

This will re-initialize the data on the server where you execute the
command, retrieving the data from the srv2.example.com replica

Add a new replication agreement:

::

    # ipa-csreplica-manage connect srv2.example.com srv4.example.com

Remove an existing replication agreement:

::

    # ipa-csreplica-manage disconnect srv1.example.com srv3.example.com

Completely remove a replica at domain level 0:

::

    # ipa-csreplica-manage del srv4.example.com

Completely remove a replica at domain level 1:

::

    # ipa-replica-manage del srv4.example.com

Using connect/disconnect you can manage the replication topology.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

