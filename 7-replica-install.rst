Unit 7: Replica installation
==============================

**Prerequisites**:

- `Unit 1: Installing the FreeIPA server <1-server-install.rst>`_

FreeIPA is designed to be run in a replicated multi-master
environment.  In this unit, we will deploy a single FreeIPA
replica.  For recommended production topologies, see
http://www.freeipa.org/page/Deployment_Recommendations#Replicas.

If you have disabled the ``allow_all`` HBAC rule, add a new rule
that will **allow ``admin`` to access the ``sshd`` service on any
host**.

[To be confirmed] As of FreeIPA 4.3, replica installation is accomplished by
*promoting* an enrolled client machine to a server.

SSH to the ``replica`` VM and enrol it per `Unit 2: Enrolling
client machines`_.

Now promote the client to server.  We will set up the replica
*without* CA or DNS, but in a production deployment there should be
at least one instance of these services in each datacentre.  These
components can be added later via ``ipa-ca-install(1)`` and
``ipa-dns-install(1)``.

::

  [replica]$ sudo ipa-replica-install
  Password for admin@IPADEMO.LOCAL:
  ipaserver.install.server.replicainstall: ERROR    Reverse DNS resolution of address 192.168.33.10 (server.ipademo.local) failed. Clients may not function properly. Please check your DNS setup. (Note that this check queries IPA DNS directly and ignores /etc/hosts.)
  Continue? [no]: yes
  Run connection check to master
  Connection check OK
  Configuring directory server (dirsrv). Estimated time: 30 seconds
    [1/41]: creating directory server instance
    [2/41]: enabling ldapi
  ...

The rest of the replica installation process is almost identical to
server installation.  One important difference is the initial
replication of data to the new Directory Server instance::

  [28/41]: setting up initial replication
  Starting replication, please wait until this has completed.
  Update in progress, 4 seconds elapsed
  Update succeeded

After ``ipa-replica-install`` finishes, the replica is operational.
LDAP changes on any server will be replicated to all other servers.

You can proceed to
`Unit 8: Sudo rule management <8-sudorule.rst>`_
or
`return to the curriculum overview <workshop.rst#curriculum-overview>`_
to see all the available topics.
