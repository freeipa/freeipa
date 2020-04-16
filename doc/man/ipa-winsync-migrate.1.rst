.. AUTO-GENERATED FILE, DO NOT EDIT!

===========================================================================
ipa-winsync-migrate(1) -- Seamless migration of AD users created by winsync
===========================================================================
to native AD users.

SYNOPSIS
========

ipa-winsync-migrate

DESCRIPTION
===========

Migrates AD users created by winsync agreement to ID overrides in the
Default Trust View, thus preserving the actual POSIX attributes already
established.

Prior to the actual migration, the winsync replication agreement will be
removed to protect the removal of the user accounts on the Active
Directory side.

During the migration, group, assigned roles, HBAC rules and SELinux
memberships of the synced users will be preserved. Any local copies
(created by winsync) of the migrated users will be removed.

WARNINGS
========

After the migration, any PassSync agreements need to be removed from
Active Directory Domain Controllers, otherwise they might attempt to
update passwords for accounts that no longer exist on the IPA server.

OPTIONS
=======

.. option:: --realm

   The Active Directory realm the winsynced users belong to.

.. option:: --server

   The hostname of Active Directory Domain Controller the winsync
   replication agreement is established with.

.. option:: --unattended

   Never prompts for user input.
