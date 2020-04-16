.. AUTO-GENERATED FILE, DO NOT EDIT!

===========================================
ipa-server-upgrade(1) -- upgrade IPA server
===========================================

SYNOPSIS
========

ipa-server-upgrade [options]

DESCRIPTION
===========

ipa-server-upgrade is used to upgrade IPA server when the IPA packages
are being updated. It is not intended to be executed by end-users.

ipa-server-upgrade will:

\* update LDAP schema \* process all files with the extension .update in
/usr/share/ipa/updates (including update plugins). \* upgrade local
configurations of IPA services

OPTIONS
=======

.. option:: --skip-version-check

   Skip version check. WARNING: this option may break your system

.. option:: --force

   Force upgrade (alias for --skip-version-check)

.. option:: --version

   Show IPA version

.. option:: -h, --help

   Show help message and exit

.. option:: -v, --verbose

   Print debugging information

.. option:: -q, --quiet

   Output only errors

.. option:: --log-file=FILE

   Log to given file

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred
