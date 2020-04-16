.. AUTO-GENERATED FILE, DO NOT EDIT!

===============================================
ipa-kra-install(1) -- Install a KRA on a server
===============================================

SYNOPSIS
========

ipa-kra-install [*OPTION*]...

DESCRIPTION
===========

Adds a KRA as an IPA-managed service. This requires that the IPA server
is already installed and configured, including a CA.

The KRA (Key Recovery Authority) is a component used to securely store
secrets such as passwords, symmetric keys and private asymmetric keys.
It is used as the back-end repository for the IPA Password Vault.

Domain level 0 is not supported anymore.

ipa-kra-install can be used to add KRA to the existing CA, or to install
the KRA service on a replica.

KRA can only be removed along with the entire server using
ipa-server-install --uninstall.

OPTIONS
=======

.. option:: -p <DM_PASSWORD>, --password=<DM_PASSWORD>

   Directory Manager (existing master) password

.. option:: --no-host-dns

   Do not use DNS for hostname lookup during installation

.. option:: -U, --unattended

   An unattended installation that will never prompt for user input

.. option:: -v, --verbose

   Enable debug output when more verbose output is needed

.. option:: -q, --quiet

   Output only errors

.. option:: --log-file=<FILE>

   Log to the given file

.. option:: --pki-config-override=<FILE>

   File containing overrides for KRA installation.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred
