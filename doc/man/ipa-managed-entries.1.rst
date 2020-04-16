.. AUTO-GENERATED FILE, DO NOT EDIT!

======================================================================
ipa-managed-entries(1) -- Enables or disables the schema Managed Entry
======================================================================
plugins

SYNOPSIS
========

ipa-managed-entries [options] <enable|disable|status>

DESCRIPTION
===========

Run the command with the **enable** option to enable the Managed Entry
plugin.

Run the command with the **disable** option to disable the Managed Entry
plugin.

Run the command with the **status** to determine the current status of
the Managed Entry plugin.

In all cases the user will be prompted to provide the Directory
Manager's password unless option **-p** is used.

Directory Server will need to be restarted after the Managed Entry
plugin has been enabled.

OPTIONS
=======

.. option:: -h, --help

   Show a help message and exit

.. option:: -d, --debug

   Enable debug logging when more verbose output is needed

.. option:: -e, --entry

   DN for the Managed Entry Definition

.. option:: -l, --list

   List available Managed Entries

.. option:: -p <DM_PASSWORD>, --password=<DM_PASSWORD>

   The Directory Manager password to use for authentication

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

2 if the plugin is already in the required status (enabled or disabled)
