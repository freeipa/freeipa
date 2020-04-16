.. AUTO-GENERATED FILE, DO NOT EDIT!

===========================================================================
ipa-compat-manage(1) -- Enables or disables the schema compatibility plugin
===========================================================================

SYNOPSIS
========

ipa-compat-manage [options] <enable|disable|status>

DESCRIPTION
===========

Run the command with the **enable** option to enable the compat plugin.

Run the command with the **disable** option to disable the compat
plugin.

Run the command with the **status** to determine the current status of
the compat plugin.

In all cases the user will be prompted to provide the Directory
Manager's password unless option **-y** is used.

Directory Server will need to be restarted after the schema
compatibility plugin has been enabled.

OPTIONS
=======

.. option:: -d, --debug

   Enable debug logging when more verbose output is needed

.. option:: -y <file>

   File containing the Directory Manager password

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

2 if the plugin is already in the required status (enabled or disabled)
