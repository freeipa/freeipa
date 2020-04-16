.. AUTO-GENERATED FILE, DO NOT EDIT!

================================================================
ipa-nis-manage(1) -- Enables or disables the NIS listener plugin
================================================================

SYNOPSIS
========

ipa-nis-manage [options] <enable|disable|status>

DESCRIPTION
===========

Run the command with the **enable** option to enable the NIS plugin.

Run the command with the **disable** option to disable the NIS plugin.

Run the command with the **status** option to read status of the NIS
plugin. Return code 0 indicates enabled plugin, return code 4 indicates
disabled plugin.

In all cases the user will be prompted to provide the Directory
Manager's password unless option **-y** is used.

Directory Server will need to be restarted after the NIS listener plugin
has been enabled.

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

3 if RPC services cannot be enabled.

4 if status command detected plugin in disabled state.
