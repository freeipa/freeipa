.. AUTO-GENERATED FILE, DO NOT EDIT!

====================================
ipa(1) -- IPA command-line interface
====================================

SYNOPSIS
========

::

   ipa [options] [-c FILE] [-e KEY=VAL] COMMAND [parameters]

DESCRIPTION
===========

IPA is an integrated security information management solution based on
389 Directory Server (formerly know as Fedora Directory Server), MIT
Kerberos, Dogtag Certificate System and DNS. It includes a web interface
and command-line administration tools for managing identity data.

This manual page focuses on the *ipa* script that serves as the main
command-line interface (CLI) for IPA administration.

More information about the project is available on its homepage located
at http://www.freeipa.org.

OPTIONS
=======

.. option:: -c <FILE>

   Load configuration from *FILE*.

.. option:: -d, --debug

   Produce full debugging output.

.. option:: --delegate

   Delegate the user's TGT to the IPA server

.. option:: -e <KEY=VAL>

   Set environmental variable *KEY* to the value *VAL*. This option
   overrides configuration files.

.. option:: -h, --help

   Display a help message with a list of options.

.. option:: -n, --no-prompt

   Don't prompt for any parameters of **COMMAND**, even if they are
   required.

.. option:: -a, --prompt-all

   Prompt for all parameters of *COMMAND*, even if they are optional.

.. option:: -f, --no-fallback

   Don't fall back to other IPA servers if the default doesn't work.

.. option:: -v, --verbose

   Produce verbose output. A second -v pretty-prints the JSON request
   and response. A third -v displays the HTTP request and response.

.. option:: --version

   Display the IPA version and API version.

COMMANDS
========

The principal function of the CLI is to execute administrative commands
specified by the *COMMAND* argument. The majority of commands are
executed remotely over XML-RPC on a IPA server listed in the
configuration file (see FILES section of this manual page).

From the implementation perspective, the CLI distinguishes two types of
commands - built-ins and plugin provided.

Built-in commands are static and are all available in all installations
of IPA. There are two of them:

**console**
   Start the IPA interactive Python console.

**help** [*TOPIC* \| *COMMAND* \| **topics** \| **commands**]
   Display help for a command or topic.

The **help** command invokes the built-in documentation system. Without
parameters a list of built-in commands and help topics is displayed.
Help topics are generated from loaded IPA plugin modules. Executing
**help** with the name of an available topic displays a help message
provided by the corresponding plugin module and list of commands it
contains.

Plugin provided commands, as the name suggests, originate from IPA
plugin modules. The available set may vary depending on your
configuration and can be listed using the built-in **help** command (see
above).

Most plugin provided commands are tied to a certain type of IPA object.
IPA objects encompass common abstractions such as users (user
identities/accounts), hosts (machine identities), services, password
policies, etc. Commands associated with an object are easily identified
thanks to the enforced naming convention; the command names are composed
of two parts separated with a dash: the name of the corresponding IPA
object type and the name of action performed on it. For example all
commands used to manage user identities start with "user-" (e.g.
user-add, user-del).

The following actions are available for most IPA object types:

**add** [*PRIMARYKEY*] [options]
   Create a new object.

**show** [*PRIMARYKEY*] [options]
   Display an existing object.

**mod** [*PRIMARYKEY*] [options]
   Modify an existing object.

**del** [*PRIMARYKEY*]
   Delete an existing object.

**find** [*CRITERIA*] [options]
   Search for existing objects.

The above types of commands except **find** take the objects primary key
(e.g. user name for users) as their only positional argument unless
there can be only one object of the given type. They can also take a
number of options (some of which might be required in the case of
**add**) that represent the objects attributes.

**find** commands take an optional criteria string as their only
positional argument. If present, all objects with an attribute that
contains the criteria string are displayed. If an option representing an
attribute is set, only object with the attribute exactly matching the
specified value are displayed. Options with empty values are ignored.
Without parameters all objects of the corresponding type are displayed.

For IPA objects with attributes that can contain references to other
objects (e.g. groups), the following action are usually available:

**add-member** [*PRIMARYKEY*] [options]
   Add references to other objects.

**remove-member** [*PRIMARYKEY*] [options]
   Remove references to other objects.

The above types of commands take the objects primary key as their only
positional argument unless there can be only one object of the given
type. They also take a number of options that represent lists of other
object primary keys. Each of these options represent one type of object.

For some types of objects, these commands might need to take more than
one primary key. This applies to IPA objects organized in hierarchies
where the parent object needs to be identified first. Parent primary
keys are always aligned to the left (higher in the hierarchy = more to
the left). For example the automount IPA plugin enables users to manage
automount maps per location, as a result all automount commands take an
automountlocation primary key as their first positional argument.

All commands that display objects have three special options for
controlling output:

.. option:: --all

   Display all attributes. Without this option only the most relevant
   attributes are displayed.

.. option:: --raw

   Display objects as they are stored in the backing store. Disables
   formatting and attribute labels.

.. option:: --rights

   Display effective rights on all attributes of the entry. You also
   have to specify ``**--all**`` for this to work. User rights are returned
   as Python dictionary where index is the name of an attribute and
   value is a unicode string composed (hence the u'xxxx' format) of
   letters specified below. Note that user rights are primarily used for
   internal purposes of CLI and WebUI.

r - read s - search w - write o - obliterate (delete) c - compare W -
self-write O - self-obliterate

EXAMPLES
========

**ipa help commands**
   Display a list of available commands **ipa help topics** Display a
   high-level list of help topics **ipa help user** Display
   documentation and list of commands in the "user" topic.

**ipa env**
   List IPA environmental variables and their values.

**ipa user-add foo --first foo --last bar**
   Create a new user with username "foo", first name "foo" and last name
   "bar".

**ipa group-add bar --desc "this is an example group"**
   Create a new group with name "bar" and description "this is an
   example group".

**ipa group-add-member bar --users=foo**
   Add user "foo" to the group "bar".

**ipa group-add-member bar --users={admin,foo}**
   Add users "admin" and "foo" to the group "bar". This approach depends
   on shell expansion feature.

**ipa user-show foo --raw**
   Display user "foo" as (s)he is stored on the server.

**ipa group-show bar --all**
   Display group "bar" and all of its attributes.

**ipa config-mod --maxusername 20**
   Set maximum user name length to 20 characters.

**ipa user-find foo**
   Search for all users with "foo" in either uid, first name, last name,
   full name, etc. A user with uid "foobar" would match the search
   criteria.

**ipa user-find foo --first bar**
   Same as the previous example, except this time the users first name
   has to be exactly "bar". A user with uid "foobar" and first name
   "bar" would match the search criteria.

**ipa user-find foo --first bar --last foo**
   A user with uid "foobar", first name "bar" and last name "foo" would
   match the search criteria.

**ipa user-find**
   All users would match the search criteria (as there are none).

SERVERS
=======

The ipa client will determine which server to connect to in this order:

1. The server configured in **/etc/ipa/default.conf** in the *xmlrpc_uri* directive.
2. An unordered list of servers from the ldap DNS SRV records.

If a kerberos error is raised by any of the requests then it will stop processing and display the error message.

ENVIRONMENT VARIABLES
=====================

**IPA_CONFDIR**
   Override path to confdir (default: **/etc/ipa**).

FILES
=====

**/etc/ipa/default.conf**
   IPA default configuration file.

EXIT STATUS
===========

0 if the command was successful

1 if an error occurred

2 if an entry is not found

SEE ALSO
========

ipa-client-install(1), ipa-compat-manage(1), ipactl(1),
ipa-dns-install(1), ipa-getcert(1), ipa-getkeytab(1), ipa-join(1),
ipa-ldap-updater(1), ipa-nis-manage(1), ipa-replica-install(1),
ipa-replica-manage(1), ipa-replica-prepare(1), ipa-rmkeytab(1),
ipa-server-certinstall(2), ipa-server-install(1), ipa-server-upgrade(1)
