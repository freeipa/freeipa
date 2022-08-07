# Compat Tree Rebuild

**DESIGN STAGE**

## Overview

For different reasons, the compat tree maps might get corrupted and some entries
would be missing, as a consequence the compat tree is not updating after adding
or removing users from groups. 

This RFE allows to rebuild the compat tree without having to restart the LDAP
server. It provides a way to rebuild online the whole compat tree on demand via
a DS task.

## Use Cases

Many IPA users have asked for a mechanism that allows to rebuild the compat tree
after making changes without the need to restart LDAP server.

## How to Use

A new server command is available `ipa server-compat-tree-refresh`. After
adding/removing users, the admin can issue the command to make sure that the
compat tree is updated and and the changes are reflected, this way the LDAP
queries should show the modifications.

The command can	be issued in two different modes depending if the --no-wait flag is
added or not, if so, the command will return immediately, default is to wait for the
task to be completed.

## Design

During installation/upgrade process the following container in tree is added to LDAP:

    dn: cn=Schema compatibility refresh task,cn=tasks,cn=config
    objectClass: top
    objectClass: extensibleObject
    cn: Schema compatibility refresh task

Then, the admin can issue the command `ipa server-compat-tree-refresh`. This call
internally builds an entry cn=task,cn=Schema compatibility refresh task,cn=tasks,cn=config
and adds the entry to the previous container. The addition of this entry will provoke
the rebuild of the compat tree via a 389-ds task. This is following the standard behavior
for any 389-ds task [Task Invocation Via LDAP Design](https://www.port389.org/docs/389ds/design/task-invocation-via-ldap.html).

In addition to the container in tree, the implementation must contain the proper ACIs
allowing to create the task below the container. This way, it is possible to maintain
the permission and privilege to define who is allowed to create this task including
specific users/groups.

## Implementation

The server commands are extended to handle compat tree rebuild. The server plugin class grows
two additional sub commands, one for launching the task and one for listing the tasks in
progress. The show command prints the list of tasks and also accepts the name of the task.

As default, any member of the admins group is allowed to create the refresh task but any
specific user/group should be able to trigger the task if the privilege is granted.

### UI

This option is not visible through the Web UI as there is no compat tree view available.

### CLI

Overview of the CLI commands. Example:

| Command |	Options |
| --- | ----- |
| server-compat-tree-refresh | --no-wait |
| server-compat-tree-refresh-show | --task |


### Configuration

The new plugin will be registered on new installations.

## Upgrade

The plugin will be registered on upgrades.

## Test plan

TBD

## Troubleshooting and debugging

TBD

Include as much information as possible that would help troubleshooting:
- Does the feature rely on existing files (keytabs, config file...)
- Does the feature produce logs? in a file or in the journal?
- Does the feature create/rely on LDAP entries? 
- How to enable debug logs?
- When the feature doesn't work, is it possible to diagnose which step failed? Are there intermediate steps that produce logs?
