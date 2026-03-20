# Host delegation as "namespace"

## Overview

To begin with: THIS IS NOT MULTI-TENANCY.

This design is based on a contribution from Thomas Berry at https://github.com/thomasmberry/redhat.git

This proposed design is intended to be a simplified and more robust implementation. This design breaks the ACIs into add, delete and update which will be more restrictive. It also avoids using an IPA plugin to enforce membership for a namespace. A plugin is insufficient to restrict direct changes of LDAP.

It is desirable to be able to delegate management control over a set of IPA hosts. This management would consist of a number of standard services like HBAC rules, SUDO rules and more.

An IPA host has an optional attribute visible as Class, the LDAP attribute userClass. This attribute has been available for hosts since IPA v3.2 (2013) as part of https://www.freeipa.org/page/V3/Integration_with_provisioning_systems.html . This value will be used to mark a host as part of a namespace. A host may only be a member of a single namespace.

IMPORTANT: userClass is not case sensitive so XYZ == xyz == xYz. The name of the namespace (cn) is case-sensitive so some care will be needed when comparing values. The recommendation is to require all upper-case values when creating the namespace and its delegated roles for consistency. In order to enforce this in userClass we'd have to add a normalizer to make the value upper-case but since this value has existed for over a decade its likely to impact some existing users. We should leave it alone and only enforce upper on the namespace name.

The contribution used upper-case for the namespaces so that was preserved. This author has no strong feelings either way.

The idea is to be able to group hosts at time of provisionment to be able to set the "type" of machine it is. The original purpose was to use this with automembership to put the host into an appropriate set of hostgroups. This new design extends that, though automember rules are not required.

Control over these hosts is managed via a non-POSIX group named after the namespace, e.g. XYZ.admins.

When used with other objects the namespaces are will be prefixed by the name of the namespace + dot (.). For example for the XYZ sudorules have "XYZ." as the prefix. There are some object types that allow a single entry for the namespace, automount for example. So the automount location name will match the value of the namespace (XYZ).

There are several moving parts that work in concert for this to happen:

- a group that contains members that are in a role granting access to hosts within a given namespace
- a set of permissions, privileges and a role to grant the access
- a set of hosts with userclass that puts them into the namespace

The naming of these permissions are set to include the name of the namespace. For example if the namespace is named XYZ the rules will be something like XYZ automount, XYZ HBAC rule, etc.

Delegation rules will be created for the following IPA object types:
- automount
- HBAC rule
- SUDO
- SUDO command group
- Hosts with a matching userclass
- Services for member hosts

An enrollment user for this class will be created. It can only enroll hosts when the userclass matches the namespace.

## Use Cases

There are a set of hosts for which we want delegate SUDO responsibility for a group of users to manage. These hosts are enrolled with userclass set to a unique value, say "XYZ" for hosts in a specific department. The name of a namespace must follow, at a minimum, group naming requirements.

A namespace group, XYZ.admins, will be created named "XYZ Administration".

A series of permissions, privileges and a role will be created for this delegation and the XYZ.admins group added as a member of the role.

This will grant access to members of the role to:
- Enroll hosts into the namespace by defining the userclass at host creation time.
- Create SUDO rules that are restricted to hosts within the userclass based on existing sudo commands and sudo command groups.

We will not delegate the creation of sudo commands or groups. The risk of privilege escalation is too great.

By default a namespace will have no delegated services. They will be added by the user on an as-needed basis. Follow the KISS model.

## How to Use

From a namespace administrator perspective (cn=admins), they will create a namespace and then add the service delegations to it. This will grant the least number of permissions required.

### Instructions for IPA admins

IPA admin will create the namespace which will:
* create the namespace entry
* create the namespace role
* create the namespace admin group
* create permissions and privileges for the enabled services

### Instructions for namespace admin

The host entries will be pre-created and the userclass must be set to the namespace. It will fail otherwise.

The host will be enrolled using special enrollment user which can only enroll hosts where the userclass is set to the namespace.

#### Namespace command summary (for IPA admins)

##### Add namespace

ipa namespace-add XYZ
 - creates the namespace admins group XYZ.admins
 - creates a role, XYZ Admin
 - creates host enrollment permission & privilege and add them to role

This will allow hosts to be enrolled with userclass=XYZ by those in the "XYZ Host Enroll" permission (anyone in the XYZ Admin role).

##### Add service to a namespace

ipa namespace-add-member XYZ --service hbacrule
 - The nomenclature for referencing the services is the same name as the object names, like sudorule, hbacrule, etc.
 - This will create the privilege and permissions needed and add the privileges to the role.

##### Remove service from a namespace

ipa namespace-remove-member XYZ --service hbacrule
 - Removes the permissions and privilege related to the service.

##### Listing the namespaces

ipa namespace-find

##### Displaying a single namespace

ipa namespace-show XYZ

This won't be particularly useful unless it is decided to store text strings indicating the services. Members not in cn=admins cannot read permissions, privileges or roles so this cannot be dynamically discovered.

## Design

The namespace name is used as a prefix for all namespace-related objects. Because a namespace is a group it must follow all non-POSIX group naming conventions. Additionally it cannot end with a period because that will be used as a delimiter in other naming. So the PATTERN_GROUP_NAME regex cannot be re-used directly becuase it allows a trailing period.

A new object is needed to store the namespaces. It will be simple as it is just an indicator that the namespace exists and who owns it.

It will provide the following commands:
* namespace-add: create the namespace object and associated permissions, etc.
* namespace-del: remove the namespace object and associated permissions, * etc.
* namespace-find: display all namespaces
* namespace-show: show a specific namespace
* namespace-add-member: add a member service
* namespace-del-member: remove a member service

There will be nothing to prevent cn=admins from manually creating related permissions that grant access to namespaces but should be avoided because it will introduce both confusion (what is this for?) and could introduce priviledge escalation possibilities.

The contributed system included support for subnamespacing. So for a namespace named XYZ there could be an XYZ.engineering, for example. We will not support that for a couple of reasons:
* the complexity increases for perceived little benefit
* the number of permissions could heavily increase. This could severly impact API performance.

In general, a large number, size as yet unknown, of namespaces with all services could create a performance problem for some API calls. ACIs are generally expensive so adding more of them can only hurt. This is something freeipa-perftest could conceivably measure at some point.

## Enforcement must be done in LDAP

Only a member of cn=admins can manage a namespace. This is required so that all the permissions, etc can be created or removed. We don't want to delegate the creation of them because the potential exposure is simply too great.

Two new 389-ds plugins will be required to for enforcement.

### Restrict adding service entries for hosts in the namespace

There is no way in a ACI to allow a user to add a service for a host within the namespace because there is no way to write in an ACI "allow add for service TYPE/FQDN where FQDN has userclass=XYZ and groupdn=XYZ.admins"

A plugin will be necessary to dereference the service FQDN to determine whether the associated host is within the namespace (userclass) and the user is a namespace admin. If that is true then the service can be added.

Note: I don't know exactly how this would work. Can we in fact override the ACLs?

We may need an ACL that allows members of the namespace to grant add/write/delete access to services but then enforce the userclass within the plugin.


### Restrict adding members

Namespace admins need to be allowed to manage host members within SUDO and HBAC rules. There is no way in an ACI that I can find to specify this requirement.

The plugin will validate that member changes only apply to hosts within the namespace for members in the namespace admins group.

## General rules around namespaces

Not all namespace services are mandatory. For example only SUDO can be delegated if desired. Additional delegations may be added or removed later.

hostcat=all will be prevented by not allowing a delegated user to write to this value. The whole purpose of namespaces is to only a subset of hosts so allowing hostcat=all does not fit that requirement. usercat can be delegated.

The names of namespaced permissions, privileges and the role will be hardcoded to make uniquely identifying them as easy as possible.

Namespaces will be vulnerable to a member of the admins group removing bits and pieces. For example if there is a namespace object FOO which created a group foo.admins there is nothing stopping an admin from removing that group, therefore disabling the namespace. This might be something freeipa-healthcheck could help with but the number of LDAP queries required may be extensive and we prefer healthchecks that can be completed quickly.

I do not believe that the referential integrity plugin can be relied on to do the cleanup automatically. It would involve a lot of different types of entries and could prove difficult with many namespaces. We handle cleanup manually in automount so this would not be unique.

The namespace object will be extremely simple with an objectclass of nsContainer and cn set to the name of the namespace. And that's it. It is up to members of the admins to manage namespaces. This is NOT to be delegated to users. No delegation should be made to allow creating permissions.

Namespaces will NOT work on older versions of IPA as the plugins will not be available. In fact it would be extremely dangerous to do so.

## Implementation

A new object container:

cn=namespaces,cn=accounts,$SUFFIX

The object will look like:

dn: cn=XYZ,cn=namespaces,cn=accounts,$SUFFIX
cn: XYZ
objectclass: top
objectclass: nscontainer

The list of enabled spaces (SUDO, HBAC, etc) could be tracked within the namespace if desired using a simple multi-valued attribute.

### Permissions

Users should already have read,search,compare rights to all of these objects. We only need to handle add, delete and write via these permissions.

For each object there will generally be three permissions, one for each right. Trying to do all at once within the same permission, as the contribution implemented, ends up providing more access than desired.

There may be additional permissions to grant write access to specific attributes, perhaps adding additional filters. For example, to restrict modifying members of the ipaservers hostgroup.

Delegating rights is achieved through permissions. These permissions will grant the named namespace group to do a set of operations.

For purposes of illustration these are for a namespace named XYZ.

The primary objectclass type for each container is included in the filter to restrict what kinds of entries can be managed as is done elsewhere within IPA.

#### host management

This allows for adding, removing or modifying host objects within the namespace.

##### XYZ Host Add

rights: add

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(userclass=XYZ)(objectclass=ipahost))

##### XYZ Host Delete

rights: delete

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(userclass=XYZ)(objectclass=ipahost))

##### XYZ Host Manage

rights: write

attributes:
* description
* ipaassignedidview
* ipasshpubkey
* nshardwareplatform
* nshostlocation
* nsosversion
* usercertificate

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(userclass=XYZ)(objectclass=ipahost))

#### host enrollment
Delegate enrolling a host using ipa-client-install, via ipa-join. The host must be pre-created with the namespace set.

##### XYZ Host Enroll

rights: write

attributes:
* enrolledby
* nshardwareplatform
* nshostlocation
* nsosversion
* objectclass

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(userclass=XYZ)(objectclass=ipahost))

Because issuing a certificate at enrollment is deprecated, writing to usercertificate is not provided.

##### XYZ Add krbPrincipalName to a Host

rights: write

attributes:
* krbprincipalname

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(!(krbprincipalname=*))(&(userclass=XYZ)(objectclass=ipahost)))

##### XYZ Manage Host Enrollment Password

rights: write

attributes:
* userpassword

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(userclass=XYZ)(objectclass=ipahost))

##### XYZ Manage Host Keytab

rights: write

attributes:
* ipaprotectedoperation;write_keys
* krblastpwdchange
* krbprincipalkey

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(&(userclass=XYZ)(objectclass=ipahost))(!(memberOf=cn=ipaservers,cn=hostgroups,cn=accounts,dc=example,dc=test)))

##### XYZ Manage Host Principals

rights: write

attributes:
* krbcanonicalname
* krbprincipalname

subtree: cn=computers,cn=accounts,dc=example,dc=test

extra target filter: (&(userclass=XYZ)(objectclass=ipahost))

#### service management

This allows for adding, removing or modifying service objects within the namespace.

A 389-ds plugin will be required to match userclass=XYZ of the related host entry and grant entry only to members of the XYZ.admins group. I don't know how we can restrict access to managing service entries based on a value from their host entry.

Permissions may be needed as well for this delegation but I believe work should begin with the 389-ds plugin and then any required ACIs may flow from that. They may be very simple delegations with three permissions granting access to members of the XYZ.admins group:
* XYZ Service Add
* XYZ Service Delete
* XYZ Service Manage

#### automount

For automount the namespace is the name of an automount location. The maps and keys live under the location.

##### XYZ Automount Manage Namespace

A namespace contains a single automount location named after the namespace. We give free rein to this namespace.

rights: all

attributes:
* automountinformation
* automountkey
* automountmapname
* cn
* description
* objectclass

subtree: cn=automount,dc=example,dc=test

target DN: cn=XYZ,cn=automount,dc=example,dc=test

#### sudo

All sudorules must begin with the namespace as prefix, "XYZ.".

A 389-ds plugin will be needed to enforce that host members are a member of the namespace. A sudorule add/del ACI may be needed but I think that work should begin with the plugin.

hostmask likely cannot be supported with namespaces because we cannot ensure that all hosts within the mask are always members of the namespace.

Allowing a namespace admin to allow runas* could be a route to privilege elevation and will require deeper inspection. The namespace admin is allowed to control rules on a set of hosts and since that includes sudo rules it is very possible that unwise choices could be made.

##### XYZ Sudo Rule Manage

rights: write

attributes:
* cmdcategory
* description
* externalhost
* externaluser
* ipaenabledflag
* ipasudoopt
* ipasudorunas
* ipasudorunasextgroup
* ipasudorunasextuser
* ipasudorunasgroup
* ipasudorunasusergroup
* ipasudorunasgroupcategory
* ipasudorunasusercategory
* memberallowcmd
* memberdenycmd
* memberhost
* memberuser
* sudonotafter
* sudonotbefore
* sudoorder
* usercategory

subtree: cn=sudo,dc=example,dc=test

extra target filter: (&(cn=XYZ.*)(objectclass=ipasudorule))

target DN: cn=sudo,dc=example,dc=test

#### sudocmdgroup

All command groups must begin with the namespace prefix "XYZ.".

The original design called for namespace admins to be able to create their own namespace-specific sudo command groups containing any available sudo command. This is extremely dangerous as cn=admins may create commands for their specific use (sudo /bin/bash for example).

This could be delegated if there were namespace-specific commands created by cn=admins and that pool of commands would be available for groups.

I believe in the long-run it is more straightforward for cn=admins to manage the available groups that can be added to namespace sudo rules.

#### hbac

The contribution did not allow usercat or hostcat to be set. Not allowing hostcat makes sense but its unclear what they are restricting without usercat unless they indend to add users one at a time or via groups. I believe usercat=all should be allowed.

This is another rule that lacks a way to restrict membership to only those hosts with userclass=XYZ. Additional permissions are likely necessary for add/delete granting access to XYZ.admins but the plugin should come first.

##### XYZ HBAC Rule Manage

rights: write

attributes:
* cn
* description
* ipaenabledflag
* memberhost
* memberservice
* memberuser

subtree: cn=hbac,dc=example,dc=test

extra target filter: (&(cn=XYZ.*)(objectclass=ipahbacrule))

target DN: ipauniqueid=*,cn=hbac,dc=example,dc=test


#### netgroups

Like other objects netgroups will be required to be prefixed by "namespace.", e.g XYZ.

These rules only allow for the creation, removal and minimal management of a netgroup object. Adding host members will suffer from the same limitations as other objects and will require a plugin to deal with.

##### XYZ Netgroup Add

rights: add

subtree: cn=ng,cn=alt,dc=example,dc=test

extra target filter: (&(cn=XYZ.*)(objectclass=ipanisnetgroup))

target DN: ipauniqueid=*,cn=ng,cn=alt,dc=example,dc=test

##### XYZ Netgroup Delete

rights: delete

subtree: cn=ng,cn=alt,dc=example,dc=test

extra target filter: (&(cn=XYZ.*)(objectclass=ipanisnetgroup))

target DN: ipauniqueid=*,cn=ng,cn=alt,dc=example,dc=test

##### XYZ Netgroup Manage

rights: write

attributes:
* description
* nisdomainname
* objectclass

subtree: cn=ng,cn=alt,dc=example,dc=test

extra target filter: (&(cn=XYZ.*)(objectclass=ipanisnetgroup))

target DN: ipauniqueid=*,cn=ng,cn=alt,dc=example,dc=test

#### idview

The original contribution allowed for a single idview to be created with the name of the namespace.

Delegating this authority is worrisome because one could easily create an override to allow reading/modifying another user's files, then revert back. There would be an audit but that isn't prevention, only accountability.

I've left it out of this proposal.

## Feature Management

### UI

Given how simple the namespace object is adding support to the webUI should be very straightforward. Once a user is a member of the namespace admins group they can create and modify objects as needed. It won't be obvious what rights they will have so there may be confusion.

This may affect the way that objects are visible in the webUI. These users are effectively sub-administrators so will need to be shown everything and not only self-service.

### CLI

Overview of the CLI commands. Example:

| Command |	Options |
| --- | ----- |
| ipa namespace-add | XYZ |
| ipa namespace-del | XYZ |
| ipa namespace-find | |
| ipa namespace-add-member | XYZ --service idviews |
| ipa namespace-remove-member | XYZ --service idviews |

Namespace management will not be delegated. Only members of cn=admins will be granted write access.

### Configuration

The two new 389-ds plugins will need configuration.

## Upgrade

The LDAP updater, or something new/related, will be needed to update namespace permissions in case one or more needs a revision. The names cannot be baked into update files but finding the list should be straightforward with consistent naming.

We can define the permission templates in a similar way as managed permissions and then iterate over them and replace any as needed.

It is unlikely that a namespace role or privilege would need to be updated but this should be investigated as well as part of updating the permissions. The privileges will need similar templating.

Updating namespace privileges may need to be handled in a similar way as permissions there is just a less well-defined path currently. The principal would be to have a template, then iterate over all of the namespace privileges, and compare and replace as needed.

## Test plan

This is going to require a rather massive new test suite. All delegations will need to be positively tested for what should minimally work:

* Each service can be added to a namespace
* Verify that the permission created is as expected
* Each service can be removed from a namespace
* As a delegated user, test each permission: can I add an entry? Remove it? Modify it? Add appropriate members? Add inappropriate members?
* As a delegated user can I create entries in such a way to elevate my privileges beyond the namespace? In particular SUDO and HBAC.
* As a delegated user can I modify entries such that I can inadvertently grant other users elevaged privileges? In particular SUDO and HBAC.
* Create two namespaces XYZ and XYZA. Ensure that the permissions they provide is unique across all objects.
* Remove the XYZ namespace. The XYZA namespace should be unaffected. This is a test to ensure that the search for services isn't too broad.

## Troubleshooting and debugging

This feature will rely almost entirely upon ACIs. Troubleshooting those can be cumbersome.

A few ideas:
* ensure that the service was added to the namespace
* ensure that the permissions were created
* ensure that the current user is a member of the namespace admin group (e.g XYZ.admins)
* 389-ds added configurable buffering to the errors log so that more intensive ACI debugging may be possible.
