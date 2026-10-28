# ID Range: new option for private groups


## Description

SSSD provides an option to tune its behavior regarding private groups: *auto_private_groups*. Currently, this option is designed to work with **ldap** or **ad** providers and doesn’t behave properly when the provider is **ipa** and a trust is configured between IPA and AD.

The goal of this RFE is to propose the same setting at the trust level.

References:

* [BZ 1688267](https://bugzilla.redhat.com/show_bug.cgi?id=1688267) (ipa) [RFE] IPA to allow setting a new range type
* [BZ 1649464](https://bugzilla.redhat.com/show_bug.cgi?id=1649464) (sssd) auto_private_groups not working as expected with posix ipa/ad trust
* [SSSD #4216](https://github.com/SSSD/sssd/issues/4216) [RFC] IPA: allow switching off user private groups for trusted AD users

## High level overview
### Current auto private group behavior
The *auto_private_group* setting can be configured in the **DOMAIN** section of *sssd.conf*.

The *auto_private_groups* setting can take any of these 3 values:

* **true**: always create a user private group from the user’s UID number. If a GID number already exists, it is ignored.
* **false**: always use the users’ primary GID number. A group with this GID number must already exist.
* **hybrid**: a primary group is generated if the entry has UID = GID but there is no group with this GID. If UID and GID are different, a group with this GID number must already exist.

### Transposition to AD trust environments
#### Scope
When an IPA provider is used, with an AD trust, the UIDs and GIDs belong to different ID ranges:
* The users defined in IPA contain a uidNumber and gidNumber attribute, which must fit in the *ipa-local* range
* There are 2 possibilities for the users defined in AD:
  * If they contain a uidNumber and gidNumber, the trust is established with a *ipa-ad-trust-posix* range and uidNumber and gidNumber values are taken from the user entry on AD
  * If they don’t define uidNumber/gidNumber, the trust is established with a *ipa-ad-trust* range and SSSD computes uidNumber=gidNumber from the value of the user SID.

As there can be multiple ranges defined for a single ipa provider (for instance if multiple trusts are set), the *auto_private_groups* setting cannot have a domain scope and needs to be set at the **id range** level.

=> The setting needs to be added as an option to *ipa-ad-trust-posix* and *ipa-ad-trust* ranges.

#### Default behavior
When the *auto_private_groups* option is not explicitly set, it uses a default value:
* For *ipa-ad-trust-posix* range: default value = **false**. This means that the uidNumber and gidNumber of the AD entry are always used, and a group with the gidNumber must already exist.
* For *ipa-ad-trust* range: default value = **true**. This means that the uidNumber is mapped from the entry SID, the gidNumber is always set to the same value and a private group is always created.

### User stories
#### User story #1: AD trust with posix attributes, gidNumber corresponding to an existing group
As an administrator, I want to establish a trust between my IPA domain and my AD domain. My AD users contain posix attributes (uidNumber and gidNumber) that I want to use on IPA side, and the gidNumber corresponds to an existing AD group.

On any IPA client, the *id* command must return the uidNumber and gidNumber stored in AD:
```
# id aduser@AD-DOMAIN.COM
uid=uidNumber(aduser@ad-domain.com) gid=gidNumber(adgroup@ad-domain.com) groups=gidNumber(adgroup@ad-domain.com),...
```

If the gidNumber does not correspond to an existing group, the entry is not resolved.

#### User story #2: AD trust with posix attributes, gidNumber not corresponding to any group
As an administrator, I want to establish a trust between my IPA domain and my AD domain. My AD users contain posix attributes (uidNumber and gidNumber) but there is no group with the corresponding gidNumber.
On any IPA client, the id command must return the uidNumber stored in AD:
```
# id aduser@AD-DOMAIN.COM
uid=uidNumber(aduser@ad-domain.com) gid=uidNumber(aduser@ad-domain.com) groups=uidNumber(aduser@ad-domain.com),...
```
#### User story #3: AD trust with SID mapping, private group created with the uidNumber
As an administrator, I want to establish a trust between my IPA domain and my AD domain. My AD users are not posix, and their SID is mapped to an uidNumber and gidNumber on IPA. The gidNumber is equal to the uidNumber and a corresponding private group is generated.
On any IPA client, the id command must return the value computed from the SID stored in AD:
```
# id aduser@AD-DOMAIN.COM
uid=mappedValue(aduser@ad-domain.com) gid=mappedValue(aduser@ad-domain.com) groups=mappedValue(aduser@ad-domain.com),...
```
#### User story #4: AD trust with SID mapping, primary group reusing the primaryGroupID
As an administrator, I want to establish a trust between my IPA domain and my AD domain. My AD users are not posix, and their SID is mapped to an uidNumber on IPA. I want to compute the gidNumber from the RID of the AD entry’s primaryGroupID.
On any IPA client, the id command must return the value computed from the SID stored in AD:
```
# id aduser@AD-DOMAIN.COM
uid=mappedValue(aduser@ad-domain.com) gid=mappedValuePrimaryGroupID(adgroup@ad-domain.com) groups=mappedValuePrimaryGroupID(adgroup@ad-domain.com),...
```

#### Detailed behavior
##### ipa-ad-trust-posix
When the range has the *ipa-ad-trust-posix* type, the uidNumber and gidNumber are taken from the AD entry. Currently, if the gidNumber does not correspond to an existing group, the user cannot be resolved.

This situation can be fixed by setting
* *auto_private_groups=true*: a private group is created with gidNumber = uidNumber.
* *auto_private_group=hybrid*: if uidNumber=gidNumber but there is no group with this gidNumber, a private group is created with the gidNumber


auto_private_groups | true | false | hybrid
------------------- | ---- | ----- | ------
AD User entry with uidNumber=1000 gidNumber=missing | uid=1000 gid=1000 +private group | Not resolvable | Not resolvable
AD user entry with uidNumber=1000 gidNumber=2000 Group does not exist | uid=1000 gid=1000 +private group | Not resolvable | Not resolvable
AD User entry with uidNumber=1000 gidNumber=1000 Group does not exist | uid=1000 gid=1000 +private group | Not resolvable | uid=1000 gid=1000 +private group
AD User entry with uidNumber=1000 gidNumber=2000 Group exists | uid=1000 gid=1000 +private group | uid=1000 id=2000 | uid=1000 gid=2000


##### ipa-ad-trust
When the range has the *ipa-ad-trust* type, the uidNumber and gidNumber are computed from the entry’s SID. They currently both take the same value.

There are situations where the customer doesn’t want this behavior but would prefer to use the primaryGroupID set in the AD entry as gidNumber. This can be achieved by setting *auto_private_groups=false* and would solve the ticket [SSSD #4216](https://github.com/SSSD/sssd/issues/4216).


auto_private_groups | true | false | hybrid
------------------- | ---- | ----- | ------
AD User entry with SID mapped to 1000 primaryGroupID mapped to 2000 | uid=1000 gid=1000 +private group | uid=1000 gid=2000 | uid=1000 gid=2000


## Design
### IPA part
#### Schema
The LDAP schema for ID ranges needs to be modified:
* Creation of a new attribute to store the *autoprivategroups* option (with a DirectoryString type, single valued)
* Modification of the *ipaTrustedADDomainRange* objectclass in order to allow the new attribute as OPTIONAL
```
attributeTypes: (2.16.840.1.113730.3.8.23.6 NAME 'ipaAutoPrivateGroup' DESC 'Auto private groups' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 X-ORIGIN 'IPA v3' )
objectClasses: (2.16.840.1.113730.3.8.12.17 NAME 'ipaTrustedADDomainRange' SUP ipaIDrange STRUCTURAL MUST ( ipaBaseRID $ ipaNTTrustedDomainSID ) MAY ( ipaAutoPrivateGroup ) X-ORIGIN 'IPA v3' )
```

#### ID-range-related commands
*ipa idrange-add* and *ipa idrange-mod* need to provide a new option allowing to set *autoprivategroups* for the range if the range type is either *ipa-ad-trust* or *ipa-ad-trust-posix*.
*ipa idrange-find* will also allow to use *auto-private-groups* as a search criteria.
Note that *ipa-local* range should not accept the option.

```shell
# ipa idrange-add --help
[...]
  --auto-private-groups=[‘true’, ‘false’, ‘hybrid’]
                        Automatic creation of private groups, one of allowed values.
[...]
# ipa idrange-mod --help
…
  --auto-private-groups=[‘true’, ‘false’, ‘hybrid’]
                        Automatic creation of private groups, one of allowed values.
[...]
# ipa idrange-find --help
Usage: ipa [global-options] idrange-find [CRITERIA] [options]
[...]
--type=['ipa-ad-trust', 'ipa-ad-trust-posix', 'ipa-local']
                      ID range type, one of allowed values
[...]
```
*ipa idrange-show* must display the value, if any is set.
```shell
# ipa idrange-show AD-DOM.COM_id_range
[...]
  Range name: AD-DOM.COM_id_range
  First Posix ID of the range: 1136400000
  Number of IDs in the range: 200000
  First RID of the corresponding RID range: 0
  Domain SID of the trusted domain: S-1-5-21-3005052257-2375221410-442149667
  Range type: Active Directory domain range
  Auto private groups: true
[...]
```

#### Trust establishment
*ipa trust-add* command also internally creates an idrange object but the decision is **NOT** to add new parameters for *auto-private-range* at this level. The rationale is that *ipa trust-add* currently provides only a subset of the idrange options (for instance it doesn’t allow to set *--rid-base*) and the finer configuration options are set using *ipa idrange-add* or *ipa idrange-mod*.

When the sysadmin wants to set *--auto-private-range*, he needs to do
* *ipa trust-add [options] AD-REALM*: this command also creates the idrange *AD-REALM_id_range*
* *ipa idrange-mod --auto-private-groups=value AD-REALM_id_range*
* and finally reset SSSD cache: *sss_cache -E*

#### Upgrade
There is no need to handle the new option during upgrade: SSSD must be able to assign a default value to *auto_private_groups* if none is set in the id range. The default value is picked according to the range type, in accordance with the content of sssd.conf man page:
* For *ipa-ad-trust-posix* range: default value = **false**.
* For *ipa-ad-trust* range: default value = **true**.

The schema upgrade does not require specific actions: the new attribute is optional in the existing object class and the schema is replicated to the other replicas in the topology as soon as one of them is upgraded with the new schema.

