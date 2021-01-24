# Include users and groups from a trusted Active Directory domain into SUDO rules

Allow users and groups from trusted Active Directory forests to be directly
added to SUDO rules.

## Use Cases

* As an FreeIPA administrator, I want to add AD users and groups directly to SUDO
  rules without creating an indirect POSIX group membership for them.

## Design

### FreeIPA integration

FreeIPA manages and stores SUDO rules in LDAP and SSSD retrieves the rules
related to the specific host it runs on. The rules are then provided to SUDO
via a special SUDOERS plugin which is talking to SSSD.

SUDOERS allows multiple ways of expressing users and groups as a part of the rule.

According to the SUDOERS manual page, the following syntax is supported:

```console
     User ::= '!'* user name |
              '!'* #uid |
              '!'* %group |
              '!'* %#gid |
              '!'* +netgroup |
              '!'* %:nonunix_group |
              '!'* %:#nonunix_gid |
              '!'* User_Alias
```

> A `User_List` is made up of one or more user names, user-IDs (prefixed with ‘#’),
> system group names and IDs (prefixed with `%` and `%#` respectively), netgroups
> (prefixed with ‘+’), non-Unix group names and IDs (prefixed with `%:` and `%:#`
> respectively) and `User_Aliases`. Each list item may be prefixed with zero or
> more `!` operators.  An odd number of `!` operators negate the value of the
> item; an even number just cancel each other out.  User netgroups are matched
> using the user and domain members only; the host member is not used when
> matching.

As can be seen from the SUDOERs definition of a `User`, any object that maps
into a user or a group is allowed.  LDAP schema used to model SUDO rules in
FreeIPA does require SUDO `User` references to be real LDAP objects. In order
to support non-LDAP objects both FreeIPA and SSSD support a special attribute
`externalUser`. `externalUser` is a string that is merged with other `User`
references at SSSD side.

SSSD already supports querying with first five forms. When SUDO rules are
retrieved from FreeIPA, the references for groups are converted to `%group`
format in SSSD database. Correspondingly, ID-based forms (`#uid` and `%#gid`)
are added as well.  It does not, however, support queries for non-Unix group
names and IDs.

SSSD team decided to not support `%:nonunix_group` and `%:nonunix_gid` syntax.
Without changes on SSSD side it will be not possible to support them.

Since in FreeIPA environment all AD users and groups resolvable by SSSD will
have POSIX attributes, they can be queried with the first four name forms.

### Implementation

FreeIPA framework's LDAP abstraction layer allows to validate and transform
membership information when members are added to 'group' objects or removed
from them. SUDO rules represent one such 'group' object.

LDAP abstraction layer provides `add_external_pre_callback()` method that
allows to redefine validators used to validate member names. Originally this
was done to allow hostname validation and reused default validators associated
with a parameter type associated with a specific parameter.

We extend `add_external_pre_callback()` to provide per-object validator
callbacks.

Validator callbacks can be extended to allow a fine grained validation
strategy.  This is helpful to apply an alternative validation strategy in the
case a default validator fails.

New validators can be added to `member_validator` registry in a similar
way to how API objects are registered:

```python
from .baseldap import member_validator

@member_validator(membertype='foo')
def my_new_validator(ldap, dn, keys, options, value):
    <validate value here>
```

Arguments passed to the validator are arguments passed to the
`add_external_pre_callback()` augmented with the value to validate.

This approach provides a general method to extend validation mechanism for any
parameter.  The feature utilizes existing infrastructure for resolving objects
from trusted Active Directory forests provided by ID views plugin. Any user or
group from a trusted Active Directory domain can be resolved in the validator
and mapped to a user or group member type for SUDO rule inclusion.

Since `options` dictionary is the only object shared between the caller to
`add_external_pre_callback()` and the member type validator, ID views' member
type validator returns all validated values as a list stored as a
`trusted_objects` element of the `options` dictionary.

SUDO rule plugin implementation then processes the translated trusted object
members reported after calling the `add_external_pre_callback()`. Each
translated member is the one not found in LDAP as a direct reference and found
in a trusted domain. All these members are then added to `externalUser`
attribute.

Note that direct manipulation of `externalUser` attribute through IPA
parameters is not allowed since 2011 (FreeIPA tickets
https://pagure.io/freeipa/issue/1320). With membership validation method SUDO
rules can now handle those members through the normal `--users` mechanism.

Same approach is used to provide handling of `RunAs_Member` specification
which is mapped to either `ipaSudoRunAsExtUser` or `ipaSudoRunAsExtGroup`.

#### Web UI

Web UI already allows to specify external users and groups in SUDO rules. Names
provided by the user weren't validated, now they are verified to belong to
trusted domains.

### Upgrade and migration

The changes to plugins do not require any schema updates because there are no
LDAP schema changes.

## Usage

In order to add an Active Directory user to a SUDO rule, there must be a trust
established to the Active Directory forest where a domain of the user is
located. Any modification of SUDO rules with Active Directory users and groups
should happen on Trust Controllers or Trust Agents because other IPA replica
types are unable to validate AD users and group.

### Sample usage

Below example shows a generic usage of SUDO rules with AD users. It assumes we
want to allow an Active Directory user(s) ability to operate on all hosts and
all commands without authentication. In real life it is not recommended to
grant so wide access.

1.  As admin, create an HBAC rule to permit all users to run SUDO on all hosts:
```console
   ipa hbacrule-add hbacrule --usercat=all --hostcat=all
   ipa hbacrule-add-service hbacrule --hbacsvcs=sudo
```

2. As an admin, create SUDO rule that allows to run all commands on all hosts:
```console
   ipa sudocmd-add ALL
   ipa sudorule-add sudorule --hostcat=all
   ipa sudorule-add-option sudorule --sudooption '!authenticate'
   ipa sudorule-add-allow-command sudorule --sudocmds ALL
```

2.  Add `ad-user\@ad.example.test` to the SUDO rule:
```console
   ipa sudorule-add-user sudorule --users ad-user@ad.example.test
```

3. Alternatively, add an Active Directory group `somegroup@ad.example.test` to the SUDO rule:
```console
   ipa sudorule-add-user sudorule --groups 'somegroup@ad.example.test'
```

4. On an IPA-enrolled client, perform SUDO access as an Active Directory user:
```console
   # su - ad-user@ad.example.test -c 'sudo -l'
   Matching Defaults entries for ad-user@ad.example.test on client:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

   User ad-user@ad.example.test may run the following commands on master:
    (root) NOPASSWD: ALL
```

5. To limit rule execution to a specific user and/or group, `runAsUser` and
   `runAsGroup` properties can be set individually:
```console
   ipa sudorule-add-runasuser sudorule --users 'ad-user@ad.example.test'
   ipa sudorule-add-runasgroup sudorule --groups 'somegroup@ad.example.test'
```

6. The limits will be reflected in `sudo -l` output:
```console
   # su - ad-user@ad.example.test -c 'sudo -l'
   Matching Defaults entries for ad-user@ad.example.test on client:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

   User ad-user@ad.example.test may run the following commands on master:
    (ad-user@ad.example.test : "%somegroup@ad.example.test") NOPASSWD: ALL
```

