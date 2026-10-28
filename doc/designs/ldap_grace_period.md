# LDAP Grace Period

## Overview

IPA previously allowed LDAP authentications past expiration to prevent a chicken-and-egg problem. Because all administratively-set passwords are expired a user must be given an opportunity to authenticate in order to reset their password. This allowed for unlimited authentications.

## Use Cases

Many IPA users have asked for a mechanism to deny LDAP authentications once expired.

## How to Use

A new option is added to password policies, --gracelimit. This specifies the number of allowed BINDs past expiration.

To set the global policy:

ipa pwpolicy-mod --gracelimit 3

This will allow 3 additional logins past expiration.

Setting to -1 disables the grace limit check.

Setting to 0 will do a grace limit check but will always fail because no further logins are allowed. The distinction between 0 and -1 is that with 0 a password policy control is returned.

## Design

An expired draft around LDAP password policies describes two methods for limiting account access past expiration, https://tools.ietf.org/id/draft-behera-ldap-password-policy-10.html

The RFE provides two options (which can be use simultaneously).

1. Limit the number of authentications past expiration
2. Limit by time past the expiration

This implements the first part only. 389-ds already implements this so we can reuse existing schema, using their alternative attribute names passwordGraceLimit (system) and passwordGraceUserTime (user).

A 389-ds plugin will be registered as a bind preop function which will compare the policy grace period with the user's grace period

The password policy plugin will have a new attribute added, passwordGraceLimit, to store the policy maximum.

The basic flow is:

- Register preop BIND plugin
- On BIND, get the DN
- Get the password policy for that DN
- If the policy grace limit == -1 then exit
- Compare the policy grace limit to the user's passwordGraceUserTime
- If the user's grace limit exceeds policy, fail
- If the grace limit == 0, fail
- Set a password policy control with the number of remaining logins
- Set the time in the policy to -1 to indicate no value

On successful password reset (by anyone) reset the user's passwordGraceUserTime to 0.

Range values for passwordgracelimit are:

-1 : password grace checking is disabled
 0 : no grace BIND are allowed at all post-expiration
 1..MAXINT: the number of BIND allowed post-expiration

The default value for the global policy on install/upgrade will be -1 to
retain existing behavior.

New group password policies will default to -1 to retain previous
behavior.

Existing group policies with no grace limit set are updated to use
the default unlimited value, -1. This is done because lack of value in
LDAP is treated as 0 so any existing group policies would not allow
post-expiration BIND so this will avoid confusion.

The per-user attempts will not be replicated.

## Implementation

N/A

## Feature Management

### UI

The new option is not visible in the UI yet.

### CLI

Overview of the CLI commands. Example:

| Command |	Options |
| --- | ----- |
| pwpolicy-mod | --gracelimit=<-1 to MAXINT> |

### Configuration

The plugin will be registered on new installations.

## Upgrade

The plugin will be registered on upgrades.

## Test plan

1. Set a grace limit on a custom policy, ldapsearch a few times, verify that the limit is set to what is expected
2. Keep going until authentication fails
3. Reset password, verify that authentication can happen
4. With two servers verify that an authentication one one server doesn't trigger a replication event to the other.

## Troubleshooting and debugging

$ ldapsearch -LLL -x -D 'uid=tuser,cn=users,cn=accounts,dc=example,dc=test' -w password -e ppolicy -b uid=tuser,cn=users,cn=accounts,dc=example,dc=test dn
# PasswordExpired control
ldap_bind: Success (0) (Password expired, 3 grace logins remain)
dn: uid=tuser,cn=users,cn=accounts,dc=example,dc=test
