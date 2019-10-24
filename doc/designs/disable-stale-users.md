# Disable Stale Users

**DESIGN STAGE**

## Overview

Some regulations call for accounts that have not been used for a specific
amount of time be automatically disabled in the identity management system.

FreeIPA does not keep track of successful authentication events.
The krbLastSuccessfulAuth attribute is not updated by default since
https://pagure.io/freeipa/issue/5313 for reliability reasons.
Therefore distinguishing between stale and active accounts cannot be done with
existing logon data.


## Possible approaches

### Environments with mandatory, periodic password changes

The problem is easy to solve in environments where user passwords must be
changed regularly. A user account whose associated password is past its due
change date can be considered stale and therefore be disabled by the system.
In this case, a grace period must be provided between password expiration and
the actual account locking event.
Total writes to LDAP using this approach due to the disable stale users tooling
are minimal (only nsAccountLock). However, password-change related writes are
needed every 90 days (by default).
Each password change updates the krbLastPwdChange, krbPasswordExpiration,
userPassword, krbPrincipalKey, and krbExtraData attributes.

The Disable Stale Users (DSU) tooling proposes to make sure no non-locked
account has a password expired since N days, N being 7 by default.

### Environments with no mandatory password changes

For environments where user passwords never expire, a new mechanism must be
added to FreeIPA plugins ipa-kdb and ipa-lockout to account for each user
account authentication events. Since updating a LDAP user account attribute on
each authentication event must be avoided as the update frequency could easily
be high, (see https://pagure.io/freeipa/issue/5313 for background
information), a coarse update mechanism is proposed.

An attribute containing a timestamp is added to each user:
coarseSuccessfulAuthTime. It will be added at account creation time (set to
current date).
The timestamp contained therein is not precise. It is updated by IPA plugins
whenever a successful authentication event happens, but only if the current
timestamp is sufficiently in the past. The update interval is configurable, but
to avoid replication storms, it is randomized. To achieve this, a randomized
value is added to a fixed time interval.

Some attributes must be added to the cn=ipaConfig schema:
* the first one to activate the mechanism (default: not present):
```
ipaConfigString: DSU:RecordSuccessfulAuth
```
* the second attribute contains the fixed time period (default: 28 days):
```
ipaDSURecordSucessfulAuthTimeInterval: 2419200
```
* the third one contains a time period to be added. The actual value used is
  randomized between 0 and the attribute's value (default: 7 days) whenever
  a user successfully authenticates. 
```
ipaDSURecordSucessfulAuthRandomizedTimeInterval: 604800
```

Updating this (replicated) timestamp attribute every ~30 days requires less
LDAP writes than mandating password changes every 90 days as the latter would
imply updating five (replicated) attributes at least once in that 90-day
period.

The Disable Stale Users (DSU) tooling, when the above mechanism is active,
proposes to make sure no non-locked account has a timestamp attribute 90 days
(by default) in the past.

On a successful authentication event:

```
current_date = datetime.now(timezone.utc)
last_update = coarseSuccessfulAuthTime
update_internal = ipaDSURecordSucessfulAuthTimeInterval
                  + randint(0, ipaDSURecordSucessfulAuthRandomizedTimeInterval)
if current_date - last_update > update_internal:
    coarseSuccessfulAuthTime = current_date
```

As a rule of thumb, if the requirement is to disable users not seen for 90 days
maximum, updating the attribute roughly every 35 days is good enough.
At worst, the user would have authenticated the first day and the last day of
the 35-day maximum update interval and the randomized time interval would have
been 7 days. 
The attribute would therefore contain the date from the first day, as day #35
would have been considered too close to the existing timestamp to warrant
updating it. DSU would then proceed to disable the user account 90 days after
the existing coarseSuccessfulAuthTime timestamp - this is only after 55 day
(90-35) of real inactivity, which fits the requirement (albeit loosely).

Having a 90-day inactive user disabling requirement would by default disable
accounts really inactive for 55 (90-35) to 90 days.

In short:

```
if (current_date - 90d) > coarseSuccessfulAuthTime:
    disable_account()
```

The 90-day default value is configurable (see appropriate section below).


### Notes

Installing the DSU tooling will not change the behavior of existing clusters.
DSU has to be explicitly configured and enabled to start disabling stale
accounts.

Accounts are locked out by setting the nsAccountLock attribute
(OID: 2.16.840.1.113730.3.1.610) to True.

FreeeIPA is not directly involved when a user logs in using an ssh key so it
cannot make decisions on whether an account is "active" or not. However,
setting nsaccountlock = TRUE will block all logins including those using ssh
key authentication.
For passwordless environments, S4U2Self is proposed to be added to SSSD to
account for successful user logon events through ipa-kdb:
https://pagure.io/SSSD/sssd/issue/4077
The mechanism laid out in "Environments with no mandatory password changes"
would then be applied as-is.

There is always the possibility that a long-inactive user account will be
disabled (nsAccountLock'd) by DSU even if that user managed to logon the
previous few seconds before or during the DSU window due to:
* the time it takes for the timestamp attribute to be replicated to the DSU
runner
* the time it takes for nsAccountLock to be replicated from the DSU runner
to the replica this user uses.

There is no way to prevent that from happening with the present design, but
the probability of that happening is low.


## Example

### Environments with mandatory, periodic password changes

Given the following requirements and facts:
* stale accounts must be disabled after 90 days' inactivity
* grace period is decided to be 7 days
* the tool runs every day
* replication is expected to complete in 2h maximum

setting the maximum password lifetime to 80 days or less would meet the
guidelines as 80+7+1 (give or take 2h) is less than 90.

### Environments with no mandatory password changes

If the requirement is to disable users not seen for 90 days maximum, updating
the attribute every 35 days is good enough.
At worst, the user would have authenticated the first day and at least once
during this 35 day period, say day #29. The attribute would therefore contain
the date from the first day, as day #29 would have been considered too close to
the existing timestamp to warrant updating it. The user account would then be
disabled after 61 days of inactivity which fits (loosely) the requirement.
In short, having a 90-day inactive user disabling requirement would by default
disable accounts inactive for 55 (90-35) to 90 days.


## Limitations

### Environments with mandatory, periodic password changes

If regulations call for stale/inactive accounts to be disabled within X
number of days, then the lifetime of the passwords for these accounts must be
set to a value lower than:
* X,
* minus the expected grace period mentioned above,
* minus the maximum amount of time between two invocations of the DSU tool,
* minus the expected maximum replication delay from the replica the DSU tool is
installed on to the farthest point of the cluster.

### Environments with no mandatory password changes

The longer the time period, the less update activity for the timestamp
attribute. But using a longer period runs the risk of disabling users who have
been gone for too short a time. For instance, setting the update period to 65
days would disable accounts inactive for the last 25 to 90 days. Whether this
fits the site's requirements is up to the administrators to determine.

Sites requiring a better accuracy must take care not to set the update period
too low for performance reasons. It is strongly recommended to make sure the
update period is longer than the expected maximum PTO or simply "away from IPA"
period for most user accounts to avoid replication storms when users come back.
This is especially true when these away periods are in sync, like in schools.


## Multiple runners

DSU can be installed on more than a single replica. This provides redundancy.
Having multiple DSU instances active at the same time provides no advantage,
so the systemd timer helper script includes a randomized time wait period.

On very busy clusters, using dedicated replicas (hidden replicas) for DSU is
recommended.


## How to Use DSU

### Installation

The Disable Stale Users tooling will be shipped with a new version of the
FreeIPA server package so it will be included in default installs.

### Configuration

#### Environments with mandatory, periodic password changes


The following attributes are added to the schema.
```
ipaConfigString: DSU:EnablePasswordBasedDSU
PasswordBasedDSUGracePeriod: 604800
DSUIgnoreGroups: admins
DSUVerbosity: 1
```
Adding DSU:EnablePasswordBasedDSU to the cn=ipaconfig schema will let
DSU disable accounts after a grace period defined in
PasswordBasedDSUGracePeriod (by default 604800 seconds).
This is the time delta after password expiry date on which to disable accounts.

The DSU:IgnoreGroups is multi-valued. Users belonging directly or
indirectly to these groups will not be affected.

DSUVerbosity's default value is "1".
A value of "1" makes the DSU tool log actions to systemd.
A value of "0" disables logging.
Other values are ignored and treated like "1".


#### Environments with no mandatory password changes

The following attributes are added to the schema:
```
ipaConfigString: DSU:EnableTimeStampBasedDSU
TimeStampBasedDSUInactivePeriod: 7776000
DSUIgnoreGroups: admins
DSUVerbosity: 1
```

Adding DSU:EnableTimeStampBasedDSU to the cn=ipaconfig schema will let
DSU disable accounts when the account's coarseSuccessfulAuthTime is more
than TimeStampBasedDSUInactivePeriod in the past.

The other variables behave the same way as the password-based-dsu case.


### Usage

The DSU tool is not a UNIX daemon. It is a CLI tool that can be triggered
by a systemd timer. 

Running ``ipa-dsu`` is enough to start the tool. If DSU is enabled (see above),
it will disable stale accounts appopriately.

The dry-run mode ``ipa-dsu --dry-run`` does not disable/lock accounts in any
way. Rather, it shows what would be done, essentially acting as a verbose mode
with "disable_accounts" set to False. The output is JSON.

There is no verbose mode combined with disable_accounts set to True. The tool
logs what it does and the reason for each account disabling action into
journald if DSUVerbosity is set to 1.


### Activation

Activate the DSU tool to run every night using the provided systemd timer:
``systemctl enable ipa-dsu.timer``


### Logs

The DSU tool logs each action in journald. Sample output:
```
ipa-dsu: disabled account uid=alice,cn=users,cn=accounts,dc=example,dc=com - password expired on 20191001.
```
```
ipa-dsu: disabled account uid=bob,cn=users,cn=accounts,dc=example,dc=com - user not seen since 20190701.
```

## Proposed Enhancements to DSU

DSU could reset passwords of locked-out accounts to a random, long string 
after a second grace period.

DSU could offer a way for admins to display which account(s) would be
disabled past a certain date using a CLI knob that would modify --dry-run.

The DSU-mandated modifications to ipa-kdb and ipa-lockout described in
"Environments with no mandatory password changes" could also update the
timestamp attribute on password changes. That way, the DSU logic could be
switched to being logon timestamp-based only.

