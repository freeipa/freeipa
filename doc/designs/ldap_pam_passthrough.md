**IMPORTANT**: This is a design proposal and is not implemented yet.

# LDAP PAM Passthrough support

## Overview

Many organizations have authentication mechanisms already in place.
They may not want to have IPA be the central repository for authentication.

RADIUS is a common authentication protocol used for external authentication
into existing systems. IPA currently has support for verifying credentails
over RADIUS for Kerberos connections using the radius authentication
indicator, but this does not work with LDAP authentication.

For this document "PAM Passthrough" is defined as any subsequent
plugin that handles authentication of the user entry using the PAM stack.

### Expected Workflow

There are a lot of components potentially involved in LDAP authentication
over RADIUS:

 - 389-ds
 - PAM
 - SSSD
 - KDC
 - ipa-otpd
 - the remote RADIUS server

The workflow starts with an LDAP bind.

 - On an LDAP BIND with uid=user,cn=users,cn=accounts,$SUFFIX, the BIND
   request will get processed by the IPA password plugin preop.
   If both radius and otp auth types are set and there are no tokens
   the plugin will return 0, allowing further authentication to happen.
   389-ds treats this as no authentication decision so allows other
   plugins to try.

 - At this point another 389-ds plugin can step in to handle the
   authentication using the PAM stack.

 - As PAM authentication processing happens, if pam_sss.so is present in
   the PAM stack, it will attempt to perform password-based authentication
   for the 'user' account using the provided credentials.

 - Since the user account matches the IPA domain, it will be treated as
   Kerberos authentication against IPA KDC running on the same host, as
   we are authenticating on a IPA server.

 - The IPA KDB driver in the KDC will notice that the 'user@IPA' principal
   has the 'radius' pre-authentication method configured with TL data
   "otp\0[{\"indicators\": [\"radius\"]}]" meaning it should advertise
   the OTP pre-auth mechanism to the Kerberos client.

 - The client (SSSD) notices the availability of the OTP pre-auth
   mechanism and uses host principal's TGT as its FAST channel wrapper to
   proceed with OTP pre-auth.

 - OTP pre-auth mechanism will talk between KDC and the client to ask
   for additional details (OTP value) via prompting mechanism it has.

 - The client (SSSD) will return the OTP value and the KDC then will
   issue a RADIUS request "Accept-Request" to a RADIUS server configured
   in the KDC configuration. The OTP value in this case is the
   credentials the user provided.

 - ipa-otpd handles OTP requests and will connect to LDAP (the LDAP URI
   is passed as part of ipa-otpd@.service definition from
   /etc/ipa/default.conf, so it'll be an LDAPI access). ipa-otpd will
   parse the RADIUS packet and look up requested user principal entry from
   LDAP.

 - If the user principal entry has the 'radius' authentication indicator
   configured (or it is default for IPA deployment) and there is a
   RADIUS proxy link in the user entry (there is no default so it must
   be set per user), it will send the same RADIUS packet to the RADIUS
   server configured as a proxy link with the credentials provided by
   KDC

 - For a native OTP setup where the user has the 'otp' authentication
   indicator the process is about the same: instead of sending a RADIUS
   proxy request, ipa-otpd will bind to LDAP with the user DN and pass
   the credentials provided by KDC.

## Existing Workaround

Due to the way passwords and OTP are handled by the current IPA
password plugin it is possible to make this work today using the
389-ds password plugin but it is complicated to setup and
prone to error.

 - Install IPA

 - Configure the 389-ds PAM pass-through plugin to a PAM service that
   relies on pam_sss.so (e.g. system-auth)

 - Add a RADIUS proxy configuration in IPA

 - Add this proxy to one or more users

 - Set default authentication indicator in IPA to 'radius, otp' or on
   one or more of those users

 - The user has no userPassword or krbPrincipalKey set

 - The user has no OTP tokens

The key is having otp as an authentication indictor. If otp is
not set as an authentication indicator then ipapwd_pre_bind_otp() will
return 1 and fail the authentication request. By setting otp but having
no tokens ipapwd_pre_bind_otp() will return 0. Next a password comparison
will happen but since the user has no password this will be skipped
and 0 returned to 389-ds as the result and then PAM passthrough plugin
can be initiated.

### Workaround confusion

Strictly speaking, a user can have this configuration and still have
a userPassword and krbPrincipalKey set but this is a no-op for an LDAP bind.
Regardless of whether the provided password is valid or not authentication
will proceed to the RADIUS server for the final word.

This is similar behavior if a user tries a raw kinit without armor:
there may be a password/key but it isn't used.

This could lead to "I can't log in" calls and an admin resetting their
password in IPA with no real effect.

### Why is otp required in the workaround?

This scheme works because RADIUS isn't considered at all in the
password plugin.

In prepost.c::ipapwd_pre_bind_otp() the user is checked to see if
they have OTP auth enabled. If they do then the tokens are examined
and if there aren't any, the function exits in a way that allows
subsequent authentication. This will then fall out and return a 0
to 389-ds to allow PAM Passthrough to execute.

If the user does not have OTP auth enabled then that code will be
skipped and return a 1 because the auth_type is not
OTP_CONFIG_AUTH_TYPE_PASSWORD.

## Proposal

This proposal may break existing installations who have found this
workaround.

Currently PAM passthrough authentication basically works by accident
and by working around the lack of direct handling of RADIUS in the
password plugin. It would be better, and more secure, to deal directly
with this in the IPA password plugin and not rely on side-effects.

### IPA Framework plugin changes:

For users with the RADIUS authentication indicator set:
1. Require no userPassword and krbPrincipalKey 
2. Require a radius proxy server set 
3. Do not allow the RADIUS authentication indicator along with others
   since the point of it is to outsource authentication.

These will not be enforced retroactivly on upgrade since LDAP bind
using RADIUS was not supported.

### IPA password plugin changes:

If the RADIUS authentication indicator is set on a user and the user
has a userPassword or krbPrincipalKey and does not have a radius 
proxy setting (ipatokenradiusconfiglink) then return
LDAP_INVALID_CREDENTIALS.

If the OTP authentication indicator is not set, in
ipapwd_pre_bind_otp() return 0 if any authentication indicator is set.

Additionally, multiple mechanisms should be supported simultaneously
so a user configured with PKINIT and RADIUS can authenticate using
either. Currently only RADIUS will work. See 
https://pagure.io/freeipa/issue/8820 for more details. This should
also work for an LDAP bind for consistency.

### The workflow

 - RADIUS will be evaluated first.

 - If RADIUS authtype is set:
    - require no userPassword and krbPrincipalKey
    - require radius proxy setting

 - If RADIUS is an authentication indicator for a user on a BIND request
     - If these conditions are not set then LOG_FATAL() and end the
       authentication attempt by returning LDAP_INVALID_CREDENTIALS.
     - Otherwise continue the authentication process.

 - If RADIUS is not an authentication indicator then proceed with
   authentication.

 - If OTP is an authentication indictorn or the user
     - Evaluate tokens using the existing workflow
     - Otherwise fall back to PASSWORD authentication

OTP checking is done in ipapwd_pre_bind_otp() which is called unless
there is a sync request. Authentication indicator type handling needs to
be better centralized here. There are two paths that can return different
results (assuming otpreq = False).

1. User has otp auth type and has no tokens it will return 0.
2. User does not have otp auth type it will only return 0 if the
   user has OTP_CONFIG_AUTH_TYPE_PASSWORD.

This loophole needs to be closed. Perhaps change to return false if
auth type is OTP_CONFIG_AUTH_TYPE_NONE. This would likely be more
future-proof if more authentication indicators are added.

If the OTP check doesn't return an error then the password will be
authenticted, if there is one. This is the two-step first check
OTP, then check the password.

Since a 389-ds plugin returning 0 will allow subsequent authentication,
for the case of RADIUS we need to enforce the no password(s) and
RADIUS server requirements because with any PAM passthrough method
enabled it becomes the defacto default method. In fact we may want
to always ensure there is no RADIUS server defined if the RADIUS
authentication indicator is not set to set. This would need to check
both the global and per-use authentication indicators.

389-ds FATAL logging is recommended because the authentication path is
so opaque that administrators won't know why or where it failed. This
will ensure a useful message is logged, at least for the administrators.

It might be nice to check that PAM passthrough is enabled but there
is is no way to validate the configuration so we may well skip it.

## Testing

This creates quite a large test matrix as a number of different
tests are required. These are only for LDAP binds. Kerberos should be
unaffected.

- RADIUS authentication indicator set globally and the user is not
  configured properly
  - user has a password
  - user has a principal key
  - user has no radius proxy set

- RADIUS authentication indicator set for the user and the user is not
  configured properly
  - user has a password
  - user has a principal key
  - user has no radius proxy set

- RADIUS authentication indicator set globally and user is ok
  - test user with correct password
  - test user with incorrect password

- RADIUS authentication indicator set for the user and user is ok
  - test user with correct password
  - test user with incorrect password

Others depending on whether we will allow the RADIUS authentication
indicator with others. If we restrict the authentication indicators
to either be only RADIUS or anything but RADIUS this should not
affect other mechanisms and will be covered by other tests. But this
poses a problem with upgrades.

### Setup using the 389-ds PAM Passthrough plugin

In order to test we'll need to setup a RADIUS server to test against.
The pyrad project provides a sample in
https://raw.githubusercontent.com/pyradius/pyrad/master/example

It would need to be adapted for our needs to actually do authentication
and ideally dynamically setup its listening hosts. The passwords
could be hardcoded with a "good" one that is always accepted.

And the ldapserver PAM service needs to be created and cleaned up.
Making a copy of system-auth is sufficient.

To enable the PAM Passthrough plugin in 389-ds can be done with this
ldif:

dn: cn=PAM Pass Through Auth,cn=plugins,cn=config
changetype: modify
replace: nsslapd-pluginEnabled
nsslapd-pluginEnabled: on
-
replace: pamSecure
pamSecure: FALSE
-
replace: pamService
pamService: ldapserver

Followed by a restart of dirsrv.target.

The dsconf configuration for enabling/configuring Passthrough
is currently not working in 389-ds.

### Creating a RADIUS proxy server

Create a radius proxy named 'pyrad' pointing to the current server.

$ echo somesecret | ipa radiusproxy-add pyrad --server ipa.example.test --secret

### Creating an appropriate user to test with

Create a user with the RADIUS authentication indicator and a radius proxy link.

$ ipa user-add --first=tim --last=user --radius pyrad --user-auth-type radius tuser

### Executing the search

$ ldapsearch -x -w password -D "uid=tuser1,cn=users,cn=accounts,dc=example,dc=test" -b "cn=users,cn=accounts,dc=example,dc=test" uid=admin

The password here is the RADIUS password. In the case of pyrad it currently
accepts anything.

## Backup/Restore

There should be no impact for backup and restore as this only modifies
the IPA password plugin and does not ship new files or configuration.

## Upgrades

The additional enforcement of no userPassword/krbPrincipalKey and
radius link for the RADIUS authentication indicator could cause issues
for some users. We will need to be absolutely clear in error logging
why authentication is failing, and document the change in a release
note.

If we require that RADIUS be a standalone indicator that could also
pose upgrade problems.
