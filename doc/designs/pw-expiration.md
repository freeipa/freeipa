# Password expiration enforcement for passwordless authentication

## Overview

MIT krb5 checks `pw_expiration` in `validate_as_request()` before pre-authentication runs. At that point the KDC does not know which authentication method will be used. For users who have both password-based and passwordless methods configured (e.g. password + PKINIT), the KDC would reject the AS-REQ before the passwordless method even gets a chance to run.

FreeIPA solves this by deferring the password expiration check for passwordless-capable users to the kdcpolicy plugin, which runs after pre-authentication, when the actual method used is known.

## Use Cases

A user has both password and PKINIT authentication configured. Their password has expired, but they want to authenticate using their certificate. Without special handling, the KDC rejects the request with `CLIENT KEY EXPIRED` before PKINIT pre-authentication can run.

The same problem applies to users with RADIUS, external IdP, or passkey methods configured alongside a password.

## Design

### MIT krb5 baseline

In vanilla MIT krb5, password expiration is enforced in `validate_as_request()` (in `kdc_util.c`), which runs at the VALIDATE_POL stage of AS-REQ processing, before pre-authentication:

```c
if (client->pw_expiration && ts_after(kdc_time, client->pw_expiration) &&
    !isflagset(server->attributes, KRB5_KDB_PWCHANGE_SERVICE)) {
    *status = "CLIENT KEY EXPIRED";
    return KRB5KDC_ERR_KEY_EXP;
}
```

This check includes two exemptions:

- `KRB5_KDB_PWCHANGE_SERVICE`: the target service is `kadmin/changepw`, allowing users with expired passwords to obtain a ticket to change their password.
- `KRB5_KDB_REQUIRES_PWCHANGE`: users flagged with this attribute can only authenticate to password change services.

The kdcpolicy plugin (`check_as` callback) runs after pre-authentication at the ENCR_REP stage. Vanilla MIT krb5 does not ship a plugin that performs password expiration checks at this stage.

.. uml:: pw-expiration-mit-krb5-flow.puml

### FreeIPA two-phase approach

#### Phase 1: before pre-authentication

When `ipadb_parse_ldap_entry()` loads a client principal, it checks whether the user has any passwordless authentication method available (RADIUS, PKINIT, IDP, or passkey). If so, it clears `entry->pw_expiration` to 0 so that `validate_as_request()` will not reject the AS-REQ. The real expiration value is preserved in `ied->pw_expiration` (the IPA-specific e-data attached to the principal entry).

For users with only password-based methods, `entry->pw_expiration` is set normally and `validate_as_request()` enforces it with its built-in exemptions.

.. uml:: pw-expiration-ipa-common.puml

#### Phase 2: after pre-authentication (kdcpolicy plugin)

After pre-authentication completes, the KDC calls `ipa_kdcpolicy_check_as()` at the ENCR_REP stage. At this point, the authentication indicators reveal which method was actually used. The plugin enforces password expiration for password-based methods using the preserved `ied->pw_expiration` value.

Because `validate_as_request()` was bypassed for passwordless-capable users, the plugin must replicate its exemptions:

- `KRB5_KDB_PWCHANGE_SERVICE`: if the target service has this attribute, password expiration is not enforced, allowing users with expired passwords to change their password.
- `KRB5_KDB_REQUIRES_PWCHANGE`: if the client has this attribute and the target is not a password change service (already excluded above), the request is rejected with `KRB5KDC_ERR_KEY_EXP`.
- **Passwordless method used**: if the authentication indicator corresponds to a passwordless method (pkinit, radius, idp, passkey), password expiration is not enforced since the password was not used.

.. uml:: pw-expiration-ipa-flow.puml

### Check distribution

| Scenario | validate_as_request() | ipa_kdcpolicy_check_as() |
|:---------|:---------------------:|:------------------------:|
| Password-only user, password not expired | Passes | Passes (no-op) |
| Password-only user, password expired | Rejects (with PWCHANGE_SERVICE exemption) | Not reached |
| Passwordless-capable user, passwordless method used | Skipped (pw_expiration=0) | Passes (passwordless) |
| Passwordless-capable user, password used, not expired | Skipped (pw_expiration=0) | Passes |
| Passwordless-capable user, password used, expired | Skipped (pw_expiration=0) | Rejects (with PWCHANGE_SERVICE exemption) |
| Any user targeting kadmin/changepw | Exempted | Exempted |

### Impact on password change policy

Clearing `entry->pw_expiration` also affects the password change flow. When a user changes their password, `ipadb_change_pwd()` calls `ipadb_check_pw_policy()`, which passes the expiration value to `ipapwd_check_policy()`. That function uses the expiration value to detect admin password resets: when an admin resets a user's password, `krbPasswordExpiration` is set equal to `krbLastPwdChange`, and `ipapwd_check_policy()` uses this to bypass the `min_pwd_life` check.

For passwordless-capable users, `db_entry->pw_expiration` is 0, which breaks this detection: the comparison `pwd_expiration != last_pwd_change` always evaluates to true (since `last_pwd_change` is non-zero), causing the minimum password age to be enforced even after an admin reset. To avoid this, `ipadb_check_pw_policy()` must use `ied->pw_expiration` instead of `db_entry->pw_expiration`.

.. uml:: pw-expiration-ipa-pwchange-flow.puml

## Implementation

### Relevant source files

- `daemons/ipa-kdb/ipa_kdb_principals.c` — `ipadb_parse_ldap_entry()`: clears `entry->pw_expiration` for passwordless-capable users, preserves real value in `ied->pw_expiration`.
- `daemons/ipa-kdb/ipa_kdb_kdcpolicy.c` — `ipa_kdcpolicy_check_as()`: enforces password expiration after pre-authentication with `PWCHANGE_SERVICE` and `REQUIRES_PWCHANGE` exemptions.
- `daemons/ipa-kdb/ipa_kdb_passwords.c` — `ipadb_check_pw_policy()`: password policy check during password changes, must use `ied->pw_expiration` for correct `min_pwd_life` admin-reset detection.
- `daemons/ipa-kdb/ipa_kdb.h` — `struct ipadb_e_data`: the `pw_expiration` field preserving the real expiration value.
