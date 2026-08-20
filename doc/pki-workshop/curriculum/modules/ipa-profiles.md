---
back-href: ipa-certmonger.html
back-text: Service certificates with FreeIPA and Certmonger
up-href: "../index.html#toc"
up-text: Up to index
next-href: ipa-smart-cards.html
next-text: Smart cards and workstation login
---

# FreeIPA certificate profiles

A *certificate profile* is a set of rules that defines and
constrains what data appears in a certificate.  Different
certificate use cases often require specific profiles.  The profile
controls things like:

- Duration of the certificate validity period
- The *Key Usage* and *Extended Key Usage* values
- Which subject name types are required, or allowed

Different CA implementations have their own ways of defining
certificate profiles.

::: note

Certificate profiles are called *templates* in some contexts,
including Microsoft Active Directory Certificate Services (AD-CS).

:::

In this scenario you will:

1. Learn about FreeIPA certificate profiles.
2. Create a profile suitable for issuing user certificates for Smart
   Card login.
3. Define *CA ACL* rules to allow certain users to request
   certificates using this profile.
4. Confirm that the *CA ACL* is set up properly.

Actually issuing a user certificate will happen in the next module.

::: note

All steps in this module are to be performed on `client.$DOMAIN`.
SSH in, then authenticate as FreeIPA `admin` user:

```command {.client}
echo Secret.123 | kinit admin
```

:::


## FreeIPA certificate profiles

Execute `ipa certprofile-find` to list the existing profiles:

```command {.client}
ipa certprofile-find
```
```output
------------------
4 profiles matched
------------------
  Profile ID: acmeIPAServerCert
  Profile description: ACME IPA service certificate profile
  Store issued certificates: False

  Profile ID: caIPAserviceCert
  Profile description: Standard profile for network services
  Store issued certificates: True

  Profile ID: IECUserRoles
  Profile description: User profile that includes
                       IECUserRoles extension from request
  Store issued certificates: True

  Profile ID: KDCs_PKINIT_Certs
  Profile description: Profile for PKINIT support by KDCs
  Store issued certificates: False
----------------------------
Number of entries returned 4
----------------------------
```

The default profile is `caIPAserviceCert`.  It is suitable for most
TLS server use cases.

The actual profile configuration is stored in the Dogtag CA's
database.  The FreeIPA database has stub entries to indicate which
profiles are "owned by" FreeIPA, and provide minimal additional
configuration.  The *"Store issued certificates"* flag controls
whether FreeIPA adds newly issued certificates to the subject
principal's LDAP entry.

As a starting point for defining a user certificate, retrieve and
save the configuration of the `caIPAserviceCert` profile:

```command {.client}
ipa certprofile-show caIPAserviceCert \
    --out userCert.cfg
```
```output
---------------------------------------------------
Profile configuration stored in file 'userCert.cfg'
---------------------------------------------------
  Profile ID: caIPAserviceCert
  Profile description: Standard profile for network services
  Store issued certificates: True
```

Examine the file using `less`.  You will see it is quite convoluted.
Don't worry, we'll step through the required changes in the next
section.  In the meantime, here's a quick overview:

- The file mainly consists of a list of *policy objects*, which are
  introduced by the `policyset.serverCertSet.list` parameter.

- Each policy object has a `default` section, which specifies how to
  populate some attribute or extension of the certificate, and a
  `constraint` section, which specifies some validation of the data
  (or the `noConstraintImpl` no-op).

- The `input.i1.class_id=certReqInputImpl` parameter specifies that
  this profile handles ordinary PKCS #10 CSR inputs.

- `auth.instance_id=raCertAuth` means that only the IPA
  *registration authority* can use this profile to issue
  certificates.


## Defining the user certificate profile

Open `userCert.cfg` in an editor and perform the following changes:

1. *The `commonNameToSANDefaultImpl` component is not suitable for
   user certificates.*
   - Remove all **four lines** beginning with
     `policyset.serverCertSet.12`.
   - Delete `,12` from the end of the `policyset.serverCertSet.list`
     parameter.

2. *Allow elliptic curve keys.*
   - Set `policyset.serverCertSet.3.constraint.params.keyType=-`
   - Add `,nistp256,nistp384,nistp521` to the
     `policyset.serverCertSet.3.constraint.params.keyParameters`
     parameter.

3. *Set "Extended Key Usage" values suitable for Smart Card login.*
   - Set the value of
     `policyset.serverCertSet.7.default.params.exKeyUsageOIDs` to
     `1.3.6.1.5.2.3.4,1.3.6.1.4.1.311.20.2.2`

4. Delete the `profileId=caIPAserviceCert` line.


## Creating the user certificate profile

After performing the required edits, create the profile:

```command {.client}
ipa certprofile-import userCert \
    --file userCert.cfg \
    --store true \
    --desc "User PKINIT certs"
```
```output
---------------------------
Imported profile "userCert"
---------------------------
  Profile ID: userCert
  Profile description: User PKINIT certs
  Store issued certificates: True
```

The new profile has been created.

::: note

If you need to update the profile configuration later,
here's how:

```command
ipa certprofile-mod userCert --file userCert.cfg
```

:::


## CA ACLs - authorising use of a profile

Use of particular profiles can be restricted to particular
principals—by name, group, or class.  The ***CA ACL*** objects
define these access rules.  By default there is a single CA ACL; it
restricts use of the `caIPAserviceCert` profile to host and service
subject principals:

```command {.client}
ipa caacl-find
```
```output
----------------
1 CA ACL matched
----------------
  ACL name: hosts_services_caIPAserviceCert
  Enabled: True
  Host category: all
  Service category: all
----------------------------
Number of entries returned 1
----------------------------
```

Users cannot be issued a certificate via the default profile, and
that makes perfect sense.  But to be able to use the `userCert`
profile to issue certificates to user principals, you need to add a
CA ACL for that.

We *could* define an ACL that allows *all users* (`--usercat=all`).
But we'll be a bit more restrictive: the only allowed subjects will
be members of the `sclogin` user group.  Execute the commands as
below:

```command {.client}
ipa caacl-add userCert_sclogin
```
```output
-------------------------------
Added CA ACL "userCert_sclogin"
-------------------------------
  ACL name: userCert_sclogin
  Enabled: True
```

```command {.client}
ipa caacl-add-profile userCert_sclogin \
    --certprofiles userCert
```
```output
  ACL name: userCert_sclogin
  Enabled: True
  Profiles: userCert
  User Groups: sclogin
-------------------------
Number of members added 1
-------------------------
```

```command {.client}
ipa caacl-add-user userCert_sclogin \
    --groups sclogin
```
```output
  ACL name: userCert_sclogin
  Enabled: True
  User Groups: sclogin
-------------------------
Number of members added 1
-------------------------
```

## Confirm the CA ACL rejects invalid subjects

The `user1` account is *not* in the `sclogin` group.  Using the
`user.csr` *certificate signing request* you created previously,
request the certificate.

::: note

The FreeIPA `admin` account is highly privileged and bypasses CA
ACLs.  Switch to the `user1` account and perform a *self-service*
certificate request.  Self-service requests are allowed, subject to
CA ACLs.

```command {.client}
echo Secret.123 | kinit user1
```
```output
Password for user1@E1.__BASE_REALM__:
```

:::

```command {.client}
ipa cert-request user.csr \
    --profile-id userCert \
    --principal user1 \
    --certificate-out user.crt
```
```output
ipa: ERROR: Insufficient access: Principal
  'user1@E1.__BASE_REALM__' is not permitted to use CA
  'ipa' with profile 'userCert' for certificate issuance.
```


## Add user to the `sclogin` group

`kinit` as `admin` once more, and add `user1` to the `sclogin` user
group:

```command {.client}
echo Secret.123 | kinit admin
```
```output
Password for admin@E1.__BASE_REALM__:
```

```command {.client}
ipa group-add-member sclogin --users user1
```
```output
  Group name: sclogin
  GID: 1789600004
  Member users: user1
-------------------------
Number of members added 1
-------------------------
```

Now that `user1` is in the `sclogin` group, certificate requests
using the `userCert` profile should succeed.  You will actually
request the certificate in the Smart Card module.
