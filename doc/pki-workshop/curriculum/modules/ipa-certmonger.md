---
back-href: 01-keygen-and-csr.html
back-text: Key generation and CSR creation with OpenSSL
up-href: "../index.html#toc"
up-text: Up to index
next-href: ipa-profiles.html
next-text: FreeIPA certificate profiles and user certificates
---

# Service certificates with FreeIPA and Certmonger

The **FreeIPA** identity management system (also available in RHEL
as **Red Hat Identity Management**) provides an enterprise PKI for
issuing and managing host, service and user certificates.

In this module you'll use the ***Certmonger*** program to request
and manage (renew) a certificate for an enrolled host from the
FreeIPA CA.  We'll consider the real world use case of an RDP
(*Remote Desktop Protocol*) server.

::: note

All steps in this module are to be performed on `client.$DOMAIN`,
where you generated keys and CSRs.  If you are not already there,
SSH into this machine now.

:::


## Environment overview

`client.$DOMAIN` already enrolled as a client in the FreeIPA domain.
That means it has a corresponding *host principal* object in the
domain (if you're familiar with Microsoft Active Directory, *machine
account* is the equivalent).  Before proceeding, let's inspect this
entry.

FreeIPA uses the **Kerberos** protocol for authentication.
Authenticate as user `user1` (initial password = `Secret.123`).  You
will be prompted to set a new password when authenticating for the
first time (you can use the same password).

```command {.client}
kinit user1
```
```output
Password for user1@E1.__BASE_REALM__:
Password expired.  You must change it now.
Enter new password:
Enter it again:
```

```command {.client}
ipa host-show $(hostname)
```
```output
  Host name: client.e1.__BASE_DOMAIN__
  Platform: x86_64
  Operating system: 6.17.1-300.fc43.x86_64
  Principal name: host/client.e1.__BASE_DOMAIN__@E1.__BASE_REALM__
  Principal alias: host/client.e1.__BASE_DOMAIN__@E1.__BASE_REALM__
  SSH public key fingerprint: ...
  Password: False
  Keytab: True
  Managed by: client.e1.__BASE_DOMAIN__
```

(Some details elided.  Also, your domain and realm names will differ
from the above).

For the user certificate, you will submit the `user.csr` you created
in the **Key generation and CSR creation** module.  The `user1` user
account already exists in the FreeIPA domain>

You will use the `admin` account to perform administrative actions
in the FreeIPA domain.  The password of the `admin` account is
`Secret.123`.


## Preparation

Enable and start Certmonger:

```command {.client}
sudo systemctl enable --now certmonger
```
```output
  Created symlink /etc/systemd/system/multi-user.target.wants/certmonger.service
    → /usr/lib/systemd/system/certmonger.service.
```


## Request certificate

Use the `ipa-getcert` command, which is part of Certmonger, to
request a certificate.  Certmonger will automatically perform the
following steps:

1. Generate a private key (with specified ownership)
2. Sign a CSR (ephemeral)
3. Submit the CSR to the FreeIPA CA for signing
4. Save the issued certificate (with specified ownership)
5. Monitor the certificate and renew it before expiry

```command {.client}
sudo ipa-getcert request \
    -f /etc/pki/tls/certs/rdp.crt \
    -k /etc/pki/tls/private/rdp.key \
    --key-owner gnome-remote-desktop \
    --cert-owner gnome-remote-desktop \
    -K host/$(hostname) \
    -D $(hostname)
```
```output
  New signing request "{TRACKING_ID}" added.
```

::: note

Record the signing request identifier that appears in the command
output.  You will need it later.  For example:

```command {.client .no-copy}
TRACKING_ID=20260107053408
```

:::

Let's break down some of those command arguments.

`-k <path>`
: Path to private key (Certmonger will generate it)

`-f <path>`
: Path to certificate (where it will be saved after being issued)

`--key-owner` and `--cert-owner`
: When specified, Certmonger will change the ownership of the key or
  certificate to the given user (`root` by default).  There are also
  options to change the mode (file permissions) if needed.

`-K <principal>`
: Kerberos host or service principal; because different kinds of
  services may be accessed at one hostname, this argument tells
  Certmonger which service principal is the certificate subject

`-D <dnsname>`
: Requests the given domain name to appear in the *Subject
  Alternative Name (SAN)* extension; today the *Common Name (CN)*
  field is no longer used by browsers so the SAN value is essential

Another important option is `-N <subject-name>`.  It defaults to the
system hostname, which is appropriate for our use case.

Check the status of the Certmonger request using tracking ID
from the `ipa-getcert request` output:

```command {.client}
sudo getcert list -i $TRACKING_ID
```
```output
Number of certificates and requests being tracked: 1.
Request ID '{TRACKING_ID}':
  status: MONITORING
  stuck: no
  key pair storage: type=FILE,location='/etc/pki/tls/private/rdp.key',owner=gnome-remote-desktop
  certificate: type=FILE,location='/etc/pki/tls/certs/rdp.crt',owner=gnome-remote-desktop
  CA: IPA
  issuer: CN=Certificate Authority,O=E1.__BASE_REALM__
  subject: CN=client.e1.__BASE_DOMAIN__,O=E1.__BASE_REALM__
  issued: 2026-01-20 05:21:36 UTC
  expires: 2028-01-21 05:21:36 UTC
  dns: client.e1.__BASE_DOMAIN__
  principal name: host/client.e1.__BASE_DOMAIN__@E1.__BASE_REALM__
  key usage: digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
  eku: id-kp-serverAuth,id-kp-clientAuth
  pre-save command:
  post-save command:
  track: yes
  auto-renew: yes
```

Review the output to confirm that:

- The certificate was issued and that Certmonger is now
  `MONITORING`.
- Certmonger will `auto-renew` the certificate when it is
  close to expiring.

FreeIPA adds the issued certificate to the service entry (technical
detail: it is in the LDAP `userCertificate` attribute).  It now
appears in the `ipa host-show` output:

```command {.client}
ipa host-show $(hostname)
```
```output
  Host name: client.e1.__BASE_DOMAIN__
  Platform: x86_64
  Operating system: 6.17.12-300.fc43.x86_64
  Certificate: MIIFgTCCA+mgAwIBAgIRAP... (it's big!)
  Subject: CN=client.e1.__BASE_DOMAIN__,O=E1.__BASE_REALM__
  Serial Number: 326888291098119664476505843178022846962
  Serial Number (hex): 0xF5EC65138C8B0C34BAD0B112CE0B41F2
  Issuer: CN=Certificate Authority,O=E1.__BASE_REALM__
  Not Before: Tue Jan 20 05:21:36 2026 UTC
  Not After: Fri Jan 21 05:21:36 2028 UTC
  Fingerprint (SHA1): 55:89:0e:58:cc:ca:7a:10:5f:ad:5f:92:df:66:1b:06:16:be:92:26
  Fingerprint (SHA256): 8d:b8:0f:e2:de:d6:f7:aa:8c:ef:93:63:b4:7c:2d:a4:38:d2:cf:c2:39:94:42:fc:0e:e8:0a:0d:16:e5:15:81
  Principal name: host/client.e1.__BASE_DOMAIN__@E1.__BASE_REALM__
  Principal alias: host/client.e1.__BASE_DOMAIN__@E1.__BASE_REALM__
  ...
```

## What is actually happening?

Under the hood, Certmonger uses the *host keytab* (acquired upon
joining the FreeIPA domain) to issue an `ipa cert-request` command
to the FreeIPA management API.  FreeIPA authorises the request
(hosts can **self-service** certificate requests) and if everything
looks good, it passes the CSR along to the **Dogtag CA** for
signing.  It stores the signed certificate in the `userCertificate`
attribute on the subject principal LDAP entry, and also returns the
certificate to the client that performed the request.

The *operator* who executes the `cert-request` is not necessarily
the subject.  Host principals can also request certificates for
*service principals* managed by that host.


## Forcing renewal

Certmonger will automatically renew the certificate when it is close
to expiry.  But you can use the `getcert resubmit` command if you
want to renew it immediately:

```command {.client}
sudo getcert resubmit -i $TRACKING_ID
```
```output
Resubmitting "20260107053408" to "IPA".
```

After a moment, the renewal will be complete.  `getcert list` shows
the updated validity period:

```command {.client}
sudo getcert list -i $TRACKING_ID
```
```output
Number of certificates and requests being tracked: 1.
Request ID '{TRACKING_ID}':
        status: MONITORING
        ...
        issued: 2026-01-20 05:27:35 UTC
        expires: 2028-01-21 05:27:35 UTC
        ...
```
