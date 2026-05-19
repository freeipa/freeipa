---
back-href: ipa-profiles.html
back-text: FreeIPA certificate profiles and user certificates
up-href: "../index.html#toc"
up-text: Up to index
next-href: ipa-external-ca.html
next-text: Externally signing the FreeIPA CA
---

# Smart cards and workstation login

*Smart cards* are cryptographic devices that can securely store keys
and certificates to enable a variety of authentication and
encryption applications.  Common use cases include:

- Physical access badges
- Workstation login (maybe you've seen this at a bank)
- Storing OpenPGP or SSH keys

Smart cards use a variety of physical interfaces including USB, NFC,
and the classic plastic card with contact pad.  TPMs and smartphone
*secure elements* can also be configured as smart cards.  The **PKCS
#11** standard provides a common interface to access smart card
cryptographic operations, including key generation and signing.  The
principle is that keys cannot be extracted from the hardware.

::: note

Software implementations are also possible, but offer none of the
physical security benefits.

:::

In this module you will configure a *software* smart card token and
walk through some real world scenarios:

- Generate a key on the token and sign a CSR
- Install the issued certificate on the device
- Configure a FreeIPA domain for smart card authentication
- Authenticate to Kerberos using the smart card
- Configure a workstation for smart card based login
- Set up *GNOME Remote Desktop* to enable remote graphical login

::: note

Most activities in this module are to be performed on
`client.$DOMAIN`.  SSH into this machine now.

**You will also need an RDP client to perform the graphical
workstation login.**  You can still do most of the activities
without it, but you will miss out on some of the payoff.

:::


## Setting up the smart card

The exact commands for initialising and configuring a smart card
differ by vendor.  In this workshop we are using the *SoftHSM*
software token implementation.  Because it is not a physical device,
SoftHSM is **not recommended for real world use**.  But it is
perfect for developing an understanding of the general procedure
required to use smart cards for X.509 applications.

The first step is to create a token.  This is the only
SoftHSM-specific operation.  Later steps will use the PKCS #11
interface to interact with the token.

```command {.client}
sudo softhsm2-util --init-token --slot 0 \
  --label "FakeSmartCard" \
  --pin 1234 \
  --so-pin 5678
```
```output
The token has been initialized and is reassigned to slot 2017281153
```

`--label` gives a human-friendly name for the token.  `--pin` and
`--so-pin` set the codes for user and administrator access to the
token.


### Generate key pair and CSR

Now generate a private key (in this case, a NIST P-384 ECC key):

```command {.client}
sudo p11-kit generate-keypair \
    pkcs11:token=FakeSmartCard --login \
    --type=ecdsa --curve=secp384r1 \
    --label ipa-key --id deadbeef
```
```output
PIN for FakeSmartCard:
```

List objects and retrieve the PKCS #11 URI of the key:

```command {.client}
sudo p11-kit list-objects pkcs11:token=FakeSmartCard
```
```output
Object: #0
    uri: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=7c3fca5af83d4481;token=FakeSmartCard;id=%DE%AD%BE%EF;object=ipa-key;type=public
    class: public-key
    key-type: ec
    label: ipa-key
    id: de:ad:be:ef
    flags:
          local
          token
          modifiable
          copyable
          destroyable
```

The `uri` field in the output gives the PKCS #11 URI that refers to
the new key on this specific token.  Save its value; you will need
it in the next step.  **Make sure you surround the value in quotes
(`"..."`).**

```command {.client .no-copy}
PKCS11_URI="pkcs11:model=…;object=ipa-key;type=public"
```

Now create the CSR.  **OpenSSL will prompt for the user PIN** you
set when creating the token.

```command {.client}
sudo openssl req -new \
  -engine pkcs11 -keyform engine -key $PKCS11_URI \
  -config user_csr.cnf -out softhsm-user.csr
```
```output
Engine "pkcs11" set.
Enter PKCS#11 token PIN for FakeSmartCard:
```

::: note

The OpenSSL PKCS #11 engine is provided by the `openssl-pkcs11` RPM
package on Fedora and RHEL.  Other distributions might use a
different package name.

:::


### Request user certificate and import into smart card

Perform a *self-service* certificate request.  If you are not
already authenticated as `user1`, do so now:

```command {.client}
echo Secret.123 | kinit user1
```

Now request the certificate from the CA.  Given the context, this
could also be called *enrolling* the smart card.

```command {.client}
ipa cert-request softhsm-user.csr \
    --profile-id userCert \
    --principal user1 \
    --certificate-out softhsm-user.crt
```
```output
  Issuing CA: ipa
  Certificate: MIIEJjCCAo6gAwIBAgIQRmeQcXH3o/...
  Subject: CN=user1,O=E1.__BASE_REALM__
  Subject email address: user1@e1.__BASE_DOMAIN__
  Issuer: CN=Certificate Authority,O=E1.__BASE_REALM__
  Not Before: Wed Jan 07 08:00:16 2026 UTC
  Not After: Sat Jan 08 08:00:16 2028 UTC
  Serial number: 93583695936409673461838374248291191549
  Serial number (hex): 0x4667907171F7A3FADA78A182C4EF4AFD
  Request status: complete
```

Finally, import the certificate into the token:

```command {.client}
sudo p11-kit import-object pkcs11:token=FakeSmartCard \
  --file softhsm-user.crt \
  --label ipa-key --id deadbeef
```

## Enable smart card authentication for FreeIPA users

Smart card authentication requires setting a filter to control which
certificates are eligible to be matched against domain accounts.
**SSSD will always verify the certificate and ensure it chains up to
a trusted CA**.  But these match rules provide an additional filter
that can be used to further restrict certificate authentication.
This is often used to ensure that only particular issuers are used.

Let's just add a rule that accepts (valid) certificates from all
issuers (but first become `admin`).

```command {.client}
echo Secret.123 | kinit admin
```

```command {.client}
ipa certmaprule-add all-issuers \
    --matchrule '<ISSUER>.*'
```
```output
-----------------------------------------------------
Added Certificate Identity Mapping Rule "all-issuers"
-----------------------------------------------------
  Rule name: all-issuers
  Matching rule: <ISSUER>.*
  Enabled: True
```

In addition to the *match rule*, ***mapping rules*** are important
in some real world scenarios.  For example: when smart cards are
issued by a trusted third party, and you do not even see the
certificate until it is presented during login.  Or when certificate
lifetimes are so short that managing the `userCertificate`
attributes would be burdensome.

In such cases, the mapping rule lets you use information from the
certificate to match a user.  For example, the following rule
**maps** email address values in the *Subject Alternative Name*
extension to the user's `mail` attribute, but only when the
certificate issuer **matches** `O=Example Org`:

```command {.no-copy}
ipa certmaprule-add email-mapping-EXAMPLE-RULE \
    --matchrule="<ISSUER>O=Example Org" \
    --maprule="(mail={san_rfc822name})"
```


## Explicit Kerberos authentication with smart card

Now that the match rule has been created and the smart card is
ready, you can perform a Kerberos initial authentication.  Enter the
PIN when `kinit` prompts for it.

```command {.client}
sudo kinit user1 \
     -X X509_user_identity=PKCS11:libsofthsm2.so
```
```output
FakeSmartCard                    PIN:
```

Run `klist` to observe that the authentication succeeded:

```command {.client}
sudo klist
```
```output
Ticket cache: KCM:0
Default principal: user1@E1.__BASE_REALM__

Valid starting       Expires              Service principal
01/18/2026 13:29:42  01/19/2026 12:35:00  krbtgt/E1.__BASE_REALM__@E1.__BASE_REALM__
```

The explicit `kinit` is useful to verify the smart card is working
and Kerberos PKINIT is set up correctly.


## Enable smart card workstation login

It is awkward for human users to authenticate using the `kinit`
command.  Obtaining the TGT during a smart card based workstation
login would be much nicer.  Let's set that up now!


### Make the token accessible to SSSD

::: note

We are about to make the SoftHSM token usable by all users on the
system.  This is needed because of how SSSD operates.  **Never** do
something like this in a real world setting!

Real hardware smart cards use the [OpenSC] system and
don't need these hacks.

[OpenSC]: https://github.com/OpenSC/OpenSC/wiki

:::

Change the ownership of all the data to `sssd` user and group:

```command {.client}
sudo chown -R sssd:sssd /var/lib/softhsm/tokens
```

Grant all users access to the token:

```command {.client}
sudo chmod -R a+rX /var/lib/softhsm
```

One more thing: PKCS #11 tokens have a flag that indicates whether
the device is **removable** or not.  SSSD unconditionally ignores
non-removable tokens.  Fortunately, we can configure SoftHSM to make
it pretend that its tokens are removable.

Edit `/etc/softhsm2.conf`.  Change the line that says:

```
slots.removable = false
```

to say:

```
slots.removable = true
```


### Enable smart card login in SSSD and GDM

Use `authselect` to configure the PAM stack to enable smart card
login:

```command {.client}
sudo authselect enable-feature with-smartcard
```
```output
Make sure that SSSD service is configured and enabled.
See SSSD documentation for more information.

- with-smartcard is selected, make sure smartcard authentication
  is enabled in sssd.conf:
  - set "pam_cert_auth = True" in [pam] section
```

As the command output suggests, you must also edit
`/etc/sssd/sssd.conf` to enable SSSD to look up user certificates.
The `[pam]` section must look like:

```
[pam]
pam_cert_auth = True
```

SSSD also needs to know what CAs are trusted for user login.  By
default, SSSD looks at `/etc/sssd/pki/sssd_auth_ca_db.pem`.  Use a
symlink to point that location the FreeIPA CA trust store:

```command {.client}
sudo ln -s /etc/ipa/ca.crt \
    /etc/sssd/pki/sssd_auth_ca_db.pem
```

Now restart SSSD:

```command {.client}
sudo systemctl restart sssd
```


## Enable graphical login via RDP

To simulate a workstation smart card login experience, we will
enable [*Remote Desktop Protocol (RDP)*][wiki-rdp] login, using
***GNOME Remote Desktop***.

[wiki-rdp]: https://en.wikipedia.org/wiki/Remote_Desktop_Protocol

RDP uses TLS to secure the traffic between client and server.
Recall that we already requested a suitable certificate in the
*Certmonger* module!  Configure GNOME Remote Desktop to use the
Certmonger-managed key and certificate:

```command {.client}
sudo grdctl --system rdp \
  set-tls-key  /etc/pki/tls/private/rdp.key
```

```command {.client}
sudo grdctl --system rdp \
  set-tls-cert /etc/pki/tls/certs/rdp.crt
```

::: note

You can ignore error messages that mention TPM credentials.

:::

Configure an RDP username and password.  These credentials are
unrelated to FreeIPA or system accounts.

```command {.client}
sudo grdctl --system rdp \
  set-credentials rdp hunter2
```

Enable the RDP service:

```command {.client}
sudo grdctl --system rdp enable
```

And finally, restart GNOME Remote Desktop to pick up the new
configuration.

```command {.client}
sudo systemctl restart gnome-remote-desktop
```


## Bringing it all together

::: note

You need an RDP client on your local machine for these final steps.

:::

Use your RDP client to connect to `client.e$N.__BASE_DOMAIN__`.
You may need to prefix the domain name with `rdp://`.  The TCP port
is `3389`.

You may need to accept the server's certificate—which you issued and
configured!

Authenticate the RDP session with the RDP username and password
(`rdp`:`hunter2`).  If there is a *Domain* field, leave it blank.

The GDM login screen will greet you.  It will prompt you for the
smart card pin.  Enter the PIN and log in.  Then open the *Terminal*
app and run `klist`.  You will see that the user obtained a Kerberos
TGT during login.

All done!  You can log out and close your RDP client.
