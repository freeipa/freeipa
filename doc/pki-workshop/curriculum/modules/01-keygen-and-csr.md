---
up-href: "../index.html#toc"
up-text: Up to index
next-href: ipa-certmonger.html
next-text: Service certificates with FreeIPA and Certmonger
---

# Key generation and CSR creation with OpenSSL

## Introduction

Before a Certificate Authority (CA) can issue you an X.509
certificate, you must first create a **Public/Private Key Pair** and
a **Certificate Signing Request (CSR)**. The private key is the
secret component that proves your identity, and the CSR contains
your public key and identity information (like a website's domain
name or a user's email address) that the CA will embed in the final
certificate.

In this module you'll use the `openssl` command line tool to
generate keys and create CSRs.

::: note

All steps in this module are to be performed on `client.$DOMAIN`.
SSH into this machine now:

```command {.no-copy}
ssh -i path/to/key.pem fedora@client.e$N.__BASE_DOMAIN__
```

:::


## Service CSR with RSA key

Let's prepare a CSR suitable for a network service, such as an HTTP
server.  We will use a strong RSA key and include the DNS hostname
in both the Common Name (CN) field and the Subject Alternative Name
(SAN) extension.

### Generate the RSA Private Key

We will use the **RSA 3072-bit** key size, which is the minimum RSA
key size currently recommended by NIST for secure services.

```command {.client}
openssl genpkey \
    -aes256 \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -out service.key
```

The `-algorithm` and `-pkeyopt` arguments specify the public key
algorithm and key parameters.  `-out` is where to write the
generated key.

**When storing keys on disk you should encrypt them.**  The
`-aes256` option selects AES-256 for key encryption.  The command
will prompt you for a passphrase:

```output
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

In real world use you should choose a secure passphrase (or store
keys in a *hardware security module (HSM)*, *secure element* or
*TPM*).  For the purposes of this workshop choose something short
and memorable (e.g. `hunter2`).  Note that you will not see any
output as you type the passphrase.


### Create config file for service CSR

Create a configuration file to tell `openssl` what content to
include in the CSR.  The certificate binds a public key to some
identity information.  For a host or network service, this is often
just the DNS name used to reach it.

Open an editor (`vi` or `nano`) and create a file named
`service_csr.cnf` with the following content.  **Replace `$DOMAIN`
with your environment's domain.**

```command {.client}
tee service_csr.cnf >/dev/null <<EOF
[ req ]
prompt              = no
req_extensions      = req_ext
distinguished_name  = dn

[ dn ]
# NOTE: In real-world use cases, you may need to include
# other attributes (Country, Organization, etc.)
commonName = client.$DOMAIN

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
# The DNS name MUST match the Common Name for best practice.
DNS.1 = client.$DOMAIN
EOF
```

### Generate the service CSR

Execute the `openssl req` command below to build a CSR according to
the config file and sign it with the private key.  Note that it will
prompt you for the encryption passphrase you set previously.

```command {.client}
openssl req -new \
    -key service.key \
    -config service_csr.cnf \
    -out service.csr
```
```output
Enter pass phrase for service.key:
```

### Verify the service CSR

Always verify your CSRs before submission to ensure the required
extensions and names are correctly included.

Check the SAN and key parameters for the service request.

```command {.client}
openssl req -in service.csr -text -noout
```

Look for the following in the output:

```output
  Subject Public Key Info:
      Public Key Algorithm: rsaEncryption
          Public-Key: (3072 bit)
```

…and…

```output
    Requested Extensions:
        X509v3 Subject Alternative Name:
            DNS:client.$DOMAIN  -- your env's domain here
```


## CSR for user certificate with ECC key

X.509 certificates can be used for a variety of **user
authentication** scenarios (e.g. Kerberos, VPN access, email
signing).  We use RSA for the service key, so let's choose a
different algorithm for the user certificate.

*Elliptic curve cryptography (ECC)* is an alternative to RSA.  ECC
is faster than RSA, and keys and signatures are smaller.  We'll
generate an elliptic curve key and use it to sign a CSR that
includes the user's **username** and **email address**.

### Generate the ECC Private Key

We will use the **secp384r1** curve, which is recommended for high
security with efficient performance.  

```command {.client}
openssl genpkey \
    -aes256 \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:secp384r1 \
    -out user.key
```

Again, choose a simple encryption passphrase for the purposes of
this workshop.


### Create config file for user CSR

For user authentication certificates, the primary identifiers are
usually the username (in CN) and the email address (in the SAN).

Create a file named `user_csr.cnf` with an OpenSSL configuration
suitable for requesting an authentication certificate for `user1`:

```command {.client}
tee user_csr.cnf >/dev/null <<EOF
[ req ]
prompt              = no
req_extensions      = req_ext
distinguished_name  = dn

[ dn ]
commonName = user1

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
email = user1@$DOMAIN
otherName = 1.3.6.1.5.2.2;SEQUENCE:krb5principal

[ krb5principal ]
realm = EXPLICIT:0,GeneralString:$REALM
principalname = EXPLICIT:1,SEQUENCE:principalname

[ principalname ]
nametype = EXPLICIT:0,INT:1
namestring = EXPLICIT:1,SEQUENCE:namestring

[ namestring ]
part1 = GeneralString:user1
EOF
```

::: note

The CSR's SAN extension includes the user's email address, and a
representation of their Kerberos principal name.

:::

### Generate the User CSR

```command {.client}
openssl req -new \
    -key user.key \
    -config user_csr.cnf \
    -out user.csr
```
```output
Enter pass phrase for user.key:
```

### Verify user CSR

```command {.client}
openssl req -in user.csr -text -noout
```

Verify the elliptic curve parameters in the *Subject Public Key
Info* section, and the inclusion of the user's email address in the
*X509v3 Subject Alternative Name* extension.


## Key Takeaways

1. You can choose the **key type and size**.  Some CAs or
   organisational policies may restrict which key types or
   parameters are allowed.  Current NIST standards require 3072-bit
   RSA or a 256-bit elliptic curve keys as a minimum from 2031.

2. **CSR Customization:** The configuration file allows you to
   explicitly define the **Subject Distinguished Name (DN)** and
   **Subject Alternative Name (SAN)** attributes.

3. **Use case-specific SANs:** Use DNS.\* for services and email
   (rfc822Name) for user authentication certificates.  There are
   many other types of SAN values, including IP addresses (for
   servers accessed directly by IP).

**What's next?** You now have two distinct CSRs (`service.csr` and
`user.csr`).  We are ready to move on to the next module: submitting
these CSRs to our FreeIPA CA and receiving signed X.509
certificates!
