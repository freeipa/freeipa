# Hardware Security Module (HSM) Support

## Overview

An HSM provides a hardened, tamper-resistant environment for secure
cryptographic processing, key generation and encryption.

The dogtagpki CA and KRA can utilize an HSM for private key
generation and storage. 

Access to the HSM is done using a PKCS#11-compliant shared library.

The mechanism for sharing access to the key data for replicas/clones is HSM-specific and generally as a network accessible
device.

## Use Cases

- Install IPA with a CA which has its private keys stored on an HSM self-signed
- Install IPA with a CA which has its private keys stored on an HSM externally signed
- Install an IPA replica CA which utilizes the same HSM-stored private keys
- Install a KRA with private keys stored in an HSM
- Install a KRA clone which utilizes the same HSM-stored private keys

Installing with an HSM is all or nothing. There will be no mixing
and matching the subsystems stored in the HSM. For example, one will
not be able to install the KRA on an HSM without the CA as well.

Only RSA keys will be supported.


## How to Use

Using an HSM should be largely invisible to users and administrators beyond passing additional options during installation. The options required and any pre-installion work are HSM-specific.

It will not be possible to mix and match by default. PKI supports specifying the token values so a user can override these using --pki-config-override but it is, and will be, untested.

There are a few basic rules:

* If you use an HSM on the initial installation then all replicas and KRAs must also use the same HSM
* You cannot upgrade an existing installation where the keys were not generated on an HSM to an HSM-based install.
	+ It is likely that the HSM will not load externally-generated keys.
	+ If you could it would require a lot of tedious effort to reconfigure the CA, certmonger tracking, the IPA CA LDAP entry and the NSS database to manage it.

### Installation

#### CA

The token name, module name and shared library must be provided to the
CA and KRA installers. These define where the keys will be stored
and the naming convention for them.

The CA signing, OCSP, Audit and Subsystem private keys and certificates
are generated and stored in the HSM.

| Option | Description                                       |
|:------------------------ | :------------------------------ |
| --token-name             | NSS name for the token          |
| --library-path           | Path to PKCS#11 shared library  |
| --token-password         | Password for the token          |

This information will be stored in new schema so that replicas can auto-detect when an HSM is configured.

ipa-ca-install will accept the same options.

```
attributeTypes: (
  2.16.840.1.113730.3.8.21.1.TBD
  NAME 'ipaCaHSMConfiguration'
  DESC 'HSM Configuration'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.10'
)
```
This will be added as a MAY to the `ipaCa` objectclass.

This attribute will be semi-colon delimited and contain the HSM information needed to install a replica in the form of:

token-name;library-path

The token password will be prompted by ipa-replica-install or passed on the cli.

The presence of this attribute is enough to indicate that an HSM is present in the installation and the options will automatically be used for additional servers and/or services. The password will not be stored and the user must provide them on the cli. Whenever a replica, replica CA, KRA or replica KRA is added this attribute will be examined to determine whether an HSM is available or not, and what the options are.

A user can override library-path on the command-line in case it is in a different location or architecture. A different token name would mean a different token and they cannot be mixed.

The NSS module name will be the basepath of the library minus .so*.

#### KRA

The KRA transport, audit and storage private keys and certificates are
generated and stored in the HSM. This is an optional service installed
on a server with an HSM-based CA.

token-name and library-path can be determined based on the value of ipaCaHSMConfiguration.

### SubCA

SubCA private keys and certificates should be generated and stored in the HSM.

### Replica installation

#### CA

Per the pki documentation:

"In order for the master subsystem to share the same certificates and keys with its clones, the HSM must be on a network that is in shared mode and accessible by all subsystems."

Installation of a CA "clone" in PKI requires the end-user to
have the HSM keys available rather than relying on Custodia to provide the keys as a PKCS#12. pkispawn will look for keys in its NSS database if no PKCS#12 file is provided so when installing an HSM the `pkcs12_info` variable in the installers will be None.

External CA installation will follow the same procedure as a normal install. The HSM options need to be passed during the first stage of installation and will be cached for the second.

##### SoftHSM

For the purposes of development, the SoftHSM library will be used to simulate an HSM device. This is not deemed to be sufficient for production use because:

- The crypto data is available via the filesystem so is neither hardened nor tamper-proof.
- There is limited capability for remote access to the HSM for sharing the device between CA/KRA clones.

p11-kit has a method to proxy a token to another system using ssh and socket forwarding. This was investigated and not deemed a valid option. Doing this would require:

1. user/group permissions to the softokn directories
2. a user with a valid shell
3. A mechanism to share ssh private keys between IPA servers (custodia could be one way)
4. something to trigger and monitor the ssh connection

This is the definition of fragile.

While not ideal it is a better experience for the user to securely copy the token subdirectory to the new replica prior to installation.

### Certificate tracking and renewal

The IPA certmonger API needs to be extended to include the token name so certmonger will know how to find the certs and keys. The default will remain "internal".

certmonger executes its helpers as root. In order to have proper ownership of any files touched during renewal it also needs the user to execute the CA helper as pkiuser in order that filesystem permissions are correct, particularly for the softhsm2 use-case.

I see three potential solutions:

1. Add a new property to certmonger tracking requests to represent the user to setuid to (it will also setgid to the provided user's gid).
2. Override an existing properly like key-owner and use this user to setuid to.
3. Modify the helper to add the prefix: runuser -u pkiuser -.

I have a test patch to implement #2 but it seems wrong to override this behavior. It is the least invasive change though.

### Backup and restore

There are no expected impacts on backup/restore. An HSM install creates no additional files. Management of the HSM is left as an exercise for the user. For the softhsm case if restoration happens because of catastrophic failure then the user must manually restore the softhsm token directory.

### Upgrade

It will not be possible to upgrade a non-HSM installation into one with an HSM. By definition HSM keys should never leave the device so while one could import via PKCS#12 this seems antithetical to security.

Allowing portable keys would require significant extra efforts including:

- whether pki supports this
- which options need to be set/converted
- some procedure to import the keys into the HSM and remove them from NSS
- determine the impact on existing replica servers

This seems out-of-scope for initial HSM support.

## Design

The CA (and KRA) are installed using the dogtagpki installer pkispawn. It is invoked by the IPA installers as pkispawn -s SERVICE -f CONFIG-FILE. IPA generates this configuration file and merges it with any file passed in as --pki-config-override. The defaults can be found in install/share/ipaca_default.ini.

By default IPA will use the NSS softtoken (internal) for storage. The PKI override can set a different token name and library.

Without adding new command-line options the minimum required pki installation override to install an HSM is:

```
[DEFAULT]
pki_hsm_enable=True
pki_hsm_libfile=/usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename=softhsm2
pki_token_name=softhsm_token
pki_token_password=password
pki_sslserver_token=internal
```

This configuration:

- enables HSM support in pki
- sets the HSM module library and token name
- sets the HSM token password
- forces the tomcat SSL server certificate to be installed on the internal token in the NSS database rather than the HSM. This is due to pkispawn trying to export it to PKCS#12 which is not allowed in an HSM.

This is a very powerful way to install but will be prone to user error so will not be supported. Once the HSM options are set via pki-config-override they need to be passed into any subsequent installation (replica + CA, replica + CA + KRA, add CA, add KRA) or the installation will fail, requiring unnecessary cleanup. This method will not be supported.

We will proceed with storing the initial options (token and library) and auto-detect them during installation. The password will be prompted and/or we'll provide a password file option for unattended installation.

## Implementation

### Known changes required
#### IPA
- Add new installation options for token, HSM library and password. Retrieve the options from LDAP on replica installation and when adding a CA or KRA to an existing server (ipa-ca-install/ipa-kra-install).
- Skip retrieving CA/KRA keys from Custodia if an HSM is being configured.
- Extend the expected tracking to include the token name
- Depending on how certmonger addresses executing helpers, options will need to be provided to utilize it.

#### certmonger
- certmonger needs to setuid/setgid to pkiuser when performing operations to ensure filesystem permissions are retained for softhsm. https://pagure.io/certmonger/issue/243


#### NSS
- NSS requires a change to avoid prompting the user for the token PIN multiple times during installation, https://bugzilla.mozilla.org/show_bug.cgi?id=1782980

#### ipa-healthcheck
- ipa-healthcheck has no understanding at all of tokens https://github.com/freeipa/freeipa-healthcheck/issues/276

#### pki
- Requires upstream master (11.3.0) to install with an HSM. Patches continue to be submitted but a basic single server installation is successful with the current code.

#### Unsupported IPA Features

- sub CA's are generated in the softokn with a strange naming convention: `NSS Certificate DB:softhsm_token::caSigningCert cert-pki-ca UUID`. Needs investigation. Not deemed a show-stopper for MVP.


### Dependencies

HSM support for IPA relies on changes in multiple external projects:

- pki 11.3.0 contains the minimum set of changes required
- updated certmonger
- updated ipa-healthcheck
- updated NSS

### SoftHSM2 token management

To create a softhsm token:

runuser -u pkiuser -- /usr/bin/softhsm2-util --init-token --free --pin password --so-pin TokenSOpassword --label softhsm_token

The runuser is required so the resulting files are available to CA/KRA as pkiuser.

To remove the token:

softhsm2-util --delete-token --token softhsm_token

#### Initial server install w/DNS

Using the pki-config-override in Design.

ipa-server-install -a password -p dmpassword -r EXAMPLE.TEST -U --setup-dns --allow-zone-overlap --no-forwarders -N --auto-reverse --token-name softhsm_token --library-path /usr/lib64/pkcs11/libsofthsm2.so

## Feature Management

### UI

There should be no noticeable change.

### CLI

There should be no noticeable change.

The HSM attributes will not be visible via the IPA CLI except through `ipa ca-show ipa --all`

This information will be retrieved over LDAP rather than the API during service installation due to bootstrapping chicken-and-egg.

#### certmonger

In certmonger the token will be visible in getcert-list output in the key and cert storage. 

key pair storage: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='caSigningCert cert-pki-ca',token='softhsm_token',pin set

certificate: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='caSigningCert cert-pki-ca',token='softhsm_token'

#### NSS

NSS is PKCS11-based and treats all certificates and keys as if they are installed on a token. This may just be its internal token. The trust attributes that NSS uses do not have a storage equivalent in PKCS#11 so all trust is stored in NSS. Therefore even for certificates that are stored in the HSM they may appear in the  certutil output. You'll notice that there is no "u" trust because the private key is not available to the softokn.

The NSS command-line utilities can take a -h TOKEN option. With no token provided the internal token is used:

To list the output for the internal token omit the -h option.

```
#certutil -L -d /etc/pki/pki-tomcat/alias
    Certificate Nickname                                     Trust Attributes
                                                             SSL,S/MIME,JAR/XPI
caSigningCert cert-pki-ca                                    CT,C,C
ocspSigningCert cert-pki-ca                                  ,,
Server-Cert cert-pki-ca                                      u,u,u
subsystemCert cert-pki-ca                                    ,,
auditSigningCert cert-pki-ca                                 ,,P
```

With a token:

```
certutil -L -d /etc/pki/pki-tomcat/alias -h softhsm_token

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI
Enter Password or Pin for "softhsm_token":
softhsm_token:ocspSigningCert cert-pki-ca                    u,u,u
softhsm_token:subsystemCert cert-pki-ca                      u,u,u
softhsm_token:auditSigningCert cert-pki-ca                   u,u,Pu
softhsm_token:caSigningCert cert-pki-ca                      CTu,Cu,Cu
```
A couple of things to note:

- Only the `Server-Cert cert-pki-ca` certificate in the internal database has  the u flag which means the private key is available in the same token
- There is no `Server-Cert cert-pki-ca` in the HSM. This is because neither the cert nor key is stored there.
- Otherwise all certificates are in both databases. This will not be true for a replica. Only certificates with a trust flag (the CA and audit) because they are really not necessary or used in the internal database. This is a side-effect of pkispawn and while it looks odd is not a problem.

## Test plan

A subset of existing tests will be subclassed and executed with HSM enabled (softhsm) in a similar way that random serial number testing was done.

## Troubleshooting and debugging

### CA installation failure

The following logs may provide clues:
- /var/log/ipaserver-install.log
- /var/log/pki/pki-ca-spawn.date.log

### KRA installation failure
- /var/log/ipaserver-kra-install.log
- /var/log/pki/pki-kra-spawn.date.log

### SoftHSM

A blank token must be provided for a fresh installation. Be sure to remove and create a new token in between installs.

Installation will fail if there are multiple tokens created with the same name. To clean it up requires removing the directory. These names can be discovered with `softhsm2-util --delete-token --token softhsm_token`

A re-install without clearing the token will try to re-use the existing keys but fail trying to remove existing certificates due to a bug in certutil, https://bugzilla.mozilla.org/show_bug.cgi?id=1784925

To view the configured slots run:

`softhsm2-util --show-slots`

### General

The HSM configuration, if any, is stored in cn=ipa,cn=cas,cn=ca,$SUFFIX in the ipaCaHSMConfiguration attribute.

certutil is the easiest way to view the stored certificates and keys but any PKCS#11-compatible tool can access them.

To use certutil include the -h TOKEN or leave -h out to use the internal token:

`certutil -L -d /etc/pki/pki-tomcat/alias -h softhsm_token`

To use p11tool to list the certificates for a token you can run:

`p11tool --list-all-certs URL-of-token`

Like:

```
p11tool --list-all-certs pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=288f02f67556c586;token=softhsm_token
Object 0:
        URL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=288f02f67556c586;token=softhsm_token;id=%E8%99%25%CB%45%9F%F4%29%63%D6%98%D2%0B%57%1F%8F%D9%00%5B%27;object=ocspSigningCert%20cert-pki-ca;type=cert
        Type: X.509 Certificate (RSA-2048)
        Expires: Sun Oct  6 19:25:35 2024
        Label: ocspSigningCert cert-pki-ca
        ID: e8:99:25:cb:45:9f:f4:29:63:d6:98:d2:0b:57:1f:8f:d9:00:5b:27
```


## References

- https://github.com/dogtagpki/pki/wiki/HSM
- https://www.dogtagpki.org/wiki/HSM
- https://www.dogtagpki.org/wiki/SoftHSM

