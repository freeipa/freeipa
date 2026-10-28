# Random Serial Numbers v3 (RSNv3)

## Overview

Previously PKI used range-based serial numbers in order to ensure uniqueness across multiple clones. Based on their experience they determined that this would not fit well into cloud environments with short-lived certificates.

The new version 3 implementation of serial numbers uses a 128-bit random value for the serial number which they compute collisions will be mathematically small.

See https://github.com/dogtagpki/pki/wiki/Random-Certificate-Serial-Numbers-v3 for more details.

Given the known issues reported this will be supported in IPA for new installations only.

## Use Cases

RSNv3 will be supported only for new installations. If enabled it is required to use RSNv3 on all PKI services including the CA and KRA in the deployment.

The PKI team currently discourages mixing ranged and random serial numbers and in practice creating a ranged clone from a RSNv3 server will fail. At some point in the future it may be possible to write a tool to flip values in an existing deployment to enable RSNv3 on existing servers prior to creating new replicas but it will be complex and require significant testing. Currently interoperability between ranged and RSNv3 is not a good experience.

## How to Use

Instructions for installing a CA: https://github.com/dogtagpki/pki/blob/master/docs/installation/ca/Installing-CA-with-Random-Serial-Numbers-v3.adoc

Instructions for installing a KRA: https://github.com/dogtagpki/pki/blob/master/docs/installation/kra/Installig-KRA-with-Random-Serial-Numbers-v3.adoc

A new option was added for ipa-server-install and ipa-ca-install to --random-serial-numbers to enable RSNv3. This sets the configuration values as described in the documentation above.

## Design

### SerialNumber class

The first limitation within IPA related to RSNv3 is the size of the serial numbers which can be up to 40-digit decimal values. This far exceeds the limits of XML-RPC and JSON integer values.

There has never been a reason to treat serial numbers as integers and the original CA implementation transmitted them as strings. A new class will be needed to handle the huge integers as strings with some basic validation.

The validation will include:

- Minimum length of 1, no empty serial numbers
- Maximum length of 40 (2^^128)
- No negative values
- Greater than 0
- If prefixed with 0x a valid hex value

The only "math" we do on serial numbers is conversion to and from hex. Python internally can handle these huge numbers, it is only in the transmission that there is a problem.

### Determining RSN version

There are two possible methods to handle the introduction of random serial numbers:

#### Implement as a Domain Level 2

There are existing checks which will limit interoperability that may be extended as needed. This was not chosen because with RSNv3 it is an all or nothing affair according to the PKI documentation. All existing servers would need to be moved at once, not something easily enforceable or doable in large installations.

#### Store the RSN version as a value in LDAP

Instead store the version number in LDAP which is easily searchable and a common practice in IPA. A non-existent value will be treated as 0 and therefore no RSN capability. This will allow for expansion into future RSN versions. Current CA ACLs can be extended to allow read/write to this for admin users.

### KRA impact

The PKI team strongly encouraged that if RSNv3 is enabled anywhere then it should be enabled everywhere. This includes request and key IDs and a KRA. A check will be done on KRA installation to automatically enable RSNv3 if it is enabled on the underlying CA.

## Implementation

The RSN version will be stored in the IPA CA entry which will exist on any IPA server with a CA.

The new attribute is named ipaCaRandomSerialNumberVersion and consists of:

attributeTypes: (2.16.840.1.113730.3.8.21.1.9 NAME 'ipaCaRandomSerialNumberVersion' DESC 'Random Serial Number Version' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'IPA v4.9 RSNv3' )

This attribute is not yet merged into IANA pending design approval.

It will be added as MAY to ipaCa objectclass.

A sample entry looks like:
```
dn: cn=ipa,cn=cas,cn=ca,dc=example,dc=test
objectClass: top
objectClass: ipaca
cn: ipa
description: IPA CA
ipaCaId: <UUID>
ipaCaIssuerDN: CN=Certificate Authority,O=EXAMPLE.TEST
ipaCaSubjectDN: CN=Certificate Authority,O=EXAMPLE.TEST
ipaCaRandomSerialNumberVersion: 3
```

During replica install or ipa-ca-install a check will be made to determine if RSN is > 0 to determine whether it is allowed or not.

No special effort is needed to include externally signed IPA certificates.

CAless installations are unaffected. Promotion from CAless can include RSN and be held to the same standards as a new installation.

Unfortunately the PKI server provides no mechanism to determine whether the RSNv3 capability exists in the server so a straight version number check is required. It is only available in 11.2.0+.

## Feature Management

### UI

N/A

### CLI

A new option, --random-serial-numbers, is added to ipa-server-install and ipa-ca-install. If --setup-ca is provided to ipa-replica-install then RSN is determined automatically based on the capability of the remote CA.

### Configuration

N/A

## Upgrade

Not currently allowed. While theoretically possible to write a tool to enable it doing so is complex and prone to user error which could result in a non-functioning installation.

## Test plan

A RSNv3 installation varies only from a ranged installation in its CA/KRA configuration. Existing CA tests can be extended to pass the --random-serial-numbers option and from a user perspective, beyond getting certificates with potentially huge serial numbers, there is no difference.

A selected set of existing tests will be subclassed to add the RSNv3 installation option, including CA-less to CA-full installations.

Typically "is the CA ok" tests which do "ipa cert-show 1" can still work to show that communication is working (e.g. Not Found is a fine answer), existing tests will be extended to use the IPA CA serial number so we get a positive answer back.

During development the entire test suite was successfully executed with RSNv3 enabled. Doing so even on a nightly basis is an extremely heavy-weight option.

## Troubleshooting and debugging

Given this supports new installations only that greatly simplifies the possible conditions.

There are only two conditions which would disallow a server to be installed:
- PKI < 11.2.0
- The LDAP-stored RSNv3 value prevents ipa-ca-install or ipa-replica-install

It is possible that some client tools may not honor huge serial numbers but testing has not borne any out yet.
