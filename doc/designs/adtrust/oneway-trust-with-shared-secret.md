# One-way trust with shared secret

## Overview

FreeIPA does support trust to an Active Directory forest. The trust can be
established using administrative credentials from the forest root domain or
using a so-called shared secret. In the latter case no administrative access is
given to the remote side of the trust and each administrator performs their
configuration separately: FreeIPA administrator configures IPA side, Active
Directory administrator adds IPA forest as a trusted one on the Active
Directory side.

For trust to be active, one needs to validate it. Validation process includes a
sequences of DCE RPC calls that force a domain controller on the trusted side
to establish a so-called "secure channel" to a remote domain controller in the
trusting domain. This is an administrative operation and requires
administrative privileges to activate. If trust was established using a shared
secret, IPA side will lack ability to initiate a validation process.

At the same time, FreeIPA 4.6 or earlier versions do not include functionality
to allow a remote validation from Active Directory to happen before trust
objects are created and SSSD can retrieve information from the Active Directory
side. Unfortunately, the latter is not possible until trust is validated.

The purpose of this design is to extend FreeIPA setup to allow trust validation
to be initiated from Windows UI in case a shared secret is used to create a
trust agreement.

## Use Cases

As a FreeIPA administrator, I'd like to establish a trust between an Active
Directory forest and a FreeIPA deployment using a shared secret. As FreeIPA
administrator, I have no administrative access to Active Directory and would
like to delegate the operation to create trust on Active Directory side to my
counterpart in Active Directory forest.


## How to Use


1. Establish a one-way trust with a shared secret on IPA side:
   `ipa trust-add <ad-domain> --shared-secret`

2. On Windows side, open Active Directory Domain and Trusts tool
   * Open properties for the Windows forest
   * Choose 'Trusts' tab and press 'New trust' button there
   * Navigate through the trust wizard by entering:
      *  IPA forest name, then 'next'
      *  Choose 'Forest trust' on the Trust Type page
      *  Choose 'One-way: incoming' on the Direction of Trust page
      *  Choose 'This domain only' on the Sides of Trust page
      *  Enter the same shared secret one was using in step (1) with 'ipa trust-add'
   *  Complete trust wizard

3. Going back to the trust properties, one can now validate the trust from Windows side.

One limitation is that it is not possible to retrieve forest trust information
about IPA realm by Active Directory domain controllers due to the fact that
Samba configuration used by IPA does not support a remote query for this
information. It is only available when Samba is used in Samba AD configuration.

TODO: check whether it is possible to force to set forest trust information
from IPA side after both sides of trust are were configured.

## Design

There are two important parts of the solution. On IPA side, there is a module
to allow Samba to look up trusted domains and user/group information in IPA
LDAP. On the other side, there is support for POSIX identities of trusted
domain objects in SSSD.

### FreeIPA module for Samba passdb interface

FreeIPA provides a special module for Samba, `ipasam`, that looks up
information about trusted domains and user/group in FreeIPA LDAP. The module
also maintains trust-related information when trust is created via  DCE RPC
interfaces.

When trust is created, `ipasam` module needs to create a set of Kerberos
principals to allow Kerberos KDC to issue cross-realm ticket granting tickets.
These principals will have the same keys as trusted domain objects on Active
Directory level.

When a secure channel is established between two domain controllers from
separate trusted domains, both DCs rely on the trusted domain object account
credentials to be the same on both sides. However, since Samba has to perform
SMB to POSIX translation when running in POSIX environment, it also needs to
have a POSIX identity associated with the trusted domain object account.

As result, `ipasam` module needs to maintain POSIX attributes for the trusted
domain object account, along with Kerberos principals associated with the
trust.

### SSSD

When Windows successfully authenticates to Samba, Samba needs a POSIX identity
to run `smbd` processes as the authenticated 'user'. `smbd` and `winbindd`
processes use standard system calls to resolve authenticated user to a system
one (`getpwnam_r()`) and if the call fails, whole Windows request is rejected.

Given that trusted domain object accounts are associated with the cross-realm
Kerberos principals, they are located in a special subtree in FreeIPA LDAP:
`cn=trusts,$SUFFIX`. However, SSSD does not look by default in this subtree for
users. By default, SSSD configuration for user accounts looks in
`cn=users,cn=accounts,$SUFFIX` for `id_provider = ipa` and will not be able to
see trusted domain object accounts.

Thus, to allow Windows to successfully validate a one-way shared incoming trust
to FreeIPA, SSSD needs to resolve trusted domain object accounts as POSIX users
on IPA master side.


## Implementation

### FreeIPA `ipasam` module

`ipasam` module needs to create and maintain POSIX identities of the trusted
domain object accounts.

Following objects and their aliases are created and maintained by `ipasam`
module. In the description below `REMOTE` means Kerberos realm of the Active
Directory forest's root domain (e.g. `AD.EXAMPLE.COM`), `REMOTE-FLAT` is
NetBIOS name of the Active Directory forest's root domain (e.g. `AD`).
Correspondingly, `LOCAL` means FreeIPA Kerberos realm (e.g. `IPA.EXAMPLE.COM`)
and `LOCAL-FLAT` is the NetBIOS name of the FreeIPA primary domain (e.g.
`IPA`).

  Principal | Description
  --------- | -----------
  krbtgt/REMOTE@LOCAL | Cross-realm principal representing Active Directory forest root domain
  REMOTE-FLAT$@LOCAL | Trusted domain object account for the Active Directory forest root domain
  krbtgt/REMOTE-FLAT@LOCAL | Alias to REMOTE-FLAT$ TDO
  krbtgt/LOCAL@REMOTE | Cross-realm principal representing IPA domain in Active Directory forest to allow crross-realm TGT issuance from IPA KDC side
  krbtgt/LOCAL-FLAT@REMOTE | Trusted domain object account for IPA domain in Active Directory forest
  LOCAL-FLAT$@REMOTE | Alias to krbtgt/LOCAL-FLAT@REMOTE

For inbound trust `ipasam` module creates following principals:
  * `krbtgt/LOCAL@REMOTE`, enabled by default
  * `krbtgt/LOCAL-FLAT@REMOTE`, used by SSSD to talk to Active Directory domain
    controllers, with canonical name set to `krbtgt/LOCAL-FLAT@REMOTE` because
    Kerberos KDC must use this salt when issuing tickets for this principal. The
    use of this principal is disabled on IPA side (IPA KDC does not issue tickets
    in this name) --- we only retrieve a keytab for the principal in SSSD. SSSD
    retrieves a keytab for this principal using `LOCAL-FLAT$@REMOTE` Principal
    name.

For outbound trust `ipasam` module creates following principals:
  * `krbtgt/REMOTE@LOCAL`, enabled by default.
  * `REMOTE-FLAT$@LOCAL`, enabled by default. Used by a remote AD DC to
    authenticate against Samba on IPA master. This principal will have POSIX
    identity associated.


### SSSD

In IPA master mode, SSSD needs to start look into `cn=trusts,$SUFFIX` subtree
in addition to `cn=users,cn=accounts,$SUFFIX` subtree to find trusted domain
object accounts. This can be achieved either by explicitly adding a second
search base to `ldap_search_user_base` option in the `[domain/...]` section or
by automatically expanding a list of search bases when running in the IPA
master mode. The latter is already implemented in SSSD 1.16.3 and 2.1.0 with
https://pagure.io/SSSD/sssd/c/14faec9cd9437ef116ae054412d25ec2e820e409


Feature Management
------------------

We already allow to create a shared secret-based trust to Active Directory. No
functional change is needed in either Web UI or CLI.

Upgrade
-------

During upgrade POSIX identities need to be created for existing trust
agreements.

