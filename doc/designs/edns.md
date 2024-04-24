# Encrypted DNS Support
FreeIPA DNS integration allows administrator to manage and serve DNS records in a domain using the same CLI or Web UI as when managing identities and policies. At the same time, administrator can benefit from the tight DNS integration in FreeIPA management framework and have configuration changes in FreeIPA server covered by automatic DNS updates.

## What is Encrypted DNS?
Encrypted DNS, also known as DNS over HTTPS (DoH) or DNS over TLS (DoT), is a protocol that encrypts DNS queries and responses exchanged between DNS clients (such as web browsers or applications) and DNS servers. Traditional DNS queries are sent over plaintext connections, which can be intercepted and monitored by malicious actors, posing privacy and security risks.

In modern deployments, The internal network can no longer be trusted, it means that all traffic must be authenticated, authorized and encrypted. Encrypted DNS ensures secure communication by enforcing the use of DoT or DoH methods, encrypting all DNS queries and responses. This feature integrates encrypted DNS seamlessly into the FreeIPA management framework, allowing administrators to manage DNS records alongside identities and policies.

This design page outlines the implementation of DoT and DoH for the FreeIPA integrated DNS service. By integrating these encrypted DNS protocols, we aim to enhance the security, privacy, and reliability of DNS resolution within the FreeIPA environment.

## Goals
The primary goal is to provide a way to deploy integrated DNS server with the enforcement of using DNS over encrypted channels instead of using standard UDP port 53 with unencrypted communication. This means that DNS clients must talk to DNS servers using DoT or DoH methods that are fully encrypted. The scope for the traffic encryption is for all DNS queries that are leaving the host, while the local communication within the host does not require encryption.


## Use Cases
We aim to support DoT and DoH for Server, Replica, and Client deployments. However the initial version of this feature will only support DoT. The full list of use cases includes:

- Installing IPA Server with integrated DNS service with DoT enabled.
- Installing an IPA Replica with integrated DNS service with DoT enabled.
- Installing an IPA Replica without integrated DNS service with DoT enabled.
- Installing an IPA Client with DoT enabled.
- Installing IPA Server with integrated DNS service with DoH enabled.
- Installing an IPA Replica with integrated DNS service with DoH enabled.
- Installing an IPA Replica without integrated DNS service with DoH enabled.
- Installing an IPA Client with DoH enabled.


## Components
Currently, FreeIPA relies on systemd-resolved as a caching recursive resolver (enabled by default in Fedora) and BIND (also known as named) as the authoritative DNS server for managing DNS internal zones and records. BIND integrates with FreeIPA throught the bind-dyndb-ldap LDAP backend plug-in. It allows BIND to use an LDAP directory as a backend for storing DNS zone data (FreeIPA). This plugin enables BIND to perform dynamic updates to DNS records stored in an LDAP directory and provides integration between the DNS server and LDAP for DNS zone management.

With regard DNS over encrypted channels, BIND has an important limitation, it doesn't yet support forwarding over either DoT or DoH to external DNS ([LINK](https://www.isc.org/blogs/2023-BIND-9.18-extended-support/)). To address this limitation and ensure support for secure DNS resolution, we propose leveraging Unbound ([about](https://nlnetlabs.nl/projects/unbound/about/)) as an intermediary resolver. Unbound provides robust support for both DoT and DoH, allowing it to securely forward DNS queries to external DNS servers while maintaining confidentiality and integrity.

Finally, in the new DNS architecture, we opted for disabling systemd-resolved and rely solely on BIND for local caching recursive resolver functionality. This decision is made to simplify our DNS architecture and streamline our DNS resolution process.


## Design
Setting up Unbound with support for DoT/DoH is, of course, just one piece of the puzzle. FreeIPA also needs to make use of these protocols, where a typical deployment involves Servers, Replicas, and clients. The server side poses multiple challenges, with one of the pivotal obstacles residing in the configuration of the DNS service itself.

Henceforth, when we mention the "server side" we are primarily concentrating on the FreeIPA installers and the strategies for disseminating and managing the DNS configuration, as well as deploying the service. The latter aspect will need to accommodate both internal and external DNS services. "Internal" denotes that the server-side and clients (e.g., SSSD, IPA API, etc.) communicate with an internal IPA DNS server through an encrypted channel, with the assumption that the internal DNS server can forward requests to forwarders over an encrypted channel as well. Conversely, "external" implies that the server-side and clients engage with an external DNS server through an encrypted channel.

When FreeIPA is deployed with an “internal” DNS server, it means that FreeIPA operates its own DNS service for the IPA domain, DNS records and forward zones can be established to streamline resolution between IPA hosts and internal network hosts. DNS forwarding is another feature of FreeIPA: for centralized deployments, it's possible to utilize a global forwarder; for distributed setups, per-server forwarders can be configured. As the DNS service is optional, FreeIPA can be also deployed without integrated DNS where FreeIPA uses DNS services provided by an external DNS server. Even if FreeIPA Server is used as a primary DNS server, other external DNS servers can still be used as secondary servers.

The following diagram represents a topology involving FreeIPA Server, Replica and Client:

![edns-diagram](edns/FreeIPA-eDNS-version3.jpg)

Note from the diagram that encryption is needed when queries are leaving the machines. When communication happens inside the host only, encryption is not necessary.

Finally, the trust chain is a critical component of setting up a DoT DNS channel as it enables the client to verify the identity of the DNS server and establish a secure and trusted connection for encrypted DNS communication. To enhance flexibility and accommodate varying deployment scenarios, we plan to introduce additional parameters that allow administrators to provide a certificate at FreeIPA installation time by allowing administrator to specify a custom certificate. The new parameter will be optional, giving administrators the choice to either provide a certificate or rely on custodia for certificate auto enrollment if no certificate is provided.

## Implementation
Most changes involve configuration updates. New installation options for encrypted DNS ensure the deployment and activation of DNS services to encrypt all outbound traffic.


Address of our unbound server has to be set in /etc/resolv.conf.
/etc/resolv.conf
nameserver 127.0.0.1






### Dependencies

New dependencies include Unbound for DNS resolution and encryption





## How to Use

Using DNS with DoT remains largely transparent to users and administrators, requiring only additional options during installation. Pre-installation work is DNS-specific.


### Installation



#### Server
Utilize BIND and Unbound for outgoing requests.
Same CLI options as in the client part
ipa-server-install -a password -p dmpassword -r EXAMPLE.TEST -U --setup-dns --allow-zone-overlap --no-forwarders -N --auto-reverse --token-name softhsm_token --library-path /usr/lib64/pkcs11/libsofthsm2.so



#### Replica
IPA replica installation with DNS service follows the server configuration. If installed without DNS, the configuration mirrors that of the IPA client.

ipa-server-install -a password -p dmpassword -r EXAMPLE.TEST -U --setup-dns --allow-zone-overlap --no-forwarders -N --auto-reverse --token-name softhsm_token --library-path /usr/lib64/pkcs11/libsofthsm2.so



#### Client

Configure Unbound to listen on the loopback address 127.0.0.1, with resolv.conf pointing to it.



| Option | Description                                       |
|:------------------------ | :------------------------------ |
| --dot     | Deploy Unbound with DoT for outgoing DNS requests |
| --dotcert | Path to Certificate (optional)  |

ipa-server-install -a password -p dmpassword -r EXAMPLE.TEST -U --setup-dns --allow-zone-overlap --no-forwarders -N --auto-reverse --token-name softhsm_token --library-path /usr/lib64/pkcs11/libsofthsm2.so



### Upgrade

It will not be possible to upgrade a non-DNS installation into one with an DNS and DoT enabled. 

This seems out-of-scope for initial DNS DoT support.


## Feature Management

### UI

There should be no noticeable change.

### CLI

There should be no noticeable change.

The new DNS attributes will not be visible via the IPA CLI except through `ipa show config`


#### Unbound
#### BIND


## Test plan

A subset of existing tests will be subclassed and executed with DNS enabled (with DoT) in a similar way that DNS without DoT testing was done.


## Out of Scope
DNSSEC is not in the scope
NM integration is not in the scope



## Troubleshooting and debugging
named
unbound
dig


### DNS Client installation failure

The following logs may provide clues:
-

### DNS Server/replica installation failure

The following logs may provide clues:
-


### General



## References
-
