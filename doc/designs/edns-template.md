# Encrypted DNS Support
FreeIPA DNS integration allows administrator to manage and serve DNS records in a domain using the same CLI or Web UI as when managing identities and policies. At the same time, administrator can benefit from the tight DNS integration in FreeIPA management framework and have configuration changes in FreeIPA server covered by automatic DNS updates.

## Overview

Short overview of the problem set and any background material or references one would need to understand the details.

Encrypted DNS, also known as DNS over HTTPS (DoH) or DNS over TLS (DoT), is a protocol that encrypts DNS queries and responses exchanged between DNS clients (such as web browsers or applications) and DNS servers. Traditional DNS queries are sent over plaintext connections, which can be intercepted and monitored by malicious actors, posing privacy and security risks.

In modern deployments, The internal network can no longer be trusted, it means that all traffic must be authenticated, authorized and encrypted. Encrypted DNS ensures secure communication by enforcing the use of DoT or DoH methods, encrypting all DNS queries and responses. This feature integrates encrypted DNS seamlessly into the FreeIPA management framework, allowing administrators to manage DNS records alongside identities and policies.

This design page outlines the implementation of DoT and DoH for the FreeIPA integrated DNS service. By integrating these encrypted DNS protocols, we aim to enhance the security, privacy, and reliability of DNS resolution within the FreeIPA environment.


## Goals
The primary goal is to provide a way to deploy integrated DNS server with the enforcement of using DNS over encrypted channels instead of using standard UDP port 53 with unencrypted communication. This means that DNS clients must talk to DNS servers using DoT or DoH methods that are fully encrypted. The scope for the traffic encryption is for all DNS queries that are leaving the host, while the local communication within the host does not require encryption.

## Use Cases

Walk through one or more full examples of how the feature will be used. These should not all be the simplest cases. 

We aim to support DoT and DoH for Server, Replica, and Client deployments. However the initial version of this feature will only support DoT. The full list of use cases includes:

- Installing IPA Server with integrated DNS service with DoT enabled.
- Installing an IPA Replica with integrated DNS service with DoT enabled.
- Installing an IPA Replica without integrated DNS service with DoT enabled.
- Installing an IPA Client with DoT enabled.
- Installing IPA Server with integrated DNS service with DoH enabled.
- Installing an IPA Replica with integrated DNS service with DoH enabled.
- Installing an IPA Replica without integrated DNS service with DoH enabled.
- Installing an IPA Client with DoH enabled.

## How to Use

This a starting point for design discussions.

Easy to follow instructions how to use the new feature according to the [use cases](#use-cases) described above. FreeIPA user needs to be able to follow the steps and demonstrate the new features.

The chapter may be divided in sub-sections per [Use Case](#use-cases). 

## Design

The proposed solution. This may include but is not limited to:

- High Level schema([Example 1](https://www.freeipa.org/page/V4/OTP), [Example 2](https://www.freeipa.org/page/V4/Migrating_existing_environments_to_Trust))
- Information or update workflow
- Access control (may include [new permissions](https://www.freeipa.org/page/V4/Permissions_V2))
- Compatibility with other (older) version of FreeIPA. Think if the feature requires a minimum [Domain level](https://www.freeipa.org/page/V4/Domain_Levels).

For other hints what to consider see [general considerations](https://www.freeipa.org/page/General_considerations) page. 

Setting up Unbound with support for DoT/DoH is, of course, just one piece of the puzzle. FreeIPA also needs to make use of these protocols, where a typical deployment involves Servers, Replicas, and clients. The server side poses multiple challenges, with one of the pivotal obstacles residing in the configuration of the DNS service itself.

Henceforth, when we mention the "server side" we are primarily concentrating on the FreeIPA installers and the strategies for disseminating and managing the DNS configuration, as well as deploying the service. The latter aspect will need to accommodate both internal and external DNS services. "Internal" denotes that the server-side and clients (e.g., SSSD, IPA API, etc.) communicate with an internal IPA DNS server through an encrypted channel, with the assumption that the internal DNS server can forward requests to forwarders over an encrypted channel as well. Conversely, "external" implies that the server-side and clients engage with an external DNS server through an encrypted channel.

When FreeIPA is deployed with an “internal” DNS server, it means that FreeIPA operates its own DNS service for the IPA domain, DNS records and forward zones can be established to streamline resolution between IPA hosts and internal network hosts. DNS forwarding is another feature of FreeIPA: for centralized deployments, it's possible to utilize a global forwarder; for distributed setups, per-server forwarders can be configured. As the DNS service is optional, FreeIPA can be also deployed without integrated DNS where FreeIPA uses DNS services provided by an external DNS server. Even if FreeIPA Server is used as a primary DNS server, other external DNS servers can still be used as secondary servers.

The following diagram represents a topology involving FreeIPA Server, Replica and Client:

![edns-diagram](edns/FreeIPA-eDNS-version3.jpg)

Note from the diagram that encryption is needed when queries are leaving the machines. When communication happens inside the host only, encryption is not necessary.

Finally, the trust chain is a critical component of setting up a DoT DNS channel as it enables the client to verify the identity of the DNS server and establish a secure and trusted connection for encrypted DNS communication. To enhance flexibility and accommodate varying deployment scenarios, we plan to introduce additional parameters that allow administrators to provide a certificate at FreeIPA installation time by allowing administrator to specify a custom certificate. The new parameter will be optional, giving administrators the choice to either provide a certificate or rely on custodia for certificate auto enrollment if no certificate is provided.



## Implementation

Any implementation details you would like to spell out. Describe any technical details here. Make sure you cover

- Dependencies: any new dependencies that FreeIPA project packages would gain and that needs to be packaged in distros? The proposal needs to be carefully reviewed, so that FreeIPA dependency size does not increase without strong justification.
- Backup and Restore: any new file to back up or change required in [Backup and Restore](https://www.freeipa.org/page/V3/Backup_and_Restore)?

If this section is not trivial, move it to /Implementation sub page and only include link. 


Most changes involve configuration updates. New installation options for encrypted DNS ensure the deployment and activation of DNS services to encrypt all outbound traffic.

Address of our unbound server has to be set in /etc/resolv.conf.
/etc/resolv.conf
nameserver 127.0.0.1


## Feature Management

### UI

How the feature will be managed via the Web UI. 

### CLI

Overview of the CLI commands. Example:

Configuring DNS services using ipa-dns-install follows the same principles as installing DNS with the ipa-server-install utility. 

| Option | Description                                       |
|:------------------------ | :------------------------------ |
|    --dns-over-tls | enable DNS over TLS support. This option is present on both client and server. It deploys Unbound and configures BIND on the server to receive DoT requests. |
    --dot-forwarder | the upstream DNS server with DoT support. It must be specified in the format 1.2.3.4#dns.server.test |
    --dns-over-tls-key and --dns-over-tls-cert | in case user prefers to have the DoT certificate in BIND generated by themselves. If these are empty, IPA CA is used instead to request a new certificate. |



### Configuration

Any configuration options? Any commands to enable/disable the feature or turn on/off its parts? 

## Upgrade

Any impact on upgrades? Remove this section if not applicable. 

## Test plan

Test scenarios that will be transformed to test cases for FreeIPA [Continuous Integration](https://www.freeipa.org/page/V3/Integration_testing) during implementation or review phase. This can be also link to source in [pagure](https://pagure.io/freeipa.git) with the test, if appropriate. 

## Troubleshooting and debugging

Include as much information as possible that would help troubleshooting:
- Does the feature rely on existing files (keytabs, config file...)
- Does the feature produce logs? in a file or in the journal?
- Does the feature create/rely on LDAP entries? 
- How to enable debug logs?
- When the feature doesn't work, is it possible to diagnose which step failed? Are there intermediate steps that produce logs?
