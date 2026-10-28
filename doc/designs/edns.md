# FreeIPA Integrated DNS Service with DoT Support

Encrypted DNS, also known as DNS over HTTPS (DoH) or DNS over TLS (DoT), is a protocol that encrypts DNS queries and responses exchanged between DNS clients (such as web browsers or applications) and DNS servers. Traditional DNS queries are sent over plaintext connections, which can be intercepted and monitored by malicious actors, posing privacy and security risks.

In modern deployments, the internal network can no longer be trusted, it means that all traffic must be authenticated, authorized and encrypted. Encrypted DNS ensures secure communication by enforcing the use of DoT or DoH methods, encrypting all DNS queries and responses. This feature integrates encrypted DNS seamlessly into the FreeIPA management framework, allowing administrators to decide whether the DNS traffic must be encrypted or not.

FreeIPA now includes support for deploying its integrated DNS service with DoT enabled. This enhancement aligns with modern security standards, providing encrypted communication between DNS clients and the FreeIPA DNS server while retaining the same features and benefits of FreeIPA's DNS integration.

## Goals

The primary goal is to provide a way to deploy an integrated DNS server with the enforcement of using DNS over encrypted channels instead of using standard UDP port 53 with unencrypted communication. This means that DNS clients must talk to DNS servers using a DoT method that is fully encrypted. The scope for the traffic encryption is for all DNS queries that are leaving the host, while the local communication within the host does not require encryption.


## Design Choices

This feature builds upon the existing DNS component in FreeIPA, maintaining its core assumptions and goals while introducing secure communication through DoT. It is designed to enhance FreeIPA's DNS deployment options and address the growing need for encrypted DNS communication. This first version of the feature is limited and restricted as we are aiming for a simple implementation that covers basic use cases. These restrictions will be addressed in future iterations of the feature development.

The initial version of DoT is supported only for new installations, upgrade scenarios to a DoT-enabled setup have not been tested. However, administrators can enable DoT on an existing deployment by reconfiguring the integrated DNS service using `ipa-dns-install` with the new DoT options.

The deployment of the DNS service will depend on the infrastructure configuration. During server/replica/client deployment or client/replica enrollment, both unencrypted and encrypted communications will be allowed by default. However, for more restrictive scenarios where only encrypted communications are allowed, a new option is needed to enforce this behavior. The new option `--dns-policy` will have two choices: `relaxed` will allow unencrypted DNS queries, while `enforced` will restrict unencrypted queries on port 53.

The implementation of DoT in FreeIPA's DNS service leverages the following design choices:

- Current FreeIPA works with `Bind` 9.18. This version of Bind doesn't support DoT-forwarding. Therefore, for server/replica deployment, we rely on an additional component, `unbound`, which redirects encrypted DNS queries to the external DNS server. This includes enabling TLS connections on TCP port 853 and managing TLS certificates for both components `Bind` and `Unbound`. The upgrade to the latest LTS `Bind` version (9.20) is already in progress but not completed. Once this upgrade is complete, the design will be simplified by removing `unbound` as Bind will fully support DoT-forwarding. 

- Configuration Management: New FreeIPA CLI options are introduced to enable and configure DoT settings.

- Certificate Integration: FreeIPA's certificate management framework can automatically be used to generate and manage TLS certificates giving the administrators the choice to either provide a certificate or rely on custodia for certificate auto enrollment if no certificate is provided. These options are handled by the proper CLI options (please check section [CLI](#cli)).

- Service Discovery: Clients and replicas can detect DoT-capable DNS servers directly during installation. However, before using the enforced policy for replica or client enrollment `--dns-policy=enforced`, the administrator must configure the system's DNS settings in NetworkManager to ensure secure discovery of IPA servers. Specifically, the system must be set up to use a DoT-capable resolver. Currently, this manual configuration is required, but future improvements will automate the process. The plan is to enhance `ipa-client-install` to configure Unbound as a DoT forwarder before performing domain discovery, ensuring that SRV/TXT records for IPA server discovery are resolved correctly. This is purely to overcome an existing limitation with Bind 9.18. Note that once Bind 9.20 is fully integrated with IPA, Unbound will no longer be necessary, as Bind will support DoT forwarding.

- The current implementation introduces two new subpackages: `freeipa-client-encrypted-dns` and `freeipa-server-encrypted-dns`. The `freeipa-server-encrypted-dns` package must be manually installed on FreeIPA servers and replicas, while the `freeipa-client-encrypted-dns` package should be installed on client machines. This design ensures that the encrypted DNS feature, along with its configuration templates and dependencies, remains isolated from normal FreeIPA deployments. By structuring it this way, environments that do not require encrypted DNS support are unaffected. Enabling DoT functionality requires explicitly installing these subpackages, providing a clear and modular approach to integrating encrypted DNS into FreeIPA deployments.


## Design Diagram

The following diagram represents a topology involving FreeIPA Server, Replica and Client:

![edns-diagram](edns/FreeIPA-eDNS-version3.jpg)

Note from the diagram that encryption is needed when queries are leaving the machines. When communication happens inside the host only, encryption is not necessary.

FreeIPA currently relies on systemd-resolved as a local cache resolver, which is enabled by default. The design involves disabling the systemd-resolved service and replacing it with the Unbound service. The client configuration relies exclusively on Unbound, with a DoT forwarder pointing to the DNS server. The FreeIPA server configuration consists of two main components: `Bind (named)` as an integrated DNS server, accepting both incoming unencrypted queries from localhost and incoming encrypted queries from external traffic, while relying on `Unbound` for handling outgoing external encrypted traffic. We initially opted for Unbound over systemd-resolved because features such as DoT and DoH are more robust and mature in Unbound. Additionally, proposed changes to Fedora to enhance systemd-resolved were never accepted ([Changes/DNS Over TLS](https://www.fedoraproject.org/wiki/Changes/DNS_Over_TLS), [systemd issue #20801](https://github.com/systemd/systemd/issues/20801), [BZ#1889901](https://bugzilla.redhat.com/show_bug.cgi?id=1889901)).

The FreeIPA replica deployment depends on whether the DNS integrated service is deployed, distinguishing between two use cases: with and without DNS integrated service. A replica with DNS Integrated Service will mimic a client configuration: it will use Unbound with a DoT forwarder pointing to the DNS server. A replica without DNS Integrated Service will mimic a server configuration: it will use `Bind` for handling incoming unencrypted queries from localhost and encrypted queries from external sources, along with `Unbound` for outgoing encrypted traffic.

Another important aspect is the client's ability to perform DNS updates (`nsupdate`) whenever its IP address changes, ensuring that its DNS record remains up-to-date. This communication must also be secured using DoT/DoH. Currently, the client doesn't support nsupdate with GSS-TSIG (which relies on GSS-API to obtain the secret TSIG key) and unauthenticated updates. However, to address this, we integrated `nsupdate` DoT functionality from Bind 9.20 into Bind 9.18, the version currently supported by FreeIPA. As a result, `nsupdate` is now enhanced with new DoT options, allowing it to function correctly in secure environments.

## High-level workflow

Enabling DoT: Administrators enable DoT during initial setup or by updating existing DNS configurations through the CLI.

Certificate Management: FreeIPA generates and assigns TLS certificates to the DNS service. Administrators can also provide custom certificates if needed.

DoT Operations: The DNS components listen for DoT traffic on TCP port 853, providing secure communication to clients.

## How to Use

During the deployment of a FreeIPA server, replica, or client, new options are available to enable DoT support. These options allow administrators to enhance the security of DNS traffic. Here’s how to use the new options:

- Enable DoT: use the `--dns-over-tls` option to enable DoT support during the deployment of clients, servers, or replicas. This option deploys Unbound as a local cache resolver (with /etc/resolv.conf pointing to 127.0.0.1 on servers and replicas) and configures Bind on the server to receive DoT requests. On the client side, only Unbound will be deployed (with /etc/resolv.conf pointing to 127.0.0.53). Replica deployment configuration depends on whether the Integrated DNS service is deployed on the new replica. If it is, the server configuration will apply. If the Integrated DNS server is not deployed on the replica, the client configuration will apply.

- Specify an Upstream DNS Server with DoT enabled: use the `--dot-forwarder` option to specify the upstream DNS server that supports DoT. The format must be 1.2.3.4#dns.server.test. You still need to specify at least one of `--forwarder`, `--auto-forwarders`, or `--no-forwarders` options for the non-encrypted communication as well as discovery process.

- DoT Certificates. If you prefer to use certificates for DoT in Bind/Unbound, use the `--dns-over-tls-key` and `--dns-over-tls-cert` options. These options primarily works with PEM-formatted certificate files. If these options are not specified, the IPA CA will be used to request a new certificate.

- DNS Policy: use `--dns-policy` to define the DNS security policy for FreeIPA deployments. It accepts two values: `relaxed` and `enforced`. When set to `relaxed`, the system will attempt to use DoT but will fall back to unencrypted DNS if DoT is unavailable. This mode ensures compatibility with environments where encrypted DNS is not fully supported. When set to `enforced`, the system strictly requires DoT, and any DNS resolution that does not support encryption will be rejected, including discovery from clients.


### CLI

Overview of the CLI commands for the FreeIPA installers and FreeIPA DNS installers:

Configuring DNS services using ipa-dns-install follows the same principles as installing DNS with the ipa-server-install utility.


| Option | Description                                       |
|:------------------------ | :------------------------------ |
| --dns-over-tls  | enable DNS over TLS support. This option is present on both client and server. It deploys Unbound and configures Bind on the server to receive DoT requests.|
| --dot-forwarder | the upstream DNS server with DoT support. It must be specified in the format 1.2.3.4#dns.server.test|
| --dns-over-tls-key and --dns-over-tls-cert | in case user prefers to have the DoT certificate in Bind generated by themselves. If these are empty, IPA CA is used instead to request a new certificate. |
| --dns-policy | Defines the DNS security policy. Accepts `relaxed` (attempts DoT but falls back to unencrypted DNS if unavailable) or `enforced` (strictly requires DoT and rejects unencrypted DNS resolution). |


## Troubleshooting and debugging

### Testing and Debugging Unbound

If you have DNS resolution issues, confirm that the Unbound service is running with:

`# systemctl status unbound`

Other checks that can be performed:
- Verify that Unbound is listening on the correct IP addresses and ports.
- Ensure firewall settings allow traffic on port 53 (DNS) and port 853 (DNS over TLS).
- Review the Unbound configuration file `/etc/unbound/unbound.conf` to ensure proper setup.
- Check for errors in the Unbound logs: `journalctl -u unbound`


You can also increase the logging output for Unbound edit `/etc/unbound/unbound.conf` or create a specific logging configuration file (e.g. `/etc/unbound/conf.d/logging.conf`):

```
server:
    verbosity: 3
```

Restart Unbound to apply the changes:
`# systemctl restart unbound`

and monitor the Unbound logs for detailed output:

`# tail -f /var/log/unbound/unbound.log`

To test the resolution from Unbound using the unbound-host standalone utility you want to use:

`# unbound-host -C /etc/unbound/conf.d/tls-client.conf example.org`


If you have issues with encryption not working:
- Ensure that forward-tls-upstream is enabled in the Unbound configuration (`/etc/unbound/unbound.conf`).
- Verify that tls-cert-bundle or tls-system-cert is correctly configured and that the specified certificate files are accessible and have the correct permissions.
- Check if the system’s certificate bundle is located at the expected path (e.g. `/etc/pki/ca-trust/extracted/pem/`).


Alternatively you can also use bind-utils to verify that resolution works through Unbound:

`# dig @localhost example.org`

For a very basic test of Unbound using OpenSSL

`# openssl s_client -connect [::1]:853 -verify_hostname unbound < /dev/null`

Output example:

```
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = unbound
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = unbound
verify return:1
---
Certificate chain
 0 s:CN = unbound
   i:CN = unbound
   a:PKEY: rsaEncryption, 3072 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jul 13 18:09:50 2023 GMT; NotAfter: Mar 30 18:09:50 2043 GMT
---
```

### Testing and Debugging Bind

Verify that the Bind service is running correctly:

`# systemctl status named`

You can run check tool to verify the Bind configuration:

`# named-checkconf /etc/named.conf`

Check for errors related to DNS resolution in the system logs `/var/named/data/named.run` or run `journalctl -u named`

Restart the Bind service to apply changes `systemctl restart named`

You can always increase the Bind logging verbosity to debug issues. Edit the Bind configuration file to increase logging levels:

```
logging {
    channel default_debug {
        file "data/named.run";
        severity dynamic;
    };
    category default { default_debug; };
};
```
Restart Bind to apply the changes:
`# systemctl restart named`

and monitor the logs for detailed output:

`# tail -f /var/named/data/named.run`



### Monitoring Traffic with tcpdump and Wireshark

To watch DNS requests and ensure they are encrypted you can easily use tcpdump to capture traffic on port 53 and port 853:
`# tcpdump -n port 53 or port 853`

Alternatively you can rely on Wireshark for more detailed analysis where:
- Port 53 queries should be visible and decodable.
- Port 853 queries or answers should be encrypted and not decodable. A private key can be loaded into wireshark to decrypt the traffic (https://wiki.wireshark.org/TLS#tls-decryption)

### Debugging Client-Side or nsupdate Issues

To test nsupdate and ensure that DNS updates are functioning correctly you can increase the verbosity of nsupdate logs for detailed debugging when running an update, you want to provide DoT options:

`# nsupdate -A tlscafile -E tlscertfile -H tlshostname -K tlskeyfile -d -v`
