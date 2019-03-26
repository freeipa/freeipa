# Hidden replicas

**TECH PREVIEW**

## Overview

A hidden replica is an IPA master server that is not advertised to
clients or other masters. Hidden replicas have all services running
and available, but none of the services has any DNS SRV records or
enabled LDAP server roles. This makes hidden replicas invisible for
service discovery.

* IPA clients and SSSD ignore hidden replicas and don't consider them
  during installation or daily operations.
* Kerberos clients with ``dns_lookup_kdc = True`` do not auto-discover
  hidden replicas.
* Certmonger does not use a hidden replica to renew certificates.
* Masters without a CA or KRA instance never use CA or KRA services
  of a hidden replica.

By default, only services on a hidden replica use other services on
the same machine, e.g. local LDAP and Kerberos services.

## Limitations

It's critical to understand that hidden replicas have limitations. Most
importantly, hidden replicas are just concealed, but not isolated and
secluded. Other machines merely don't see hidden replicas, when they
use standard mechanisms to discover IPA servers. Other machines are
able to find hidden replicas if they know what to look for. Any machine
is able to use services on a hidden replica, when they are explicitly
configured to do so.

* Hidden replicas are neither firewalled nor do they have any ACLs in
  place to prevent connections from other machines. All IPA TCP and
  UDP ports must be open for at least all other IPA servers.
* There must be at least one regular, non-hidden server available and
  online for each service (IPA master, DNS, CA, KRA). If DNS locations
  are used, there should be at least one regular replica in each
  location.
* As of now, a hidden replica cannot be a *CA renewal master* or
  a *DNSSEC key master*. The restriction may be lifted in the future.
* Hard-coded server names and explicit configurations like
  ``ipa-client-install --server=$HOST``, SSSD config, or ``ca_host``
  setting in ``/etc/ipa/default.conf`` override auto-discovery.
* The process of demoting a regular replica to hidden replica or
  promotion from hidden to regular replica is not instantaneous. It
  takes a while until the changes have been replicated and cached
  settings are refreshed.

## Use Cases

Hidden replicas are primarily designed for dedicated services that may
otherwise disrupt clients. For example a full backup requires a
complete shutdown of all IPA services. Since a hidden replica is not
used by any clients by default, a temporary shutdown does not affect
clients.

Other use cases include operations that put a high load on the IPA
API or LDAP server, like mass imports or extensive queries.

## How to Use

### installation of a hidden replica

A new hidden replica can be installed with
``ipa-replica-install --hidden-replica``.

### demotion / promotion of hidden replicas

A new command ``ipa server-state`` can be used to modify the state of a
replica. An existing replica can be demoted to a hidden replica by
executing ``ipa server-state $HOST --state=hidden``. The command
``ipa server-state $HOST --state=enable`` turns a hidden replica
into an enabled, visible replica.

A *CA renewal master* or *DNSSEC key master* can't be demoted to hidden
replica. First the services must be moved to another replica with
``ipa-dns-install --dnssec-master`` and
``ipa config-mod --ca-renewal-master-server=$HOST``.

### query status

The ``ipa config-show`` command now shows additional information about
DNS and KRA as well as hidden servers:

```
$ ipa config-show
  ...
  IPA masters: server1.ipa.example
  Hidden IPA masters: hidden1.ipa.example
  IPA master capable of PKINIT: hidden1.ipa.example, server1.ipa.example
  IPA CA servers: server1.ipa.example
  Hidden IPA CA servers: hidden1.ipa.example
  IPA CA renewal master: server1.ipa.example
  IPA KRA servers: server1.ipa.example
  Hidden IPA KRA servers: hidden1.ipa.example
  IPA DNS servers: server1.ipa.example
  Hidden IPA DNS servers: hidden1.ipa.example
  IPA DNSSec key master: server1.ipa.example
$ ipa server-role-find --server=hidden1.ipa.example --include-master
----------------------
6 server roles matched
----------------------
  Server name: hidden1.ipa.example
  Role name: AD trust agent
  Role status: absent

  Server name: hidden1.ipa.example
  Role name: AD trust controller
  Role status: absent

  Server name: hidden1.ipa.example
  Role name: CA server
  Role status: hidden

  Server name: hidden1.ipa.example
  Role name: DNS server
  Role status: hidden

  Server name: hidden1.ipa.example
  Role name: IPA master
  Role status: hidden

  Server name: hidden1.ipa.example
  Role name: KRA server
  Role status: hidden
----------------------------
Number of entries returned 6
----------------------------
```

## Implementation

The status of a service is stored in LDAP inside the
``cn=masters,cn=ipa,cn=etc,$SUFFIX`` subtree. The subtree contains
entries for each IPA master. Each entry holds a bunch of sub entries
for services. For example
``cn=CA,cn=hidden1.ipa.example,cn=masters,cn=ipa,cn=etc,$SUFFIX`` is
the container for the *CA* service on the IPA master
*hidden1.ipa.example*. During the installation process the service
entries are created with multi-valued attribute ``ipaConfigString``
set to ``configuredService``. At the end of the installation,
``configuredService`` is either replaced with ``enabledService`` for a
standard, enabled, and visible replica. Or it is set to
``hiddenService`` for hidden, unadvertised replicas.

Auto-discovery ignores any and all hidden services. The
``dns-update-system-records`` does not create SRV records for hidden
services. The ``find_providing_servers`` API ignores hidden services
except for preferred hosts. CA and KRA service discovery use the
current host or explicit ``ca_host`` option from
``/etc/ipa/default.conf`` as preferred host.
