.. AUTO-GENERATED FILE, DO NOT EDIT!

===========================================================
ipa-dns-install(1) -- Add DNS as a service to an IPA server
===========================================================

SYNOPSIS
========

ipa-dns-install [*OPTION*]...

DESCRIPTION
===========

Configure an integrated DNS server on this IPA server, create DNS zone
with the name of the IPA primary DNS domain, and fill it in with service
records necessary for IPA deployment. In cases where the IPA server name
does not belong to the primary DNS domain and is not resolvable using
DNS, create a DNS zone containing the IPA server name as well.

IPA provides an integrated DNS server which can be used to simplify IPA
deployment. If you decide to use it, IPA will automatically maintain SRV
and other service records when you change your topology.

The DNS component in FreeIPA is optional and you may choose to manage
all your DNS records manually on another third party DNS server. IPA DNS
is not a general-purpose DNS server. If you need advanced features like
DNS views, do not deploy IPA DNS.

This command requires that an IPA server is already installed and
configured.

OPTIONS
=======

.. option:: -d, --debug

   Enable debug logging when more verbose output is needed

.. option:: --ip-address=<IP_ADDRESS>

   The IP address of the IPA server. If not provided then this is
   determined based on the hostname of the server. This option can be
   used multiple times to specify more IP addresses of the server (e.g.
   multihomed and/or dualstacked server).

.. option:: --forwarder=<FORWARDER>

   A forwarder is a DNS server where queries for a specific
   non-resolvable address can be directed. To define multiple forwarders
   use multiple instances of ``**--forwarder**``

.. option:: --no-forwarders

   Do not add any DNS forwarders, send non-resolvable addresses to the
   DNS root servers.

.. option:: --auto-forwarders

   Add DNS forwarders configured in /etc/resolv.conf to the list of
   forwarders used by IPA DNS.

.. option:: --forward-policy=<first|only>

   DNS forwarding policy for global forwarders specified using other
   options. Defaults to first if no IP address belonging to a private or
   reserved ranges is detected on local interfaces (RFC 6303). Defaults
   to only if a private IP address is detected.

.. option:: --reverse-zone=<REVERSE_ZONE>

   The reverse DNS zone to use. This option can be used multiple times
   to specify multiple reverse zones.

.. option:: --no-reverse

   Do not create new reverse DNS zone. If used on a replica and a
   reverse DNS zone already exists for the subnet, it will be used.

.. option:: --auto-reverse

   Try to resolve reverse records and reverse zones for server IP
   addresses and if neither is resolvable creates these reverse zones.

.. option:: --no-dnssec-validation

   Disable DNSSEC validation on this server.

.. option:: --dnssec-master

   Setup server to be DNSSEC key master.

.. option:: --disable-dnssec-master

   Disable the DNSSEC master on this server.

.. option:: --kasp-db=<KASP_DB>

   Copy OpenDNSSEC metadata from the specified kasp.db file. This will
   not create a new kasp.db file.

.. option:: --zonemgr

   The e-mail address of the DNS zone manager. Defaults to
   hostmaster@DOMAIN

.. option:: --allow-zone-overlap

   Allow creatin of (reverse) zone even if the zone is already
   resolvable. Using this option is discouraged as it result in later
   problems with domain name resolution.

.. option:: -U, --unattended

   An unattended installation that will never prompt for user input

DEPRECATED OPTIONS
==================

``-p <DM_PASSWORD>, --ds-password=<DM_PASSWORD>``
   The password to be used by the Directory Server for the Directory
   Manager user

EXIT STATUS
===========

0 if the installation was successful

1 if an error occurred
