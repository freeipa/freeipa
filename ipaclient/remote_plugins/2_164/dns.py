#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
Domain Name System (DNS)

Manage DNS zone and resource records.

SUPPORTED ZONE TYPES

 * Master zone (dnszone-*), contains authoritative data.
 * Forward zone (dnsforwardzone-*), forwards queries to configured forwarders
 (a set of DNS servers).

USING STRUCTURED PER-TYPE OPTIONS

There are many structured DNS RR types where DNS data stored in LDAP server
is not just a scalar value, for example an IP address or a domain name, but
a data structure which may be often complex. A good example is a LOC record
[RFC1876] which consists of many mandatory and optional parts (degrees,
minutes, seconds of latitude and longitude, altitude or precision).

It may be difficult to manipulate such DNS records without making a mistake
and entering an invalid value. DNS module provides an abstraction over these
raw records and allows to manipulate each RR type with specific options. For
each supported RR type, DNS module provides a standard option to manipulate
a raw records with format --<rrtype>-rec, e.g. --mx-rec, and special options
for every part of the RR structure with format --<rrtype>-<partname>, e.g.
--mx-preference and --mx-exchanger.

When adding a record, either RR specific options or standard option for a raw
value can be used, they just should not be combined in one add operation. When
modifying an existing entry, new RR specific options can be used to change
one part of a DNS record, where the standard option for raw value is used
to specify the modified value. The following example demonstrates
a modification of MX record preference from 0 to 1 in a record without
modifying the exchanger:
ipa dnsrecord-mod --mx-rec="0 mx.example.com." --mx-preference=1


EXAMPLES:

 Add new zone:
   ipa dnszone-add example.com --admin-email=admin@example.com

 Add system permission that can be used for per-zone privilege delegation:
   ipa dnszone-add-permission example.com

 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:
   ipa dnszone-mod example.com --dynamic-update=TRUE

   This is the equivalent of:
     ipa dnszone-mod example.com --dynamic-update=TRUE \
      --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA; grant EXAMPLE.COM krb5-self * SSHFP;"

 Modify the zone to allow zone transfers for local network only:
   ipa dnszone-mod example.com --allow-transfer=192.0.2.0/24

 Add new reverse zone specified by network IP address:
   ipa dnszone-add --name-from-ip=192.0.2.0/24

 Add second nameserver for example.com:
   ipa dnsrecord-add example.com @ --ns-rec=nameserver2.example.com

 Add a mail server for example.com:
   ipa dnsrecord-add example.com @ --mx-rec="10 mail1"

 Add another record using MX record specific options:
  ipa dnsrecord-add example.com @ --mx-preference=20 --mx-exchanger=mail2

 Add another record using interactive mode (started when dnsrecord-add, dnsrecord-mod,
 or dnsrecord-del are executed with no options):
  ipa dnsrecord-add example.com @
  Please choose a type of DNS resource record to be added
  The most common types for this type of zone are: NS, MX, LOC

  DNS resource record type: MX
  MX Preference: 30
  MX Exchanger: mail3
    Record name: example.com
    MX record: 10 mail1, 20 mail2, 30 mail3
    NS record: nameserver.example.com., nameserver2.example.com.

 Delete previously added nameserver from example.com:
   ipa dnsrecord-del example.com @ --ns-rec=nameserver2.example.com.

 Add LOC record for example.com:
   ipa dnsrecord-add example.com @ --loc-rec="49 11 42.4 N 16 36 29.6 E 227.64m"

 Add new A record for www.example.com. Create a reverse record in appropriate
 reverse zone as well. In this case a PTR record "2" pointing to www.example.com
 will be created in zone 2.0.192.in-addr.arpa.
   ipa dnsrecord-add example.com www --a-rec=192.0.2.2 --a-create-reverse

 Add new PTR record for www.example.com
   ipa dnsrecord-add 2.0.192.in-addr.arpa. 2 --ptr-rec=www.example.com.

 Add new SRV records for LDAP servers. Three quarters of the requests
 should go to fast.example.com, one quarter to slow.example.com. If neither
 is available, switch to backup.example.com.
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 3 389 fast.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="0 1 389 slow.example.com"
   ipa dnsrecord-add example.com _ldap._tcp --srv-rec="1 1 389 backup.example.com"

 The interactive mode can be used for easy modification:
  ipa dnsrecord-mod example.com _ldap._tcp
  No option to modify specific record provided.
  Current DNS record contents:

  SRV record: 0 3 389 fast.example.com, 0 1 389 slow.example.com, 1 1 389 backup.example.com

  Modify SRV record '0 3 389 fast.example.com'? Yes/No (default No):
  Modify SRV record '0 1 389 slow.example.com'? Yes/No (default No): y
  SRV Priority [0]:                     (keep the default value)
  SRV Weight [1]: 2                     (modified value)
  SRV Port [389]:                       (keep the default value)
  SRV Target [slow.example.com]:        (keep the default value)
  1 SRV record skipped. Only one value per DNS record type can be modified at one time.
    Record name: _ldap._tcp
    SRV record: 0 3 389 fast.example.com, 1 1 389 backup.example.com, 0 2 389 slow.example.com

 After this modification, three fifths of the requests should go to
 fast.example.com and two fifths to slow.example.com.

 An example of the interactive mode for dnsrecord-del command:
   ipa dnsrecord-del example.com www
   No option to delete specific record provided.
   Delete all? Yes/No (default No):     (do not delete all records)
   Current DNS record contents:

   A record: 192.0.2.2, 192.0.2.3

   Delete A record '192.0.2.2'? Yes/No (default No):
   Delete A record '192.0.2.3'? Yes/No (default No): y
     Record name: www
     A record: 192.0.2.2               (A record 192.0.2.3 has been deleted)

 Show zone example.com:
   ipa dnszone-show example.com

 Find zone with "example" in its domain name:
   ipa dnszone-find example

 Find records for resources with "www" in their name in zone example.com:
   ipa dnsrecord-find example.com www

 Find A records with value 192.0.2.2 in zone example.com
   ipa dnsrecord-find example.com --a-rec=192.0.2.2

 Show records for resource www in zone example.com
   ipa dnsrecord-show example.com www

 Delegate zone sub.example to another nameserver:
   ipa dnsrecord-add example.com ns.sub --a-rec=203.0.113.1
   ipa dnsrecord-add example.com sub --ns-rec=ns.sub.example.com.

 Delete zone example.com with all resource records:
   ipa dnszone-del example.com

 If a global forwarder is configured, all queries for which this server is not
 authoritative (e.g. sub.example.com) will be routed to the global forwarder.
 Global forwarding configuration can be overridden per-zone.

 Semantics of forwarding in IPA matches BIND semantics and depends on the type
 of zone:
   * Master zone: local BIND replies authoritatively to queries for data in
   the given zone (including authoritative NXDOMAIN answers) and forwarding
   affects only queries for names below zone cuts (NS records) of locally
   served zones.

   * Forward zone: forward zone contains no authoritative data. BIND forwards
   queries, which cannot be answered from its local cache, to configured
   forwarders.

 Semantics of the --forward-policy option:
   * none - disable forwarding for the given zone.
   * first - forward all queries to configured forwarders. If they fail,
   do resolution using DNS root servers.
   * only - forward all queries to configured forwarders and if they fail,
   return failure.

 Disable global forwarding for given sub-tree:
   ipa dnszone-mod example.com --forward-policy=none

 This configuration forwards all queries for names outside the example.com
 sub-tree to global forwarders. Normal recursive resolution process is used
 for names inside the example.com sub-tree (i.e. NS records are followed etc.).

 Forward all requests for the zone external.example.com to another forwarder
 using a "first" policy (it will send the queries to the selected forwarder
 and if not answered it will use global root servers):
   ipa dnsforwardzone-add external.example.com --forward-policy=first \
                               --forwarder=203.0.113.1

 Change forward-policy for external.example.com:
   ipa dnsforwardzone-mod external.example.com --forward-policy=only

 Show forward zone external.example.com:
   ipa dnsforwardzone-show external.example.com

 List all forward zones:
   ipa dnsforwardzone-find

 Delete forward zone external.example.com:
   ipa dnsforwardzone-del external.example.com

 Resolve a host name to see if it exists (will add default IPA domain
 if one is not included):
   ipa dns-resolve www.example.com
   ipa dns-resolve www


GLOBAL DNS CONFIGURATION

DNS configuration passed to command line install script is stored in a local
configuration file on each IPA server where DNS service is configured. These
local settings can be overridden with a common configuration stored in LDAP
server:

 Show global DNS configuration:
   ipa dnsconfig-show

 Modify global DNS configuration and set a list of global forwarders:
   ipa dnsconfig-mod --forwarder=203.0.113.113
""")

register = Registry()


@register()
class dnsconfig(Object):
    takes_params = (
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            label=_('Global forwarders'),
            doc=_('Global forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            label=_('Forward policy'),
            doc=_('Global forwarding policy. Set to "none" to disable any configured global forwarders.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records'),
        ),
        parameters.Int(
            'idnszonerefresh',
            required=False,
            label=_('Zone refresh interval'),
        ),
    )


@register()
class dnsforwardzone(Object):
    takes_params = (
        parameters.DNSNameParam(
            'idnsname',
            primary_key=True,
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
        ),
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Bool(
            'idnszoneactive',
            required=False,
            label=_('Active zone'),
            doc=_('Is zone active?'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
    )


@register()
class dnsrecord(Object):
    takes_params = (
        parameters.DNSNameParam(
            'idnsname',
            primary_key=True,
            label=_('Record name'),
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            label=_('Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
        ),
        parameters.Any(
            'dnsrecords',
            required=False,
            label=_('Records'),
        ),
        parameters.Str(
            'dnstype',
            required=False,
            label=_('Record type'),
        ),
        parameters.Str(
            'dnsdata',
            required=False,
            label=_('Record data'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            label=_('A record'),
            doc=_('Raw A records'),
        ),
        parameters.Str(
            'a_part_ip_address',
            required=False,
            label=_('A IP Address'),
            doc=_('IP Address'),
        ),
        parameters.Flag(
            'a_extra_create_reverse',
            required=False,
            label=_('A Create reverse'),
            doc=_('Create reverse record for this IP Address'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            label=_('AAAA record'),
            doc=_('Raw AAAA records'),
        ),
        parameters.Str(
            'aaaa_part_ip_address',
            required=False,
            label=_('AAAA IP Address'),
            doc=_('IP Address'),
        ),
        parameters.Flag(
            'aaaa_extra_create_reverse',
            required=False,
            label=_('AAAA Create reverse'),
            doc=_('Create reverse record for this IP Address'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            label=_('A6 record'),
            doc=_('Raw A6 records'),
        ),
        parameters.Str(
            'a6_part_data',
            required=False,
            label=_('A6 Record data'),
            doc=_('Record data'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            label=_('AFSDB record'),
            doc=_('Raw AFSDB records'),
        ),
        parameters.Int(
            'afsdb_part_subtype',
            required=False,
            label=_('AFSDB Subtype'),
            doc=_('Subtype'),
        ),
        parameters.DNSNameParam(
            'afsdb_part_hostname',
            required=False,
            label=_('AFSDB Hostname'),
            doc=_('Hostname'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            label=_('APL record'),
            doc=_('Raw APL records'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            label=_('CERT record'),
            doc=_('Raw CERT records'),
        ),
        parameters.Int(
            'cert_part_type',
            required=False,
            label=_('CERT Certificate Type'),
            doc=_('Certificate Type'),
        ),
        parameters.Int(
            'cert_part_key_tag',
            required=False,
            label=_('CERT Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'cert_part_algorithm',
            required=False,
            label=_('CERT Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Str(
            'cert_part_certificate_or_crl',
            required=False,
            label=_('CERT Certificate/CRL'),
            doc=_('Certificate/CRL'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            label=_('CNAME record'),
            doc=_('Raw CNAME records'),
        ),
        parameters.DNSNameParam(
            'cname_part_hostname',
            required=False,
            label=_('CNAME Hostname'),
            doc=_('A hostname which this alias hostname points to'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            label=_('DHCID record'),
            doc=_('Raw DHCID records'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            label=_('DLV record'),
            doc=_('Raw DLV records'),
        ),
        parameters.Int(
            'dlv_part_key_tag',
            required=False,
            label=_('DLV Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'dlv_part_algorithm',
            required=False,
            label=_('DLV Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'dlv_part_digest_type',
            required=False,
            label=_('DLV Digest Type'),
            doc=_('Digest Type'),
        ),
        parameters.Str(
            'dlv_part_digest',
            required=False,
            label=_('DLV Digest'),
            doc=_('Digest'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            label=_('DNAME record'),
            doc=_('Raw DNAME records'),
        ),
        parameters.DNSNameParam(
            'dname_part_target',
            required=False,
            label=_('DNAME Target'),
            doc=_('Target'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            label=_('DS record'),
            doc=_('Raw DS records'),
        ),
        parameters.Int(
            'ds_part_key_tag',
            required=False,
            label=_('DS Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'ds_part_algorithm',
            required=False,
            label=_('DS Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'ds_part_digest_type',
            required=False,
            label=_('DS Digest Type'),
            doc=_('Digest Type'),
        ),
        parameters.Str(
            'ds_part_digest',
            required=False,
            label=_('DS Digest'),
            doc=_('Digest'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            label=_('HIP record'),
            doc=_('Raw HIP records'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            label=_('IPSECKEY record'),
            doc=_('Raw IPSECKEY records'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            label=_('KEY record'),
            doc=_('Raw KEY records'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            label=_('KX record'),
            doc=_('Raw KX records'),
        ),
        parameters.Int(
            'kx_part_preference',
            required=False,
            label=_('KX Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.DNSNameParam(
            'kx_part_exchanger',
            required=False,
            label=_('KX Exchanger'),
            doc=_('A host willing to act as a key exchanger'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            label=_('LOC record'),
            doc=_('Raw LOC records'),
        ),
        parameters.Int(
            'loc_part_lat_deg',
            required=False,
            label=_('LOC Degrees Latitude'),
            doc=_('Degrees Latitude'),
        ),
        parameters.Int(
            'loc_part_lat_min',
            required=False,
            label=_('LOC Minutes Latitude'),
            doc=_('Minutes Latitude'),
        ),
        parameters.Decimal(
            'loc_part_lat_sec',
            required=False,
            label=_('LOC Seconds Latitude'),
            doc=_('Seconds Latitude'),
        ),
        parameters.Str(
            'loc_part_lat_dir',
            required=False,
            label=_('LOC Direction Latitude'),
            doc=_('Direction Latitude'),
        ),
        parameters.Int(
            'loc_part_lon_deg',
            required=False,
            label=_('LOC Degrees Longitude'),
            doc=_('Degrees Longitude'),
        ),
        parameters.Int(
            'loc_part_lon_min',
            required=False,
            label=_('LOC Minutes Longitude'),
            doc=_('Minutes Longitude'),
        ),
        parameters.Decimal(
            'loc_part_lon_sec',
            required=False,
            label=_('LOC Seconds Longitude'),
            doc=_('Seconds Longitude'),
        ),
        parameters.Str(
            'loc_part_lon_dir',
            required=False,
            label=_('LOC Direction Longitude'),
            doc=_('Direction Longitude'),
        ),
        parameters.Decimal(
            'loc_part_altitude',
            required=False,
            label=_('LOC Altitude'),
            doc=_('Altitude'),
        ),
        parameters.Decimal(
            'loc_part_size',
            required=False,
            label=_('LOC Size'),
            doc=_('Size'),
        ),
        parameters.Decimal(
            'loc_part_h_precision',
            required=False,
            label=_('LOC Horizontal Precision'),
            doc=_('Horizontal Precision'),
        ),
        parameters.Decimal(
            'loc_part_v_precision',
            required=False,
            label=_('LOC Vertical Precision'),
            doc=_('Vertical Precision'),
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            label=_('MX record'),
            doc=_('Raw MX records'),
        ),
        parameters.Int(
            'mx_part_preference',
            required=False,
            label=_('MX Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.DNSNameParam(
            'mx_part_exchanger',
            required=False,
            label=_('MX Exchanger'),
            doc=_('A host willing to act as a mail exchanger'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            label=_('NAPTR record'),
            doc=_('Raw NAPTR records'),
        ),
        parameters.Int(
            'naptr_part_order',
            required=False,
            label=_('NAPTR Order'),
            doc=_('Order'),
        ),
        parameters.Int(
            'naptr_part_preference',
            required=False,
            label=_('NAPTR Preference'),
            doc=_('Preference'),
        ),
        parameters.Str(
            'naptr_part_flags',
            required=False,
            label=_('NAPTR Flags'),
            doc=_('Flags'),
        ),
        parameters.Str(
            'naptr_part_service',
            required=False,
            label=_('NAPTR Service'),
            doc=_('Service'),
        ),
        parameters.Str(
            'naptr_part_regexp',
            required=False,
            label=_('NAPTR Regular Expression'),
            doc=_('Regular Expression'),
        ),
        parameters.Str(
            'naptr_part_replacement',
            required=False,
            label=_('NAPTR Replacement'),
            doc=_('Replacement'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            label=_('NS record'),
            doc=_('Raw NS records'),
        ),
        parameters.DNSNameParam(
            'ns_part_hostname',
            required=False,
            label=_('NS Hostname'),
            doc=_('Hostname'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            label=_('NSEC record'),
            doc=_('Raw NSEC records'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            label=_('PTR record'),
            doc=_('Raw PTR records'),
        ),
        parameters.DNSNameParam(
            'ptr_part_hostname',
            required=False,
            label=_('PTR Hostname'),
            doc=_('The hostname this reverse record points to'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            label=_('RRSIG record'),
            doc=_('Raw RRSIG records'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            label=_('RP record'),
            doc=_('Raw RP records'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            label=_('SIG record'),
            doc=_('Raw SIG records'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            label=_('SPF record'),
            doc=_('Raw SPF records'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            label=_('SRV record'),
            doc=_('Raw SRV records'),
        ),
        parameters.Int(
            'srv_part_priority',
            required=False,
            label=_('SRV Priority'),
            doc=_('Priority'),
        ),
        parameters.Int(
            'srv_part_weight',
            required=False,
            label=_('SRV Weight'),
            doc=_('Weight'),
        ),
        parameters.Int(
            'srv_part_port',
            required=False,
            label=_('SRV Port'),
            doc=_('Port'),
        ),
        parameters.DNSNameParam(
            'srv_part_target',
            required=False,
            label=_('SRV Target'),
            doc=_("The domain name of the target host or '.' if the service is decidedly not available at this domain"),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            label=_('SSHFP record'),
            doc=_('Raw SSHFP records'),
        ),
        parameters.Int(
            'sshfp_part_algorithm',
            required=False,
            label=_('SSHFP Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'sshfp_part_fp_type',
            required=False,
            label=_('SSHFP Fingerprint Type'),
            doc=_('Fingerprint Type'),
        ),
        parameters.Str(
            'sshfp_part_fingerprint',
            required=False,
            label=_('SSHFP Fingerprint'),
            doc=_('Fingerprint'),
        ),
        parameters.Str(
            'tlsarecord',
            required=False,
            multivalue=True,
            label=_('TLSA record'),
            doc=_('Raw TLSA records'),
        ),
        parameters.Int(
            'tlsa_part_cert_usage',
            required=False,
            label=_('TLSA Certificate Usage'),
            doc=_('Certificate Usage'),
        ),
        parameters.Int(
            'tlsa_part_selector',
            required=False,
            label=_('TLSA Selector'),
            doc=_('Selector'),
        ),
        parameters.Int(
            'tlsa_part_matching_type',
            required=False,
            label=_('TLSA Matching Type'),
            doc=_('Matching Type'),
        ),
        parameters.Str(
            'tlsa_part_cert_association_data',
            required=False,
            label=_('TLSA Certificate Association Data'),
            doc=_('Certificate Association Data'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            label=_('TXT record'),
            doc=_('Raw TXT records'),
        ),
        parameters.Str(
            'txt_part_data',
            required=False,
            label=_('TXT Text Data'),
            doc=_('Text Data'),
        ),
    )


@register()
class dnszone(Object):
    takes_params = (
        parameters.DNSNameParam(
            'idnsname',
            primary_key=True,
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
        ),
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Bool(
            'idnszoneactive',
            required=False,
            label=_('Active zone'),
            doc=_('Is zone active?'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.DNSNameParam(
            'idnssoamname',
            required=False,
            label=_('Authoritative nameserver'),
            doc=_('Authoritative nameserver domain name'),
        ),
        parameters.DNSNameParam(
            'idnssoarname',
            label=_('Administrator e-mail address'),
        ),
        parameters.Int(
            'idnssoaserial',
            label=_('SOA serial'),
            doc=_('SOA record serial number'),
        ),
        parameters.Int(
            'idnssoarefresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
        ),
        parameters.Int(
            'idnssoaretry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
        ),
        parameters.Int(
            'idnssoaexpire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
        ),
        parameters.Int(
            'idnssoaminimum',
            label=_('SOA minimum'),
            doc=_('How long should negative responses be cached'),
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            label=_('Time to live'),
            doc=_('Time to live for records at zone apex'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            label=_('BIND update policy'),
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            label=_('Dynamic update'),
            doc=_('Allow dynamic updates.'),
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            label=_('Allow query'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            label=_('Allow transfer'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Bool(
            'idnssecinlinesigning',
            required=False,
            label=_('Allow in-line DNSSEC signing'),
            doc=_('Allow inline DNSSEC signing of records in the zone'),
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            label=_('NSEC3PARAM record'),
            doc=_('NSEC3PARAM record for zone in format: hash_algorithm flags iterations salt'),
        ),
    )


@register()
class dns_is_enabled(Command):
    __doc__ = _("Checks if any of the servers has the DNS service enabled.")

    NO_CLI = True

    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dns_resolve(Command):
    __doc__ = _("Resolve a host name in DNS. (Deprecated)")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'hostname',
            label=_('Hostname (FQDN)'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsconfig_mod(Method):
    __doc__ = _("Modify global DNS configuration.")

    takes_options = (
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Global forwarders'),
            doc=_('Global forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Global forwarding policy. Set to "none" to disable any configured global forwarders.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records'),
        ),
        parameters.Int(
            'idnszonerefresh',
            required=False,
            deprecated=True,
            cli_name='zone_refresh',
            label=_('Zone refresh interval'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_('Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsconfig_show(Method):
    __doc__ = _("Show the current global DNS configuration.")

    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsforwardzone_add(Method):
    __doc__ = _("Create new DNS forward zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'skip_overlap_check',
            doc=_('Force DNS zone creation even if it will overlap with an existing zone.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsforwardzone_add_permission(Method):
    __doc__ = _("Add a permission for per-forward zone access delegation.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.Output(
            'value',
            str,
            doc=_('Permission value'),
        ),
    )


@register()
class dnsforwardzone_del(Method):
    __doc__ = _("Delete DNS forward zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            multivalue=True,
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_('List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class dnsforwardzone_disable(Method):
    __doc__ = _("Disable DNS Forward Zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsforwardzone_enable(Method):
    __doc__ = _("Enable DNS Forward Zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsforwardzone_find(Method):
    __doc__ = _("Search for DNS forward zones.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.DNSNameParam(
            'idnsname',
            required=False,
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Bool(
            'idnszoneactive',
            required=False,
            cli_name='zone_active',
            label=_('Active zone'),
            doc=_('Is zone active?'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_('Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_('True if not all results were returned'),
        ),
    )


@register()
class dnsforwardzone_mod(Method):
    __doc__ = _("Modify DNS forward zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_('Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsforwardzone_remove_permission(Method):
    __doc__ = _("Remove a permission for per-forward zone access delegation.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.Output(
            'value',
            str,
            doc=_('Permission value'),
        ),
    )


@register()
class dnsforwardzone_show(Method):
    __doc__ = _("Display information about a DNS forward zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_add(Method):
    __doc__ = _("Add new DNS resource record.")

    takes_args = (
        parameters.DNSNameParam(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Record name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            option_group='A Record',
            label=_('A record'),
            doc=_('Raw A records'),
        ),
        parameters.Str(
            'a_part_ip_address',
            required=False,
            cli_name='a_ip_address',
            option_group='A Record',
            label=_('A IP Address'),
            doc=_('IP Address'),
        ),
        parameters.Flag(
            'a_extra_create_reverse',
            required=False,
            cli_name='a_create_reverse',
            option_group='A Record',
            label=_('A Create reverse'),
            doc=_('Create reverse record for this IP Address'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            option_group='AAAA Record',
            label=_('AAAA record'),
            doc=_('Raw AAAA records'),
        ),
        parameters.Str(
            'aaaa_part_ip_address',
            required=False,
            cli_name='aaaa_ip_address',
            option_group='AAAA Record',
            label=_('AAAA IP Address'),
            doc=_('IP Address'),
        ),
        parameters.Flag(
            'aaaa_extra_create_reverse',
            required=False,
            cli_name='aaaa_create_reverse',
            option_group='AAAA Record',
            label=_('AAAA Create reverse'),
            doc=_('Create reverse record for this IP Address'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            option_group='A6 Record',
            label=_('A6 record'),
            doc=_('Raw A6 records'),
        ),
        parameters.Str(
            'a6_part_data',
            required=False,
            cli_name='a6_data',
            option_group='A6 Record',
            label=_('A6 Record data'),
            doc=_('Record data'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            option_group='AFSDB Record',
            label=_('AFSDB record'),
            doc=_('Raw AFSDB records'),
        ),
        parameters.Int(
            'afsdb_part_subtype',
            required=False,
            cli_name='afsdb_subtype',
            option_group='AFSDB Record',
            label=_('AFSDB Subtype'),
            doc=_('Subtype'),
        ),
        parameters.DNSNameParam(
            'afsdb_part_hostname',
            required=False,
            cli_name='afsdb_hostname',
            option_group='AFSDB Record',
            label=_('AFSDB Hostname'),
            doc=_('Hostname'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            option_group='APL Record',
            label=_('APL record'),
            doc=_('Raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            option_group='CERT Record',
            label=_('CERT record'),
            doc=_('Raw CERT records'),
        ),
        parameters.Int(
            'cert_part_type',
            required=False,
            cli_name='cert_type',
            option_group='CERT Record',
            label=_('CERT Certificate Type'),
            doc=_('Certificate Type'),
        ),
        parameters.Int(
            'cert_part_key_tag',
            required=False,
            cli_name='cert_key_tag',
            option_group='CERT Record',
            label=_('CERT Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'cert_part_algorithm',
            required=False,
            cli_name='cert_algorithm',
            option_group='CERT Record',
            label=_('CERT Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Str(
            'cert_part_certificate_or_crl',
            required=False,
            cli_name='cert_certificate_or_crl',
            option_group='CERT Record',
            label=_('CERT Certificate/CRL'),
            doc=_('Certificate/CRL'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            option_group='CNAME Record',
            label=_('CNAME record'),
            doc=_('Raw CNAME records'),
        ),
        parameters.DNSNameParam(
            'cname_part_hostname',
            required=False,
            cli_name='cname_hostname',
            option_group='CNAME Record',
            label=_('CNAME Hostname'),
            doc=_('A hostname which this alias hostname points to'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            option_group='DHCID Record',
            label=_('DHCID record'),
            doc=_('Raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            option_group='DLV Record',
            label=_('DLV record'),
            doc=_('Raw DLV records'),
        ),
        parameters.Int(
            'dlv_part_key_tag',
            required=False,
            cli_name='dlv_key_tag',
            option_group='DLV Record',
            label=_('DLV Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'dlv_part_algorithm',
            required=False,
            cli_name='dlv_algorithm',
            option_group='DLV Record',
            label=_('DLV Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'dlv_part_digest_type',
            required=False,
            cli_name='dlv_digest_type',
            option_group='DLV Record',
            label=_('DLV Digest Type'),
            doc=_('Digest Type'),
        ),
        parameters.Str(
            'dlv_part_digest',
            required=False,
            cli_name='dlv_digest',
            option_group='DLV Record',
            label=_('DLV Digest'),
            doc=_('Digest'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            option_group='DNAME Record',
            label=_('DNAME record'),
            doc=_('Raw DNAME records'),
        ),
        parameters.DNSNameParam(
            'dname_part_target',
            required=False,
            cli_name='dname_target',
            option_group='DNAME Record',
            label=_('DNAME Target'),
            doc=_('Target'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            option_group='DS Record',
            label=_('DS record'),
            doc=_('Raw DS records'),
        ),
        parameters.Int(
            'ds_part_key_tag',
            required=False,
            cli_name='ds_key_tag',
            option_group='DS Record',
            label=_('DS Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'ds_part_algorithm',
            required=False,
            cli_name='ds_algorithm',
            option_group='DS Record',
            label=_('DS Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'ds_part_digest_type',
            required=False,
            cli_name='ds_digest_type',
            option_group='DS Record',
            label=_('DS Digest Type'),
            doc=_('Digest Type'),
        ),
        parameters.Str(
            'ds_part_digest',
            required=False,
            cli_name='ds_digest',
            option_group='DS Record',
            label=_('DS Digest'),
            doc=_('Digest'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            option_group='HIP Record',
            label=_('HIP record'),
            doc=_('Raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            option_group='IPSECKEY Record',
            label=_('IPSECKEY record'),
            doc=_('Raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            option_group='KEY Record',
            label=_('KEY record'),
            doc=_('Raw KEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            option_group='KX Record',
            label=_('KX record'),
            doc=_('Raw KX records'),
        ),
        parameters.Int(
            'kx_part_preference',
            required=False,
            cli_name='kx_preference',
            option_group='KX Record',
            label=_('KX Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.DNSNameParam(
            'kx_part_exchanger',
            required=False,
            cli_name='kx_exchanger',
            option_group='KX Record',
            label=_('KX Exchanger'),
            doc=_('A host willing to act as a key exchanger'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            option_group='LOC Record',
            label=_('LOC record'),
            doc=_('Raw LOC records'),
        ),
        parameters.Int(
            'loc_part_lat_deg',
            required=False,
            cli_name='loc_lat_deg',
            option_group='LOC Record',
            label=_('LOC Degrees Latitude'),
            doc=_('Degrees Latitude'),
        ),
        parameters.Int(
            'loc_part_lat_min',
            required=False,
            cli_name='loc_lat_min',
            option_group='LOC Record',
            label=_('LOC Minutes Latitude'),
            doc=_('Minutes Latitude'),
        ),
        parameters.Decimal(
            'loc_part_lat_sec',
            required=False,
            cli_name='loc_lat_sec',
            option_group='LOC Record',
            label=_('LOC Seconds Latitude'),
            doc=_('Seconds Latitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lat_dir',
            required=False,
            cli_name='loc_lat_dir',
            option_group='LOC Record',
            cli_metavar="['N', 'S']",
            label=_('LOC Direction Latitude'),
            doc=_('Direction Latitude'),
        ),
        parameters.Int(
            'loc_part_lon_deg',
            required=False,
            cli_name='loc_lon_deg',
            option_group='LOC Record',
            label=_('LOC Degrees Longitude'),
            doc=_('Degrees Longitude'),
        ),
        parameters.Int(
            'loc_part_lon_min',
            required=False,
            cli_name='loc_lon_min',
            option_group='LOC Record',
            label=_('LOC Minutes Longitude'),
            doc=_('Minutes Longitude'),
        ),
        parameters.Decimal(
            'loc_part_lon_sec',
            required=False,
            cli_name='loc_lon_sec',
            option_group='LOC Record',
            label=_('LOC Seconds Longitude'),
            doc=_('Seconds Longitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lon_dir',
            required=False,
            cli_name='loc_lon_dir',
            option_group='LOC Record',
            cli_metavar="['E', 'W']",
            label=_('LOC Direction Longitude'),
            doc=_('Direction Longitude'),
        ),
        parameters.Decimal(
            'loc_part_altitude',
            required=False,
            cli_name='loc_altitude',
            option_group='LOC Record',
            label=_('LOC Altitude'),
            doc=_('Altitude'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_size',
            required=False,
            cli_name='loc_size',
            option_group='LOC Record',
            label=_('LOC Size'),
            doc=_('Size'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_h_precision',
            required=False,
            cli_name='loc_h_precision',
            option_group='LOC Record',
            label=_('LOC Horizontal Precision'),
            doc=_('Horizontal Precision'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_v_precision',
            required=False,
            cli_name='loc_v_precision',
            option_group='LOC Record',
            label=_('LOC Vertical Precision'),
            doc=_('Vertical Precision'),
            no_convert=True,
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            option_group='MX Record',
            label=_('MX record'),
            doc=_('Raw MX records'),
        ),
        parameters.Int(
            'mx_part_preference',
            required=False,
            cli_name='mx_preference',
            option_group='MX Record',
            label=_('MX Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.DNSNameParam(
            'mx_part_exchanger',
            required=False,
            cli_name='mx_exchanger',
            option_group='MX Record',
            label=_('MX Exchanger'),
            doc=_('A host willing to act as a mail exchanger'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            option_group='NAPTR Record',
            label=_('NAPTR record'),
            doc=_('Raw NAPTR records'),
        ),
        parameters.Int(
            'naptr_part_order',
            required=False,
            cli_name='naptr_order',
            option_group='NAPTR Record',
            label=_('NAPTR Order'),
            doc=_('Order'),
        ),
        parameters.Int(
            'naptr_part_preference',
            required=False,
            cli_name='naptr_preference',
            option_group='NAPTR Record',
            label=_('NAPTR Preference'),
            doc=_('Preference'),
        ),
        parameters.Str(
            'naptr_part_flags',
            required=False,
            cli_name='naptr_flags',
            option_group='NAPTR Record',
            label=_('NAPTR Flags'),
            doc=_('Flags'),
            no_convert=True,
        ),
        parameters.Str(
            'naptr_part_service',
            required=False,
            cli_name='naptr_service',
            option_group='NAPTR Record',
            label=_('NAPTR Service'),
            doc=_('Service'),
        ),
        parameters.Str(
            'naptr_part_regexp',
            required=False,
            cli_name='naptr_regexp',
            option_group='NAPTR Record',
            label=_('NAPTR Regular Expression'),
            doc=_('Regular Expression'),
        ),
        parameters.Str(
            'naptr_part_replacement',
            required=False,
            cli_name='naptr_replacement',
            option_group='NAPTR Record',
            label=_('NAPTR Replacement'),
            doc=_('Replacement'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            option_group='NS Record',
            label=_('NS record'),
            doc=_('Raw NS records'),
        ),
        parameters.DNSNameParam(
            'ns_part_hostname',
            required=False,
            cli_name='ns_hostname',
            option_group='NS Record',
            label=_('NS Hostname'),
            doc=_('Hostname'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            option_group='NSEC Record',
            label=_('NSEC record'),
            doc=_('Raw NSEC records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            option_group='PTR Record',
            label=_('PTR record'),
            doc=_('Raw PTR records'),
        ),
        parameters.DNSNameParam(
            'ptr_part_hostname',
            required=False,
            cli_name='ptr_hostname',
            option_group='PTR Record',
            label=_('PTR Hostname'),
            doc=_('The hostname this reverse record points to'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            option_group='RRSIG Record',
            label=_('RRSIG record'),
            doc=_('Raw RRSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            option_group='RP Record',
            label=_('RP record'),
            doc=_('Raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            option_group='SIG Record',
            label=_('SIG record'),
            doc=_('Raw SIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            option_group='SPF Record',
            label=_('SPF record'),
            doc=_('Raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            option_group='SRV Record',
            label=_('SRV record'),
            doc=_('Raw SRV records'),
        ),
        parameters.Int(
            'srv_part_priority',
            required=False,
            cli_name='srv_priority',
            option_group='SRV Record',
            label=_('SRV Priority'),
            doc=_('Priority'),
        ),
        parameters.Int(
            'srv_part_weight',
            required=False,
            cli_name='srv_weight',
            option_group='SRV Record',
            label=_('SRV Weight'),
            doc=_('Weight'),
        ),
        parameters.Int(
            'srv_part_port',
            required=False,
            cli_name='srv_port',
            option_group='SRV Record',
            label=_('SRV Port'),
            doc=_('Port'),
        ),
        parameters.DNSNameParam(
            'srv_part_target',
            required=False,
            cli_name='srv_target',
            option_group='SRV Record',
            label=_('SRV Target'),
            doc=_("The domain name of the target host or '.' if the service is decidedly not available at this domain"),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            option_group='SSHFP Record',
            label=_('SSHFP record'),
            doc=_('Raw SSHFP records'),
        ),
        parameters.Int(
            'sshfp_part_algorithm',
            required=False,
            cli_name='sshfp_algorithm',
            option_group='SSHFP Record',
            label=_('SSHFP Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'sshfp_part_fp_type',
            required=False,
            cli_name='sshfp_fp_type',
            option_group='SSHFP Record',
            label=_('SSHFP Fingerprint Type'),
            doc=_('Fingerprint Type'),
        ),
        parameters.Str(
            'sshfp_part_fingerprint',
            required=False,
            cli_name='sshfp_fingerprint',
            option_group='SSHFP Record',
            label=_('SSHFP Fingerprint'),
            doc=_('Fingerprint'),
        ),
        parameters.Str(
            'tlsarecord',
            required=False,
            multivalue=True,
            cli_name='tlsa_rec',
            option_group='TLSA Record',
            label=_('TLSA record'),
            doc=_('Raw TLSA records'),
        ),
        parameters.Int(
            'tlsa_part_cert_usage',
            required=False,
            cli_name='tlsa_cert_usage',
            option_group='TLSA Record',
            label=_('TLSA Certificate Usage'),
            doc=_('Certificate Usage'),
        ),
        parameters.Int(
            'tlsa_part_selector',
            required=False,
            cli_name='tlsa_selector',
            option_group='TLSA Record',
            label=_('TLSA Selector'),
            doc=_('Selector'),
        ),
        parameters.Int(
            'tlsa_part_matching_type',
            required=False,
            cli_name='tlsa_matching_type',
            option_group='TLSA Record',
            label=_('TLSA Matching Type'),
            doc=_('Matching Type'),
        ),
        parameters.Str(
            'tlsa_part_cert_association_data',
            required=False,
            cli_name='tlsa_cert_association_data',
            option_group='TLSA Record',
            label=_('TLSA Certificate Association Data'),
            doc=_('Certificate Association Data'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            option_group='TXT Record',
            label=_('TXT record'),
            doc=_('Raw TXT records'),
        ),
        parameters.Str(
            'txt_part_data',
            required=False,
            cli_name='txt_data',
            option_group='TXT Record',
            label=_('TXT Text Data'),
            doc=_('Text Data'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'force',
            label=_('Force'),
            doc=_('force NS record creation even if its hostname is not in DNS'),
            exclude=('cli', 'webui'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_('Structured'),
            doc=_('Parse all raw DNS records and return them in a '
                  'structured way. Can not be used with --raw.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_del(Method):
    __doc__ = _("Delete DNS resource record.")

    takes_args = (
        parameters.DNSNameParam(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Record name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            label=_('A record'),
            doc=_('Raw A records'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            label=_('AAAA record'),
            doc=_('Raw AAAA records'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            label=_('A6 record'),
            doc=_('Raw A6 records'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            label=_('AFSDB record'),
            doc=_('Raw AFSDB records'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            label=_('APL record'),
            doc=_('Raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            label=_('CERT record'),
            doc=_('Raw CERT records'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            label=_('CNAME record'),
            doc=_('Raw CNAME records'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            label=_('DHCID record'),
            doc=_('Raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            label=_('DLV record'),
            doc=_('Raw DLV records'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            label=_('DNAME record'),
            doc=_('Raw DNAME records'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            label=_('DS record'),
            doc=_('Raw DS records'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            label=_('HIP record'),
            doc=_('Raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            label=_('IPSECKEY record'),
            doc=_('Raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            label=_('KEY record'),
            doc=_('Raw KEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            label=_('KX record'),
            doc=_('Raw KX records'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            label=_('LOC record'),
            doc=_('Raw LOC records'),
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            label=_('MX record'),
            doc=_('Raw MX records'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            label=_('NAPTR record'),
            doc=_('Raw NAPTR records'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            label=_('NS record'),
            doc=_('Raw NS records'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            label=_('NSEC record'),
            doc=_('Raw NSEC records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            label=_('PTR record'),
            doc=_('Raw PTR records'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            label=_('RRSIG record'),
            doc=_('Raw RRSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            label=_('RP record'),
            doc=_('Raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            label=_('SIG record'),
            doc=_('Raw SIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            label=_('SPF record'),
            doc=_('Raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            label=_('SRV record'),
            doc=_('Raw SRV records'),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            label=_('SSHFP record'),
            doc=_('Raw SSHFP records'),
        ),
        parameters.Str(
            'tlsarecord',
            required=False,
            multivalue=True,
            cli_name='tlsa_rec',
            label=_('TLSA record'),
            doc=_('Raw TLSA records'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            label=_('TXT record'),
            doc=_('Raw TXT records'),
        ),
        parameters.Flag(
            'del_all',
            label=_('Delete all associated records'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_('Structured'),
            doc=_('Parse all raw DNS records and return them in a '
                  'structured way. Can not be used with --raw.'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_('List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class dnsrecord_delentry(Method):
    __doc__ = _("Delete DNS record entry.")

    NO_CLI = True

    takes_args = (
        parameters.DNSNameParam(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.DNSNameParam(
            'idnsname',
            multivalue=True,
            cli_name='name',
            label=_('Record name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_('List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class dnsrecord_find(Method):
    __doc__ = _("Search for DNS resources.")

    takes_args = (
        parameters.DNSNameParam(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.DNSNameParam(
            'idnsname',
            required=False,
            cli_name='name',
            label=_('Record name'),
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            label=_('A record'),
            doc=_('Raw A records'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            label=_('AAAA record'),
            doc=_('Raw AAAA records'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            label=_('A6 record'),
            doc=_('Raw A6 records'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            label=_('AFSDB record'),
            doc=_('Raw AFSDB records'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            label=_('APL record'),
            doc=_('Raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            label=_('CERT record'),
            doc=_('Raw CERT records'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            label=_('CNAME record'),
            doc=_('Raw CNAME records'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            label=_('DHCID record'),
            doc=_('Raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            label=_('DLV record'),
            doc=_('Raw DLV records'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            label=_('DNAME record'),
            doc=_('Raw DNAME records'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            label=_('DS record'),
            doc=_('Raw DS records'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            label=_('HIP record'),
            doc=_('Raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            label=_('IPSECKEY record'),
            doc=_('Raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            label=_('KEY record'),
            doc=_('Raw KEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            label=_('KX record'),
            doc=_('Raw KX records'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            label=_('LOC record'),
            doc=_('Raw LOC records'),
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            label=_('MX record'),
            doc=_('Raw MX records'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            label=_('NAPTR record'),
            doc=_('Raw NAPTR records'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            label=_('NS record'),
            doc=_('Raw NS records'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            label=_('NSEC record'),
            doc=_('Raw NSEC records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            label=_('PTR record'),
            doc=_('Raw PTR records'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            label=_('RRSIG record'),
            doc=_('Raw RRSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            label=_('RP record'),
            doc=_('Raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            label=_('SIG record'),
            doc=_('Raw SIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            label=_('SPF record'),
            doc=_('Raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            label=_('SRV record'),
            doc=_('Raw SRV records'),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            label=_('SSHFP record'),
            doc=_('Raw SSHFP records'),
        ),
        parameters.Str(
            'tlsarecord',
            required=False,
            multivalue=True,
            cli_name='tlsa_rec',
            label=_('TLSA record'),
            doc=_('Raw TLSA records'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            label=_('TXT record'),
            doc=_('Raw TXT records'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'structured',
            label=_('Structured'),
            doc=_('Parse all raw DNS records and return them in a '
                  'structured way. Can not be used with --raw.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_('Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_('True if not all results were returned'),
        ),
    )


@register()
class dnsrecord_mod(Method):
    __doc__ = _("Modify a DNS resource record.")

    takes_args = (
        parameters.DNSNameParam(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Record name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            option_group='A Record',
            label=_('A record'),
            doc=_('Raw A records'),
        ),
        parameters.Str(
            'a_part_ip_address',
            required=False,
            cli_name='a_ip_address',
            option_group='A Record',
            label=_('A IP Address'),
            doc=_('IP Address'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            option_group='AAAA Record',
            label=_('AAAA record'),
            doc=_('Raw AAAA records'),
        ),
        parameters.Str(
            'aaaa_part_ip_address',
            required=False,
            cli_name='aaaa_ip_address',
            option_group='AAAA Record',
            label=_('AAAA IP Address'),
            doc=_('IP Address'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            option_group='A6 Record',
            label=_('A6 record'),
            doc=_('Raw A6 records'),
        ),
        parameters.Str(
            'a6_part_data',
            required=False,
            cli_name='a6_data',
            option_group='A6 Record',
            label=_('A6 Record data'),
            doc=_('Record data'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            option_group='AFSDB Record',
            label=_('AFSDB record'),
            doc=_('Raw AFSDB records'),
        ),
        parameters.Int(
            'afsdb_part_subtype',
            required=False,
            cli_name='afsdb_subtype',
            option_group='AFSDB Record',
            label=_('AFSDB Subtype'),
            doc=_('Subtype'),
        ),
        parameters.DNSNameParam(
            'afsdb_part_hostname',
            required=False,
            cli_name='afsdb_hostname',
            option_group='AFSDB Record',
            label=_('AFSDB Hostname'),
            doc=_('Hostname'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            option_group='APL Record',
            label=_('APL record'),
            doc=_('Raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            option_group='CERT Record',
            label=_('CERT record'),
            doc=_('Raw CERT records'),
        ),
        parameters.Int(
            'cert_part_type',
            required=False,
            cli_name='cert_type',
            option_group='CERT Record',
            label=_('CERT Certificate Type'),
            doc=_('Certificate Type'),
        ),
        parameters.Int(
            'cert_part_key_tag',
            required=False,
            cli_name='cert_key_tag',
            option_group='CERT Record',
            label=_('CERT Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'cert_part_algorithm',
            required=False,
            cli_name='cert_algorithm',
            option_group='CERT Record',
            label=_('CERT Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Str(
            'cert_part_certificate_or_crl',
            required=False,
            cli_name='cert_certificate_or_crl',
            option_group='CERT Record',
            label=_('CERT Certificate/CRL'),
            doc=_('Certificate/CRL'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            option_group='CNAME Record',
            label=_('CNAME record'),
            doc=_('Raw CNAME records'),
        ),
        parameters.DNSNameParam(
            'cname_part_hostname',
            required=False,
            cli_name='cname_hostname',
            option_group='CNAME Record',
            label=_('CNAME Hostname'),
            doc=_('A hostname which this alias hostname points to'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            option_group='DHCID Record',
            label=_('DHCID record'),
            doc=_('Raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            option_group='DLV Record',
            label=_('DLV record'),
            doc=_('Raw DLV records'),
        ),
        parameters.Int(
            'dlv_part_key_tag',
            required=False,
            cli_name='dlv_key_tag',
            option_group='DLV Record',
            label=_('DLV Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'dlv_part_algorithm',
            required=False,
            cli_name='dlv_algorithm',
            option_group='DLV Record',
            label=_('DLV Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'dlv_part_digest_type',
            required=False,
            cli_name='dlv_digest_type',
            option_group='DLV Record',
            label=_('DLV Digest Type'),
            doc=_('Digest Type'),
        ),
        parameters.Str(
            'dlv_part_digest',
            required=False,
            cli_name='dlv_digest',
            option_group='DLV Record',
            label=_('DLV Digest'),
            doc=_('Digest'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            option_group='DNAME Record',
            label=_('DNAME record'),
            doc=_('Raw DNAME records'),
        ),
        parameters.DNSNameParam(
            'dname_part_target',
            required=False,
            cli_name='dname_target',
            option_group='DNAME Record',
            label=_('DNAME Target'),
            doc=_('Target'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            option_group='DS Record',
            label=_('DS record'),
            doc=_('Raw DS records'),
        ),
        parameters.Int(
            'ds_part_key_tag',
            required=False,
            cli_name='ds_key_tag',
            option_group='DS Record',
            label=_('DS Key Tag'),
            doc=_('Key Tag'),
        ),
        parameters.Int(
            'ds_part_algorithm',
            required=False,
            cli_name='ds_algorithm',
            option_group='DS Record',
            label=_('DS Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'ds_part_digest_type',
            required=False,
            cli_name='ds_digest_type',
            option_group='DS Record',
            label=_('DS Digest Type'),
            doc=_('Digest Type'),
        ),
        parameters.Str(
            'ds_part_digest',
            required=False,
            cli_name='ds_digest',
            option_group='DS Record',
            label=_('DS Digest'),
            doc=_('Digest'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            option_group='HIP Record',
            label=_('HIP record'),
            doc=_('Raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            option_group='IPSECKEY Record',
            label=_('IPSECKEY record'),
            doc=_('Raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            option_group='KEY Record',
            label=_('KEY record'),
            doc=_('Raw KEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            option_group='KX Record',
            label=_('KX record'),
            doc=_('Raw KX records'),
        ),
        parameters.Int(
            'kx_part_preference',
            required=False,
            cli_name='kx_preference',
            option_group='KX Record',
            label=_('KX Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.DNSNameParam(
            'kx_part_exchanger',
            required=False,
            cli_name='kx_exchanger',
            option_group='KX Record',
            label=_('KX Exchanger'),
            doc=_('A host willing to act as a key exchanger'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            option_group='LOC Record',
            label=_('LOC record'),
            doc=_('Raw LOC records'),
        ),
        parameters.Int(
            'loc_part_lat_deg',
            required=False,
            cli_name='loc_lat_deg',
            option_group='LOC Record',
            label=_('LOC Degrees Latitude'),
            doc=_('Degrees Latitude'),
        ),
        parameters.Int(
            'loc_part_lat_min',
            required=False,
            cli_name='loc_lat_min',
            option_group='LOC Record',
            label=_('LOC Minutes Latitude'),
            doc=_('Minutes Latitude'),
        ),
        parameters.Decimal(
            'loc_part_lat_sec',
            required=False,
            cli_name='loc_lat_sec',
            option_group='LOC Record',
            label=_('LOC Seconds Latitude'),
            doc=_('Seconds Latitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lat_dir',
            required=False,
            cli_name='loc_lat_dir',
            option_group='LOC Record',
            cli_metavar="['N', 'S']",
            label=_('LOC Direction Latitude'),
            doc=_('Direction Latitude'),
        ),
        parameters.Int(
            'loc_part_lon_deg',
            required=False,
            cli_name='loc_lon_deg',
            option_group='LOC Record',
            label=_('LOC Degrees Longitude'),
            doc=_('Degrees Longitude'),
        ),
        parameters.Int(
            'loc_part_lon_min',
            required=False,
            cli_name='loc_lon_min',
            option_group='LOC Record',
            label=_('LOC Minutes Longitude'),
            doc=_('Minutes Longitude'),
        ),
        parameters.Decimal(
            'loc_part_lon_sec',
            required=False,
            cli_name='loc_lon_sec',
            option_group='LOC Record',
            label=_('LOC Seconds Longitude'),
            doc=_('Seconds Longitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lon_dir',
            required=False,
            cli_name='loc_lon_dir',
            option_group='LOC Record',
            cli_metavar="['E', 'W']",
            label=_('LOC Direction Longitude'),
            doc=_('Direction Longitude'),
        ),
        parameters.Decimal(
            'loc_part_altitude',
            required=False,
            cli_name='loc_altitude',
            option_group='LOC Record',
            label=_('LOC Altitude'),
            doc=_('Altitude'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_size',
            required=False,
            cli_name='loc_size',
            option_group='LOC Record',
            label=_('LOC Size'),
            doc=_('Size'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_h_precision',
            required=False,
            cli_name='loc_h_precision',
            option_group='LOC Record',
            label=_('LOC Horizontal Precision'),
            doc=_('Horizontal Precision'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_v_precision',
            required=False,
            cli_name='loc_v_precision',
            option_group='LOC Record',
            label=_('LOC Vertical Precision'),
            doc=_('Vertical Precision'),
            no_convert=True,
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            option_group='MX Record',
            label=_('MX record'),
            doc=_('Raw MX records'),
        ),
        parameters.Int(
            'mx_part_preference',
            required=False,
            cli_name='mx_preference',
            option_group='MX Record',
            label=_('MX Preference'),
            doc=_('Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.DNSNameParam(
            'mx_part_exchanger',
            required=False,
            cli_name='mx_exchanger',
            option_group='MX Record',
            label=_('MX Exchanger'),
            doc=_('A host willing to act as a mail exchanger'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            option_group='NAPTR Record',
            label=_('NAPTR record'),
            doc=_('Raw NAPTR records'),
        ),
        parameters.Int(
            'naptr_part_order',
            required=False,
            cli_name='naptr_order',
            option_group='NAPTR Record',
            label=_('NAPTR Order'),
            doc=_('Order'),
        ),
        parameters.Int(
            'naptr_part_preference',
            required=False,
            cli_name='naptr_preference',
            option_group='NAPTR Record',
            label=_('NAPTR Preference'),
            doc=_('Preference'),
        ),
        parameters.Str(
            'naptr_part_flags',
            required=False,
            cli_name='naptr_flags',
            option_group='NAPTR Record',
            label=_('NAPTR Flags'),
            doc=_('Flags'),
            no_convert=True,
        ),
        parameters.Str(
            'naptr_part_service',
            required=False,
            cli_name='naptr_service',
            option_group='NAPTR Record',
            label=_('NAPTR Service'),
            doc=_('Service'),
        ),
        parameters.Str(
            'naptr_part_regexp',
            required=False,
            cli_name='naptr_regexp',
            option_group='NAPTR Record',
            label=_('NAPTR Regular Expression'),
            doc=_('Regular Expression'),
        ),
        parameters.Str(
            'naptr_part_replacement',
            required=False,
            cli_name='naptr_replacement',
            option_group='NAPTR Record',
            label=_('NAPTR Replacement'),
            doc=_('Replacement'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            option_group='NS Record',
            label=_('NS record'),
            doc=_('Raw NS records'),
        ),
        parameters.DNSNameParam(
            'ns_part_hostname',
            required=False,
            cli_name='ns_hostname',
            option_group='NS Record',
            label=_('NS Hostname'),
            doc=_('Hostname'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            option_group='NSEC Record',
            label=_('NSEC record'),
            doc=_('Raw NSEC records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            option_group='PTR Record',
            label=_('PTR record'),
            doc=_('Raw PTR records'),
        ),
        parameters.DNSNameParam(
            'ptr_part_hostname',
            required=False,
            cli_name='ptr_hostname',
            option_group='PTR Record',
            label=_('PTR Hostname'),
            doc=_('The hostname this reverse record points to'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            option_group='RRSIG Record',
            label=_('RRSIG record'),
            doc=_('Raw RRSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            option_group='RP Record',
            label=_('RP record'),
            doc=_('Raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            option_group='SIG Record',
            label=_('SIG record'),
            doc=_('Raw SIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            option_group='SPF Record',
            label=_('SPF record'),
            doc=_('Raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            option_group='SRV Record',
            label=_('SRV record'),
            doc=_('Raw SRV records'),
        ),
        parameters.Int(
            'srv_part_priority',
            required=False,
            cli_name='srv_priority',
            option_group='SRV Record',
            label=_('SRV Priority'),
            doc=_('Priority'),
        ),
        parameters.Int(
            'srv_part_weight',
            required=False,
            cli_name='srv_weight',
            option_group='SRV Record',
            label=_('SRV Weight'),
            doc=_('Weight'),
        ),
        parameters.Int(
            'srv_part_port',
            required=False,
            cli_name='srv_port',
            option_group='SRV Record',
            label=_('SRV Port'),
            doc=_('Port'),
        ),
        parameters.DNSNameParam(
            'srv_part_target',
            required=False,
            cli_name='srv_target',
            option_group='SRV Record',
            label=_('SRV Target'),
            doc=_("The domain name of the target host or '.' if the service is decidedly not available at this domain"),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            option_group='SSHFP Record',
            label=_('SSHFP record'),
            doc=_('Raw SSHFP records'),
        ),
        parameters.Int(
            'sshfp_part_algorithm',
            required=False,
            cli_name='sshfp_algorithm',
            option_group='SSHFP Record',
            label=_('SSHFP Algorithm'),
            doc=_('Algorithm'),
        ),
        parameters.Int(
            'sshfp_part_fp_type',
            required=False,
            cli_name='sshfp_fp_type',
            option_group='SSHFP Record',
            label=_('SSHFP Fingerprint Type'),
            doc=_('Fingerprint Type'),
        ),
        parameters.Str(
            'sshfp_part_fingerprint',
            required=False,
            cli_name='sshfp_fingerprint',
            option_group='SSHFP Record',
            label=_('SSHFP Fingerprint'),
            doc=_('Fingerprint'),
        ),
        parameters.Str(
            'tlsarecord',
            required=False,
            multivalue=True,
            cli_name='tlsa_rec',
            option_group='TLSA Record',
            label=_('TLSA record'),
            doc=_('Raw TLSA records'),
        ),
        parameters.Int(
            'tlsa_part_cert_usage',
            required=False,
            cli_name='tlsa_cert_usage',
            option_group='TLSA Record',
            label=_('TLSA Certificate Usage'),
            doc=_('Certificate Usage'),
        ),
        parameters.Int(
            'tlsa_part_selector',
            required=False,
            cli_name='tlsa_selector',
            option_group='TLSA Record',
            label=_('TLSA Selector'),
            doc=_('Selector'),
        ),
        parameters.Int(
            'tlsa_part_matching_type',
            required=False,
            cli_name='tlsa_matching_type',
            option_group='TLSA Record',
            label=_('TLSA Matching Type'),
            doc=_('Matching Type'),
        ),
        parameters.Str(
            'tlsa_part_cert_association_data',
            required=False,
            cli_name='tlsa_cert_association_data',
            option_group='TLSA Record',
            label=_('TLSA Certificate Association Data'),
            doc=_('Certificate Association Data'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            option_group='TXT Record',
            label=_('TXT record'),
            doc=_('Raw TXT records'),
        ),
        parameters.Str(
            'txt_part_data',
            required=False,
            cli_name='txt_data',
            option_group='TXT Record',
            label=_('TXT Text Data'),
            doc=_('Text Data'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_('Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_('Structured'),
            doc=_('Parse all raw DNS records and return them in a '
                  'structured way. Can not be used with --raw.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.DNSNameParam(
            'rename',
            required=False,
            label=_('Rename'),
            doc=_('Rename the DNS resource record object'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_show(Method):
    __doc__ = _("Display DNS resource.")

    takes_args = (
        parameters.DNSNameParam(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Record name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_('Structured'),
            doc=_('Parse all raw DNS records and return them in a '
                  'structured way. Can not be used with --raw.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_add(Method):
    __doc__ = _("Create new DNS zone (SOA record).")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.DNSNameParam(
            'idnssoamname',
            required=False,
            cli_name='name_server',
            label=_('Authoritative nameserver'),
            doc=_('Authoritative nameserver domain name'),
        ),
        parameters.DNSNameParam(
            'idnssoarname',
            cli_name='admin_email',
            label=_('Administrator e-mail address'),
            default=DNSName('hostmaster'),
            autofill=True,
            no_convert=True,
        ),
        parameters.Int(
            'idnssoaserial',
            cli_name='serial',
            label=_('SOA serial'),
            doc=_('SOA record serial number'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # def _create_zone_serial():
            # """
            # Generate serial number for zones. bind-dyndb-ldap expects unix time in
            # to be used for SOA serial.
            #
            # SOA serial in a date format would also work, but it may be set to far
            # future when many DNS updates are done per day (more than 100). Unix
            # timestamp is more resilient to this issue.
            # """
            # return int(time.time())
            autofill=True,
        ),
        parameters.Int(
            'idnssoarefresh',
            cli_name='refresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
            default=3600,
            autofill=True,
        ),
        parameters.Int(
            'idnssoaretry',
            cli_name='retry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
            default=900,
            autofill=True,
        ),
        parameters.Int(
            'idnssoaexpire',
            cli_name='expire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
            default=1209600,
            autofill=True,
        ),
        parameters.Int(
            'idnssoaminimum',
            cli_name='minimum',
            label=_('SOA minimum'),
            doc=_('How long should negative responses be cached'),
            default=3600,
            autofill=True,
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
            doc=_('Time to live for records at zone apex'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            cli_name='update_policy',
            label=_('BIND update policy'),
            default_from=DefaultFrom(lambda idnsname: None, 'idnsname'),
            # FIXME:
            # lambda idnsname: default_zone_update_policy(idnsname)
            autofill=True,
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            cli_name='dynamic_update',
            label=_('Dynamic update'),
            doc=_('Allow dynamic updates.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            cli_name='allow_query',
            label=_('Allow query'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default='any;',
            autofill=True,
            no_convert=True,
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            cli_name='allow_transfer',
            label=_('Allow transfer'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default='none;',
            autofill=True,
            no_convert=True,
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Bool(
            'idnssecinlinesigning',
            required=False,
            cli_name='dnssec',
            label=_('Allow in-line DNSSEC signing'),
            doc=_('Allow inline DNSSEC signing of records in the zone'),
            default=False,
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            cli_name='nsec3param_rec',
            label=_('NSEC3PARAM record'),
            doc=_('NSEC3PARAM record for zone in format: hash_algorithm flags iterations salt'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'skip_overlap_check',
            doc=_('Force DNS zone creation even if it will overlap with an existing zone.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'force',
            doc=_('Force DNS zone creation even if nameserver is not resolvable. (Deprecated)'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'skip_nameserver_check',
            doc=_('Force DNS zone creation even if nameserver is not resolvable.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'ip_address',
            required=False,
            exclude=('cli', 'webui'),
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_add_permission(Method):
    __doc__ = _("Add a permission for per-zone access delegation.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.Output(
            'value',
            str,
            doc=_('Permission value'),
        ),
    )


@register()
class dnszone_del(Method):
    __doc__ = _("Delete DNS zone (SOA record).")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            multivalue=True,
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_("Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_('List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class dnszone_disable(Method):
    __doc__ = _("Disable DNS Zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_enable(Method):
    __doc__ = _("Enable DNS Zone.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_find(Method):
    __doc__ = _("Search for DNS zones (SOA records).")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_('A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.DNSNameParam(
            'idnsname',
            required=False,
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Bool(
            'idnszoneactive',
            required=False,
            cli_name='zone_active',
            label=_('Active zone'),
            doc=_('Is zone active?'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.DNSNameParam(
            'idnssoamname',
            required=False,
            cli_name='name_server',
            label=_('Authoritative nameserver'),
            doc=_('Authoritative nameserver domain name'),
        ),
        parameters.DNSNameParam(
            'idnssoarname',
            required=False,
            cli_name='admin_email',
            label=_('Administrator e-mail address'),
            default=DNSName('hostmaster'),
            no_convert=True,
        ),
        parameters.Int(
            'idnssoaserial',
            required=False,
            cli_name='serial',
            label=_('SOA serial'),
            doc=_('SOA record serial number'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # def _create_zone_serial():
            # """
            # Generate serial number for zones. bind-dyndb-ldap expects unix time in
            # to be used for SOA serial.
            #
            # SOA serial in a date format would also work, but it may be set to far
            # future when many DNS updates are done per day (more than 100). Unix
            # timestamp is more resilient to this issue.
            # """
            # return int(time.time())
        ),
        parameters.Int(
            'idnssoarefresh',
            required=False,
            cli_name='refresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
            default=3600,
        ),
        parameters.Int(
            'idnssoaretry',
            required=False,
            cli_name='retry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
            default=900,
        ),
        parameters.Int(
            'idnssoaexpire',
            required=False,
            cli_name='expire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
            default=1209600,
        ),
        parameters.Int(
            'idnssoaminimum',
            required=False,
            cli_name='minimum',
            label=_('SOA minimum'),
            doc=_('How long should negative responses be cached'),
            default=3600,
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
            doc=_('Time to live for records at zone apex'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            cli_name='update_policy',
            label=_('BIND update policy'),
            default_from=DefaultFrom(lambda idnsname: None, 'idnsname'),
            # FIXME:
            # lambda idnsname: default_zone_update_policy(idnsname)
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            cli_name='dynamic_update',
            label=_('Dynamic update'),
            doc=_('Allow dynamic updates.'),
            default=False,
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            cli_name='allow_query',
            label=_('Allow query'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default='any;',
            no_convert=True,
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            cli_name='allow_transfer',
            label=_('Allow transfer'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default='none;',
            no_convert=True,
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Bool(
            'idnssecinlinesigning',
            required=False,
            cli_name='dnssec',
            label=_('Allow in-line DNSSEC signing'),
            doc=_('Allow inline DNSSEC signing of records in the zone'),
            default=False,
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            cli_name='nsec3param_rec',
            label=_('NSEC3PARAM record'),
            doc=_('NSEC3PARAM record for zone in format: hash_algorithm flags iterations salt'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'forward_only',
            label=_('Forward zones only'),
            doc=_('Search for forward zones only'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_('Primary key only'),
            doc=_('Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_('Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_('True if not all results were returned'),
        ),
    )


@register()
class dnszone_mod(Method):
    __doc__ = _("Modify DNS zone (SOA record).")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_('Reverse zone IP network'),
            doc=_('IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_('Zone forwarders'),
            doc=_('Per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_('Forward policy'),
            doc=_('Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.DNSNameParam(
            'idnssoamname',
            required=False,
            cli_name='name_server',
            label=_('Authoritative nameserver'),
            doc=_('Authoritative nameserver domain name'),
        ),
        parameters.DNSNameParam(
            'idnssoarname',
            required=False,
            cli_name='admin_email',
            label=_('Administrator e-mail address'),
            default=DNSName('hostmaster'),
            no_convert=True,
        ),
        parameters.Int(
            'idnssoaserial',
            required=False,
            cli_name='serial',
            label=_('SOA serial'),
            doc=_('SOA record serial number'),
            default_from=DefaultFrom(lambda : None),
            # FIXME:
            # def _create_zone_serial():
            # """
            # Generate serial number for zones. bind-dyndb-ldap expects unix time in
            # to be used for SOA serial.
            #
            # SOA serial in a date format would also work, but it may be set to far
            # future when many DNS updates are done per day (more than 100). Unix
            # timestamp is more resilient to this issue.
            # """
            # return int(time.time())
        ),
        parameters.Int(
            'idnssoarefresh',
            required=False,
            cli_name='refresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
            default=3600,
        ),
        parameters.Int(
            'idnssoaretry',
            required=False,
            cli_name='retry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
            default=900,
        ),
        parameters.Int(
            'idnssoaexpire',
            required=False,
            cli_name='expire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
            default=1209600,
        ),
        parameters.Int(
            'idnssoaminimum',
            required=False,
            cli_name='minimum',
            label=_('SOA minimum'),
            doc=_('How long should negative responses be cached'),
            default=3600,
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_('Time to live'),
            doc=_('Time to live for records at zone apex'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            cli_name='update_policy',
            label=_('BIND update policy'),
            default_from=DefaultFrom(lambda idnsname: None, 'idnsname'),
            # FIXME:
            # lambda idnsname: default_zone_update_policy(idnsname)
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            cli_name='dynamic_update',
            label=_('Dynamic update'),
            doc=_('Allow dynamic updates.'),
            default=False,
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            cli_name='allow_query',
            label=_('Allow query'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default='any;',
            no_convert=True,
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            cli_name='allow_transfer',
            label=_('Allow transfer'),
            doc=_('Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default='none;',
            no_convert=True,
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_('Allow PTR sync'),
            doc=_('Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Bool(
            'idnssecinlinesigning',
            required=False,
            cli_name='dnssec',
            label=_('Allow in-line DNSSEC signing'),
            doc=_('Allow inline DNSSEC signing of records in the zone'),
            default=False,
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            cli_name='nsec3param_rec',
            label=_('NSEC3PARAM record'),
            doc=_('NSEC3PARAM record for zone in format: hash_algorithm flags iterations salt'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_('Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_('Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_('Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'force',
            label=_('Force'),
            doc=_('Force nameserver change even if nameserver not in DNS'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_remove_permission(Method):
    __doc__ = _("Remove a permission for per-zone access delegation.")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_('True means the operation was successful'),
        ),
        output.Output(
            'value',
            str,
            doc=_('Permission value'),
        ),
    )


@register()
class dnszone_show(Method):
    __doc__ = _("Display information about a DNS zone (SOA record).")

    takes_args = (
        parameters.DNSNameParam(
            'idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_('Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_('Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
