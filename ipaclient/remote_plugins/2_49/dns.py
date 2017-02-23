#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
Domain Name System (DNS)

Manage DNS zone and resource records.


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
   ipa dnszone-add example.com --name-server=ns \
                               --admin-email=admin@example.com \
                               --ip-address=10.0.0.1

 Add system permission that can be used for per-zone privilege delegation:
   ipa dnszone-add-permission example.com

 Modify the zone to allow dynamic updates for hosts own records in realm EXAMPLE.COM:
   ipa dnszone-mod example.com --dynamic-update=TRUE

   This is the equivalent of:
     ipa dnszone-mod example.com --dynamic-update=TRUE \
      --update-policy="grant EXAMPLE.COM krb5-self * A; grant EXAMPLE.COM krb5-self * AAAA; grant EXAMPLE.COM krb5-self * SSHFP;"

 Modify the zone to allow zone transfers for local network only:
   ipa dnszone-mod example.com --allow-transfer=10.0.0.0/8

 Add new reverse zone specified by network IP address:
   ipa dnszone-add --name-from-ip=80.142.15.0/24 \
                   --name-server=ns.example.com.

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
 will be created in zone 15.142.80.in-addr.arpa.
   ipa dnsrecord-add example.com www --a-rec=80.142.15.2 --a-create-reverse

 Add new PTR record for www.example.com
   ipa dnsrecord-add 15.142.80.in-addr.arpa. 2 --ptr-rec=www.example.com.

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

   A record: 1.2.3.4, 11.22.33.44

   Delete A record '1.2.3.4'? Yes/No (default No):
   Delete A record '11.22.33.44'? Yes/No (default No): y
     Record name: www
     A record: 1.2.3.4                  (A record 11.22.33.44 has been deleted)

 Show zone example.com:
   ipa dnszone-show example.com

 Find zone with "example" in its domain name:
   ipa dnszone-find example

 Find records for resources with "www" in their name in zone example.com:
   ipa dnsrecord-find example.com www

 Find A records with value 10.10.0.1 in zone example.com
   ipa dnsrecord-find example.com --a-rec=10.10.0.1

 Show records for resource www in zone example.com
   ipa dnsrecord-show example.com www

 Delegate zone sub.example to another nameserver:
   ipa dnsrecord-add example.com ns.sub --a-rec=10.0.100.5
   ipa dnsrecord-add example.com sub --ns-rec=ns.sub.example.com.

 If global forwarder is configured, all requests to sub.example.com will be
 routed through the global forwarder. To change the behavior for example.com
 zone only and forward the request directly to ns.sub.example.com., global
 forwarding may be disabled per-zone:
   ipa dnszone-mod example.com --forward-policy=none

 Forward all requests for the zone external.com to another nameserver using
 a "first" policy (it will send the queries to the selected forwarder and if
 not answered it will use global resolvers):
   ipa dnszone-add external.com
   ipa dnszone-mod external.com --forwarder=10.20.0.1 \
                                --forward-policy=first

 Delete zone example.com with all resource records:
   ipa dnszone-del example.com

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
   ipa dnsconfig-mod --forwarder=10.0.0.1
""")

register = Registry()


@register()
class dnsconfig(Object):
    takes_params = (
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            label=_(u'Global forwarders'),
            doc=_(u'A list of global forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            label=_(u'Forward policy'),
            doc=_(u'Global forwarding policy. Set to "none" to disable any configured global forwarders.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            label=_(u'Allow PTR sync'),
            doc=_(u'Allow synchronization of forward (A, AAAA) and reverse (PTR) records'),
        ),
        parameters.Int(
            'idnszonerefresh',
            required=False,
            label=_(u'Zone refresh interval'),
            doc=_(u'An interval between regular polls of the name server for new DNS zones'),
        ),
    )


@register()
class dnsrecord(Object):
    takes_params = (
        parameters.Str(
            'idnsname',
            primary_key=True,
            label=_(u'Record name'),
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            label=_(u'Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            label=_(u'Class'),
            doc=_(u'DNS class'),
        ),
        parameters.Any(
            'dnsrecords',
            required=False,
            label=_(u'Records'),
        ),
        parameters.Str(
            'dnstype',
            required=False,
            label=_(u'Record type'),
        ),
        parameters.Str(
            'dnsdata',
            required=False,
            label=_(u'Record data'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            label=_(u'A record'),
            doc=_(u'Comma-separated list of raw A records'),
        ),
        parameters.Str(
            'a_part_ip_address',
            required=False,
            label=_(u'A IP Address'),
            doc=_(u'IP Address'),
        ),
        parameters.Flag(
            'a_extra_create_reverse',
            required=False,
            label=_(u'A Create reverse'),
            doc=_(u'Create reverse record for this IP Address'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            label=_(u'AAAA record'),
            doc=_(u'Comma-separated list of raw AAAA records'),
        ),
        parameters.Str(
            'aaaa_part_ip_address',
            required=False,
            label=_(u'AAAA IP Address'),
            doc=_(u'IP Address'),
        ),
        parameters.Flag(
            'aaaa_extra_create_reverse',
            required=False,
            label=_(u'AAAA Create reverse'),
            doc=_(u'Create reverse record for this IP Address'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            label=_(u'A6 record'),
            doc=_(u'Comma-separated list of raw A6 records'),
        ),
        parameters.Str(
            'a6_part_data',
            required=False,
            label=_(u'A6 Record data'),
            doc=_(u'Record data'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            label=_(u'AFSDB record'),
            doc=_(u'Comma-separated list of raw AFSDB records'),
        ),
        parameters.Int(
            'afsdb_part_subtype',
            required=False,
            label=_(u'AFSDB Subtype'),
            doc=_(u'Subtype'),
        ),
        parameters.Str(
            'afsdb_part_hostname',
            required=False,
            label=_(u'AFSDB Hostname'),
            doc=_(u'Hostname'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            label=_(u'APL record'),
            doc=_(u'Comma-separated list of raw APL records'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            label=_(u'CERT record'),
            doc=_(u'Comma-separated list of raw CERT records'),
        ),
        parameters.Int(
            'cert_part_type',
            required=False,
            label=_(u'CERT Certificate Type'),
            doc=_(u'Certificate Type'),
        ),
        parameters.Int(
            'cert_part_key_tag',
            required=False,
            label=_(u'CERT Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Int(
            'cert_part_algorithm',
            required=False,
            label=_(u'CERT Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Str(
            'cert_part_certificate_or_crl',
            required=False,
            label=_(u'CERT Certificate/CRL'),
            doc=_(u'Certificate/CRL'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            label=_(u'CNAME record'),
            doc=_(u'Comma-separated list of raw CNAME records'),
        ),
        parameters.Str(
            'cname_part_hostname',
            required=False,
            label=_(u'CNAME Hostname'),
            doc=_(u'A hostname which this alias hostname points to'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            label=_(u'DHCID record'),
            doc=_(u'Comma-separated list of raw DHCID records'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            label=_(u'DLV record'),
            doc=_(u'Comma-separated list of raw DLV records'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            label=_(u'DNAME record'),
            doc=_(u'Comma-separated list of raw DNAME records'),
        ),
        parameters.Str(
            'dname_part_target',
            required=False,
            label=_(u'DNAME Target'),
            doc=_(u'Target'),
        ),
        parameters.Str(
            'dnskeyrecord',
            required=False,
            multivalue=True,
            label=_(u'DNSKEY record'),
            doc=_(u'Comma-separated list of raw DNSKEY records'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            label=_(u'DS record'),
            doc=_(u'Comma-separated list of raw DS records'),
        ),
        parameters.Int(
            'ds_part_key_tag',
            required=False,
            label=_(u'DS Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Int(
            'ds_part_algorithm',
            required=False,
            label=_(u'DS Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'ds_part_digest_type',
            required=False,
            label=_(u'DS Digest Type'),
            doc=_(u'Digest Type'),
        ),
        parameters.Str(
            'ds_part_digest',
            required=False,
            label=_(u'DS Digest'),
            doc=_(u'Digest'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            label=_(u'HIP record'),
            doc=_(u'Comma-separated list of raw HIP records'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            label=_(u'IPSECKEY record'),
            doc=_(u'Comma-separated list of raw IPSECKEY records'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            label=_(u'KEY record'),
            doc=_(u'Comma-separated list of raw KEY records'),
        ),
        parameters.Int(
            'key_part_flags',
            required=False,
            label=_(u'KEY Flags'),
            doc=_(u'Flags'),
        ),
        parameters.Int(
            'key_part_protocol',
            required=False,
            label=_(u'KEY Protocol'),
            doc=_(u'Protocol'),
        ),
        parameters.Int(
            'key_part_algorithm',
            required=False,
            label=_(u'KEY Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Str(
            'key_part_public_key',
            required=False,
            label=_(u'KEY Public Key'),
            doc=_(u'Public Key'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            label=_(u'KX record'),
            doc=_(u'Comma-separated list of raw KX records'),
        ),
        parameters.Int(
            'kx_part_preference',
            required=False,
            label=_(u'KX Preference'),
            doc=_(u'Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.Str(
            'kx_part_exchanger',
            required=False,
            label=_(u'KX Exchanger'),
            doc=_(u'A host willing to act as a key exchanger'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            label=_(u'LOC record'),
            doc=_(u'Comma-separated list of raw LOC records'),
        ),
        parameters.Int(
            'loc_part_lat_deg',
            required=False,
            label=_(u'LOC Degrees Latitude'),
            doc=_(u'Degrees Latitude'),
        ),
        parameters.Int(
            'loc_part_lat_min',
            required=False,
            label=_(u'LOC Minutes Latitude'),
            doc=_(u'Minutes Latitude'),
        ),
        parameters.Decimal(
            'loc_part_lat_sec',
            required=False,
            label=_(u'LOC Seconds Latitude'),
            doc=_(u'Seconds Latitude'),
        ),
        parameters.Str(
            'loc_part_lat_dir',
            required=False,
            label=_(u'LOC Direction Latitude'),
            doc=_(u'Direction Latitude'),
        ),
        parameters.Int(
            'loc_part_lon_deg',
            required=False,
            label=_(u'LOC Degrees Longitude'),
            doc=_(u'Degrees Longitude'),
        ),
        parameters.Int(
            'loc_part_lon_min',
            required=False,
            label=_(u'LOC Minutes Longitude'),
            doc=_(u'Minutes Longitude'),
        ),
        parameters.Decimal(
            'loc_part_lon_sec',
            required=False,
            label=_(u'LOC Seconds Longitude'),
            doc=_(u'Seconds Longitude'),
        ),
        parameters.Str(
            'loc_part_lon_dir',
            required=False,
            label=_(u'LOC Direction Longitude'),
            doc=_(u'Direction Longitude'),
        ),
        parameters.Decimal(
            'loc_part_altitude',
            required=False,
            label=_(u'LOC Altitude'),
            doc=_(u'Altitude'),
        ),
        parameters.Decimal(
            'loc_part_size',
            required=False,
            label=_(u'LOC Size'),
            doc=_(u'Size'),
        ),
        parameters.Decimal(
            'loc_part_h_precision',
            required=False,
            label=_(u'LOC Horizontal Precision'),
            doc=_(u'Horizontal Precision'),
        ),
        parameters.Decimal(
            'loc_part_v_precision',
            required=False,
            label=_(u'LOC Vertical Precision'),
            doc=_(u'Vertical Precision'),
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            label=_(u'MX record'),
            doc=_(u'Comma-separated list of raw MX records'),
        ),
        parameters.Int(
            'mx_part_preference',
            required=False,
            label=_(u'MX Preference'),
            doc=_(u'Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.Str(
            'mx_part_exchanger',
            required=False,
            label=_(u'MX Exchanger'),
            doc=_(u'A host willing to act as a mail exchanger'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            label=_(u'NAPTR record'),
            doc=_(u'Comma-separated list of raw NAPTR records'),
        ),
        parameters.Int(
            'naptr_part_order',
            required=False,
            label=_(u'NAPTR Order'),
            doc=_(u'Order'),
        ),
        parameters.Int(
            'naptr_part_preference',
            required=False,
            label=_(u'NAPTR Preference'),
            doc=_(u'Preference'),
        ),
        parameters.Str(
            'naptr_part_flags',
            required=False,
            label=_(u'NAPTR Flags'),
            doc=_(u'Flags'),
        ),
        parameters.Str(
            'naptr_part_service',
            required=False,
            label=_(u'NAPTR Service'),
            doc=_(u'Service'),
        ),
        parameters.Str(
            'naptr_part_regexp',
            required=False,
            label=_(u'NAPTR Regular Expression'),
            doc=_(u'Regular Expression'),
        ),
        parameters.Str(
            'naptr_part_replacement',
            required=False,
            label=_(u'NAPTR Replacement'),
            doc=_(u'Replacement'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            label=_(u'NS record'),
            doc=_(u'Comma-separated list of raw NS records'),
        ),
        parameters.Str(
            'ns_part_hostname',
            required=False,
            label=_(u'NS Hostname'),
            doc=_(u'Hostname'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            label=_(u'NSEC record'),
            doc=_(u'Comma-separated list of raw NSEC records'),
        ),
        parameters.Str(
            'nsec_part_next',
            required=False,
            label=_(u'NSEC Next Domain Name'),
            doc=_(u'Next Domain Name'),
        ),
        parameters.Str(
            'nsec_part_types',
            required=False,
            multivalue=True,
            label=_(u'NSEC Type Map'),
            doc=_(u'Type Map'),
        ),
        parameters.Str(
            'nsec3record',
            required=False,
            multivalue=True,
            label=_(u'NSEC3 record'),
            doc=_(u'Comma-separated list of raw NSEC3 records'),
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            multivalue=True,
            label=_(u'NSEC3PARAM record'),
            doc=_(u'Comma-separated list of raw NSEC3PARAM records'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            label=_(u'PTR record'),
            doc=_(u'Comma-separated list of raw PTR records'),
        ),
        parameters.Str(
            'ptr_part_hostname',
            required=False,
            label=_(u'PTR Hostname'),
            doc=_(u'The hostname this reverse record points to'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            label=_(u'RRSIG record'),
            doc=_(u'Comma-separated list of raw RRSIG records'),
        ),
        parameters.Str(
            'rrsig_part_type_covered',
            required=False,
            label=_(u'RRSIG Type Covered'),
            doc=_(u'Type Covered'),
        ),
        parameters.Int(
            'rrsig_part_algorithm',
            required=False,
            label=_(u'RRSIG Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'rrsig_part_labels',
            required=False,
            label=_(u'RRSIG Labels'),
            doc=_(u'Labels'),
        ),
        parameters.Int(
            'rrsig_part_original_ttl',
            required=False,
            label=_(u'RRSIG Original TTL'),
            doc=_(u'Original TTL'),
        ),
        parameters.Str(
            'rrsig_part_signature_expiration',
            required=False,
            label=_(u'RRSIG Signature Expiration'),
            doc=_(u'Signature Expiration'),
        ),
        parameters.Str(
            'rrsig_part_signature_inception',
            required=False,
            label=_(u'RRSIG Signature Inception'),
            doc=_(u'Signature Inception'),
        ),
        parameters.Int(
            'rrsig_part_key_tag',
            required=False,
            label=_(u'RRSIG Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Str(
            'rrsig_part_signers_name',
            required=False,
            label=_(u"RRSIG Signer's Name"),
            doc=_(u"Signer's Name"),
        ),
        parameters.Str(
            'rrsig_part_signature',
            required=False,
            label=_(u'RRSIG Signature'),
            doc=_(u'Signature'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            label=_(u'RP record'),
            doc=_(u'Comma-separated list of raw RP records'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            label=_(u'SIG record'),
            doc=_(u'Comma-separated list of raw SIG records'),
        ),
        parameters.Str(
            'sig_part_type_covered',
            required=False,
            label=_(u'SIG Type Covered'),
            doc=_(u'Type Covered'),
        ),
        parameters.Int(
            'sig_part_algorithm',
            required=False,
            label=_(u'SIG Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'sig_part_labels',
            required=False,
            label=_(u'SIG Labels'),
            doc=_(u'Labels'),
        ),
        parameters.Int(
            'sig_part_original_ttl',
            required=False,
            label=_(u'SIG Original TTL'),
            doc=_(u'Original TTL'),
        ),
        parameters.Str(
            'sig_part_signature_expiration',
            required=False,
            label=_(u'SIG Signature Expiration'),
            doc=_(u'Signature Expiration'),
        ),
        parameters.Str(
            'sig_part_signature_inception',
            required=False,
            label=_(u'SIG Signature Inception'),
            doc=_(u'Signature Inception'),
        ),
        parameters.Int(
            'sig_part_key_tag',
            required=False,
            label=_(u'SIG Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Str(
            'sig_part_signers_name',
            required=False,
            label=_(u"SIG Signer's Name"),
            doc=_(u"Signer's Name"),
        ),
        parameters.Str(
            'sig_part_signature',
            required=False,
            label=_(u'SIG Signature'),
            doc=_(u'Signature'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            label=_(u'SPF record'),
            doc=_(u'Comma-separated list of raw SPF records'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            label=_(u'SRV record'),
            doc=_(u'Comma-separated list of raw SRV records'),
        ),
        parameters.Int(
            'srv_part_priority',
            required=False,
            label=_(u'SRV Priority'),
            doc=_(u'Priority'),
        ),
        parameters.Int(
            'srv_part_weight',
            required=False,
            label=_(u'SRV Weight'),
            doc=_(u'Weight'),
        ),
        parameters.Int(
            'srv_part_port',
            required=False,
            label=_(u'SRV Port'),
            doc=_(u'Port'),
        ),
        parameters.Str(
            'srv_part_target',
            required=False,
            label=_(u'SRV Target'),
            doc=_(u"The domain name of the target host or '.' if the service is decidedly not available at this domain"),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            label=_(u'SSHFP record'),
            doc=_(u'Comma-separated list of raw SSHFP records'),
        ),
        parameters.Int(
            'sshfp_part_algorithm',
            required=False,
            label=_(u'SSHFP Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'sshfp_part_fp_type',
            required=False,
            label=_(u'SSHFP Fingerprint Type'),
            doc=_(u'Fingerprint Type'),
        ),
        parameters.Str(
            'sshfp_part_fingerprint',
            required=False,
            label=_(u'SSHFP Fingerprint'),
            doc=_(u'Fingerprint'),
        ),
        parameters.Str(
            'tarecord',
            required=False,
            multivalue=True,
            label=_(u'TA record'),
            doc=_(u'Comma-separated list of raw TA records'),
        ),
        parameters.Str(
            'tkeyrecord',
            required=False,
            multivalue=True,
            label=_(u'TKEY record'),
            doc=_(u'Comma-separated list of raw TKEY records'),
        ),
        parameters.Str(
            'tsigrecord',
            required=False,
            multivalue=True,
            label=_(u'TSIG record'),
            doc=_(u'Comma-separated list of raw TSIG records'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            label=_(u'TXT record'),
            doc=_(u'Comma-separated list of raw TXT records'),
        ),
        parameters.Str(
            'txt_part_data',
            required=False,
            label=_(u'TXT Text Data'),
            doc=_(u'Text Data'),
        ),
    )


@register()
class dnszone(Object):
    takes_params = (
        parameters.Str(
            'idnsname',
            primary_key=True,
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
        ),
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_(u'Reverse zone IP network'),
            doc=_(u'IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnssoamname',
            label=_(u'Authoritative nameserver'),
            doc=_(u'Authoritative nameserver domain name'),
        ),
        parameters.Str(
            'idnssoarname',
            label=_(u'Administrator e-mail address'),
        ),
        parameters.Int(
            'idnssoaserial',
            label=_(u'SOA serial'),
            doc=_(u'SOA record serial number'),
        ),
        parameters.Int(
            'idnssoarefresh',
            label=_(u'SOA refresh'),
            doc=_(u'SOA record refresh time'),
        ),
        parameters.Int(
            'idnssoaretry',
            label=_(u'SOA retry'),
            doc=_(u'SOA record retry time'),
        ),
        parameters.Int(
            'idnssoaexpire',
            label=_(u'SOA expire'),
            doc=_(u'SOA record expire time'),
        ),
        parameters.Int(
            'idnssoaminimum',
            label=_(u'SOA minimum'),
            doc=_(u'How long should negative responses be cached'),
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            label=_(u'SOA time to live'),
            doc=_(u'SOA record time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            label=_(u'SOA class'),
            doc=_(u'SOA record class'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            label=_(u'BIND update policy'),
        ),
        parameters.Bool(
            'idnszoneactive',
            required=False,
            label=_(u'Active zone'),
            doc=_(u'Is zone active?'),
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            label=_(u'Dynamic update'),
            doc=_(u'Allow dynamic updates.'),
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            label=_(u'Allow query'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            label=_(u'Allow transfer'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            label=_(u'Zone forwarders'),
            doc=_(u'A list of per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            label=_(u'Forward policy'),
            doc=_(u'Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            label=_(u'Allow PTR sync'),
            doc=_(u'Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
    )


@register()
class dns_is_enabled(Command):
    __doc__ = _("Checks if any of the servers has the DNS service enabled.")

    NO_CLI = True

    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dns_resolve(Command):
    __doc__ = _("Resolve a host name in DNS.")

    takes_args = (
        parameters.Str(
            'hostname',
            label=_(u'Hostname'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
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
            label=_(u'Global forwarders'),
            doc=_(u'A list of global forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_(u'Forward policy'),
            doc=_(u'Global forwarding policy. Set to "none" to disable any configured global forwarders.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_(u'Allow PTR sync'),
            doc=_(u'Allow synchronization of forward (A, AAAA) and reverse (PTR) records'),
        ),
        parameters.Int(
            'idnszonerefresh',
            required=False,
            cli_name='zone_refresh',
            label=_(u'Zone refresh interval'),
            doc=_(u'An interval between regular polls of the name server for new DNS zones'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsconfig_show(Method):
    __doc__ = _("Show the current global DNS configuration.")

    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_add(Method):
    __doc__ = _("Add new DNS resource record.")

    takes_args = (
        parameters.Str(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_(u'Zone name'),
        ),
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Record name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'Class'),
            doc=_(u'DNS class'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            option_group=u'A Record',
            label=_(u'A record'),
            doc=_(u'Comma-separated list of raw A records'),
        ),
        parameters.Str(
            'a_part_ip_address',
            required=False,
            cli_name='a_ip_address',
            option_group=u'A Record',
            label=_(u'A IP Address'),
            doc=_(u'IP Address'),
        ),
        parameters.Flag(
            'a_extra_create_reverse',
            required=False,
            cli_name='a_create_reverse',
            option_group=u'A Record',
            label=_(u'A Create reverse'),
            doc=_(u'Create reverse record for this IP Address'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            option_group=u'AAAA Record',
            label=_(u'AAAA record'),
            doc=_(u'Comma-separated list of raw AAAA records'),
        ),
        parameters.Str(
            'aaaa_part_ip_address',
            required=False,
            cli_name='aaaa_ip_address',
            option_group=u'AAAA Record',
            label=_(u'AAAA IP Address'),
            doc=_(u'IP Address'),
        ),
        parameters.Flag(
            'aaaa_extra_create_reverse',
            required=False,
            cli_name='aaaa_create_reverse',
            option_group=u'AAAA Record',
            label=_(u'AAAA Create reverse'),
            doc=_(u'Create reverse record for this IP Address'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            option_group=u'A6 Record',
            label=_(u'A6 record'),
            doc=_(u'Comma-separated list of raw A6 records'),
        ),
        parameters.Str(
            'a6_part_data',
            required=False,
            cli_name='a6_data',
            option_group=u'A6 Record',
            label=_(u'A6 Record data'),
            doc=_(u'Record data'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            option_group=u'AFSDB Record',
            label=_(u'AFSDB record'),
            doc=_(u'Comma-separated list of raw AFSDB records'),
        ),
        parameters.Int(
            'afsdb_part_subtype',
            required=False,
            cli_name='afsdb_subtype',
            option_group=u'AFSDB Record',
            label=_(u'AFSDB Subtype'),
            doc=_(u'Subtype'),
        ),
        parameters.Str(
            'afsdb_part_hostname',
            required=False,
            cli_name='afsdb_hostname',
            option_group=u'AFSDB Record',
            label=_(u'AFSDB Hostname'),
            doc=_(u'Hostname'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            option_group=u'APL Record',
            label=_(u'APL record'),
            doc=_(u'Comma-separated list of raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            option_group=u'CERT Record',
            label=_(u'CERT record'),
            doc=_(u'Comma-separated list of raw CERT records'),
        ),
        parameters.Int(
            'cert_part_type',
            required=False,
            cli_name='cert_type',
            option_group=u'CERT Record',
            label=_(u'CERT Certificate Type'),
            doc=_(u'Certificate Type'),
        ),
        parameters.Int(
            'cert_part_key_tag',
            required=False,
            cli_name='cert_key_tag',
            option_group=u'CERT Record',
            label=_(u'CERT Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Int(
            'cert_part_algorithm',
            required=False,
            cli_name='cert_algorithm',
            option_group=u'CERT Record',
            label=_(u'CERT Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Str(
            'cert_part_certificate_or_crl',
            required=False,
            cli_name='cert_certificate_or_crl',
            option_group=u'CERT Record',
            label=_(u'CERT Certificate/CRL'),
            doc=_(u'Certificate/CRL'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            option_group=u'CNAME Record',
            label=_(u'CNAME record'),
            doc=_(u'Comma-separated list of raw CNAME records'),
        ),
        parameters.Str(
            'cname_part_hostname',
            required=False,
            cli_name='cname_hostname',
            option_group=u'CNAME Record',
            label=_(u'CNAME Hostname'),
            doc=_(u'A hostname which this alias hostname points to'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            option_group=u'DHCID Record',
            label=_(u'DHCID record'),
            doc=_(u'Comma-separated list of raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            option_group=u'DLV Record',
            label=_(u'DLV record'),
            doc=_(u'Comma-separated list of raw DLV records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            option_group=u'DNAME Record',
            label=_(u'DNAME record'),
            doc=_(u'Comma-separated list of raw DNAME records'),
        ),
        parameters.Str(
            'dname_part_target',
            required=False,
            cli_name='dname_target',
            option_group=u'DNAME Record',
            label=_(u'DNAME Target'),
            doc=_(u'Target'),
        ),
        parameters.Str(
            'dnskeyrecord',
            required=False,
            multivalue=True,
            cli_name='dnskey_rec',
            option_group=u'DNSKEY Record',
            label=_(u'DNSKEY record'),
            doc=_(u'Comma-separated list of raw DNSKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            option_group=u'DS Record',
            label=_(u'DS record'),
            doc=_(u'Comma-separated list of raw DS records'),
        ),
        parameters.Int(
            'ds_part_key_tag',
            required=False,
            cli_name='ds_key_tag',
            option_group=u'DS Record',
            label=_(u'DS Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Int(
            'ds_part_algorithm',
            required=False,
            cli_name='ds_algorithm',
            option_group=u'DS Record',
            label=_(u'DS Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'ds_part_digest_type',
            required=False,
            cli_name='ds_digest_type',
            option_group=u'DS Record',
            label=_(u'DS Digest Type'),
            doc=_(u'Digest Type'),
        ),
        parameters.Str(
            'ds_part_digest',
            required=False,
            cli_name='ds_digest',
            option_group=u'DS Record',
            label=_(u'DS Digest'),
            doc=_(u'Digest'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            option_group=u'HIP Record',
            label=_(u'HIP record'),
            doc=_(u'Comma-separated list of raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            option_group=u'IPSECKEY Record',
            label=_(u'IPSECKEY record'),
            doc=_(u'Comma-separated list of raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            option_group=u'KEY Record',
            label=_(u'KEY record'),
            doc=_(u'Comma-separated list of raw KEY records'),
        ),
        parameters.Int(
            'key_part_flags',
            required=False,
            cli_name='key_flags',
            option_group=u'KEY Record',
            label=_(u'KEY Flags'),
            doc=_(u'Flags'),
        ),
        parameters.Int(
            'key_part_protocol',
            required=False,
            cli_name='key_protocol',
            option_group=u'KEY Record',
            label=_(u'KEY Protocol'),
            doc=_(u'Protocol'),
        ),
        parameters.Int(
            'key_part_algorithm',
            required=False,
            cli_name='key_algorithm',
            option_group=u'KEY Record',
            label=_(u'KEY Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Str(
            'key_part_public_key',
            required=False,
            cli_name='key_public_key',
            option_group=u'KEY Record',
            label=_(u'KEY Public Key'),
            doc=_(u'Public Key'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            option_group=u'KX Record',
            label=_(u'KX record'),
            doc=_(u'Comma-separated list of raw KX records'),
        ),
        parameters.Int(
            'kx_part_preference',
            required=False,
            cli_name='kx_preference',
            option_group=u'KX Record',
            label=_(u'KX Preference'),
            doc=_(u'Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.Str(
            'kx_part_exchanger',
            required=False,
            cli_name='kx_exchanger',
            option_group=u'KX Record',
            label=_(u'KX Exchanger'),
            doc=_(u'A host willing to act as a key exchanger'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            option_group=u'LOC Record',
            label=_(u'LOC record'),
            doc=_(u'Comma-separated list of raw LOC records'),
        ),
        parameters.Int(
            'loc_part_lat_deg',
            required=False,
            cli_name='loc_lat_deg',
            option_group=u'LOC Record',
            label=_(u'LOC Degrees Latitude'),
            doc=_(u'Degrees Latitude'),
        ),
        parameters.Int(
            'loc_part_lat_min',
            required=False,
            cli_name='loc_lat_min',
            option_group=u'LOC Record',
            label=_(u'LOC Minutes Latitude'),
            doc=_(u'Minutes Latitude'),
        ),
        parameters.Decimal(
            'loc_part_lat_sec',
            required=False,
            cli_name='loc_lat_sec',
            option_group=u'LOC Record',
            label=_(u'LOC Seconds Latitude'),
            doc=_(u'Seconds Latitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lat_dir',
            required=False,
            cli_name='loc_lat_dir',
            option_group=u'LOC Record',
            cli_metavar="['N', 'S']",
            label=_(u'LOC Direction Latitude'),
            doc=_(u'Direction Latitude'),
        ),
        parameters.Int(
            'loc_part_lon_deg',
            required=False,
            cli_name='loc_lon_deg',
            option_group=u'LOC Record',
            label=_(u'LOC Degrees Longitude'),
            doc=_(u'Degrees Longitude'),
        ),
        parameters.Int(
            'loc_part_lon_min',
            required=False,
            cli_name='loc_lon_min',
            option_group=u'LOC Record',
            label=_(u'LOC Minutes Longitude'),
            doc=_(u'Minutes Longitude'),
        ),
        parameters.Decimal(
            'loc_part_lon_sec',
            required=False,
            cli_name='loc_lon_sec',
            option_group=u'LOC Record',
            label=_(u'LOC Seconds Longitude'),
            doc=_(u'Seconds Longitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lon_dir',
            required=False,
            cli_name='loc_lon_dir',
            option_group=u'LOC Record',
            cli_metavar="['E', 'W']",
            label=_(u'LOC Direction Longitude'),
            doc=_(u'Direction Longitude'),
        ),
        parameters.Decimal(
            'loc_part_altitude',
            required=False,
            cli_name='loc_altitude',
            option_group=u'LOC Record',
            label=_(u'LOC Altitude'),
            doc=_(u'Altitude'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_size',
            required=False,
            cli_name='loc_size',
            option_group=u'LOC Record',
            label=_(u'LOC Size'),
            doc=_(u'Size'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_h_precision',
            required=False,
            cli_name='loc_h_precision',
            option_group=u'LOC Record',
            label=_(u'LOC Horizontal Precision'),
            doc=_(u'Horizontal Precision'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_v_precision',
            required=False,
            cli_name='loc_v_precision',
            option_group=u'LOC Record',
            label=_(u'LOC Vertical Precision'),
            doc=_(u'Vertical Precision'),
            no_convert=True,
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            option_group=u'MX Record',
            label=_(u'MX record'),
            doc=_(u'Comma-separated list of raw MX records'),
        ),
        parameters.Int(
            'mx_part_preference',
            required=False,
            cli_name='mx_preference',
            option_group=u'MX Record',
            label=_(u'MX Preference'),
            doc=_(u'Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.Str(
            'mx_part_exchanger',
            required=False,
            cli_name='mx_exchanger',
            option_group=u'MX Record',
            label=_(u'MX Exchanger'),
            doc=_(u'A host willing to act as a mail exchanger'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR record'),
            doc=_(u'Comma-separated list of raw NAPTR records'),
        ),
        parameters.Int(
            'naptr_part_order',
            required=False,
            cli_name='naptr_order',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Order'),
            doc=_(u'Order'),
        ),
        parameters.Int(
            'naptr_part_preference',
            required=False,
            cli_name='naptr_preference',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Preference'),
            doc=_(u'Preference'),
        ),
        parameters.Str(
            'naptr_part_flags',
            required=False,
            cli_name='naptr_flags',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Flags'),
            doc=_(u'Flags'),
            no_convert=True,
        ),
        parameters.Str(
            'naptr_part_service',
            required=False,
            cli_name='naptr_service',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Service'),
            doc=_(u'Service'),
        ),
        parameters.Str(
            'naptr_part_regexp',
            required=False,
            cli_name='naptr_regexp',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Regular Expression'),
            doc=_(u'Regular Expression'),
        ),
        parameters.Str(
            'naptr_part_replacement',
            required=False,
            cli_name='naptr_replacement',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Replacement'),
            doc=_(u'Replacement'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            option_group=u'NS Record',
            label=_(u'NS record'),
            doc=_(u'Comma-separated list of raw NS records'),
        ),
        parameters.Str(
            'ns_part_hostname',
            required=False,
            cli_name='ns_hostname',
            option_group=u'NS Record',
            label=_(u'NS Hostname'),
            doc=_(u'Hostname'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            option_group=u'NSEC Record',
            label=_(u'NSEC record'),
            doc=_(u'Comma-separated list of raw NSEC records'),
        ),
        parameters.Str(
            'nsec_part_next',
            required=False,
            cli_name='nsec_next',
            option_group=u'NSEC Record',
            label=_(u'NSEC Next Domain Name'),
            doc=_(u'Next Domain Name'),
        ),
        parameters.Str(
            'nsec_part_types',
            required=False,
            multivalue=True,
            cli_name='nsec_types',
            option_group=u'NSEC Record',
            cli_metavar="['SOA', 'A', 'AAAA', 'A6', 'AFSDB', 'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SIG', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']",
            label=_(u'NSEC Type Map'),
            doc=_(u'Type Map'),
        ),
        parameters.Str(
            'nsec3record',
            required=False,
            multivalue=True,
            cli_name='nsec3_rec',
            option_group=u'NSEC3 Record',
            label=_(u'NSEC3 record'),
            doc=_(u'Comma-separated list of raw NSEC3 records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            multivalue=True,
            cli_name='nsec3param_rec',
            option_group=u'NSEC3PARAM Record',
            label=_(u'NSEC3PARAM record'),
            doc=_(u'Comma-separated list of raw NSEC3PARAM records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            option_group=u'PTR Record',
            label=_(u'PTR record'),
            doc=_(u'Comma-separated list of raw PTR records'),
        ),
        parameters.Str(
            'ptr_part_hostname',
            required=False,
            cli_name='ptr_hostname',
            option_group=u'PTR Record',
            label=_(u'PTR Hostname'),
            doc=_(u'The hostname this reverse record points to'),
            no_convert=True,
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG record'),
            doc=_(u'Comma-separated list of raw RRSIG records'),
        ),
        parameters.Str(
            'rrsig_part_type_covered',
            required=False,
            cli_name='rrsig_type_covered',
            option_group=u'RRSIG Record',
            cli_metavar="['SOA', 'A', 'AAAA', 'A6', 'AFSDB', 'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']",
            label=_(u'RRSIG Type Covered'),
            doc=_(u'Type Covered'),
        ),
        parameters.Int(
            'rrsig_part_algorithm',
            required=False,
            cli_name='rrsig_algorithm',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'rrsig_part_labels',
            required=False,
            cli_name='rrsig_labels',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Labels'),
            doc=_(u'Labels'),
        ),
        parameters.Int(
            'rrsig_part_original_ttl',
            required=False,
            cli_name='rrsig_original_ttl',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Original TTL'),
            doc=_(u'Original TTL'),
        ),
        parameters.Str(
            'rrsig_part_signature_expiration',
            required=False,
            cli_name='rrsig_signature_expiration',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Signature Expiration'),
            doc=_(u'Signature Expiration'),
        ),
        parameters.Str(
            'rrsig_part_signature_inception',
            required=False,
            cli_name='rrsig_signature_inception',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Signature Inception'),
            doc=_(u'Signature Inception'),
        ),
        parameters.Int(
            'rrsig_part_key_tag',
            required=False,
            cli_name='rrsig_key_tag',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Str(
            'rrsig_part_signers_name',
            required=False,
            cli_name='rrsig_signers_name',
            option_group=u'RRSIG Record',
            label=_(u"RRSIG Signer's Name"),
            doc=_(u"Signer's Name"),
        ),
        parameters.Str(
            'rrsig_part_signature',
            required=False,
            cli_name='rrsig_signature',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Signature'),
            doc=_(u'Signature'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            option_group=u'RP Record',
            label=_(u'RP record'),
            doc=_(u'Comma-separated list of raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            option_group=u'SIG Record',
            label=_(u'SIG record'),
            doc=_(u'Comma-separated list of raw SIG records'),
        ),
        parameters.Str(
            'sig_part_type_covered',
            required=False,
            cli_name='sig_type_covered',
            option_group=u'SIG Record',
            cli_metavar="['SOA', 'A', 'AAAA', 'A6', 'AFSDB', 'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']",
            label=_(u'SIG Type Covered'),
            doc=_(u'Type Covered'),
        ),
        parameters.Int(
            'sig_part_algorithm',
            required=False,
            cli_name='sig_algorithm',
            option_group=u'SIG Record',
            label=_(u'SIG Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'sig_part_labels',
            required=False,
            cli_name='sig_labels',
            option_group=u'SIG Record',
            label=_(u'SIG Labels'),
            doc=_(u'Labels'),
        ),
        parameters.Int(
            'sig_part_original_ttl',
            required=False,
            cli_name='sig_original_ttl',
            option_group=u'SIG Record',
            label=_(u'SIG Original TTL'),
            doc=_(u'Original TTL'),
        ),
        parameters.Str(
            'sig_part_signature_expiration',
            required=False,
            cli_name='sig_signature_expiration',
            option_group=u'SIG Record',
            label=_(u'SIG Signature Expiration'),
            doc=_(u'Signature Expiration'),
        ),
        parameters.Str(
            'sig_part_signature_inception',
            required=False,
            cli_name='sig_signature_inception',
            option_group=u'SIG Record',
            label=_(u'SIG Signature Inception'),
            doc=_(u'Signature Inception'),
        ),
        parameters.Int(
            'sig_part_key_tag',
            required=False,
            cli_name='sig_key_tag',
            option_group=u'SIG Record',
            label=_(u'SIG Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Str(
            'sig_part_signers_name',
            required=False,
            cli_name='sig_signers_name',
            option_group=u'SIG Record',
            label=_(u"SIG Signer's Name"),
            doc=_(u"Signer's Name"),
        ),
        parameters.Str(
            'sig_part_signature',
            required=False,
            cli_name='sig_signature',
            option_group=u'SIG Record',
            label=_(u'SIG Signature'),
            doc=_(u'Signature'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            option_group=u'SPF Record',
            label=_(u'SPF record'),
            doc=_(u'Comma-separated list of raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            option_group=u'SRV Record',
            label=_(u'SRV record'),
            doc=_(u'Comma-separated list of raw SRV records'),
        ),
        parameters.Int(
            'srv_part_priority',
            required=False,
            cli_name='srv_priority',
            option_group=u'SRV Record',
            label=_(u'SRV Priority'),
            doc=_(u'Priority'),
        ),
        parameters.Int(
            'srv_part_weight',
            required=False,
            cli_name='srv_weight',
            option_group=u'SRV Record',
            label=_(u'SRV Weight'),
            doc=_(u'Weight'),
        ),
        parameters.Int(
            'srv_part_port',
            required=False,
            cli_name='srv_port',
            option_group=u'SRV Record',
            label=_(u'SRV Port'),
            doc=_(u'Port'),
        ),
        parameters.Str(
            'srv_part_target',
            required=False,
            cli_name='srv_target',
            option_group=u'SRV Record',
            label=_(u'SRV Target'),
            doc=_(u"The domain name of the target host or '.' if the service is decidedly not available at this domain"),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP record'),
            doc=_(u'Comma-separated list of raw SSHFP records'),
        ),
        parameters.Int(
            'sshfp_part_algorithm',
            required=False,
            cli_name='sshfp_algorithm',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'sshfp_part_fp_type',
            required=False,
            cli_name='sshfp_fp_type',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP Fingerprint Type'),
            doc=_(u'Fingerprint Type'),
        ),
        parameters.Str(
            'sshfp_part_fingerprint',
            required=False,
            cli_name='sshfp_fingerprint',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP Fingerprint'),
            doc=_(u'Fingerprint'),
        ),
        parameters.Str(
            'tarecord',
            required=False,
            multivalue=True,
            cli_name='ta_rec',
            option_group=u'TA Record',
            label=_(u'TA record'),
            doc=_(u'Comma-separated list of raw TA records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tkeyrecord',
            required=False,
            multivalue=True,
            cli_name='tkey_rec',
            option_group=u'TKEY Record',
            label=_(u'TKEY record'),
            doc=_(u'Comma-separated list of raw TKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tsigrecord',
            required=False,
            multivalue=True,
            cli_name='tsig_rec',
            option_group=u'TSIG Record',
            label=_(u'TSIG record'),
            doc=_(u'Comma-separated list of raw TSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            option_group=u'TXT Record',
            label=_(u'TXT record'),
            doc=_(u'Comma-separated list of raw TXT records'),
        ),
        parameters.Str(
            'txt_part_data',
            required=False,
            cli_name='txt_data',
            option_group=u'TXT Record',
            label=_(u'TXT Text Data'),
            doc=_(u'Text Data'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'force',
            label=_(u'Force'),
            doc=_(u'force NS record creation even if its hostname is not in DNS'),
            exclude=('cli', 'webui'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_(u'Structured'),
            doc=_(u'Parse all raw DNS records and return them in a structured way'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_del(Method):
    __doc__ = _("Delete DNS resource record.")

    takes_args = (
        parameters.Str(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_(u'Zone name'),
        ),
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Record name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'Class'),
            doc=_(u'DNS class'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            label=_(u'A record'),
            doc=_(u'Comma-separated list of raw A records'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            label=_(u'AAAA record'),
            doc=_(u'Comma-separated list of raw AAAA records'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            label=_(u'A6 record'),
            doc=_(u'Comma-separated list of raw A6 records'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            label=_(u'AFSDB record'),
            doc=_(u'Comma-separated list of raw AFSDB records'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            label=_(u'APL record'),
            doc=_(u'Comma-separated list of raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            label=_(u'CERT record'),
            doc=_(u'Comma-separated list of raw CERT records'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            label=_(u'CNAME record'),
            doc=_(u'Comma-separated list of raw CNAME records'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            label=_(u'DHCID record'),
            doc=_(u'Comma-separated list of raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            label=_(u'DLV record'),
            doc=_(u'Comma-separated list of raw DLV records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            label=_(u'DNAME record'),
            doc=_(u'Comma-separated list of raw DNAME records'),
        ),
        parameters.Str(
            'dnskeyrecord',
            required=False,
            multivalue=True,
            cli_name='dnskey_rec',
            label=_(u'DNSKEY record'),
            doc=_(u'Comma-separated list of raw DNSKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            label=_(u'DS record'),
            doc=_(u'Comma-separated list of raw DS records'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            label=_(u'HIP record'),
            doc=_(u'Comma-separated list of raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            label=_(u'IPSECKEY record'),
            doc=_(u'Comma-separated list of raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            label=_(u'KEY record'),
            doc=_(u'Comma-separated list of raw KEY records'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            label=_(u'KX record'),
            doc=_(u'Comma-separated list of raw KX records'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            label=_(u'LOC record'),
            doc=_(u'Comma-separated list of raw LOC records'),
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            label=_(u'MX record'),
            doc=_(u'Comma-separated list of raw MX records'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            label=_(u'NAPTR record'),
            doc=_(u'Comma-separated list of raw NAPTR records'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            label=_(u'NS record'),
            doc=_(u'Comma-separated list of raw NS records'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            label=_(u'NSEC record'),
            doc=_(u'Comma-separated list of raw NSEC records'),
        ),
        parameters.Str(
            'nsec3record',
            required=False,
            multivalue=True,
            cli_name='nsec3_rec',
            label=_(u'NSEC3 record'),
            doc=_(u'Comma-separated list of raw NSEC3 records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            multivalue=True,
            cli_name='nsec3param_rec',
            label=_(u'NSEC3PARAM record'),
            doc=_(u'Comma-separated list of raw NSEC3PARAM records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            label=_(u'PTR record'),
            doc=_(u'Comma-separated list of raw PTR records'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            label=_(u'RRSIG record'),
            doc=_(u'Comma-separated list of raw RRSIG records'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            label=_(u'RP record'),
            doc=_(u'Comma-separated list of raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            label=_(u'SIG record'),
            doc=_(u'Comma-separated list of raw SIG records'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            label=_(u'SPF record'),
            doc=_(u'Comma-separated list of raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            label=_(u'SRV record'),
            doc=_(u'Comma-separated list of raw SRV records'),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            label=_(u'SSHFP record'),
            doc=_(u'Comma-separated list of raw SSHFP records'),
        ),
        parameters.Str(
            'tarecord',
            required=False,
            multivalue=True,
            cli_name='ta_rec',
            label=_(u'TA record'),
            doc=_(u'Comma-separated list of raw TA records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tkeyrecord',
            required=False,
            multivalue=True,
            cli_name='tkey_rec',
            label=_(u'TKEY record'),
            doc=_(u'Comma-separated list of raw TKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tsigrecord',
            required=False,
            multivalue=True,
            cli_name='tsig_rec',
            label=_(u'TSIG record'),
            doc=_(u'Comma-separated list of raw TSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            label=_(u'TXT record'),
            doc=_(u'Comma-separated list of raw TXT records'),
        ),
        parameters.Flag(
            'del_all',
            label=_(u'Delete all associated records'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_(u'Structured'),
            doc=_(u'Parse all raw DNS records and return them in a structured way'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_delentry(Method):
    __doc__ = _("Delete DNS record entry.")

    NO_CLI = True

    takes_args = (
        parameters.Str(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_(u'Zone name'),
        ),
        parameters.Str(
            'idnsname',
            multivalue=True,
            cli_name='name',
            label=_(u'Record name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_find(Method):
    __doc__ = _("Search for DNS resources.")

    takes_args = (
        parameters.Str(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_(u'Zone name'),
        ),
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'idnsname',
            required=False,
            cli_name='name',
            label=_(u'Record name'),
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'Class'),
            doc=_(u'DNS class'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            label=_(u'A record'),
            doc=_(u'Comma-separated list of raw A records'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            label=_(u'AAAA record'),
            doc=_(u'Comma-separated list of raw AAAA records'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            label=_(u'A6 record'),
            doc=_(u'Comma-separated list of raw A6 records'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            label=_(u'AFSDB record'),
            doc=_(u'Comma-separated list of raw AFSDB records'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            label=_(u'APL record'),
            doc=_(u'Comma-separated list of raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            label=_(u'CERT record'),
            doc=_(u'Comma-separated list of raw CERT records'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            label=_(u'CNAME record'),
            doc=_(u'Comma-separated list of raw CNAME records'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            label=_(u'DHCID record'),
            doc=_(u'Comma-separated list of raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            label=_(u'DLV record'),
            doc=_(u'Comma-separated list of raw DLV records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            label=_(u'DNAME record'),
            doc=_(u'Comma-separated list of raw DNAME records'),
        ),
        parameters.Str(
            'dnskeyrecord',
            required=False,
            multivalue=True,
            cli_name='dnskey_rec',
            label=_(u'DNSKEY record'),
            doc=_(u'Comma-separated list of raw DNSKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            label=_(u'DS record'),
            doc=_(u'Comma-separated list of raw DS records'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            label=_(u'HIP record'),
            doc=_(u'Comma-separated list of raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            label=_(u'IPSECKEY record'),
            doc=_(u'Comma-separated list of raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            label=_(u'KEY record'),
            doc=_(u'Comma-separated list of raw KEY records'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            label=_(u'KX record'),
            doc=_(u'Comma-separated list of raw KX records'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            label=_(u'LOC record'),
            doc=_(u'Comma-separated list of raw LOC records'),
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            label=_(u'MX record'),
            doc=_(u'Comma-separated list of raw MX records'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            label=_(u'NAPTR record'),
            doc=_(u'Comma-separated list of raw NAPTR records'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            label=_(u'NS record'),
            doc=_(u'Comma-separated list of raw NS records'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            label=_(u'NSEC record'),
            doc=_(u'Comma-separated list of raw NSEC records'),
        ),
        parameters.Str(
            'nsec3record',
            required=False,
            multivalue=True,
            cli_name='nsec3_rec',
            label=_(u'NSEC3 record'),
            doc=_(u'Comma-separated list of raw NSEC3 records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            multivalue=True,
            cli_name='nsec3param_rec',
            label=_(u'NSEC3PARAM record'),
            doc=_(u'Comma-separated list of raw NSEC3PARAM records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            label=_(u'PTR record'),
            doc=_(u'Comma-separated list of raw PTR records'),
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            label=_(u'RRSIG record'),
            doc=_(u'Comma-separated list of raw RRSIG records'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            label=_(u'RP record'),
            doc=_(u'Comma-separated list of raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            label=_(u'SIG record'),
            doc=_(u'Comma-separated list of raw SIG records'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            label=_(u'SPF record'),
            doc=_(u'Comma-separated list of raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            label=_(u'SRV record'),
            doc=_(u'Comma-separated list of raw SRV records'),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            label=_(u'SSHFP record'),
            doc=_(u'Comma-separated list of raw SSHFP records'),
        ),
        parameters.Str(
            'tarecord',
            required=False,
            multivalue=True,
            cli_name='ta_rec',
            label=_(u'TA record'),
            doc=_(u'Comma-separated list of raw TA records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tkeyrecord',
            required=False,
            multivalue=True,
            cli_name='tkey_rec',
            label=_(u'TKEY record'),
            doc=_(u'Comma-separated list of raw TKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tsigrecord',
            required=False,
            multivalue=True,
            cli_name='tsig_rec',
            label=_(u'TSIG record'),
            doc=_(u'Comma-separated list of raw TSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            label=_(u'TXT record'),
            doc=_(u'Comma-separated list of raw TXT records'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned'),
        ),
        parameters.Flag(
            'structured',
            label=_(u'Structured'),
            doc=_(u'Parse all raw DNS records and return them in a structured way'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class dnsrecord_mod(Method):
    __doc__ = _("Modify a DNS resource record.")

    takes_args = (
        parameters.Str(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_(u'Zone name'),
        ),
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Record name'),
        ),
    )
    takes_options = (
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'Time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'Class'),
            doc=_(u'DNS class'),
        ),
        parameters.Str(
            'arecord',
            required=False,
            multivalue=True,
            cli_name='a_rec',
            option_group=u'A Record',
            label=_(u'A record'),
            doc=_(u'Comma-separated list of raw A records'),
        ),
        parameters.Str(
            'a_part_ip_address',
            required=False,
            cli_name='a_ip_address',
            option_group=u'A Record',
            label=_(u'A IP Address'),
            doc=_(u'IP Address'),
        ),
        parameters.Str(
            'aaaarecord',
            required=False,
            multivalue=True,
            cli_name='aaaa_rec',
            option_group=u'AAAA Record',
            label=_(u'AAAA record'),
            doc=_(u'Comma-separated list of raw AAAA records'),
        ),
        parameters.Str(
            'aaaa_part_ip_address',
            required=False,
            cli_name='aaaa_ip_address',
            option_group=u'AAAA Record',
            label=_(u'AAAA IP Address'),
            doc=_(u'IP Address'),
        ),
        parameters.Str(
            'a6record',
            required=False,
            multivalue=True,
            cli_name='a6_rec',
            option_group=u'A6 Record',
            label=_(u'A6 record'),
            doc=_(u'Comma-separated list of raw A6 records'),
        ),
        parameters.Str(
            'a6_part_data',
            required=False,
            cli_name='a6_data',
            option_group=u'A6 Record',
            label=_(u'A6 Record data'),
            doc=_(u'Record data'),
        ),
        parameters.Str(
            'afsdbrecord',
            required=False,
            multivalue=True,
            cli_name='afsdb_rec',
            option_group=u'AFSDB Record',
            label=_(u'AFSDB record'),
            doc=_(u'Comma-separated list of raw AFSDB records'),
        ),
        parameters.Int(
            'afsdb_part_subtype',
            required=False,
            cli_name='afsdb_subtype',
            option_group=u'AFSDB Record',
            label=_(u'AFSDB Subtype'),
            doc=_(u'Subtype'),
        ),
        parameters.Str(
            'afsdb_part_hostname',
            required=False,
            cli_name='afsdb_hostname',
            option_group=u'AFSDB Record',
            label=_(u'AFSDB Hostname'),
            doc=_(u'Hostname'),
        ),
        parameters.Str(
            'aplrecord',
            required=False,
            multivalue=True,
            cli_name='apl_rec',
            option_group=u'APL Record',
            label=_(u'APL record'),
            doc=_(u'Comma-separated list of raw APL records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'certrecord',
            required=False,
            multivalue=True,
            cli_name='cert_rec',
            option_group=u'CERT Record',
            label=_(u'CERT record'),
            doc=_(u'Comma-separated list of raw CERT records'),
        ),
        parameters.Int(
            'cert_part_type',
            required=False,
            cli_name='cert_type',
            option_group=u'CERT Record',
            label=_(u'CERT Certificate Type'),
            doc=_(u'Certificate Type'),
        ),
        parameters.Int(
            'cert_part_key_tag',
            required=False,
            cli_name='cert_key_tag',
            option_group=u'CERT Record',
            label=_(u'CERT Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Int(
            'cert_part_algorithm',
            required=False,
            cli_name='cert_algorithm',
            option_group=u'CERT Record',
            label=_(u'CERT Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Str(
            'cert_part_certificate_or_crl',
            required=False,
            cli_name='cert_certificate_or_crl',
            option_group=u'CERT Record',
            label=_(u'CERT Certificate/CRL'),
            doc=_(u'Certificate/CRL'),
        ),
        parameters.Str(
            'cnamerecord',
            required=False,
            multivalue=True,
            cli_name='cname_rec',
            option_group=u'CNAME Record',
            label=_(u'CNAME record'),
            doc=_(u'Comma-separated list of raw CNAME records'),
        ),
        parameters.Str(
            'cname_part_hostname',
            required=False,
            cli_name='cname_hostname',
            option_group=u'CNAME Record',
            label=_(u'CNAME Hostname'),
            doc=_(u'A hostname which this alias hostname points to'),
        ),
        parameters.Str(
            'dhcidrecord',
            required=False,
            multivalue=True,
            cli_name='dhcid_rec',
            option_group=u'DHCID Record',
            label=_(u'DHCID record'),
            doc=_(u'Comma-separated list of raw DHCID records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dlvrecord',
            required=False,
            multivalue=True,
            cli_name='dlv_rec',
            option_group=u'DLV Record',
            label=_(u'DLV record'),
            doc=_(u'Comma-separated list of raw DLV records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dnamerecord',
            required=False,
            multivalue=True,
            cli_name='dname_rec',
            option_group=u'DNAME Record',
            label=_(u'DNAME record'),
            doc=_(u'Comma-separated list of raw DNAME records'),
        ),
        parameters.Str(
            'dname_part_target',
            required=False,
            cli_name='dname_target',
            option_group=u'DNAME Record',
            label=_(u'DNAME Target'),
            doc=_(u'Target'),
        ),
        parameters.Str(
            'dnskeyrecord',
            required=False,
            multivalue=True,
            cli_name='dnskey_rec',
            option_group=u'DNSKEY Record',
            label=_(u'DNSKEY record'),
            doc=_(u'Comma-separated list of raw DNSKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'dsrecord',
            required=False,
            multivalue=True,
            cli_name='ds_rec',
            option_group=u'DS Record',
            label=_(u'DS record'),
            doc=_(u'Comma-separated list of raw DS records'),
        ),
        parameters.Int(
            'ds_part_key_tag',
            required=False,
            cli_name='ds_key_tag',
            option_group=u'DS Record',
            label=_(u'DS Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Int(
            'ds_part_algorithm',
            required=False,
            cli_name='ds_algorithm',
            option_group=u'DS Record',
            label=_(u'DS Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'ds_part_digest_type',
            required=False,
            cli_name='ds_digest_type',
            option_group=u'DS Record',
            label=_(u'DS Digest Type'),
            doc=_(u'Digest Type'),
        ),
        parameters.Str(
            'ds_part_digest',
            required=False,
            cli_name='ds_digest',
            option_group=u'DS Record',
            label=_(u'DS Digest'),
            doc=_(u'Digest'),
        ),
        parameters.Str(
            'hiprecord',
            required=False,
            multivalue=True,
            cli_name='hip_rec',
            option_group=u'HIP Record',
            label=_(u'HIP record'),
            doc=_(u'Comma-separated list of raw HIP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ipseckeyrecord',
            required=False,
            multivalue=True,
            cli_name='ipseckey_rec',
            option_group=u'IPSECKEY Record',
            label=_(u'IPSECKEY record'),
            doc=_(u'Comma-separated list of raw IPSECKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'keyrecord',
            required=False,
            multivalue=True,
            cli_name='key_rec',
            option_group=u'KEY Record',
            label=_(u'KEY record'),
            doc=_(u'Comma-separated list of raw KEY records'),
        ),
        parameters.Int(
            'key_part_flags',
            required=False,
            cli_name='key_flags',
            option_group=u'KEY Record',
            label=_(u'KEY Flags'),
            doc=_(u'Flags'),
        ),
        parameters.Int(
            'key_part_protocol',
            required=False,
            cli_name='key_protocol',
            option_group=u'KEY Record',
            label=_(u'KEY Protocol'),
            doc=_(u'Protocol'),
        ),
        parameters.Int(
            'key_part_algorithm',
            required=False,
            cli_name='key_algorithm',
            option_group=u'KEY Record',
            label=_(u'KEY Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Str(
            'key_part_public_key',
            required=False,
            cli_name='key_public_key',
            option_group=u'KEY Record',
            label=_(u'KEY Public Key'),
            doc=_(u'Public Key'),
        ),
        parameters.Str(
            'kxrecord',
            required=False,
            multivalue=True,
            cli_name='kx_rec',
            option_group=u'KX Record',
            label=_(u'KX record'),
            doc=_(u'Comma-separated list of raw KX records'),
        ),
        parameters.Int(
            'kx_part_preference',
            required=False,
            cli_name='kx_preference',
            option_group=u'KX Record',
            label=_(u'KX Preference'),
            doc=_(u'Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.Str(
            'kx_part_exchanger',
            required=False,
            cli_name='kx_exchanger',
            option_group=u'KX Record',
            label=_(u'KX Exchanger'),
            doc=_(u'A host willing to act as a key exchanger'),
        ),
        parameters.Str(
            'locrecord',
            required=False,
            multivalue=True,
            cli_name='loc_rec',
            option_group=u'LOC Record',
            label=_(u'LOC record'),
            doc=_(u'Comma-separated list of raw LOC records'),
        ),
        parameters.Int(
            'loc_part_lat_deg',
            required=False,
            cli_name='loc_lat_deg',
            option_group=u'LOC Record',
            label=_(u'LOC Degrees Latitude'),
            doc=_(u'Degrees Latitude'),
        ),
        parameters.Int(
            'loc_part_lat_min',
            required=False,
            cli_name='loc_lat_min',
            option_group=u'LOC Record',
            label=_(u'LOC Minutes Latitude'),
            doc=_(u'Minutes Latitude'),
        ),
        parameters.Decimal(
            'loc_part_lat_sec',
            required=False,
            cli_name='loc_lat_sec',
            option_group=u'LOC Record',
            label=_(u'LOC Seconds Latitude'),
            doc=_(u'Seconds Latitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lat_dir',
            required=False,
            cli_name='loc_lat_dir',
            option_group=u'LOC Record',
            cli_metavar="['N', 'S']",
            label=_(u'LOC Direction Latitude'),
            doc=_(u'Direction Latitude'),
        ),
        parameters.Int(
            'loc_part_lon_deg',
            required=False,
            cli_name='loc_lon_deg',
            option_group=u'LOC Record',
            label=_(u'LOC Degrees Longitude'),
            doc=_(u'Degrees Longitude'),
        ),
        parameters.Int(
            'loc_part_lon_min',
            required=False,
            cli_name='loc_lon_min',
            option_group=u'LOC Record',
            label=_(u'LOC Minutes Longitude'),
            doc=_(u'Minutes Longitude'),
        ),
        parameters.Decimal(
            'loc_part_lon_sec',
            required=False,
            cli_name='loc_lon_sec',
            option_group=u'LOC Record',
            label=_(u'LOC Seconds Longitude'),
            doc=_(u'Seconds Longitude'),
            no_convert=True,
        ),
        parameters.Str(
            'loc_part_lon_dir',
            required=False,
            cli_name='loc_lon_dir',
            option_group=u'LOC Record',
            cli_metavar="['E', 'W']",
            label=_(u'LOC Direction Longitude'),
            doc=_(u'Direction Longitude'),
        ),
        parameters.Decimal(
            'loc_part_altitude',
            required=False,
            cli_name='loc_altitude',
            option_group=u'LOC Record',
            label=_(u'LOC Altitude'),
            doc=_(u'Altitude'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_size',
            required=False,
            cli_name='loc_size',
            option_group=u'LOC Record',
            label=_(u'LOC Size'),
            doc=_(u'Size'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_h_precision',
            required=False,
            cli_name='loc_h_precision',
            option_group=u'LOC Record',
            label=_(u'LOC Horizontal Precision'),
            doc=_(u'Horizontal Precision'),
            no_convert=True,
        ),
        parameters.Decimal(
            'loc_part_v_precision',
            required=False,
            cli_name='loc_v_precision',
            option_group=u'LOC Record',
            label=_(u'LOC Vertical Precision'),
            doc=_(u'Vertical Precision'),
            no_convert=True,
        ),
        parameters.Str(
            'mxrecord',
            required=False,
            multivalue=True,
            cli_name='mx_rec',
            option_group=u'MX Record',
            label=_(u'MX record'),
            doc=_(u'Comma-separated list of raw MX records'),
        ),
        parameters.Int(
            'mx_part_preference',
            required=False,
            cli_name='mx_preference',
            option_group=u'MX Record',
            label=_(u'MX Preference'),
            doc=_(u'Preference given to this exchanger. Lower values are more preferred'),
        ),
        parameters.Str(
            'mx_part_exchanger',
            required=False,
            cli_name='mx_exchanger',
            option_group=u'MX Record',
            label=_(u'MX Exchanger'),
            doc=_(u'A host willing to act as a mail exchanger'),
        ),
        parameters.Str(
            'naptrrecord',
            required=False,
            multivalue=True,
            cli_name='naptr_rec',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR record'),
            doc=_(u'Comma-separated list of raw NAPTR records'),
        ),
        parameters.Int(
            'naptr_part_order',
            required=False,
            cli_name='naptr_order',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Order'),
            doc=_(u'Order'),
        ),
        parameters.Int(
            'naptr_part_preference',
            required=False,
            cli_name='naptr_preference',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Preference'),
            doc=_(u'Preference'),
        ),
        parameters.Str(
            'naptr_part_flags',
            required=False,
            cli_name='naptr_flags',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Flags'),
            doc=_(u'Flags'),
            no_convert=True,
        ),
        parameters.Str(
            'naptr_part_service',
            required=False,
            cli_name='naptr_service',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Service'),
            doc=_(u'Service'),
        ),
        parameters.Str(
            'naptr_part_regexp',
            required=False,
            cli_name='naptr_regexp',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Regular Expression'),
            doc=_(u'Regular Expression'),
        ),
        parameters.Str(
            'naptr_part_replacement',
            required=False,
            cli_name='naptr_replacement',
            option_group=u'NAPTR Record',
            label=_(u'NAPTR Replacement'),
            doc=_(u'Replacement'),
        ),
        parameters.Str(
            'nsrecord',
            required=False,
            multivalue=True,
            cli_name='ns_rec',
            option_group=u'NS Record',
            label=_(u'NS record'),
            doc=_(u'Comma-separated list of raw NS records'),
        ),
        parameters.Str(
            'ns_part_hostname',
            required=False,
            cli_name='ns_hostname',
            option_group=u'NS Record',
            label=_(u'NS Hostname'),
            doc=_(u'Hostname'),
        ),
        parameters.Str(
            'nsecrecord',
            required=False,
            multivalue=True,
            cli_name='nsec_rec',
            option_group=u'NSEC Record',
            label=_(u'NSEC record'),
            doc=_(u'Comma-separated list of raw NSEC records'),
        ),
        parameters.Str(
            'nsec_part_next',
            required=False,
            cli_name='nsec_next',
            option_group=u'NSEC Record',
            label=_(u'NSEC Next Domain Name'),
            doc=_(u'Next Domain Name'),
        ),
        parameters.Str(
            'nsec_part_types',
            required=False,
            multivalue=True,
            cli_name='nsec_types',
            option_group=u'NSEC Record',
            cli_metavar="['SOA', 'A', 'AAAA', 'A6', 'AFSDB', 'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SIG', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']",
            label=_(u'NSEC Type Map'),
            doc=_(u'Type Map'),
        ),
        parameters.Str(
            'nsec3record',
            required=False,
            multivalue=True,
            cli_name='nsec3_rec',
            option_group=u'NSEC3 Record',
            label=_(u'NSEC3 record'),
            doc=_(u'Comma-separated list of raw NSEC3 records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'nsec3paramrecord',
            required=False,
            multivalue=True,
            cli_name='nsec3param_rec',
            option_group=u'NSEC3PARAM Record',
            label=_(u'NSEC3PARAM record'),
            doc=_(u'Comma-separated list of raw NSEC3PARAM records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'ptrrecord',
            required=False,
            multivalue=True,
            cli_name='ptr_rec',
            option_group=u'PTR Record',
            label=_(u'PTR record'),
            doc=_(u'Comma-separated list of raw PTR records'),
        ),
        parameters.Str(
            'ptr_part_hostname',
            required=False,
            cli_name='ptr_hostname',
            option_group=u'PTR Record',
            label=_(u'PTR Hostname'),
            doc=_(u'The hostname this reverse record points to'),
            no_convert=True,
        ),
        parameters.Str(
            'rrsigrecord',
            required=False,
            multivalue=True,
            cli_name='rrsig_rec',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG record'),
            doc=_(u'Comma-separated list of raw RRSIG records'),
        ),
        parameters.Str(
            'rrsig_part_type_covered',
            required=False,
            cli_name='rrsig_type_covered',
            option_group=u'RRSIG Record',
            cli_metavar="['SOA', 'A', 'AAAA', 'A6', 'AFSDB', 'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']",
            label=_(u'RRSIG Type Covered'),
            doc=_(u'Type Covered'),
        ),
        parameters.Int(
            'rrsig_part_algorithm',
            required=False,
            cli_name='rrsig_algorithm',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'rrsig_part_labels',
            required=False,
            cli_name='rrsig_labels',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Labels'),
            doc=_(u'Labels'),
        ),
        parameters.Int(
            'rrsig_part_original_ttl',
            required=False,
            cli_name='rrsig_original_ttl',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Original TTL'),
            doc=_(u'Original TTL'),
        ),
        parameters.Str(
            'rrsig_part_signature_expiration',
            required=False,
            cli_name='rrsig_signature_expiration',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Signature Expiration'),
            doc=_(u'Signature Expiration'),
        ),
        parameters.Str(
            'rrsig_part_signature_inception',
            required=False,
            cli_name='rrsig_signature_inception',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Signature Inception'),
            doc=_(u'Signature Inception'),
        ),
        parameters.Int(
            'rrsig_part_key_tag',
            required=False,
            cli_name='rrsig_key_tag',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Str(
            'rrsig_part_signers_name',
            required=False,
            cli_name='rrsig_signers_name',
            option_group=u'RRSIG Record',
            label=_(u"RRSIG Signer's Name"),
            doc=_(u"Signer's Name"),
        ),
        parameters.Str(
            'rrsig_part_signature',
            required=False,
            cli_name='rrsig_signature',
            option_group=u'RRSIG Record',
            label=_(u'RRSIG Signature'),
            doc=_(u'Signature'),
        ),
        parameters.Str(
            'rprecord',
            required=False,
            multivalue=True,
            cli_name='rp_rec',
            option_group=u'RP Record',
            label=_(u'RP record'),
            doc=_(u'Comma-separated list of raw RP records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'sigrecord',
            required=False,
            multivalue=True,
            cli_name='sig_rec',
            option_group=u'SIG Record',
            label=_(u'SIG record'),
            doc=_(u'Comma-separated list of raw SIG records'),
        ),
        parameters.Str(
            'sig_part_type_covered',
            required=False,
            cli_name='sig_type_covered',
            option_group=u'SIG Record',
            cli_metavar="['SOA', 'A', 'AAAA', 'A6', 'AFSDB', 'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']",
            label=_(u'SIG Type Covered'),
            doc=_(u'Type Covered'),
        ),
        parameters.Int(
            'sig_part_algorithm',
            required=False,
            cli_name='sig_algorithm',
            option_group=u'SIG Record',
            label=_(u'SIG Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'sig_part_labels',
            required=False,
            cli_name='sig_labels',
            option_group=u'SIG Record',
            label=_(u'SIG Labels'),
            doc=_(u'Labels'),
        ),
        parameters.Int(
            'sig_part_original_ttl',
            required=False,
            cli_name='sig_original_ttl',
            option_group=u'SIG Record',
            label=_(u'SIG Original TTL'),
            doc=_(u'Original TTL'),
        ),
        parameters.Str(
            'sig_part_signature_expiration',
            required=False,
            cli_name='sig_signature_expiration',
            option_group=u'SIG Record',
            label=_(u'SIG Signature Expiration'),
            doc=_(u'Signature Expiration'),
        ),
        parameters.Str(
            'sig_part_signature_inception',
            required=False,
            cli_name='sig_signature_inception',
            option_group=u'SIG Record',
            label=_(u'SIG Signature Inception'),
            doc=_(u'Signature Inception'),
        ),
        parameters.Int(
            'sig_part_key_tag',
            required=False,
            cli_name='sig_key_tag',
            option_group=u'SIG Record',
            label=_(u'SIG Key Tag'),
            doc=_(u'Key Tag'),
        ),
        parameters.Str(
            'sig_part_signers_name',
            required=False,
            cli_name='sig_signers_name',
            option_group=u'SIG Record',
            label=_(u"SIG Signer's Name"),
            doc=_(u"Signer's Name"),
        ),
        parameters.Str(
            'sig_part_signature',
            required=False,
            cli_name='sig_signature',
            option_group=u'SIG Record',
            label=_(u'SIG Signature'),
            doc=_(u'Signature'),
        ),
        parameters.Str(
            'spfrecord',
            required=False,
            multivalue=True,
            cli_name='spf_rec',
            option_group=u'SPF Record',
            label=_(u'SPF record'),
            doc=_(u'Comma-separated list of raw SPF records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'srvrecord',
            required=False,
            multivalue=True,
            cli_name='srv_rec',
            option_group=u'SRV Record',
            label=_(u'SRV record'),
            doc=_(u'Comma-separated list of raw SRV records'),
        ),
        parameters.Int(
            'srv_part_priority',
            required=False,
            cli_name='srv_priority',
            option_group=u'SRV Record',
            label=_(u'SRV Priority'),
            doc=_(u'Priority'),
        ),
        parameters.Int(
            'srv_part_weight',
            required=False,
            cli_name='srv_weight',
            option_group=u'SRV Record',
            label=_(u'SRV Weight'),
            doc=_(u'Weight'),
        ),
        parameters.Int(
            'srv_part_port',
            required=False,
            cli_name='srv_port',
            option_group=u'SRV Record',
            label=_(u'SRV Port'),
            doc=_(u'Port'),
        ),
        parameters.Str(
            'srv_part_target',
            required=False,
            cli_name='srv_target',
            option_group=u'SRV Record',
            label=_(u'SRV Target'),
            doc=_(u"The domain name of the target host or '.' if the service is decidedly not available at this domain"),
        ),
        parameters.Str(
            'sshfprecord',
            required=False,
            multivalue=True,
            cli_name='sshfp_rec',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP record'),
            doc=_(u'Comma-separated list of raw SSHFP records'),
        ),
        parameters.Int(
            'sshfp_part_algorithm',
            required=False,
            cli_name='sshfp_algorithm',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP Algorithm'),
            doc=_(u'Algorithm'),
        ),
        parameters.Int(
            'sshfp_part_fp_type',
            required=False,
            cli_name='sshfp_fp_type',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP Fingerprint Type'),
            doc=_(u'Fingerprint Type'),
        ),
        parameters.Str(
            'sshfp_part_fingerprint',
            required=False,
            cli_name='sshfp_fingerprint',
            option_group=u'SSHFP Record',
            label=_(u'SSHFP Fingerprint'),
            doc=_(u'Fingerprint'),
        ),
        parameters.Str(
            'tarecord',
            required=False,
            multivalue=True,
            cli_name='ta_rec',
            option_group=u'TA Record',
            label=_(u'TA record'),
            doc=_(u'Comma-separated list of raw TA records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tkeyrecord',
            required=False,
            multivalue=True,
            cli_name='tkey_rec',
            option_group=u'TKEY Record',
            label=_(u'TKEY record'),
            doc=_(u'Comma-separated list of raw TKEY records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'tsigrecord',
            required=False,
            multivalue=True,
            cli_name='tsig_rec',
            option_group=u'TSIG Record',
            label=_(u'TSIG record'),
            doc=_(u'Comma-separated list of raw TSIG records'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'txtrecord',
            required=False,
            multivalue=True,
            cli_name='txt_rec',
            option_group=u'TXT Record',
            label=_(u'TXT record'),
            doc=_(u'Comma-separated list of raw TXT records'),
        ),
        parameters.Str(
            'txt_part_data',
            required=False,
            cli_name='txt_data',
            option_group=u'TXT Record',
            label=_(u'TXT Text Data'),
            doc=_(u'Text Data'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_(u'Structured'),
            doc=_(u'Parse all raw DNS records and return them in a structured way'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'rename',
            required=False,
            label=_(u'Rename'),
            doc=_(u'Rename the DNS resource record object'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnsrecord_show(Method):
    __doc__ = _("Display DNS resource.")

    takes_args = (
        parameters.Str(
            'dnszoneidnsname',
            cli_name='dnszone',
            label=_(u'Zone name'),
        ),
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Record name'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'structured',
            label=_(u'Structured'),
            doc=_(u'Parse all raw DNS records and return them in a structured way'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_add(Method):
    __doc__ = _("Create new DNS zone (SOA record).")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
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
            label=_(u'Reverse zone IP network'),
            doc=_(u'IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnssoamname',
            cli_name='name_server',
            label=_(u'Authoritative nameserver'),
            doc=_(u'Authoritative nameserver domain name'),
            no_convert=True,
        ),
        parameters.Str(
            'idnssoarname',
            cli_name='admin_email',
            label=_(u'Administrator e-mail address'),
            default_from=DefaultFrom(lambda idnsname: 'hostmaster.%s' % idnsname, 'name_from_ip'),
            no_convert=True,
        ),
        parameters.Int(
            'idnssoaserial',
            cli_name='serial',
            label=_(u'SOA serial'),
            doc=_(u'SOA record serial number'),
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
            label=_(u'SOA refresh'),
            doc=_(u'SOA record refresh time'),
            default=3600,
            autofill=True,
        ),
        parameters.Int(
            'idnssoaretry',
            cli_name='retry',
            label=_(u'SOA retry'),
            doc=_(u'SOA record retry time'),
            default=900,
            autofill=True,
        ),
        parameters.Int(
            'idnssoaexpire',
            cli_name='expire',
            label=_(u'SOA expire'),
            doc=_(u'SOA record expire time'),
            default=1209600,
            autofill=True,
        ),
        parameters.Int(
            'idnssoaminimum',
            cli_name='minimum',
            label=_(u'SOA minimum'),
            doc=_(u'How long should negative responses be cached'),
            default=3600,
            autofill=True,
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'SOA time to live'),
            doc=_(u'SOA record time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'SOA class'),
            doc=_(u'SOA record class'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            cli_name='update_policy',
            label=_(u'BIND update policy'),
            default_from=DefaultFrom(lambda idnsname: None, 'idnsname'),
            # FIXME:
            # lambda idnsname: default_zone_update_policy(idnsname)
            autofill=True,
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            cli_name='dynamic_update',
            label=_(u'Dynamic update'),
            doc=_(u'Allow dynamic updates.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            cli_name='allow_query',
            label=_(u'Allow query'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default=u'any;',
            autofill=True,
            no_convert=True,
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            cli_name='allow_transfer',
            label=_(u'Allow transfer'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default=u'none;',
            autofill=True,
            no_convert=True,
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_(u'Zone forwarders'),
            doc=_(u'A list of per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_(u'Forward policy'),
            doc=_(u'Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_(u'Allow PTR sync'),
            doc=_(u'Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'force',
            label=_(u'Force'),
            doc=_(u'Force DNS zone creation even if nameserver is not resolvable.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'ip_address',
            required=False,
            doc=_(u'Add forward record for nameserver located in the created zone'),
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_add_permission(Method):
    __doc__ = _("Add a permission for per-zone access delegation.")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_del(Method):
    __doc__ = _("Delete DNS zone (SOA record).")

    takes_args = (
        parameters.Str(
            'idnsname',
            multivalue=True,
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_disable(Method):
    __doc__ = _("Disable DNS Zone.")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_enable(Method):
    __doc__ = _("Enable DNS Zone.")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_find(Method):
    __doc__ = _("Search for DNS zones (SOA records).")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'idnsname',
            required=False,
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
        parameters.Str(
            'name_from_ip',
            required=False,
            label=_(u'Reverse zone IP network'),
            doc=_(u'IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnssoamname',
            required=False,
            cli_name='name_server',
            label=_(u'Authoritative nameserver'),
            doc=_(u'Authoritative nameserver domain name'),
            no_convert=True,
        ),
        parameters.Str(
            'idnssoarname',
            required=False,
            cli_name='admin_email',
            label=_(u'Administrator e-mail address'),
            default_from=DefaultFrom(lambda idnsname: 'hostmaster.%s' % idnsname, 'name_from_ip'),
            no_convert=True,
        ),
        parameters.Int(
            'idnssoaserial',
            required=False,
            cli_name='serial',
            label=_(u'SOA serial'),
            doc=_(u'SOA record serial number'),
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
            label=_(u'SOA refresh'),
            doc=_(u'SOA record refresh time'),
            default=3600,
        ),
        parameters.Int(
            'idnssoaretry',
            required=False,
            cli_name='retry',
            label=_(u'SOA retry'),
            doc=_(u'SOA record retry time'),
            default=900,
        ),
        parameters.Int(
            'idnssoaexpire',
            required=False,
            cli_name='expire',
            label=_(u'SOA expire'),
            doc=_(u'SOA record expire time'),
            default=1209600,
        ),
        parameters.Int(
            'idnssoaminimum',
            required=False,
            cli_name='minimum',
            label=_(u'SOA minimum'),
            doc=_(u'How long should negative responses be cached'),
            default=3600,
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'SOA time to live'),
            doc=_(u'SOA record time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'SOA class'),
            doc=_(u'SOA record class'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            cli_name='update_policy',
            label=_(u'BIND update policy'),
            default_from=DefaultFrom(lambda idnsname: None, 'idnsname'),
            # FIXME:
            # lambda idnsname: default_zone_update_policy(idnsname)
        ),
        parameters.Bool(
            'idnszoneactive',
            required=False,
            cli_name='zone_active',
            label=_(u'Active zone'),
            doc=_(u'Is zone active?'),
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            cli_name='dynamic_update',
            label=_(u'Dynamic update'),
            doc=_(u'Allow dynamic updates.'),
            default=False,
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            cli_name='allow_query',
            label=_(u'Allow query'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default=u'any;',
            no_convert=True,
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            cli_name='allow_transfer',
            label=_(u'Allow transfer'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default=u'none;',
            no_convert=True,
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_(u'Zone forwarders'),
            doc=_(u'A list of per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_(u'Forward policy'),
            doc=_(u'Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_(u'Allow PTR sync'),
            doc=_(u'Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned'),
        ),
        parameters.Flag(
            'forward_only',
            label=_(u'Forward zones only'),
            doc=_(u'Search for forward zones only'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("name")'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class dnszone_mod(Method):
    __doc__ = _("Modify DNS zone (SOA record).")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
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
            label=_(u'Reverse zone IP network'),
            doc=_(u'IP network to create reverse zone name from'),
        ),
        parameters.Str(
            'idnssoamname',
            required=False,
            cli_name='name_server',
            label=_(u'Authoritative nameserver'),
            doc=_(u'Authoritative nameserver domain name'),
            no_convert=True,
        ),
        parameters.Str(
            'idnssoarname',
            required=False,
            cli_name='admin_email',
            label=_(u'Administrator e-mail address'),
            default_from=DefaultFrom(lambda idnsname: 'hostmaster.%s' % idnsname, 'name_from_ip'),
            no_convert=True,
        ),
        parameters.Int(
            'idnssoaserial',
            required=False,
            cli_name='serial',
            label=_(u'SOA serial'),
            doc=_(u'SOA record serial number'),
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
            label=_(u'SOA refresh'),
            doc=_(u'SOA record refresh time'),
            default=3600,
        ),
        parameters.Int(
            'idnssoaretry',
            required=False,
            cli_name='retry',
            label=_(u'SOA retry'),
            doc=_(u'SOA record retry time'),
            default=900,
        ),
        parameters.Int(
            'idnssoaexpire',
            required=False,
            cli_name='expire',
            label=_(u'SOA expire'),
            doc=_(u'SOA record expire time'),
            default=1209600,
        ),
        parameters.Int(
            'idnssoaminimum',
            required=False,
            cli_name='minimum',
            label=_(u'SOA minimum'),
            doc=_(u'How long should negative responses be cached'),
            default=3600,
        ),
        parameters.Int(
            'dnsttl',
            required=False,
            cli_name='ttl',
            label=_(u'SOA time to live'),
            doc=_(u'SOA record time to live'),
        ),
        parameters.Str(
            'dnsclass',
            required=False,
            cli_name='class',
            cli_metavar="['IN', 'CS', 'CH', 'HS']",
            label=_(u'SOA class'),
            doc=_(u'SOA record class'),
        ),
        parameters.Str(
            'idnsupdatepolicy',
            required=False,
            cli_name='update_policy',
            label=_(u'BIND update policy'),
            default_from=DefaultFrom(lambda idnsname: None, 'idnsname'),
            # FIXME:
            # lambda idnsname: default_zone_update_policy(idnsname)
        ),
        parameters.Bool(
            'idnsallowdynupdate',
            required=False,
            cli_name='dynamic_update',
            label=_(u'Dynamic update'),
            doc=_(u'Allow dynamic updates.'),
            default=False,
        ),
        parameters.Str(
            'idnsallowquery',
            required=False,
            cli_name='allow_query',
            label=_(u'Allow query'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to issue queries'),
            default=u'any;',
            no_convert=True,
        ),
        parameters.Str(
            'idnsallowtransfer',
            required=False,
            cli_name='allow_transfer',
            label=_(u'Allow transfer'),
            doc=_(u'Semicolon separated list of IP addresses or networks which are allowed to transfer the zone'),
            default=u'none;',
            no_convert=True,
        ),
        parameters.Str(
            'idnsforwarders',
            required=False,
            multivalue=True,
            cli_name='forwarder',
            label=_(u'Zone forwarders'),
            doc=_(u'A list of per-zone forwarders. A custom port can be specified for each forwarder using a standard format "IP_ADDRESS port PORT"'),
        ),
        parameters.Str(
            'idnsforwardpolicy',
            required=False,
            cli_name='forward_policy',
            cli_metavar="['only', 'first', 'none']",
            label=_(u'Forward policy'),
            doc=_(u'Per-zone conditional forwarding policy. Set to "none" to disable forwarding to global forwarder for this zone. In that case, conditional zone forwarders are disregarded.'),
        ),
        parameters.Bool(
            'idnsallowsyncptr',
            required=False,
            cli_name='allow_sync_ptr',
            label=_(u'Allow PTR sync'),
            doc=_(u'Allow synchronization of forward (A, AAAA) and reverse (PTR) records in the zone'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'force',
            label=_(u'Force'),
            doc=_(u'Force nameserver change even if nameserver not in DNS'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_remove_permission(Method):
    __doc__ = _("Remove a permission for per-zone access delegation.")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class dnszone_show(Method):
    __doc__ = _("Display information about a DNS zone (SOA record).")

    takes_args = (
        parameters.Str(
            'idnsname',
            cli_name='name',
            label=_(u'Zone name'),
            doc=_(u'Zone name (FQDN)'),
            default_from=DefaultFrom(lambda name_from_ip: None, 'name_from_ip'),
            # FIXME:
            # lambda name_from_ip: _reverse_zone_name(name_from_ip)
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
