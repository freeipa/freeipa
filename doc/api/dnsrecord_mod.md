[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnsrecord_mod
Modify a DNS resource record.

### Arguments
|Name|Type|Required
|-|-|-
|dnszoneidnsname|:ref:`DNSNameParam<DNSNameParam>`|True
|idnsname|:ref:`DNSNameParam<DNSNameParam>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* structured : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* dnsttl : :ref:`Int<Int>`
* dnsclass : :ref:`StrEnum<StrEnum>`
 * Values: ('IN', 'CS', 'CH', 'HS')
* arecord : :ref:`ARecord<ARecord>`
* a_part_ip_address : :ref:`Str<Str>`
* aaaarecord : :ref:`AAAARecord<AAAARecord>`
* aaaa_part_ip_address : :ref:`Str<Str>`
* a6record : :ref:`A6Record<A6Record>`
* a6_part_data : :ref:`Str<Str>`
* afsdbrecord : :ref:`AFSDBRecord<AFSDBRecord>`
* afsdb_part_subtype : :ref:`Int<Int>`
* afsdb_part_hostname : :ref:`DNSNameParam<DNSNameParam>`
* aplrecord : :ref:`APLRecord<APLRecord>`
* certrecord : :ref:`CERTRecord<CERTRecord>`
* cert_part_type : :ref:`Int<Int>`
* cert_part_key_tag : :ref:`Int<Int>`
* cert_part_algorithm : :ref:`Int<Int>`
* cert_part_certificate_or_crl : :ref:`Str<Str>`
* cnamerecord : :ref:`CNAMERecord<CNAMERecord>`
* cname_part_hostname : :ref:`DNSNameParam<DNSNameParam>`
* dhcidrecord : :ref:`DHCIDRecord<DHCIDRecord>`
* dlvrecord : :ref:`DLVRecord<DLVRecord>`
* dlv_part_key_tag : :ref:`Int<Int>`
* dlv_part_algorithm : :ref:`Int<Int>`
* dlv_part_digest_type : :ref:`Int<Int>`
* dlv_part_digest : :ref:`Str<Str>`
* dnamerecord : :ref:`DNAMERecord<DNAMERecord>`
* dname_part_target : :ref:`DNSNameParam<DNSNameParam>`
* dsrecord : :ref:`DSRecord<DSRecord>`
* ds_part_key_tag : :ref:`Int<Int>`
* ds_part_algorithm : :ref:`Int<Int>`
* ds_part_digest_type : :ref:`Int<Int>`
* ds_part_digest : :ref:`Str<Str>`
* hiprecord : :ref:`HIPRecord<HIPRecord>`
* ipseckeyrecord : :ref:`IPSECKEYRecord<IPSECKEYRecord>`
* keyrecord : :ref:`KEYRecord<KEYRecord>`
* kxrecord : :ref:`KXRecord<KXRecord>`
* kx_part_preference : :ref:`Int<Int>`
* kx_part_exchanger : :ref:`DNSNameParam<DNSNameParam>`
* locrecord : :ref:`LOCRecord<LOCRecord>`
* loc_part_lat_deg : :ref:`Int<Int>`
* loc_part_lat_min : :ref:`Int<Int>`
* loc_part_lat_sec : :ref:`Decimal<Decimal>`
* loc_part_lat_dir : :ref:`StrEnum<StrEnum>`
 * Values: ('N', 'S')
* loc_part_lon_deg : :ref:`Int<Int>`
* loc_part_lon_min : :ref:`Int<Int>`
* loc_part_lon_sec : :ref:`Decimal<Decimal>`
* loc_part_lon_dir : :ref:`StrEnum<StrEnum>`
 * Values: ('E', 'W')
* loc_part_altitude : :ref:`Decimal<Decimal>`
* loc_part_size : :ref:`Decimal<Decimal>`
* loc_part_h_precision : :ref:`Decimal<Decimal>`
* loc_part_v_precision : :ref:`Decimal<Decimal>`
* mxrecord : :ref:`MXRecord<MXRecord>`
* mx_part_preference : :ref:`Int<Int>`
* mx_part_exchanger : :ref:`DNSNameParam<DNSNameParam>`
* naptrrecord : :ref:`NAPTRRecord<NAPTRRecord>`
* naptr_part_order : :ref:`Int<Int>`
* naptr_part_preference : :ref:`Int<Int>`
* naptr_part_flags : :ref:`Str<Str>`
* naptr_part_service : :ref:`Str<Str>`
* naptr_part_regexp : :ref:`Str<Str>`
* naptr_part_replacement : :ref:`Str<Str>`
* nsrecord : :ref:`NSRecord<NSRecord>`
* ns_part_hostname : :ref:`DNSNameParam<DNSNameParam>`
* nsecrecord : :ref:`NSECRecord<NSECRecord>`
* ptrrecord : :ref:`PTRRecord<PTRRecord>`
* ptr_part_hostname : :ref:`DNSNameParam<DNSNameParam>`
* rrsigrecord : :ref:`RRSIGRecord<RRSIGRecord>`
* rprecord : :ref:`RPRecord<RPRecord>`
* sigrecord : :ref:`SIGRecord<SIGRecord>`
* spfrecord : :ref:`SPFRecord<SPFRecord>`
* srvrecord : :ref:`SRVRecord<SRVRecord>`
* srv_part_priority : :ref:`Int<Int>`
* srv_part_weight : :ref:`Int<Int>`
* srv_part_port : :ref:`Int<Int>`
* srv_part_target : :ref:`DNSNameParam<DNSNameParam>`
* sshfprecord : :ref:`SSHFPRecord<SSHFPRecord>`
* sshfp_part_algorithm : :ref:`Int<Int>`
* sshfp_part_fp_type : :ref:`Int<Int>`
* sshfp_part_fingerprint : :ref:`Str<Str>`
* tlsarecord : :ref:`TLSARecord<TLSARecord>`
* tlsa_part_cert_usage : :ref:`Int<Int>`
* tlsa_part_selector : :ref:`Int<Int>`
* tlsa_part_matching_type : :ref:`Int<Int>`
* tlsa_part_cert_association_data : :ref:`Str<Str>`
* txtrecord : :ref:`TXTRecord<TXTRecord>`
* txt_part_data : :ref:`Str<Str>`
* urirecord : :ref:`URIRecord<URIRecord>`
* uri_part_priority : :ref:`Int<Int>`
* uri_part_weight : :ref:`Int<Int>`
* uri_part_target : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* version : :ref:`Str<Str>`
* rename : :ref:`DNSNameParam<DNSNameParam>`

### Output
|Name|Type
|-|-
|result|Entry
|summary|Output
|value|PrimaryKey

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences