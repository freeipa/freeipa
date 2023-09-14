[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnsrecord_find
Search for DNS resources.

### Arguments
|Name|Type|Required
|-|-|-
|dnszoneidnsname|:ref:`DNSNameParam<DNSNameParam>`|True
|criteria|:ref:`Str<Str>`|False

### Options
* structured : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* idnsname : :ref:`DNSNameParam<DNSNameParam>`
* dnsttl : :ref:`Int<Int>`
* dnsclass : :ref:`StrEnum<StrEnum>`
 * Values: ('IN', 'CS', 'CH', 'HS')
* arecord : :ref:`ARecord<ARecord>`
* aaaarecord : :ref:`AAAARecord<AAAARecord>`
* a6record : :ref:`A6Record<A6Record>`
* afsdbrecord : :ref:`AFSDBRecord<AFSDBRecord>`
* aplrecord : :ref:`APLRecord<APLRecord>`
* certrecord : :ref:`CERTRecord<CERTRecord>`
* cnamerecord : :ref:`CNAMERecord<CNAMERecord>`
* dhcidrecord : :ref:`DHCIDRecord<DHCIDRecord>`
* dlvrecord : :ref:`DLVRecord<DLVRecord>`
* dnamerecord : :ref:`DNAMERecord<DNAMERecord>`
* dsrecord : :ref:`DSRecord<DSRecord>`
* hiprecord : :ref:`HIPRecord<HIPRecord>`
* ipseckeyrecord : :ref:`IPSECKEYRecord<IPSECKEYRecord>`
* keyrecord : :ref:`KEYRecord<KEYRecord>`
* kxrecord : :ref:`KXRecord<KXRecord>`
* locrecord : :ref:`LOCRecord<LOCRecord>`
* mxrecord : :ref:`MXRecord<MXRecord>`
* naptrrecord : :ref:`NAPTRRecord<NAPTRRecord>`
* nsrecord : :ref:`NSRecord<NSRecord>`
* nsecrecord : :ref:`NSECRecord<NSECRecord>`
* ptrrecord : :ref:`PTRRecord<PTRRecord>`
* rrsigrecord : :ref:`RRSIGRecord<RRSIGRecord>`
* rprecord : :ref:`RPRecord<RPRecord>`
* sigrecord : :ref:`SIGRecord<SIGRecord>`
* spfrecord : :ref:`SPFRecord<SPFRecord>`
* srvrecord : :ref:`SRVRecord<SRVRecord>`
* sshfprecord : :ref:`SSHFPRecord<SSHFPRecord>`
* tlsarecord : :ref:`TLSARecord<TLSARecord>`
* txtrecord : :ref:`TXTRecord<TXTRecord>`
* urirecord : :ref:`URIRecord<URIRecord>`
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False

### Output
|Name|Type
|-|-
|count|Output
|result|ListOfEntries
|summary|Output
|truncated|Output

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences