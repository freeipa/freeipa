[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnsrecord_del
Delete DNS resource record.

### Arguments
|Name|Type|Required
|-|-|-
|dnszoneidnsname|:ref:`DNSNameParam<DNSNameParam>`|True
|idnsname|:ref:`DNSNameParam<DNSNameParam>`|True

### Options
* del_all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* structured : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
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
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|result|Output
|summary|Output
|value|ListOfPrimaryKeys

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences