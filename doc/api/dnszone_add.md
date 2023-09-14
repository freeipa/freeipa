[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnszone_add
Create new DNS zone (SOA record).

### Arguments
|Name|Type|Required
|-|-|-
|idnsname|:ref:`DNSNameParam<DNSNameParam>`|True

### Options
* idnssoarname : :ref:`DNSNameParam<DNSNameParam>` **(Required)**
 * Default: hostmaster
* idnssoarefresh : :ref:`Int<Int>` **(Required)**
 * Default: 3600
* idnssoaretry : :ref:`Int<Int>` **(Required)**
 * Default: 900
* idnssoaexpire : :ref:`Int<Int>` **(Required)**
 * Default: 1209600
* idnssoaminimum : :ref:`Int<Int>` **(Required)**
 * Default: 3600
* skip_overlap_check : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* force : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* skip_nameserver_check : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* name_from_ip : :ref:`Str<Str>`
* idnsforwarders : :ref:`Str<Str>`
* idnsforwardpolicy : :ref:`StrEnum<StrEnum>`
 * Values: ('only', 'first', 'none')
* idnssoamname : :ref:`DNSNameParam<DNSNameParam>`
* idnssoaserial : :ref:`Int<Int>`
* dnsttl : :ref:`Int<Int>`
* dnsdefaultttl : :ref:`Int<Int>`
* dnsclass : :ref:`StrEnum<StrEnum>`
 * Values: ('IN', 'CS', 'CH', 'HS')
* idnsupdatepolicy : :ref:`Str<Str>`
* idnsallowdynupdate : :ref:`Bool<Bool>`
 * Default: False
* idnsallowquery : :ref:`Str<Str>`
 * Default: any;
* idnsallowtransfer : :ref:`Str<Str>`
 * Default: none;
* idnsallowsyncptr : :ref:`Bool<Bool>`
* idnssecinlinesigning : :ref:`Bool<Bool>`
 * Default: False
* nsec3paramrecord : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* ip_address : :ref:`Str<Str>`
* version : :ref:`Str<Str>`

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