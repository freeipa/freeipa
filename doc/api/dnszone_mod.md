[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnszone_mod
Modify DNS zone (SOA record).

### Arguments
|Name|Type|Required
|-|-|-
|idnsname|:ref:`DNSNameParam<DNSNameParam>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* force : :ref:`Flag<Flag>` **(Required)**
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
* idnssoarname : :ref:`DNSNameParam<DNSNameParam>`
 * Default: hostmaster
* idnssoaserial : :ref:`Int<Int>`
* idnssoarefresh : :ref:`Int<Int>`
 * Default: 3600
* idnssoaretry : :ref:`Int<Int>`
 * Default: 900
* idnssoaexpire : :ref:`Int<Int>`
 * Default: 1209600
* idnssoaminimum : :ref:`Int<Int>`
 * Default: 3600
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
* delattr : :ref:`Str<Str>`
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