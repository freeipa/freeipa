[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnszone_find
Search for DNS zones (SOA records).

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* forward_only : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* idnsname : :ref:`DNSNameParam<DNSNameParam>`
* name_from_ip : :ref:`Str<Str>`
* idnszoneactive : :ref:`Bool<Bool>`
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