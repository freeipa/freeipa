[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnsforwardzone_find
Search for DNS forward zones.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
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