[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# dnsforwardzone_add
Create new DNS forward zone.

### Arguments
|Name|Type|Required
|-|-|-
|idnsname|:ref:`DNSNameParam<DNSNameParam>`|True

### Options
* skip_overlap_check : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* name_from_ip : :ref:`Str<Str>`
* idnsforwarders : :ref:`Str<Str>`
* idnsforwardpolicy : :ref:`StrEnum<StrEnum>`
 * Values: ('only', 'first', 'none')
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
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