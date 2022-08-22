[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# certmaprule_mod
Modify a Certificate Identity Mapping Rule.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* ipacertmapmaprule : :ref:`Str<Str>`
* ipacertmapmatchrule : :ref:`Str<Str>`
* associateddomain : :ref:`DNSNameParam<DNSNameParam>`
* ipacertmappriority : :ref:`Int<Int>`
* ipaenabledflag : :ref:`Flag<Flag>`
 * Default: True
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