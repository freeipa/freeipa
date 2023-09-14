[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# certmaprule_find
Search for Certificate Identity Mapping Rules.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* cn : :ref:`Str<Str>`
* description : :ref:`Str<Str>`
* ipacertmapmaprule : :ref:`Str<Str>`
* ipacertmapmatchrule : :ref:`Str<Str>`
* associateddomain : :ref:`DNSNameParam<DNSNameParam>`
* ipacertmappriority : :ref:`Int<Int>`
* ipaenabledflag : :ref:`Bool<Bool>`
 * Default: True
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