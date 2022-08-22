[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# vault_find
Search for vaults.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: True
* cn : :ref:`Str<Str>`
* description : :ref:`Str<Str>`
* ipavaulttype : :ref:`StrEnum<StrEnum>`
 * Default: symmetric
 * Values: ('standard', 'symmetric', 'asymmetric')
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* service : :ref:`Principal<Principal>`
* shared : :ref:`Flag<Flag>`
 * Default: False
* username : :ref:`Str<Str>`
* services : :ref:`Flag<Flag>`
 * Default: False
* users : :ref:`Flag<Flag>`
 * Default: False
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