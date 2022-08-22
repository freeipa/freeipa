[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# topologysegment_find
Search for topology segments.

### Arguments
|Name|Type|Required
|-|-|-
|topologysuffixcn|:ref:`Str<Str>`|True
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* cn : :ref:`Str<Str>`
* iparepltoposegmentleftnode : :ref:`Str<Str>`
* iparepltoposegmentrightnode : :ref:`Str<Str>`
* iparepltoposegmentdirection : :ref:`StrEnum<StrEnum>`
 * Default: both
 * Values: ('both', 'left-right', 'right-left')
* nsds5replicastripattrs : :ref:`Str<Str>`
* nsds5replicatedattributelist : :ref:`Str<Str>`
* nsds5replicatedattributelisttotal : :ref:`Str<Str>`
* nsds5replicatimeout : :ref:`Int<Int>`
* nsds5replicaenabled : :ref:`StrEnum<StrEnum>`
 * Values: ('on', 'off')
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