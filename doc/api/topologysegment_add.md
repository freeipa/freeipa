[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# topologysegment_add
Add a new segment.

### Arguments
|Name|Type|Required
|-|-|-
|topologysuffixcn|:ref:`Str<Str>`|True
|cn|:ref:`Str<Str>`|True

### Options
* iparepltoposegmentleftnode : :ref:`Str<Str>` **(Required)**
* iparepltoposegmentrightnode : :ref:`Str<Str>` **(Required)**
* iparepltoposegmentdirection : :ref:`StrEnum<StrEnum>` **(Required)**
 * Default: both
 * Values: ('both', 'left-right', 'right-left')
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* nsds5replicastripattrs : :ref:`Str<Str>`
* nsds5replicatedattributelist : :ref:`Str<Str>`
* nsds5replicatedattributelisttotal : :ref:`Str<Str>`
* nsds5replicatimeout : :ref:`Int<Int>`
* nsds5replicaenabled : :ref:`StrEnum<StrEnum>`
 * Values: ('on', 'off')
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