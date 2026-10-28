[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# automountmap_add_indirect
Create a new indirect mount point.

### Arguments
|Name|Type|Required
|-|-|-
|automountlocationcn|:ref:`Str<Str>`|True
|automountmapname|:ref:`IA5Str<IA5Str>`|True

### Options
* key : :ref:`Str<Str>` **(Required)**
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* parentmap : :ref:`Str<Str>`
 * Default: auto.master
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