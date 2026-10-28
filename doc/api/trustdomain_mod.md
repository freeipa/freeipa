[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trustdomain_mod
Modify trustdomain of the trust

### Arguments
|Name|Type|Required
|-|-|-
|trustcn|:ref:`Str<Str>`|True
|cn|:ref:`Str<Str>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* trust_type : :ref:`StrEnum<StrEnum>` **(Required)**
 * Default: ad
 * Values: ('ad',)
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipantflatname : :ref:`Str<Str>`
* ipanttrusteddomainsid : :ref:`Str<Str>`
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