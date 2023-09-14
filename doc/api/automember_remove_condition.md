[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# automember_remove_condition

Remove conditions from an automember rule.


### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* key : :ref:`Str<Str>` **(Required)**
* type : :ref:`StrEnum<StrEnum>` **(Required)**
 * Values: ('group', 'hostgroup')
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* automemberinclusiveregex : :ref:`Str<Str>`
* automemberexclusiveregex : :ref:`Str<Str>`
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|completed|Output
|failed|Output
|result|Entry
|summary|Output
|value|PrimaryKey

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences