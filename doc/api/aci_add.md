[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# aci_add
Create new ACI.

### Arguments
|Name|Type|Required
|-|-|-
|aciname|:ref:`Str<Str>`|True

### Options
* permissions : :ref:`Str<Str>` **(Required)**
* aciprefix : :ref:`StrEnum<StrEnum>` **(Required)**
 * Values: ('permission', 'delegation', 'selfservice', 'none')
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* permission : :ref:`Str<Str>`
* group : :ref:`Str<Str>`
* attrs : :ref:`Str<Str>`
* type : :ref:`StrEnum<StrEnum>`
 * Values: ('user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord')
* memberof : :ref:`Str<Str>`
* filter : :ref:`Str<Str>`
* subtree : :ref:`Str<Str>`
* targetgroup : :ref:`Str<Str>`
* selfaci : :ref:`Flag<Flag>`
 * Default: False
* test : :ref:`Flag<Flag>`
 * Default: False
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