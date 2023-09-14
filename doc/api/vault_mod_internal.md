[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# vault_mod_internal
Modify a vault.

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
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* ipavaulttype : :ref:`StrEnum<StrEnum>`
 * Default: symmetric
 * Values: ('standard', 'symmetric', 'asymmetric')
* ipavaultsalt : :ref:`Bytes<Bytes>`
* ipavaultpublickey : :ref:`Bytes<Bytes>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* service : :ref:`Principal<Principal>`
* shared : :ref:`Flag<Flag>`
 * Default: False
* username : :ref:`Str<Str>`
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