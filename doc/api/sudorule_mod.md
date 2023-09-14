[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# sudorule_mod
Modify Sudo Rule.

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
* ipaenabledflag : :ref:`Bool<Bool>`
* usercategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* hostcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* cmdcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* ipasudorunasusercategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* ipasudorunasgroupcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* sudoorder : :ref:`Int<Int>`
 * Default: 0
* externaluser : :ref:`Str<Str>`
* externalhost : :ref:`Str<Str>`
* ipasudorunasextuser : :ref:`Str<Str>`
* ipasudorunasextgroup : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* version : :ref:`Str<Str>`
* rename : :ref:`Str<Str>`

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