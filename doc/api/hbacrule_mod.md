[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# hbacrule_mod
Modify an HBAC rule.

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
* accessruletype : :ref:`StrEnum<StrEnum>`
 * Default: allow
 * Values: ('allow', 'deny')
* usercategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* hostcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* sourcehostcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* servicecategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* description : :ref:`Str<Str>`
* ipaenabledflag : :ref:`Bool<Bool>`
* externalhost : :ref:`Str<Str>`
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