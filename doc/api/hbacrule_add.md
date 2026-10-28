[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# hbacrule_add
Create a new HBAC rule.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* accessruletype : :ref:`StrEnum<StrEnum>` **(Required)**
 * Default: allow
 * Values: ('allow', 'deny')
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
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