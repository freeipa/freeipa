[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# hbacrule_find
Search for HBAC rules.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: True
* cn : :ref:`Str<Str>`
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