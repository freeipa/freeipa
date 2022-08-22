[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# sudorule_find
Search for Sudo Rule.

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