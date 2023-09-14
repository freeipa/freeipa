[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# selinuxusermap_add
Create a new SELinux User Map.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* ipaselinuxuser : :ref:`Str<Str>` **(Required)**
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* seealso : :ref:`Str<Str>`
* usercategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* hostcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* description : :ref:`Str<Str>`
* ipaenabledflag : :ref:`Bool<Bool>`
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