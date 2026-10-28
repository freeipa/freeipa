[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# permission_find
Search for permissions.

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
* ipapermright : :ref:`StrEnum<StrEnum>`
 * Values: ('read', 'search', 'compare', 'write', 'add', 'delete', 'all')
* attrs : :ref:`Str<Str>`
* ipapermincludedattr : :ref:`Str<Str>`
* ipapermexcludedattr : :ref:`Str<Str>`
* ipapermdefaultattr : :ref:`Str<Str>`
* ipapermbindruletype : :ref:`StrEnum<StrEnum>`
 * Default: permission
 * Values: ('permission', 'all', 'anonymous', 'self')
* ipapermlocation : :ref:`DNOrURL<DNOrURL>`
* extratargetfilter : :ref:`Str<Str>`
* ipapermtargetfilter : :ref:`Str<Str>`
* ipapermtarget : :ref:`DNParam<DNParam>`
* ipapermtargetto : :ref:`DNParam<DNParam>`
* ipapermtargetfrom : :ref:`DNParam<DNParam>`
* memberof : :ref:`Str<Str>`
* targetgroup : :ref:`Str<Str>`
* type : :ref:`Str<Str>`
* permissions : :ref:`Str<Str>`
* filter : :ref:`Str<Str>`
* subtree : :ref:`Str<Str>`
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