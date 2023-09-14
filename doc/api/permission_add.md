[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# permission_add
Add a new permission.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* ipapermbindruletype : :ref:`StrEnum<StrEnum>` **(Required)**
 * Default: permission
 * Values: ('permission', 'all', 'anonymous', 'self')
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipapermright : :ref:`StrEnum<StrEnum>`
 * Values: ('read', 'search', 'compare', 'write', 'add', 'delete', 'all')
* attrs : :ref:`Str<Str>`
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