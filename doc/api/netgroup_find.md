[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# netgroup_find
Search for a netgroup.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* private : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* managed : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: True
* cn : :ref:`Str<Str>`
* description : :ref:`Str<Str>`
* nisdomainname : :ref:`Str<Str>`
* ipauniqueid : :ref:`Str<Str>`
* usercategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* hostcategory : :ref:`StrEnum<StrEnum>`
 * Values: ('all',)
* externalhost : :ref:`Str<Str>`
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* netgroup : :ref:`Str<Str>`
* no_netgroup : :ref:`Str<Str>`
* user : :ref:`Str<Str>`
* no_user : :ref:`Str<Str>`
* group : :ref:`Str<Str>`
* no_group : :ref:`Str<Str>`
* host : :ref:`Str<Str>`
* no_host : :ref:`Str<Str>`
* hostgroup : :ref:`Str<Str>`
* no_hostgroup : :ref:`Str<Str>`
* in_netgroup : :ref:`Str<Str>`
* not_in_netgroup : :ref:`Str<Str>`

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