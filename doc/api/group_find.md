[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# group_find
Search for groups.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* private : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* posix : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* external : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* nonposix : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: True
* cn : :ref:`Str<Str>`
* description : :ref:`Str<Str>`
* gidnumber : :ref:`Int<Int>`
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* user : :ref:`Str<Str>`
* no_user : :ref:`Str<Str>`
* group : :ref:`Str<Str>`
* no_group : :ref:`Str<Str>`
* service : :ref:`Principal<Principal>`
* no_service : :ref:`Principal<Principal>`
* idoverrideuser : :ref:`Str<Str>`
* no_idoverrideuser : :ref:`Str<Str>`
* in_group : :ref:`Str<Str>`
* not_in_group : :ref:`Str<Str>`
* in_netgroup : :ref:`Str<Str>`
* not_in_netgroup : :ref:`Str<Str>`
* in_role : :ref:`Str<Str>`
* not_in_role : :ref:`Str<Str>`
* in_hbacrule : :ref:`Str<Str>`
* not_in_hbacrule : :ref:`Str<Str>`
* in_sudorule : :ref:`Str<Str>`
* not_in_sudorule : :ref:`Str<Str>`
* membermanager_user : :ref:`Str<Str>`
* not_membermanager_user : :ref:`Str<Str>`
* membermanager_group : :ref:`Str<Str>`
* not_membermanager_group : :ref:`Str<Str>`

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