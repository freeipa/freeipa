[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# hostgroup_find
Search for hostgroups.

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
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* host : :ref:`Str<Str>`
* no_host : :ref:`Str<Str>`
* hostgroup : :ref:`Str<Str>`
* no_hostgroup : :ref:`Str<Str>`
* in_hostgroup : :ref:`Str<Str>`
* not_in_hostgroup : :ref:`Str<Str>`
* in_netgroup : :ref:`Str<Str>`
* not_in_netgroup : :ref:`Str<Str>`
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