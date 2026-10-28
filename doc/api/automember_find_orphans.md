[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# automember_find_orphans

Search for orphan automember rules. The command might need to be run as
a privileged user user to get all orphan rules.


### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* type : :ref:`StrEnum<StrEnum>` **(Required)**
 * Values: ('group', 'hostgroup')
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* remove : :ref:`Flag<Flag>`
 * Default: False
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