[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# server_role_find
Find a server role on a server(s)

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* include_master : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* server_server : :ref:`Str<Str>`
* role_servrole : :ref:`Str<Str>`
* status : :ref:`StrEnum<StrEnum>`
 * Default: enabled
 * Values: ('enabled', 'configured', 'hidden', 'absent')
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`

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