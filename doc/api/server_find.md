[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# server_find
Search for IPA servers.

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
* ipamindomainlevel : :ref:`Int<Int>`
* ipamaxdomainlevel : :ref:`Int<Int>`
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* topologysuffix : :ref:`Str<Str>`
* no_topologysuffix : :ref:`Str<Str>`
* in_location : :ref:`DNSNameParam<DNSNameParam>`
* not_in_location : :ref:`DNSNameParam<DNSNameParam>`
* servrole : :ref:`Str<Str>`

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