[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# idrange_find
Search for ranges.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* cn : :ref:`Str<Str>`
* ipabaseid : :ref:`Int<Int>`
* ipaidrangesize : :ref:`Int<Int>`
* ipabaserid : :ref:`Int<Int>`
* ipasecondarybaserid : :ref:`Int<Int>`
* ipanttrusteddomainsid : :ref:`Str<Str>`
* iparangetype : :ref:`StrEnum<StrEnum>`
 * Values: ('ipa-ad-trust', 'ipa-ad-trust-posix', 'ipa-local')
* ipaautoprivategroups : :ref:`StrEnum<StrEnum>`
 * Values: ('true', 'false', 'hybrid')
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