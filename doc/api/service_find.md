[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# service_find
Search for IPA services.

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
* krbcanonicalname : :ref:`Principal<Principal>`
* krbprincipalname : :ref:`Principal<Principal>`
* ipakrbauthzdata : :ref:`StrEnum<StrEnum>`
 * Values: ('MS-PAC', 'PAD', 'NONE')
* krbprincipalauthind : :ref:`StrEnum<StrEnum>`
 * Values: ('radius', 'otp', 'pkinit', 'hardened', 'idp')
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* man_by_host : :ref:`Str<Str>`
* not_man_by_host : :ref:`Str<Str>`

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