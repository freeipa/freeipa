[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# pwpolicy_find
Search for group password policies.

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
* krbmaxpwdlife : :ref:`Int<Int>`
* krbminpwdlife : :ref:`Int<Int>`
* krbpwdhistorylength : :ref:`Int<Int>`
* krbpwdmindiffchars : :ref:`Int<Int>`
* krbpwdminlength : :ref:`Int<Int>`
* cospriority : :ref:`Int<Int>`
* krbpwdmaxfailure : :ref:`Int<Int>`
* krbpwdfailurecountinterval : :ref:`Int<Int>`
* krbpwdlockoutduration : :ref:`Int<Int>`
* ipapwdmaxrepeat : :ref:`Int<Int>`
 * Default: 0
* ipapwdmaxsequence : :ref:`Int<Int>`
 * Default: 0
* ipapwddictcheck : :ref:`Bool<Bool>`
 * Default: False
* ipapwdusercheck : :ref:`Bool<Bool>`
 * Default: False
* passwordgracelimit : :ref:`Int<Int>`
 * Default: -1
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