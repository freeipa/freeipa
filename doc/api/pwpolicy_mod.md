[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# pwpolicy_mod
Modify a group password policy.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|False

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
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
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
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