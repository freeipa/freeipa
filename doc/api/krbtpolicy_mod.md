[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# krbtpolicy_mod
Modify Kerberos ticket policy.

### Arguments
|Name|Type|Required
|-|-|-
|uid|:ref:`Str<Str>`|False

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* krbmaxticketlife : :ref:`Int<Int>`
* krbmaxrenewableage : :ref:`Int<Int>`
* krbauthindmaxticketlife_otp : :ref:`Int<Int>`
* krbauthindmaxrenewableage_otp : :ref:`Int<Int>`
* krbauthindmaxticketlife_radius : :ref:`Int<Int>`
* krbauthindmaxrenewableage_radius : :ref:`Int<Int>`
* krbauthindmaxticketlife_pkinit : :ref:`Int<Int>`
* krbauthindmaxrenewableage_pkinit : :ref:`Int<Int>`
* krbauthindmaxticketlife_hardened : :ref:`Int<Int>`
* krbauthindmaxrenewableage_hardened : :ref:`Int<Int>`
* krbauthindmaxticketlife_idp : :ref:`Int<Int>`
* krbauthindmaxrenewableage_idp : :ref:`Int<Int>`
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