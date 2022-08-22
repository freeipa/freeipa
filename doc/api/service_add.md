[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# service_add
Add a new IPA service.

### Arguments
|Name|Type|Required
|-|-|-
|krbcanonicalname|:ref:`Principal<Principal>`|True

### Options
* force : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* skip_host_check : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* usercertificate : :ref:`Certificate<Certificate>`
* ipakrbauthzdata : :ref:`StrEnum<StrEnum>`
 * Values: ('MS-PAC', 'PAD', 'NONE')
* krbprincipalauthind : :ref:`StrEnum<StrEnum>`
 * Values: ('radius', 'otp', 'pkinit', 'hardened', 'idp')
* ipakrbrequirespreauth : :ref:`Bool<Bool>`
* ipakrbokasdelegate : :ref:`Bool<Bool>`
* ipakrboktoauthasdelegate : :ref:`Bool<Bool>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
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