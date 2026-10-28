[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# otptoken_find
Search for OTP token.

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
* ipatokenuniqueid : :ref:`Str<Str>`
* type : :ref:`StrEnum<StrEnum>`
 * Default: totp
 * Values: ('totp', 'hotp', 'TOTP', 'HOTP')
* description : :ref:`Str<Str>`
* ipatokenowner : :ref:`Str<Str>`
* ipatokendisabled : :ref:`Bool<Bool>`
* ipatokennotbefore : :ref:`DateTime<DateTime>`
* ipatokennotafter : :ref:`DateTime<DateTime>`
* ipatokenvendor : :ref:`Str<Str>`
* ipatokenmodel : :ref:`Str<Str>`
* ipatokenserial : :ref:`Str<Str>`
* ipatokenotpalgorithm : :ref:`StrEnum<StrEnum>`
 * Default: sha1
 * Values: ('sha1', 'sha256', 'sha384', 'sha512')
* ipatokenotpdigits : :ref:`IntEnum<IntEnum>`
 * Default: 6
 * Values: (6, 8)
* ipatokentotpclockoffset : :ref:`Int<Int>`
 * Default: 0
* ipatokentotptimestep : :ref:`Int<Int>`
 * Default: 30
* ipatokenhotpcounter : :ref:`Int<Int>`
 * Default: 0
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