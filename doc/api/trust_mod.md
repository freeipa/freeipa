[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_mod

Modify a trust (for future use).

Currently only the default option to modify the LDAP attributes is
available. More specific options will be added in coming releases.


### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipantsidblacklistincoming : :ref:`Str<Str>`
* ipantsidblacklistoutgoing : :ref:`Str<Str>`
* ipantadditionalsuffixes : :ref:`Str<Str>`
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