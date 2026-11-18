[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_mod

Modify a trust.

Use the UPN suffix and TLN exclusion options to replace the complete
lists, or the add and delete options to modify individual values.


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
* ipanttrusttlnexclusions : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* add_upn_suffix : :ref:`Str<Str>`
* del_upn_suffix : :ref:`Str<Str>`
* add_tln_exclusion : :ref:`Str<Str>`
* del_tln_exclusion : :ref:`Str<Str>`
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|result|Entry
|summary|Output
|value|PrimaryKey

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

`ipantadditionalsuffixes` and `ipanttrusttlnexclusions` replace the
respective lists. The `add_upn_suffix`, `del_upn_suffix`,
`add_tln_exclusion`, and `del_tln_exclusion` options accept multiple values
and modify the existing list. Replacement and incremental options for the
same attribute cannot be combined.

### Notes

### Version differences