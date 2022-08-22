[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# idrange_mod
Modify ID range.

-------
WARNING:

DNA plugin in 389-ds will allocate IDs based on the ranges configured for the
local domain. Currently the DNA plugin *cannot* be reconfigured itself based
on the local ranges set via this family of commands.

Manual configuration change has to be done in the DNA plugin configuration for
the new local range. Specifically, The dnaNextRange attribute of 'cn=Posix
IDs,cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config' has to be
modified to match the new range.

-------

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
* ipabaseid : :ref:`Int<Int>`
* ipaidrangesize : :ref:`Int<Int>`
* ipabaserid : :ref:`Int<Int>`
* ipasecondarybaserid : :ref:`Int<Int>`
* ipaautoprivategroups : :ref:`StrEnum<StrEnum>`
 * Values: ('true', 'false', 'hybrid')
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* ipanttrusteddomainsid : :ref:`Str<Str>`
* ipanttrusteddomainname : :ref:`Str<Str>`
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