[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# idrange_add

Add new ID range.

To add a new ID range you always have to specify

--base-id
--range-size

Additionally

--rid-base
--secondary-rid-base

may be given for a new ID range for the local domain while

--auto-private-groups

may be given for a new ID range for a trusted AD domain and

--rid-base
--dom-sid

must be given to add a new range for a trusted AD domain.

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
* ipabaseid : :ref:`Int<Int>` **(Required)**
* ipaidrangesize : :ref:`Int<Int>` **(Required)**
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipabaserid : :ref:`Int<Int>`
* ipasecondarybaserid : :ref:`Int<Int>`
* ipanttrusteddomainsid : :ref:`Str<Str>`
* ipanttrusteddomainname : :ref:`Str<Str>`
* iparangetype : :ref:`StrEnum<StrEnum>`
 * Values: ('ipa-ad-trust', 'ipa-ad-trust-posix', 'ipa-local')
* ipaautoprivategroups : :ref:`StrEnum<StrEnum>`
 * Values: ('true', 'false', 'hybrid')
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