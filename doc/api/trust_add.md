[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_add

Add new trust to use.

This command establishes trust relationship to another domain
which becomes 'trusted'. As result, users of the trusted domain
may access resources of this domain.

Only trusts to Active Directory domains are supported right now.

The command can be safely run multiple times against the same domain,
this will cause change to trust relationship credentials on both
sides.

Note that if the command was previously run with a specific range type,
or with automatic detection of the range type, and you want to configure a
different range type, you may need to delete first the ID range using
ipa idrange-del before retrying the command with the desired range type.


### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* trust_type : :ref:`StrEnum<StrEnum>` **(Required)**
 * Default: ad
 * Values: ('ad',)
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* realm_admin : :ref:`Str<Str>`
* realm_passwd : :ref:`Password<Password>`
* realm_server : :ref:`Str<Str>`
* trust_secret : :ref:`Password<Password>`
* base_id : :ref:`Int<Int>`
* range_size : :ref:`Int<Int>`
* range_type : :ref:`StrEnum<StrEnum>`
 * Values: ('ipa-ad-trust', 'ipa-ad-trust-posix')
* bidirectional : :ref:`Bool<Bool>`
 * Default: False
* external : :ref:`Bool<Bool>`
 * Default: False
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