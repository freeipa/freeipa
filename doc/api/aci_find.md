[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# aci_find

Search for ACIs.

Returns a list of ACIs

EXAMPLES:

To find all ACIs that apply directly to members of the group ipausers:
ipa aci-find --memberof=ipausers

To find all ACIs that grant add access:
ipa aci-find --permissions=add

Note that the find command only looks for the given text in the set of
ACIs, it does not evaluate the ACIs to see if something would apply.
For example, searching on memberof=ipausers will find all ACIs that
have ipausers as a memberof. There may be other ACIs that apply to
members of that group indirectly.


### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* aciname : :ref:`Str<Str>`
* permission : :ref:`Str<Str>`
* group : :ref:`Str<Str>`
* permissions : :ref:`Str<Str>`
* attrs : :ref:`Str<Str>`
* type : :ref:`StrEnum<StrEnum>`
 * Values: ('user', 'group', 'host', 'service', 'hostgroup', 'netgroup', 'dnsrecord')
* memberof : :ref:`Str<Str>`
* filter : :ref:`Str<Str>`
* subtree : :ref:`Str<Str>`
* targetgroup : :ref:`Str<Str>`
* selfaci : :ref:`Bool<Bool>`
 * Default: False
* aciprefix : :ref:`StrEnum<StrEnum>`
 * Values: ('permission', 'delegation', 'selfservice', 'none')
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* version : :ref:`Str<Str>`

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