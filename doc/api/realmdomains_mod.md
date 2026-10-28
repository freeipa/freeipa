[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# realmdomains_mod

Modify realm domains

DNS check: When manually adding a domain to the list, a DNS check is
performed by default. It ensures that the domain is associated with
the IPA realm, by checking whether the domain has a _kerberos TXT record
containing the IPA realm name. This check can be skipped by specifying
--force option.

Removal: when a realm domain which has a matching DNS zone managed by
IPA is being removed, a corresponding _kerberos TXT record in the zone is
removed automatically as well. Other records in the zone or the zone
itself are not affected.


### Arguments
No arguments.

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* force : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* associateddomain : :ref:`Str<Str>`
* add_domain : :ref:`Str<Str>`
* del_domain : :ref:`Str<Str>`
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