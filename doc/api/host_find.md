[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# host_find
Search for hosts.

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
* fqdn : :ref:`Str<Str>`
* description : :ref:`Str<Str>`
* l : :ref:`Str<Str>`
* nshostlocation : :ref:`Str<Str>`
* nshardwareplatform : :ref:`Str<Str>`
* nsosversion : :ref:`Str<Str>`
* usercertificate : :ref:`Certificate<Certificate>`
* macaddress : :ref:`Str<Str>`
* userclass : :ref:`Str<Str>`
* ipaassignedidview : :ref:`Str<Str>`
* krbprincipalauthind : :ref:`StrEnum<StrEnum>`
 * Values: ('radius', 'otp', 'pkinit', 'hardened', 'idp')
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* in_hostgroup : :ref:`Str<Str>`
* not_in_hostgroup : :ref:`Str<Str>`
* in_netgroup : :ref:`Str<Str>`
* not_in_netgroup : :ref:`Str<Str>`
* in_role : :ref:`Str<Str>`
* not_in_role : :ref:`Str<Str>`
* in_hbacrule : :ref:`Str<Str>`
* not_in_hbacrule : :ref:`Str<Str>`
* in_sudorule : :ref:`Str<Str>`
* not_in_sudorule : :ref:`Str<Str>`
* enroll_by_user : :ref:`Str<Str>`
* not_enroll_by_user : :ref:`Str<Str>`
* man_by_host : :ref:`Str<Str>`
* not_man_by_host : :ref:`Str<Str>`
* man_host : :ref:`Str<Str>`
* not_man_host : :ref:`Str<Str>`

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