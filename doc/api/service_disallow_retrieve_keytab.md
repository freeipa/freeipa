[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# service_disallow_retrieve_keytab
Disallow users, groups, hosts or host groups to retrieve a keytab of this service.

### Arguments
|Name|Type|Required
|-|-|-
|krbcanonicalname|:ref:`Principal<Principal>`|True

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* version : :ref:`Str<Str>`
* user : :ref:`Str<Str>`
* group : :ref:`Str<Str>`
* host : :ref:`Str<Str>`
* hostgroup : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|completed|Output
|failed|Output
|result|Entry

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences