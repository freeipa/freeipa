[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# migrate_ds
Migrate users and groups from DS to IPA.

### Arguments
|Name|Type|Required
|-|-|-
|ldapuri|:ref:`Str<Str>`|True
|bindpw|:ref:`Password<Password>`|True

### Options
* usercontainer : :ref:`DNParam<DNParam>` **(Required)**
 * Default: ou=people
* groupcontainer : :ref:`DNParam<DNParam>` **(Required)**
 * Default: ou=groups
* userobjectclass : :ref:`Str<Str>` **(Required)**
 * Default: ('person',)
* groupobjectclass : :ref:`Str<Str>` **(Required)**
 * Default: ('groupOfUniqueNames', 'groupOfNames')
* groupoverwritegid : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* scope : :ref:`StrEnum<StrEnum>` **(Required)**
 * Default: onelevel
 * Values: ('base', 'onelevel', 'subtree')
* binddn : :ref:`DNParam<DNParam>`
 * Default: cn=directory manager
* userignoreobjectclass : :ref:`Str<Str>`
 * Default: ()
* userignoreattribute : :ref:`Str<Str>`
 * Default: ()
* groupignoreobjectclass : :ref:`Str<Str>`
 * Default: ()
* groupignoreattribute : :ref:`Str<Str>`
 * Default: ()
* schema : :ref:`StrEnum<StrEnum>`
 * Default: RFC2307bis
 * Values: ('RFC2307bis', 'RFC2307')
* continue : :ref:`Flag<Flag>`
 * Default: False
* basedn : :ref:`DNParam<DNParam>`
* compat : :ref:`Flag<Flag>`
 * Default: False
* cacertfile : :ref:`Str<Str>`
* use_def_group : :ref:`Bool<Bool>`
 * Default: True
* version : :ref:`Str<Str>`
* exclude_users : :ref:`Str<Str>`
 * Default: ()
* exclude_groups : :ref:`Str<Str>`
 * Default: ()

### Output
|Name|Type
|-|-
|compat|Output
|enabled|Output
|failed|Output
|result|Output

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences