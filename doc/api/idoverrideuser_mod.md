[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# idoverrideuser_mod
Modify an User ID override.

### Arguments
|Name|Type|Required
|-|-|-
|idviewcn|:ref:`Str<Str>`|True
|ipaanchoruuid|:ref:`Str<Str>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* uid : :ref:`Str<Str>`
* uidnumber : :ref:`Int<Int>`
* gecos : :ref:`Str<Str>`
* gidnumber : :ref:`Int<Int>`
* homedirectory : :ref:`Str<Str>`
* loginshell : :ref:`Str<Str>`
* ipaoriginaluid : :ref:`Str<Str>`
* ipasshpubkey : :ref:`Str<Str>`
* usercertificate : :ref:`Certificate<Certificate>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* fallback_to_ldap : :ref:`Flag<Flag>`
 * Default: False
* version : :ref:`Str<Str>`
* rename : :ref:`Str<Str>`

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