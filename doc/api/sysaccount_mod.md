[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# sysaccount_mod
Modify an existing IPA system account.

### Arguments
|Name|Type|Required
|-|-|-
|uid|:ref:`Str<Str>`|True

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
* userpassword : :ref:`Password<Password>`
* random : :ref:`Flag<Flag>`
 * Default: False
* nsaccountlock : :ref:`Bool<Bool>`
 * Default: False
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* privileged : :ref:`Bool<Bool>`
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