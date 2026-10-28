[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# idp_add
Add a new Identity Provider reference.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* ipaidpclientid : :ref:`Str<Str>` **(Required)**
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipaidpauthendpoint : :ref:`Str<Str>`
* ipaidpdevauthendpoint : :ref:`Str<Str>`
* ipaidptokenendpoint : :ref:`Str<Str>`
* ipaidpuserinfoendpoint : :ref:`Str<Str>`
* ipaidpkeysendpoint : :ref:`Str<Str>`
* ipaidpissuerurl : :ref:`Str<Str>`
* ipaidpclientsecret : :ref:`Password<Password>`
* ipaidpscope : :ref:`Str<Str>`
* ipaidpsub : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* ipaidpprovider : :ref:`StrEnum<StrEnum>`
 * Values: ('google', 'github', 'microsoft', 'okta', 'keycloak')
* ipaidporg : :ref:`Str<Str>`
* ipaidpbaseurl : :ref:`Str<Str>`
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