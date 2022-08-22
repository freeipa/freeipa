[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# radiusproxy_mod
Modify a RADIUS proxy server.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* ipatokenradiusserver : :ref:`Str<Str>`
* ipatokenradiussecret : :ref:`Password<Password>`
* ipatokenradiustimeout : :ref:`Int<Int>`
* ipatokenradiusretries : :ref:`Int<Int>`
* ipatokenusermapattribute : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
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