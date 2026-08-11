[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# service_add_attestation_key
Register a service attestation public key for S4U2Self attestation

### Arguments
|Name|Type|Required
|-|-|-
|krbcanonicalname|:ref:`Principal<Principal>`|True

### Options
* service_type : :ref:`Str<Str>` **(Required)**
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipakrbserviceattestationkey : :ref:`Bytes<Bytes>` **(Required)**
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