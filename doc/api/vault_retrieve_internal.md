[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# vault_retrieve_internal
Retrieve data from a vault.

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* session_key : :ref:`Bytes<Bytes>` **(Required)**
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* service : :ref:`Principal<Principal>`
* shared : :ref:`Flag<Flag>`
 * Default: False
* username : :ref:`Str<Str>`
* wrapping_algo : :ref:`StrEnum<StrEnum>`
 * Default: des-ede3-cbc
 * Values: ('aes-128-cbc', 'des-ede3-cbc')
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