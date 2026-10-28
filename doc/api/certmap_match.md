[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# certmap_match

Search for users matching the provided certificate.

This command relies on SSSD to retrieve the list of matching users and
may return cached data. For more information on purging SSSD cache,
please refer to sss_cache documentation.


### Arguments
|Name|Type|Required
|-|-|-
|certificate|:ref:`Certificate<Certificate>`|True

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* version : :ref:`Str<Str>`

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