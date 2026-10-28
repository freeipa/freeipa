[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# topologysuffix_verify

Verify replication topology for suffix.

Checks done:
1. check if a topology is not disconnected. In other words if there are
replication paths between all servers.
2. check if servers don't have more than the recommended number of
replication agreements

### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|result|Output

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences