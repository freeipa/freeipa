[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# cert_find
Search for existing certificates.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: True
* certificate : :ref:`Certificate<Certificate>`
* issuer : :ref:`DNParam<DNParam>`
* revocation_reason : :ref:`Int<Int>`
* cacn : :ref:`Str<Str>`
* subject : :ref:`Str<Str>`
* min_serial_number : :ref:`SerialNumber<SerialNumber>`
* max_serial_number : :ref:`SerialNumber<SerialNumber>`
* exactly : :ref:`Flag<Flag>`
 * Default: False
* validnotafter_from : :ref:`DateTime<DateTime>`
* validnotafter_to : :ref:`DateTime<DateTime>`
* validnotbefore_from : :ref:`DateTime<DateTime>`
* validnotbefore_to : :ref:`DateTime<DateTime>`
* issuedon_from : :ref:`DateTime<DateTime>`
* issuedon_to : :ref:`DateTime<DateTime>`
* revokedon_from : :ref:`DateTime<DateTime>`
* revokedon_to : :ref:`DateTime<DateTime>`
* status : :ref:`StrEnum<StrEnum>`
 * Values: ('VALID', 'INVALID', 'REVOKED', 'EXPIRED', 'REVOKED_EXPIRED')
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* user : :ref:`Str<Str>`
* no_user : :ref:`Str<Str>`
* host : :ref:`Str<Str>`
* no_host : :ref:`Str<Str>`
* service : :ref:`Principal<Principal>`
* no_service : :ref:`Principal<Principal>`

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