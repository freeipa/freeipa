[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# cert_request
Submit a certificate signing request.

### Arguments
|Name|Type|Required
|-|-|-
|csr|:ref:`CertificateSigningRequest<CertificateSigningRequest>`|True

### Options
* request_type : :ref:`Str<Str>` **(Required)**
 * Default: pkcs10
* principal : :ref:`Principal<Principal>` **(Required)**
* add : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* chain : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* profile_id : :ref:`Str<Str>`
* cacn : :ref:`Str<Str>`
 * Default: ipa
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