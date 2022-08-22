[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# host_add
Add a new host.

### Arguments
|Name|Type|Required
|-|-|-
|fqdn|:ref:`Str<Str>`|True

### Options
* force : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_reverse : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* description : :ref:`Str<Str>`
* l : :ref:`Str<Str>`
* nshostlocation : :ref:`Str<Str>`
* nshardwareplatform : :ref:`Str<Str>`
* nsosversion : :ref:`Str<Str>`
* userpassword : :ref:`HostPassword<HostPassword>`
* random : :ref:`Flag<Flag>`
 * Default: False
* usercertificate : :ref:`Certificate<Certificate>`
* macaddress : :ref:`Str<Str>`
* ipasshpubkey : :ref:`Str<Str>`
* userclass : :ref:`Str<Str>`
* ipaassignedidview : :ref:`Str<Str>`
* krbprincipalauthind : :ref:`StrEnum<StrEnum>`
 * Values: ('radius', 'otp', 'pkinit', 'hardened', 'idp')
* ipakrbrequirespreauth : :ref:`Bool<Bool>`
* ipakrbokasdelegate : :ref:`Bool<Bool>`
* ipakrboktoauthasdelegate : :ref:`Bool<Bool>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* ip_address : :ref:`Str<Str>`
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