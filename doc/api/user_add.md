[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# user_add
Add a new user.

### Arguments
|Name|Type|Required
|-|-|-
|uid|:ref:`Str<Str>`|True

### Options
* givenname : :ref:`Str<Str>` **(Required)**
* sn : :ref:`Str<Str>` **(Required)**
* cn : :ref:`Str<Str>` **(Required)**
* noprivate : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* displayname : :ref:`Str<Str>`
* initials : :ref:`Str<Str>`
* homedirectory : :ref:`Str<Str>`
* gecos : :ref:`Str<Str>`
* loginshell : :ref:`Str<Str>`
* krbprincipalname : :ref:`Principal<Principal>`
* krbprincipalexpiration : :ref:`DateTime<DateTime>`
* krbpasswordexpiration : :ref:`DateTime<DateTime>`
* mail : :ref:`Str<Str>`
* userpassword : :ref:`Password<Password>`
* random : :ref:`Flag<Flag>`
 * Default: False
* uidnumber : :ref:`Int<Int>`
* gidnumber : :ref:`Int<Int>`
* street : :ref:`Str<Str>`
* l : :ref:`Str<Str>`
* st : :ref:`Str<Str>`
* postalcode : :ref:`Str<Str>`
* telephonenumber : :ref:`Str<Str>`
* mobile : :ref:`Str<Str>`
* pager : :ref:`Str<Str>`
* facsimiletelephonenumber : :ref:`Str<Str>`
* ou : :ref:`Str<Str>`
* title : :ref:`Str<Str>`
* manager : :ref:`Str<Str>`
* carlicense : :ref:`Str<Str>`
* ipasshpubkey : :ref:`Str<Str>`
* ipauserauthtype : :ref:`StrEnum<StrEnum>`
 * Values: ('password', 'radius', 'otp', 'pkinit', 'hardened', 'idp')
* userclass : :ref:`Str<Str>`
* ipatokenradiusconfiglink : :ref:`Str<Str>`
* ipatokenradiususername : :ref:`Str<Str>`
* ipaidpconfiglink : :ref:`Str<Str>`
* ipaidpsub : :ref:`Str<Str>`
* departmentnumber : :ref:`Str<Str>`
* employeenumber : :ref:`Str<Str>`
* employeetype : :ref:`Str<Str>`
* preferredlanguage : :ref:`Str<Str>`
* usercertificate : :ref:`Certificate<Certificate>`
* nsaccountlock : :ref:`Bool<Bool>`
 * Default: False
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
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