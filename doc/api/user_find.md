[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# user_find
Search for users.

### Arguments
|Name|Type|Required
|-|-|-
|criteria|:ref:`Str<Str>`|False

### Options
* whoami : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* no_members : :ref:`Flag<Flag>` **(Required)**
 * Default: True
* uid : :ref:`Str<Str>`
* givenname : :ref:`Str<Str>`
* sn : :ref:`Str<Str>`
* cn : :ref:`Str<Str>`
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
* ipantlogonscript : :ref:`Str<Str>`
* ipantprofilepath : :ref:`Str<Str>`
* ipanthomedirectory : :ref:`Str<Str>`
* ipanthomedirectorydrive : :ref:`StrEnum<StrEnum>`
 * Values: ('A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:')
* nsaccountlock : :ref:`Bool<Bool>`
 * Default: False
* preserved : :ref:`Bool<Bool>`
 * Default: False
* timelimit : :ref:`Int<Int>`
* sizelimit : :ref:`Int<Int>`
* version : :ref:`Str<Str>`
* pkey_only : :ref:`Flag<Flag>`
 * Default: False
* in_group : :ref:`Str<Str>`
* not_in_group : :ref:`Str<Str>`
* in_netgroup : :ref:`Str<Str>`
* not_in_netgroup : :ref:`Str<Str>`
* in_role : :ref:`Str<Str>`
* not_in_role : :ref:`Str<Str>`
* in_hbacrule : :ref:`Str<Str>`
* not_in_hbacrule : :ref:`Str<Str>`
* in_sudorule : :ref:`Str<Str>`
* not_in_sudorule : :ref:`Str<Str>`
* in_subid : :ref:`Str<Str>`
* not_in_subid : :ref:`Str<Str>`

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