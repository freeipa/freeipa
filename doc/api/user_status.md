[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# user_status

Lockout status of a user account

An account may become locked if the password is entered incorrectly too
many times within a specific time period as controlled by password
policy. A locked account is a temporary condition and may be unlocked by
an administrator.

This connects to each IPA master and displays the lockout status on
each one.

To determine whether an account is locked on a given server you need
to compare the number of failed logins and the time of the last failure.
For an account to be locked it must exceed the maxfail failures within
the failinterval duration as specified in the password policy associated
with the user.

The failed login counter is modified only when a user attempts a log in
so it is possible that an account may appear locked but the last failed
login attempt is older than the lockouttime of the password policy. This
means that the user may attempt a login again.

### Arguments
|Name|Type|Required
|-|-|-
|useruid|:ref:`Str<Str>`|True

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