[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
.. _DateTime:

# DateTime
[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)

DateTime parameter type.

Accepts LDAP Generalized time without in the following format:
   '%Y%m%d%H%M%SZ'

Accepts subset of values defined by ISO 8601:
    '%Y-%m-%dT%H:%M:%SZ'
    '%Y-%m-%dT%H:%MZ'
    '%Y-%m-%dZ'

Also accepts above formats using ' ' (space) as a separator instead of 'T'.

Refer to the `man strftime` for the explanations for the %Y,%m,%d,%H.%M,%S.
