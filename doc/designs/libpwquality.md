# Password quality using libpwquality

## Overview

Improved password quality checking using the capabilities of libpwquality.

Tickets:
    [https://pagure.io/freeipa/issue/6964](https://pagure.io/freeipa/issue/6964)
    [https://pagure.io/freeipa/issue/5948](https://pagure.io/freeipa/issue/5948)
    [https://pagure.io/freeipa/issue/2445](https://pagure.io/freeipa/issue/2445)
    [https://pagure.io/freeipa/issue/298](https://pagure.io/freeipa/issue/298)

## User Stories

Condensing down all four tickets: As an IPA admininstrator, I want improved password checking including the following features:

* length
* character classes
* username is not in the password
* dictionary words (preferrably via cracklib)
* replacing numbers and symbols for letters
* repeating characters
* non-sequential passwords (password1, password2, etc)
* explicit requests for libpwquality

Length and character classes are supported in current password policy with slightly different semantics.

Username, dictionary using cracklib, numbers and symbols replacement and repeating characters are supported by libpwquality.

Doing sequential passwords would require the previous cleartext passwords be maintained. This will not be supported.

## libpwquality features to be exposed

maxrepeat: The maximum number of allowed same consecutive characters in the new password.

maxsequence: The maximum lenggth of monotonic character sequences in the new password. An example is '12345'.

dictcheck: Check whether the password (with possible modifications) matches a word in a dictionary (using cracklib).

usercheck: Check whether the password (with possible modifications) contains the user name in some form (if the name is > 3 characters).

Other checks are implicitly enabled when any libpwquality feature is enabled like the character/number substitution and palindrome testing.

## libpwquality features NOT exposed

libpwquality supports detailed class checking with overrides. This will not be enabled in favor of the existing class checking.

libpwquality also supports checking against the GECOS value but this will not be enabled now in order to save the nss lookup.

The ability to set the path to the cracklib dictionary will not be supported. Only the system dictionary.

A user-provided list of bad words will not be supported.

## libpwquality limitations

libpwquality has a hardcoded minimum password length of 6. Existing policy has no such limitation, so treat the libpwquality features as a bolt-on to existing policy.  If any libpwquality features are enabled then require minlength be at least 6.

If libpwquality features are not enabled then password policy works as it always has with no minimum value for minlength.

## Compatibility with existing policy

In order to maintain backwards compatibilty and not require migrating policy configuration the existing class-based policy will be maintained and the libpwquality class support will not be enabled.

Trying to migrate would generally be problematic in a mixed version environment as it is unclear how the existing policy would be maintained without duplicating values. As it is the addition of this new policy in a mixed version environment will create the possibility of different password requirements depending on the IPA server a user connects to.

## Enforcement

Policy must be applied whether the request comes over LDAP or Kerberos. One policy to rule them all.

The per-group policy rule will still select the appropriate policy using krbPwdPoliclicyreference.

## Testing

### Unit tests

Password policy is applied to all mechanisms in util/ipa_pwd.c. A unit test will be added to setup various policies and do direct testing using ipapwd_check_policy().

### Integration tests

Test using kinit and ldappassword in various policy configurations to ensure passwords are rejected when against policy and accepted when compliant.

## Schema

New LDAP schema will need to be allocated to store the policy configuration.

Add objectclass ipaPwdPolicy to store the new attributes:

`objectClasses: (2.16.840.1.113730.3.8.24.1 NAME 'ipaPwdPolicy' DESC ' IPA Password policy object class' SUP top MAY (ipaPwdMaxRepeat $ ipaPwdMaxSequence $ ipaPwdDictCheck $ ipaPwdUserCheck) X-ORIGIN 'IPA v4')`

Add new attributes to store the knobs for the four enabled features:

`attributeTypes: (2.16.840.1.113730.3.8.23.2 NAME 'ipaPwdMaxRepeat' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'IPA v4')`
`attributeTypes: (2.16.840.1.113730.3.8.23.3 NAME 'ipaPwdMaxSequence' QUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'IPA v4')`
`attributeTypes: (2.16.840.1.113730.3.8.23.4 NAME 'ipaPwdDictCheck' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE X-ORIGIN 'IPA v4')`
`attributeTypes: (2.16.840.1.113730.3.8.23.5 NAME 'ipaPwdUserCheck' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE X-ORIGIN 'IPA v4')`
